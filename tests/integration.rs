use flate2::Compression;
use flate2::write::GzEncoder;
use raxohost::config::Config;
use raxohost::release::{self, InstallOutcome};
use raxohost::state::State;
use raxohost::systemd::Systemd;
use raxohost::{Ctx, sentineldb, units, util};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;

// ---------- fakes & fixtures ----------

#[derive(Clone, Default)]
struct FakeSystemd {
    calls: Rc<RefCell<Vec<String>>>,
    states: Rc<RefCell<BTreeMap<String, String>>>,
}

impl FakeSystemd {
    fn calls(&self) -> Vec<String> {
        self.calls.borrow().clone()
    }
    fn log(&self, s: String) {
        self.calls.borrow_mut().push(s);
    }
}

impl Systemd for FakeSystemd {
    fn is_active(&self, unit: &str) -> String {
        self.states
            .borrow()
            .get(unit)
            .cloned()
            .unwrap_or_else(|| "active".into())
    }
    fn start(&self, unit: &str) -> anyhow::Result<()> {
        self.log(format!("start {unit}"));
        Ok(())
    }
    fn stop(&self, unit: &str) -> anyhow::Result<()> {
        self.log(format!("stop {unit}"));
        Ok(())
    }
    fn restart(&self, unit: &str) -> anyhow::Result<()> {
        self.log(format!("restart {unit}"));
        Ok(())
    }
    fn daemon_reload(&self) -> anyhow::Result<()> {
        self.log("daemon-reload".into());
        Ok(())
    }
    fn enable(&self, unit: &str) -> anyhow::Result<()> {
        self.log(format!("enable {unit}"));
        Ok(())
    }
    fn status(&self, _units: &[String]) -> anyhow::Result<()> {
        Ok(())
    }
    fn logs(&self, _units: &[String], _lines: u32, _follow: bool) -> anyhow::Result<()> {
        Ok(())
    }
}

fn sha(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

struct Env {
    _tmp: tempfile::TempDir,
    dist: PathBuf,
    root: PathBuf,
    sd: PathBuf,
}

impl Env {
    fn new() -> Env {
        let tmp = tempfile::Builder::new()
            .prefix("raxohost-test-")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap();
        let dist = tmp.path().join("dist");
        let root = tmp.path().join("deploy");
        let sd = tmp.path().join("systemd-system");
        for d in raxohost::doctor::LAYOUT {
            fs::create_dir_all(root.join(d)).unwrap();
        }
        fs::create_dir_all(&dist).unwrap();
        fs::create_dir_all(&sd).unwrap();
        Env {
            _tmp: tmp,
            dist,
            root,
            sd,
        }
    }

    fn config(&self, extra: &str) -> Config {
        let text = format!(
            r#"
deploy_root = "{}"
sources = ["{}"]
systemd_dir = "{}"
health_interval_secs = 0
{extra}
"#,
            self.root.display(),
            self.dist.display(),
            self.sd.display()
        );
        let p = self.root.join("config/raxohost/raxohost.toml");
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, text).unwrap();
        Config::load(&p).unwrap()
    }

    fn ctx(&self, extra: &str) -> (Ctx, FakeSystemd) {
        let fake = FakeSystemd::default();
        (
            Ctx::new(self.config(extra), Box::new(fake.clone()), false),
            fake,
        )
    }
}

/// Raw tar entry for building archives (including malicious ones).
enum Entry<'a> {
    File(&'a str, &'a [u8], u32),
    Symlink(&'a str, &'a str),
}

fn write_raw_name(h: &mut tar::Header, name: &str) {
    let gnu = h.as_gnu_mut().unwrap();
    gnu.name = [0; 100];
    gnu.name[..name.len()].copy_from_slice(name.as_bytes());
}

fn build_tar_gz(entries: &[Entry]) -> Vec<u8> {
    let mut b = tar::Builder::new(GzEncoder::new(Vec::new(), Compression::fast()));
    for e in entries {
        let mut h = tar::Header::new_gnu();
        match e {
            Entry::File(name, data, mode) => {
                h.set_entry_type(tar::EntryType::Regular);
                h.set_size(data.len() as u64);
                h.set_mode(*mode);
                write_raw_name(&mut h, name);
                h.set_cksum();
                b.append(&h, *data).unwrap();
            }
            Entry::Symlink(name, target) => {
                h.set_entry_type(tar::EntryType::Symlink);
                h.set_size(0);
                h.set_mode(0o777);
                write_raw_name(&mut h, name);
                h.set_link_name(target).unwrap();
                h.set_cksum();
                b.append(&h, &[][..]).unwrap();
            }
        }
    }
    b.into_inner().unwrap().finish().unwrap()
}

fn manifest_json(project: &str, version: &str, commit: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
    let files: Vec<_> = files
        .iter()
        .map(|(p, d)| serde_json::json!({"path": p, "sha256": sha(d)}))
        .collect();
    serde_json::to_vec_pretty(&serde_json::json!({
        "project": project, "version": version, "git_commit": commit, "git_ref": "HEAD",
        "target": "x86_64-unknown-linux-gnu", "rustc": "test", "built_at": "now",
        "schema_version": "", "requires": "", "files": files,
    }))
    .unwrap()
}

/// Publish a bundle dir `<dist>/<dir>/<id>/` with archive, manifest and SHA256SUMS.
fn publish(dist: &Path, dir: &str, id: &str, archive_name: &str, tgz: &[u8], manifest: &[u8]) {
    let out = dist.join(dir).join(id);
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join(archive_name), tgz).unwrap();
    fs::write(out.join("manifest.json"), manifest).unwrap();
    fs::write(
        out.join("SHA256SUMS"),
        format!(
            "{}  {archive_name}\n{}  manifest.json\n",
            sha(tgz),
            sha(manifest)
        ),
    )
    .unwrap();
}

/// A well-formed release: returns the release id.
fn make_release(
    dist: &Path,
    project: &str,
    version: &str,
    commit: &str,
    files: &[(&str, &[u8])],
) -> String {
    let rid = format!("{version}+{}", &commit[..7]);
    let top = format!("{project}-{rid}-x86_64-unknown-linux-gnu");
    let manifest = manifest_json(project, version, commit, files);
    let names: Vec<String> = files.iter().map(|(p, _)| format!("{top}/{p}")).collect();
    let mpath = format!("{top}/manifest.json");
    let mut entries: Vec<Entry> = files
        .iter()
        .zip(&names)
        .map(|((p, d), n)| Entry::File(n, d, if p.starts_with("bin/") { 0o755 } else { 0o644 }))
        .collect();
    entries.push(Entry::File(&mpath, &manifest, 0o644));
    let tgz = build_tar_gz(&entries);
    publish(
        dist,
        project,
        &rid,
        &format!("{top}.tar.gz"),
        &tgz,
        &manifest,
    );
    rid
}

const C1: &str = "1111111aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const C2: &str = "2222222bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const C3: &str = "3333333ccccccccccccccccccccccccccccccccc";

const APP: &str = r#"
[projects.app]
services = ["app.service", "app-worker.service"]
"#;

fn mode(p: &Path) -> u32 {
    fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

// ---------- releases ----------

#[test]
fn install_success_readonly_and_idempotent() {
    let env = Env::new();
    let rid = make_release(
        &env.dist,
        "app",
        "0.1.0",
        C1,
        &[
            ("bin/app", b"#!bin"),
            ("migrations/001.sql", b"create table x;"),
        ],
    );
    let (ctx, _) = env.ctx(APP);
    assert_eq!(
        release::install(&ctx, "app", &rid).unwrap(),
        InstallOutcome::Installed
    );
    let dir = env.root.join("releases/app").join(&rid);
    assert_eq!(fs::read(dir.join("bin/app")).unwrap(), b"#!bin");
    assert_eq!(mode(&dir), 0o555);
    assert_eq!(mode(&dir.join("bin")), 0o555);
    assert_eq!(mode(&dir.join("bin/app")), 0o555);
    assert_eq!(mode(&dir.join("migrations/001.sql")), 0o444);
    assert_eq!(mode(&dir.join("manifest.json")), 0o444);
    assert!(
        release::verify(&ctx.cfg, "app", &rid)
            .unwrap()
            .problems
            .is_empty()
    );
    // no staging leftovers
    assert_eq!(
        release::installed(&ctx.cfg, "app").unwrap(),
        vec![rid.clone()]
    );
    assert_eq!(
        fs::read_dir(env.root.join("releases/app")).unwrap().count(),
        1
    );
    // second install is an idempotent no-op
    assert_eq!(
        release::install(&ctx, "app", &rid).unwrap(),
        InstallOutcome::AlreadyInstalled
    );
    let st = State::load(&ctx.cfg.state_file()).unwrap();
    assert!(st.projects["app"].installed.contains_key(&rid));
}

#[test]
fn archive_checksum_mismatch_rejected() {
    let env = Env::new();
    let rid = make_release(&env.dist, "app", "0.1.0", C1, &[("bin/app", b"x")]);
    let sums = env.dist.join("app").join(&rid).join("SHA256SUMS");
    let text = fs::read_to_string(&sums).unwrap();
    fs::write(&sums, format!("{}{}", "0".repeat(64), &text[64..])).unwrap();
    let (ctx, _) = env.ctx(APP);
    let err = release::install(&ctx, "app", &rid).unwrap_err();
    assert!(format!("{err:#}").contains("checksum mismatch"), "{err:#}");
    assert!(release::installed(&ctx.cfg, "app").unwrap().is_empty());
    assert_eq!(
        fs::read_dir(env.root.join("releases/app")).unwrap().count(),
        0
    );
}

#[test]
fn file_checksum_mismatch_against_manifest_rejected() {
    let env = Env::new();
    let rid = format!("0.1.0+{}", &C1[..7]);
    let top = format!("app-{rid}-x86_64-unknown-linux-gnu");
    let manifest = manifest_json("app", "0.1.0", C1, &[("bin/app", b"original")]);
    let tgz = build_tar_gz(&[
        Entry::File(&format!("{top}/bin/app"), b"tampered", 0o755),
        Entry::File(&format!("{top}/manifest.json"), &manifest, 0o644),
    ]);
    publish(
        &env.dist,
        "app",
        &rid,
        &format!("{top}.tar.gz"),
        &tgz,
        &manifest,
    );
    let (ctx, _) = env.ctx(APP);
    let err = release::install(&ctx, "app", &rid).unwrap_err();
    assert!(
        format!("{err:#}").contains("checksum mismatch for bin/app"),
        "{err:#}"
    );
    assert!(release::installed(&ctx.cfg, "app").unwrap().is_empty());
}

fn malicious_release(env: &Env, evil: Entry) -> String {
    let rid = format!("0.1.0+{}", &C1[..7]);
    let top = format!("app-{rid}-x86_64-unknown-linux-gnu");
    let manifest = manifest_json("app", "0.1.0", C1, &[("bin/app", b"ok")]);
    let tgz = build_tar_gz(&[
        Entry::File(&format!("{top}/bin/app"), b"ok", 0o755),
        Entry::File(&format!("{top}/manifest.json"), &manifest, 0o644),
        evil,
    ]);
    publish(
        &env.dist,
        "app",
        &rid,
        &format!("{top}.tar.gz"),
        &tgz,
        &manifest,
    );
    rid
}

#[test]
fn path_traversal_rejected() {
    let env = Env::new();
    let rid = malicious_release(
        &env,
        Entry::File(
            "app-0.1.0+1111111-x86_64-unknown-linux-gnu/../../../evil",
            b"x",
            0o644,
        ),
    );
    let (ctx, _) = env.ctx(APP);
    let err = release::install(&ctx, "app", &rid).unwrap_err();
    assert!(format!("{err:#}").contains("path traversal"), "{err:#}");
    assert!(!env.root.join("evil").exists());
    assert!(!env.root.parent().unwrap().join("evil").exists());
    assert!(release::installed(&ctx.cfg, "app").unwrap().is_empty());
}

#[test]
fn absolute_path_and_symlink_rejected() {
    let env = Env::new();
    let rid = malicious_release(&env, Entry::File("/etc/raxohost-test-evil", b"x", 0o644));
    let (ctx, _) = env.ctx(APP);
    let err = release::install(&ctx, "app", &rid).unwrap_err();
    assert!(format!("{err:#}").contains("absolute path"), "{err:#}");
    assert!(!Path::new("/etc/raxohost-test-evil").exists());

    let env = Env::new();
    let rid = malicious_release(
        &env,
        Entry::Symlink(
            "app-0.1.0+1111111-x86_64-unknown-linux-gnu/bin/sh",
            "/bin/sh",
        ),
    );
    let (ctx, _) = env.ctx(APP);
    let err = release::install(&ctx, "app", &rid).unwrap_err();
    assert!(format!("{err:#}").contains("symlink"), "{err:#}");
    assert!(release::installed(&ctx.cfg, "app").unwrap().is_empty());
}

#[test]
fn unlisted_file_and_wrong_release_id_rejected() {
    let env = Env::new();
    let rid = malicious_release(
        &env,
        Entry::File(
            "app-0.1.0+1111111-x86_64-unknown-linux-gnu/bin/extra",
            b"x",
            0o755,
        ),
    );
    let (ctx, _) = env.ctx(APP);
    let err = release::install(&ctx, "app", &rid).unwrap_err();
    assert!(
        format!("{err:#}").contains("not listed in manifest"),
        "{err:#}"
    );

    // A bundle published under a release id that does not match its manifest.
    let env = Env::new();
    let rid = make_release(&env.dist, "app", "0.1.0", C1, &[("bin/app", b"x")]);
    fs::rename(
        env.dist.join("app").join(&rid),
        env.dist.join("app/9.9.9+1111111"),
    )
    .unwrap();
    let (ctx, _) = env.ctx(APP);
    let err = release::install(&ctx, "app", "9.9.9+1111111").unwrap_err();
    assert!(
        format!("{err:#}").contains("manifest describes release"),
        "{err:#}"
    );
}

#[test]
fn prebuilt_flat_archive_installs_listed_files_only() {
    let env = Env::new();
    let rid = format!("0.1.0+{}", &C1[..7]);
    let bin = b"prebuilt-binary";
    let mut m: serde_json::Value =
        serde_json::from_slice(&manifest_json("app", "0.1.0", C1, &[("bin/app", bin)])).unwrap();
    m["prebuilt"] = true.into();
    let manifest = serde_json::to_vec(&m).unwrap();
    let tgz = build_tar_gz(&[
        Entry::File("./LICENSE", b"license", 0o644),
        Entry::File("./bin/app", bin, 0o755),
        Entry::File("./install-staging.sh", b"#!/bin/sh", 0o755),
    ]);
    let out = env.dist.join("app").join(&rid);
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("app-1111111-linux-x86_64.tar.gz"), &tgz).unwrap();
    fs::write(out.join("manifest.json"), &manifest).unwrap();
    fs::write(
        out.join("SHA256SUMS"),
        format!("{}  app-1111111-linux-x86_64.tar.gz\n", sha(&tgz)),
    )
    .unwrap();
    let (ctx, _) = env.ctx(APP);
    release::install(&ctx, "app", &rid).unwrap();
    let dir = env.root.join("releases/app").join(&rid);
    assert_eq!(fs::read(dir.join("bin/app")).unwrap(), bin);
    assert!(!dir.join("LICENSE").exists());
    assert!(!dir.join("install-staging.sh").exists());
    assert_eq!(fs::read(dir.join("manifest.json")).unwrap(), manifest);
    assert!(
        release::verify(&ctx.cfg, "app", &rid)
            .unwrap()
            .problems
            .is_empty()
    );
}

#[test]
fn verify_detects_tampering() {
    let env = Env::new();
    let rid = make_release(&env.dist, "app", "0.1.0", C1, &[("bin/app", b"good")]);
    let (ctx, _) = env.ctx(APP);
    release::install(&ctx, "app", &rid).unwrap();
    let f = env.root.join("releases/app").join(&rid).join("bin/app");
    fs::set_permissions(&f, fs::Permissions::from_mode(0o755)).unwrap();
    fs::write(&f, b"evil").unwrap();
    let rep = release::verify(&ctx.cfg, "app", &rid).unwrap();
    assert!(rep.problems.iter().any(|p| p.contains("checksum mismatch")));
    assert!(rep.problems.iter().any(|p| p.contains("writable")));
    let err = release::activate(&ctx, "app", &rid, true, "activate").unwrap_err();
    assert!(format!("{err:#}").contains("verification failed"));
    assert!(fs::symlink_metadata(env.root.join("current/app")).is_err());
}

#[test]
fn activate_and_rollback_symlink_and_state() {
    let env = Env::new();
    let r1 = make_release(&env.dist, "app", "0.1.0", C1, &[("bin/app", b"v1")]);
    let r2 = make_release(&env.dist, "app", "0.2.0", C2, &[("bin/app", b"v2")]);
    let (ctx, fake) = env.ctx(APP);
    release::deploy(&ctx, "app", &r1, true).unwrap();
    release::deploy(&ctx, "app", &r2, true).unwrap();

    let link = env.root.join("current/app");
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from(format!("../releases/app/{r2}"))
    );
    assert_eq!(fs::read(link.join("bin/app")).unwrap(), b"v2");
    let st = State::load(&ctx.cfg.state_file()).unwrap();
    assert_eq!(st.projects["app"].active.as_deref(), Some(r2.as_str()));
    assert_eq!(st.projects["app"].previous.as_deref(), Some(r1.as_str()));
    assert_eq!(
        fake.calls(),
        vec![
            "restart app.service",
            "restart app-worker.service",
            "restart app.service",
            "restart app-worker.service"
        ]
    );

    release::rollback(&ctx, "app", true).unwrap();
    assert_eq!(fs::read(link.join("bin/app")).unwrap(), b"v1");
    let st = State::load(&ctx.cfg.state_file()).unwrap();
    assert_eq!(st.projects["app"].active.as_deref(), Some(r1.as_str()));
    assert_eq!(st.projects["app"].previous.as_deref(), Some(r2.as_str()));
    assert_eq!(
        st.projects["app"].history.last().unwrap().action,
        "rollback"
    );

    // --no-restart does not touch services
    let n = fake.calls().len();
    release::activate(&ctx, "app", &r2, false, "activate").unwrap();
    assert_eq!(fake.calls().len(), n);
    assert_eq!(fs::read(link.join("bin/app")).unwrap(), b"v2");
    // no temp symlinks left behind
    assert_eq!(fs::read_dir(env.root.join("current")).unwrap().count(), 1);
}

#[test]
fn auto_rollback_on_failing_health_check() {
    let env = Env::new();
    let r1 = make_release(
        &env.dist,
        "app",
        "0.1.0",
        C1,
        &[("bin/app", b"v1"), ("bin/healthy", b"#!/bin/sh\n")],
    );
    let r2 = make_release(&env.dist, "app", "0.2.0", C2, &[("bin/app", b"v2")]);
    let extra = r#"
[projects.app]
services = ["app.service"]
health_retries = 2
health_interval_secs = 0
[[projects.app.health]]
type = "command"
argv = ["test", "-f", "{{current:app}}/bin/healthy"]
[[projects.app.health]]
type = "unit"
unit = "app.service"
"#;
    let (ctx, fake) = env.ctx(extra);
    release::deploy(&ctx, "app", &r1, true).unwrap();
    let err = release::deploy(&ctx, "app", &r2, true).unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("automatically rolled back"), "{msg}");
    assert!(!msg.contains("also unhealthy"), "{msg}");

    let link = env.root.join("current/app");
    assert_eq!(
        fs::read_link(&link).unwrap(),
        PathBuf::from(format!("../releases/app/{r1}"))
    );
    let st = State::load(&ctx.cfg.state_file()).unwrap();
    let t = &st.projects["app"];
    assert_eq!(t.active.as_deref(), Some(r1.as_str()));
    assert_eq!(t.previous, None);
    assert_eq!(t.history.last().unwrap().action, "auto-rollback");
    assert_eq!(t.history.last().unwrap().from.as_deref(), Some(r2.as_str()));
    // initial deploy, failed deploy, restart after rollback
    assert_eq!(fake.calls(), vec!["restart app.service"; 3]);

    // A failed unit state also triggers rollback.
    let r3 = make_release(
        &env.dist,
        "app",
        "0.3.0",
        C3,
        &[("bin/app", b"v3"), ("bin/healthy", b"#!/bin/sh\n")],
    );
    fake.states
        .borrow_mut()
        .insert("app.service".into(), "failed".into());
    let err = release::deploy(&ctx, "app", &r3, true).unwrap_err();
    assert!(format!("{err:#}").contains("also unhealthy"), "{err:#}");
    assert_eq!(
        release::active(&ctx.cfg, "app").as_deref(),
        Some(r1.as_str())
    );
}

#[test]
fn prune_keeps_active_and_previous() {
    let env = Env::new();
    let r1 = make_release(&env.dist, "app", "0.1.0", C1, &[("bin/app", b"v1")]);
    let r2 = make_release(&env.dist, "app", "0.2.0", C2, &[("bin/app", b"v2")]);
    let r3 = make_release(&env.dist, "app", "0.3.0", C3, &[("bin/app", b"v3")]);
    let (ctx, _) = env.ctx(APP);
    release::deploy(&ctx, "app", &r1, false).unwrap();
    release::install(&ctx, "app", &r2).unwrap();
    release::deploy(&ctx, "app", &r3, false).unwrap();
    // active r3, previous r1 -> only r2 is a candidate
    assert_eq!(
        release::prune_candidates(&ctx.cfg, "app", 0).unwrap(),
        vec![r2.clone()]
    );
    assert!(release::prune(&ctx, "app", 0, false).is_err());
    release::prune(&ctx, "app", 0, true).unwrap();
    assert_eq!(release::installed(&ctx.cfg, "app").unwrap(), vec![r1, r3]);
}

#[test]
fn dry_run_changes_nothing() {
    let env = Env::new();
    let rid = make_release(&env.dist, "app", "0.1.0", C1, &[("bin/app", b"v1")]);
    let fake = FakeSystemd::default();
    let ctx = Ctx::new(env.config(APP), Box::new(fake.clone()), true);
    release::deploy(&ctx, "app", &rid, true).unwrap();
    assert!(release::installed(&ctx.cfg, "app").unwrap().is_empty());
    assert!(fs::symlink_metadata(env.root.join("current/app")).is_err());
    assert!(!ctx.cfg.state_file().exists());
    assert!(fake.calls().is_empty());
}

#[test]
fn lock_is_exclusive() {
    let env = Env::new();
    let (ctx, _) = env.ctx(APP);
    let g = ctx.lock().unwrap();
    let err = ctx.lock().err().unwrap();
    assert!(format!("{err:#}").contains("another raxohost"));
    drop(g);
    ctx.lock().unwrap();
}

// ---------- sentinel db ----------

const DB_CFG: &str = r#"
[projects.raxosentinel]
services = ["raxosentinel.service"]
"#;

fn make_db(dist: &Path, generation: &str, db: &[u8], manifest_sha: Option<&str>) {
    let dbpath = format!("./{generation}/database.rsidb");
    let reg = format!("./{generation}/registry.json");
    let tgz = build_tar_gz(&[
        Entry::File("./current", generation.as_bytes(), 0o600),
        Entry::File(&dbpath, db, 0o600),
        Entry::File(&reg, b"{}", 0o600),
        Entry::File("./update_status.json", b"{}", 0o600),
    ]);
    let manifest = serde_json::to_vec(&serde_json::json!({
        "project": "raxosentinel-db", "generation": generation,
        "database_file_sha256": manifest_sha.map(str::to_string).unwrap_or_else(|| sha(db)),
        "private": true,
    }))
    .unwrap();
    let out = dist.join("raxosentinel-db").join(generation);
    fs::create_dir_all(&out).unwrap();
    let name = format!("raxosentinel-private-{generation}.tar.gz");
    fs::write(out.join(&name), &tgz).unwrap();
    fs::write(out.join("manifest.json"), &manifest).unwrap();
    fs::write(out.join("SHA256SUMS"), format!("{}  {name}\n", sha(&tgz))).unwrap();
}

#[test]
fn sentineldb_install_activate_rollback() {
    let env = Env::new();
    make_db(&env.dist, "gen-a", b"DB-A", None);
    make_db(&env.dist, "gen-b", b"DB-B", None);
    make_db(&env.dist, "gen-bad", b"DB-X", Some(&"0".repeat(64)));
    let (ctx, fake) = env.ctx(DB_CFG);
    let root = env.root.join("data/raxosentinel/rsidb");

    sentineldb::install(&ctx, "gen-a").unwrap();
    sentineldb::install(&ctx, "gen-b").unwrap();
    assert_eq!(
        fs::read(root.join("gen-a/database.rsidb")).unwrap(),
        b"DB-A"
    );
    assert!(root.join("gen-a/registry.json").is_file());
    assert!(!root.join("gen-a/current").exists());
    assert_eq!(mode(&root.join("gen-a")), 0o700);
    assert_eq!(mode(&root.join("gen-a/database.rsidb")), 0o600);
    assert_eq!(
        sentineldb::installed(&ctx.cfg).unwrap(),
        vec!["gen-a", "gen-b"]
    );

    let err = sentineldb::install(&ctx, "gen-bad").unwrap_err();
    assert!(format!("{err:#}").contains("checksum mismatch"), "{err:#}");
    assert!(!root.join("gen-bad").exists());

    sentineldb::activate(&ctx, "gen-a", true, "activate").unwrap();
    sentineldb::activate(&ctx, "gen-b", true, "activate").unwrap();
    assert_eq!(fs::read_to_string(root.join("current")).unwrap(), "gen-b");
    assert_eq!(mode(&root.join("current")), 0o600);
    let st = State::load(&ctx.cfg.state_file()).unwrap();
    assert_eq!(st.sentineldb.active.as_deref(), Some("gen-b"));
    assert_eq!(st.sentineldb.previous.as_deref(), Some("gen-a"));

    sentineldb::rollback(&ctx, true).unwrap();
    assert_eq!(sentineldb::active(&ctx.cfg).as_deref(), Some("gen-a"));
    assert_eq!(fake.calls(), vec!["restart raxosentinel.service"; 3]);

    // corrupting the database file blocks activation
    fs::write(root.join("gen-b/database.rsidb"), b"corrupt").unwrap();
    assert!(sentineldb::activate(&ctx, "gen-b", true, "activate").is_err());
    assert_eq!(sentineldb::active(&ctx.cfg).as_deref(), Some("gen-a"));
}

#[test]
fn sentineldb_auto_rollback_on_health_failure() {
    let env = Env::new();
    make_db(&env.dist, "gen-a", b"DB-A", None);
    make_db(&env.dist, "gen-b", b"DB-B", None);
    let marker = env.root.join("run/healthy");
    let extra = format!(
        r#"{DB_CFG}
[sentineldb]
[[sentineldb.health]]
type = "command"
argv = ["test", "-e", "{}"]
"#,
        marker.display()
    );
    let (ctx, _) = env.ctx(&extra);
    sentineldb::install(&ctx, "gen-a").unwrap();
    sentineldb::install(&ctx, "gen-b").unwrap();
    fs::write(&marker, b"").unwrap();
    sentineldb::activate(&ctx, "gen-a", true, "activate").unwrap();
    fs::remove_file(&marker).unwrap();
    let err = sentineldb::activate(&ctx, "gen-b", true, "activate").unwrap_err();
    assert!(
        format!("{err:#}").contains("rolled back to gen-a"),
        "{err:#}"
    );
    assert_eq!(sentineldb::active(&ctx.cfg).as_deref(), Some("gen-a"));
}

// ---------- units ----------

#[test]
fn template_rendering_and_service_install() {
    let env = Env::new();
    let (ctx, fake) = env.ctx(r#"enable = ["raxo.target"]"#);
    let ud = ctx.cfg.units_dir();
    fs::create_dir_all(&ud).unwrap();
    fs::write(
        ud.join("raxosentinel.service"),
        "ExecStart={{current:raxosentinel}}/bin/raxosentinel --private-db-root {{data:raxosentinel}}/rsidb\n\
         EnvironmentFile={{config:raxosentinel}}/env\nRuntimeDirectory={{ run:raxosentinel }}\nRoot={{deploy_root}}\n",
    )
    .unwrap();
    fs::write(ud.join("raxo.target"), "[Unit]\nDescription=raxo\n").unwrap();
    fs::write(ud.join("README"), "ignored").unwrap();

    let r = env.root.display().to_string();
    let rendered = units::render_all(&ctx.cfg).unwrap();
    assert_eq!(rendered.len(), 2);
    assert_eq!(
        rendered[1].1,
        format!(
            "ExecStart={r}/current/raxosentinel/bin/raxosentinel --private-db-root {r}/data/raxosentinel/rsidb\n\
             EnvironmentFile={r}/config/raxosentinel/env\nRuntimeDirectory={r}/run/raxosentinel\nRoot={r}\n"
        )
    );

    units::install(&ctx).unwrap();
    assert!(env.sd.join("raxosentinel.service").is_file());
    assert!(env.root.join("systemd/raxo.target").is_file());
    assert_eq!(fake.calls(), vec!["daemon-reload", "enable raxo.target"]);
    // unchanged second time: no daemon-reload
    units::install(&ctx).unwrap();
    assert_eq!(
        fake.calls()
            .iter()
            .filter(|c| *c == "daemon-reload")
            .count(),
        1
    );
    assert!(
        units::diff(&ctx.cfg)
            .unwrap()
            .iter()
            .all(|(_, _, s)| *s == units::UnitStatus::Unchanged)
    );

    // unknown placeholders are errors
    fs::write(ud.join("bad.service"), "X={{secret:foo}}\n").unwrap();
    assert!(units::render_all(&ctx.cfg).is_err());
    assert!(util::safe_relative("../x").is_err());
}
