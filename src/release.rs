//! Project releases: install, verify, activate, rollback, prune.

use crate::Ctx;
use crate::activation::{self, Target};
use crate::archive::{self, Mapping};
use crate::config::{Config, SELF_PROJECT};
use crate::source;
use crate::state::{InstallRecord, State};
use crate::util::{
    atomic_symlink, force_remove_dir, fsync_dir, now_rfc3339, safe_relative, set_tree_modes,
    sha256_file, validate_name, walk,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Manifest {
    pub project: String,
    pub version: String,
    pub git_commit: String,
    #[serde(default)]
    pub git_ref: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub rustc: Option<String>,
    #[serde(default)]
    pub built_at: Option<String>,
    #[serde(default)]
    pub schema_version: Option<String>,
    #[serde(default)]
    pub requires: Option<String>,
    #[serde(default)]
    pub prebuilt: bool,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ManifestFile {
    pub path: String,
    pub sha256: String,
}

impl Manifest {
    pub fn parse(bytes: &[u8]) -> Result<Manifest> {
        serde_json::from_slice(bytes).context("parse manifest.json")
    }

    /// Check identity and file list sanity. Returns path -> sha256.
    pub fn validate(&self, project: &str, rid: &str) -> Result<BTreeMap<PathBuf, String>> {
        if self.project != project {
            bail!(
                "manifest project is {:?}, expected {project:?}",
                self.project
            );
        }
        let short: String = self.git_commit.chars().take(7).collect();
        let expect = format!("{}+{}", self.version, short);
        if expect != rid {
            bail!("manifest describes release {expect}, expected {rid}");
        }
        if self.files.is_empty() {
            bail!("manifest lists no files");
        }
        let mut out = BTreeMap::new();
        for f in &self.files {
            let p = safe_relative(&f.path).context("manifest file path")?;
            if p == Path::new("manifest.json") {
                bail!("manifest must not list manifest.json itself");
            }
            if f.sha256.len() != 64 || !f.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("manifest: invalid sha256 for {}", f.path);
            }
            if out.insert(p, f.sha256.to_ascii_lowercase()).is_some() {
                bail!("manifest lists {} twice", f.path);
            }
        }
        Ok(out)
    }
}

pub fn release_dir(cfg: &Config, project: &str, rid: &str) -> PathBuf {
    cfg.releases_dir(project).join(rid)
}

/// Installed release ids (sorted).
pub fn installed(cfg: &Config, project: &str) -> Result<Vec<String>> {
    let dir = cfg.releases_dir(project);
    let rd = match fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e).with_context(|| format!("read {}", dir.display())),
    };
    let mut v: Vec<String> = rd
        .flatten()
        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| !n.starts_with('.'))
        .collect();
    v.sort();
    Ok(v)
}

/// Release id the `current/<project>` symlink points at.
pub fn active(cfg: &Config, project: &str) -> Option<String> {
    let target = fs::read_link(cfg.current_link(project)).ok()?;
    target
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_string)
}

fn link_target(project: &str, rid: &str) -> PathBuf {
    Path::new("..").join("releases").join(project).join(rid)
}

/// Removes a staging directory on drop (also when read-only).
pub struct Staging(pub PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = force_remove_dir(&self.0);
    }
}

/// rename(2) without replacing an existing destination.
pub fn rename_noreplace(from: &Path, to: &Path) -> Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let a = std::ffi::CString::new(from.as_os_str().as_bytes())?;
    let b = std::ffi::CString::new(to.as_os_str().as_bytes())?;
    // SAFETY: valid NUL-terminated paths; AT_FDCWD for both.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            a.as_ptr(),
            libc::AT_FDCWD,
            b.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("rename {} -> {}", from.display(), to.display()));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    Installed,
    AlreadyInstalled,
    DryRun,
}

pub fn install(ctx: &Ctx, project: &str, rid: &str) -> Result<InstallOutcome> {
    let cfg = &ctx.cfg;
    cfg.project(project)?;
    validate_name("release id", rid)?;
    let final_dir = release_dir(cfg, project, rid);
    if fs::symlink_metadata(&final_dir).is_ok() {
        let rep = verify(cfg, project, rid)?;
        if rep.problems.is_empty() {
            println!(
                "{project} {rid}: already installed ({} files verified)",
                rep.files
            );
            return Ok(InstallOutcome::AlreadyInstalled);
        }
        bail!(
            "{project} {rid} is already installed but fails verification (not modifying it):\n  {}",
            rep.problems.join("\n  ")
        );
    }
    if ctx.dry_run {
        match source::locate(&cfg.sources, project, rid)? {
            Some(s) => println!(
                "[dry-run] would install {project} {rid} from {} into {}",
                s.display(),
                final_dir.display()
            ),
            None => bail!("{project}/{rid} not found in any source"),
        }
        return Ok(InstallOutcome::DryRun);
    }

    let rel_dir = cfg.releases_dir(project);
    fs::create_dir_all(&rel_dir).with_context(|| format!("create {}", rel_dir.display()))?;
    let staging = Staging(rel_dir.join(format!(".staging-{rid}-{}", std::process::id())));
    force_remove_dir(&staging.0)?;
    fs::create_dir(&staging.0)?;
    fs::set_permissions(&staging.0, fs::Permissions::from_mode(0o700))?;

    let bundle = source::fetch_bundle(&cfg.sources, project, rid, &staging.0.join("download"))?;
    println!(
        "{project} {rid}: fetched from {} (archive sha256 OK)",
        bundle.source
    );
    if !bundle.manifest_checksummed {
        println!(
            "  note: manifest.json is not listed in SHA256SUMS; trusting the archive checksum"
        );
    }
    let manifest = Manifest::parse(&bundle.manifest_bytes)?;
    let expected = manifest.validate(project, rid)?;
    if let Some(t) = &manifest.target
        && !t.starts_with(std::env::consts::ARCH)
    {
        println!(
            "  warning: release target {t} does not match host arch {}",
            std::env::consts::ARCH
        );
    }

    // Standard releases wrap everything in a single `<project>-<release>-<target>/` dir;
    // prebuilt ones may be flat.
    let members = archive::list(&bundle.archive)?;
    let tops: BTreeSet<_> = members
        .iter()
        .filter_map(|(p, _)| p.components().next().map(|c| c.as_os_str().to_owned()))
        .collect();
    let prefix: Option<PathBuf> = match tops.iter().collect::<Vec<_>>().as_slice() {
        [one]
            if one.to_string_lossy().starts_with(&format!("{project}-"))
                && members.iter().any(|(p, _)| p.components().count() > 1) =>
        {
            Some(PathBuf::from(one))
        }
        _ => None,
    };
    if prefix.is_none() && !manifest.prebuilt {
        bail!(
            "archive layout unexpected: expected a single top directory {project}-{rid}-<target>/"
        );
    }

    let tree = staging.0.join("tree");
    fs::create_dir(&tree)?;
    let mut skipped = Vec::new();
    let hashes = archive::extract(&bundle.archive, &tree, |path, is_dir| {
        let rel = match &prefix {
            Some(p) => match path.strip_prefix(p) {
                Ok(r) => r.to_path_buf(),
                Err(_) => bail!("archive member outside top directory: {}", path.display()),
            },
            None => path.to_path_buf(),
        };
        if is_dir || rel.as_os_str().is_empty() {
            return Ok(Mapping::Skip);
        }
        if rel == Path::new("manifest.json") || expected.contains_key(&rel) {
            return Ok(Mapping::Extract(rel));
        }
        if manifest.prebuilt {
            skipped.push(rel.display().to_string());
            return Ok(Mapping::Skip);
        }
        bail!(
            "archive contains file not listed in manifest: {}",
            rel.display()
        )
    })?;

    for (p, sha) in &expected {
        match hashes.get(p) {
            None => bail!(
                "file listed in manifest missing from archive: {}",
                p.display()
            ),
            Some(h) if h != sha => bail!(
                "checksum mismatch for {}: manifest {sha}, archive {h}",
                p.display()
            ),
            Some(_) => {}
        }
    }
    let inner_manifest = tree.join("manifest.json");
    if inner_manifest.exists() {
        if fs::read(&inner_manifest)? != bundle.manifest_bytes {
            bail!("manifest.json inside the archive differs from the published manifest.json");
        }
    } else {
        fs::write(&inner_manifest, &bundle.manifest_bytes)?;
    }
    if !skipped.is_empty() {
        println!(
            "  prebuilt archive: skipped files not listed in manifest: {}",
            skipped.join(", ")
        );
    }

    set_tree_modes(&tree, 0o555, &|rel: &Path| {
        if rel.starts_with("bin") { 0o555 } else { 0o444 }
    })?;
    rename_noreplace(&tree, &final_dir)?;
    fsync_dir(&rel_dir)?;
    drop(staging);

    let mut state = State::load(&cfg.state_file())?;
    state.project_mut(project).installed.insert(
        rid.to_string(),
        InstallRecord {
            installed_at: now_rfc3339(),
            source: bundle.source.clone(),
            archive_sha256: bundle.archive_sha256.clone(),
            database_sha256: None,
        },
    );
    state.project_mut(project).push("install", rid, None);
    state.save(&cfg.state_file())?;
    println!(
        "{project} {rid}: installed {} file(s) into {}",
        expected.len(),
        final_dir.display()
    );
    Ok(InstallOutcome::Installed)
}

#[derive(Debug, Default, Serialize)]
pub struct VerifyReport {
    pub files: usize,
    pub problems: Vec<String>,
}

/// Re-verify an installed release against its manifest. Never modifies anything.
pub fn verify(cfg: &Config, project: &str, rid: &str) -> Result<VerifyReport> {
    validate_name("release id", rid)?;
    let dir = release_dir(cfg, project, rid);
    let md = fs::symlink_metadata(&dir)
        .with_context(|| format!("{project} {rid} is not installed ({})", dir.display()))?;
    let mut rep = VerifyReport::default();
    if !md.is_dir() {
        rep.problems
            .push(format!("{} is not a directory", dir.display()));
        return Ok(rep);
    }
    let manifest = match fs::read(dir.join("manifest.json"))
        .map_err(anyhow::Error::from)
        .and_then(|b| Manifest::parse(&b))
    {
        Ok(m) => m,
        Err(e) => {
            rep.problems.push(format!("manifest.json: {e:#}"));
            return Ok(rep);
        }
    };
    let expected = match manifest.validate(project, rid) {
        Ok(e) => e,
        Err(e) => {
            rep.problems.push(format!("manifest.json: {e:#}"));
            return Ok(rep);
        }
    };
    if md.permissions().mode() & 0o222 != 0 {
        rep.problems.push("release directory is writable".into());
    }
    for (rel, md) in walk(&dir)? {
        if md.file_type().is_symlink() {
            rep.problems
                .push(format!("unexpected symlink {}", rel.display()));
        } else if md.is_file() {
            if rel != Path::new("manifest.json") && !expected.contains_key(&rel) {
                rep.problems
                    .push(format!("unexpected file {}", rel.display()));
            }
            if md.permissions().mode() & 0o222 != 0 {
                rep.problems.push(format!("{} is writable", rel.display()));
            }
        } else if md.is_dir() {
            if md.permissions().mode() & 0o222 != 0 {
                rep.problems.push(format!("{}/ is writable", rel.display()));
            }
        } else {
            rep.problems
                .push(format!("unexpected special file {}", rel.display()));
        }
    }
    for (rel, sha) in &expected {
        let p = dir.join(rel);
        match fs::symlink_metadata(&p) {
            Ok(m) if m.is_file() => {
                let actual = sha256_file(&p)?;
                if &actual != sha {
                    rep.problems
                        .push(format!("checksum mismatch: {}", rel.display()));
                }
                rep.files += 1;
            }
            _ => rep.problems.push(format!("missing file {}", rel.display())),
        }
    }
    Ok(rep)
}

fn switch_fn(cfg: &Config, project: &str) -> impl Fn(&str) -> Result<()> {
    let cur_dir = cfg.deploy_root.join("current");
    let link = cfg.current_link(project);
    let project = project.to_string();
    move |rid: &str| {
        fs::create_dir_all(&cur_dir)?;
        atomic_symlink(&link_target(&project, rid), &link)
    }
}

pub fn activate(ctx: &Ctx, project: &str, rid: &str, restart: bool, action: &str) -> Result<()> {
    let cfg = &ctx.cfg;
    cfg.project(project)?;
    validate_name("release id", rid)?;
    let rep = verify(cfg, project, rid)?;
    if !rep.problems.is_empty() {
        bail!(
            "refusing to activate {project} {rid}: verification failed:\n  {}",
            rep.problems.join("\n  ")
        );
    }
    let switch = switch_fn(cfg, project);
    let target = Target {
        label: project.to_string(),
        policy: cfg.project_policy(project)?,
        switch: &switch,
        key: crate::state::TrackKey::Project(project.to_string()),
    };
    activation::activate(ctx, &target, rid, active(cfg, project), restart, action)
}

pub fn rollback(ctx: &Ctx, project: &str, restart: bool) -> Result<()> {
    let state = State::load(&ctx.cfg.state_file())?;
    let prev = state
        .projects
        .get(project)
        .and_then(|t| t.previous.clone())
        .with_context(|| format!("{project}: no previous release recorded"))?;
    if !release_dir(&ctx.cfg, project, &prev).is_dir() {
        bail!("{project}: previous release {prev} is no longer installed");
    }
    activate(ctx, project, &prev, restart, "rollback")
}

pub fn deploy(ctx: &Ctx, project: &str, rid: &str, restart: bool) -> Result<()> {
    install(ctx, project, rid)?;
    if ctx.dry_run && !release_dir(&ctx.cfg, project, rid).is_dir() {
        println!("[dry-run] would then activate {project} {rid}");
        return Ok(());
    }
    activate(ctx, project, rid, restart, "deploy")
}

/// Releases that `prune --keep N` would remove: everything except active, previous and the
/// N most recently installed.
pub fn prune_candidates(cfg: &Config, project: &str, keep: usize) -> Result<Vec<String>> {
    let state = State::load(&cfg.state_file())?;
    let track = state.projects.get(project).cloned().unwrap_or_default();
    let protect: BTreeSet<String> = [active(cfg, project), track.active, track.previous]
        .into_iter()
        .flatten()
        .collect();
    let mut all: Vec<(String, String)> = installed(cfg, project)?
        .into_iter()
        .map(|r| {
            let when = track
                .installed
                .get(&r)
                .map(|i| i.installed_at.clone())
                .unwrap_or_default();
            (when, r)
        })
        .collect();
    all.sort_by(|a, b| b.cmp(a));
    Ok(all
        .into_iter()
        .skip(keep)
        .map(|(_, r)| r)
        .filter(|r| !protect.contains(r))
        .collect())
}

pub fn prune(ctx: &Ctx, project: &str, keep: usize, yes: bool) -> Result<()> {
    let cfg = &ctx.cfg;
    cfg.project(project)?;
    let victims = prune_candidates(cfg, project, keep)?;
    if victims.is_empty() {
        println!("{project}: nothing to prune");
        return Ok(());
    }
    for v in &victims {
        println!("{project}: prune {v}");
    }
    if ctx.dry_run {
        println!("[dry-run] would remove {} release(s)", victims.len());
        return Ok(());
    }
    if !yes {
        bail!("re-run with --yes to remove {} release(s)", victims.len());
    }
    let mut state = State::load(&cfg.state_file())?;
    for v in &victims {
        let dir = release_dir(cfg, project, v);
        let trash = cfg
            .releases_dir(project)
            .join(format!(".trash-{v}-{}", std::process::id()));
        fs::rename(&dir, &trash).with_context(|| format!("move {} aside", dir.display()))?;
        force_remove_dir(&trash)?;
        let t = state.project_mut(project);
        t.installed.remove(v);
        t.push("prune", v, None);
        println!("{project}: removed {v}");
    }
    state.save(&cfg.state_file())?;
    Ok(())
}

/// Install + activate raxohost itself and point <deploy_root>/bin/raxohost at it.
pub fn self_install(ctx: &Ctx, rid: &str, restart: bool) -> Result<()> {
    deploy(ctx, SELF_PROJECT, rid, restart)?;
    let link = ctx.cfg.deploy_root.join("bin/raxohost");
    let target = Path::new("../current/raxohost/bin/raxohost");
    if ctx.dry_run {
        println!(
            "[dry-run] would point {} -> {}",
            link.display(),
            target.display()
        );
        return Ok(());
    }
    if !ctx
        .cfg
        .current_link(SELF_PROJECT)
        .join("bin/raxohost")
        .is_file()
    {
        bail!("active raxohost release has no bin/raxohost");
    }
    fs::create_dir_all(link.parent().unwrap())?;
    atomic_symlink(target, &link)?;
    println!("{} -> {}", link.display(), target.display());
    Ok(())
}
