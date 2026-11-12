//! `raxohost doctor`: read-only sanity checks of the deploy root.

use crate::Ctx;
use crate::util::{disk_space, human_bytes};
use crate::{release, sentineldb, units};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub const LAYOUT: &[&str] = &[
    "bin", "releases", "current", "config", "data", "run", "logs", "backups", "systemd",
];

#[derive(Default)]
pub struct Report {
    pub ok: usize,
    pub warn: usize,
    pub fail: usize,
}

impl Report {
    fn ok(&mut self, m: impl AsRef<str>) {
        self.ok += 1;
        println!("  OK    {}", m.as_ref());
    }
    fn warn(&mut self, m: impl AsRef<str>) {
        self.warn += 1;
        println!("  WARN  {}", m.as_ref());
    }
    fn fail(&mut self, m: impl AsRef<str>) {
        self.fail += 1;
        println!("  FAIL  {}", m.as_ref());
    }
}

fn world_writable(p: &Path) -> bool {
    fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o002 != 0)
        .unwrap_or(false)
}

pub fn run(ctx: &Ctx, config_path: &Path) -> Report {
    let cfg = &ctx.cfg;
    let mut r = Report::default();
    let root = &cfg.deploy_root;

    println!("config");
    r.ok(format!("{} parsed and valid", config_path.display()));
    if world_writable(config_path) {
        r.fail(format!("{} is world-writable", config_path.display()));
    }
    if cfg.sources.is_empty() {
        r.warn("no release sources configured");
    }
    for s in &cfg.sources {
        if !s.starts_with("https://") && !Path::new(s).is_dir() {
            r.warn(format!("source {s} is not an existing directory"));
        }
    }

    println!("layout");
    if !root.is_dir() {
        r.fail(format!("deploy root {} missing", root.display()));
        return r;
    }
    let before = r.fail;
    if world_writable(root) {
        r.fail(format!("{} is world-writable", root.display()));
    }
    for d in LAYOUT {
        let p = root.join(d);
        if !p.is_dir() {
            r.fail(format!("{} missing", p.display()));
        } else if world_writable(&p) {
            r.fail(format!("{} is world-writable", p.display()));
        }
    }
    if r.fail == before {
        r.ok(format!("{} layout present", root.display()));
    }

    println!("releases");
    for p in cfg.project_names() {
        let installed = release::installed(cfg, &p).unwrap_or_default();
        let link = cfg.current_link(&p);
        match fs::read_link(&link) {
            Ok(t) => {
                let name = release::active(cfg, &p).unwrap_or_default();
                if t != Path::new("..").join("releases").join(&p).join(&name) {
                    r.warn(format!(
                        "current/{p} -> {} (unexpected target form)",
                        t.display()
                    ));
                }
                if installed.contains(&name) {
                    r.ok(format!("current/{p} -> {name}"));
                } else {
                    r.fail(format!("current/{p} -> {} is dangling", t.display()));
                }
            }
            Err(_) if link.exists() => r.fail(format!("current/{p} is not a symlink")),
            Err(_) => {
                if cfg.projects.contains_key(&p) {
                    r.warn(format!("{p}: no active release"));
                }
            }
        }
        for rid in installed {
            match release::verify(cfg, &p, &rid) {
                Ok(v) if v.problems.is_empty() => {
                    r.ok(format!("{p} {rid}: {} files verified", v.files))
                }
                Ok(v) => r.fail(format!("{p} {rid}: {}", v.problems.join("; "))),
                Err(e) => r.fail(format!("{p} {rid}: {e:#}")),
            }
        }
    }
    let self_link = root.join("bin/raxohost");
    if fs::symlink_metadata(&self_link).is_ok() {
        if self_link.is_file() {
            r.ok("bin/raxohost resolves");
        } else {
            r.fail("bin/raxohost is dangling");
        }
    }

    println!("sentinel db");
    let db_root = cfg.sentineldb_root();
    if db_root.exists() {
        let mode = fs::metadata(&db_root)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0);
        if mode & 0o077 != 0 {
            r.warn(format!(
                "{} mode {mode:o} (expected 0700)",
                db_root.display()
            ));
        }
        match sentineldb::active(cfg) {
            Some(g) if sentineldb::generation_dir(cfg, &g).is_dir() => {
                match sentineldb::verify(cfg, &g) {
                    Ok(p) if p.is_empty() => r.ok(format!("active generation {g}")),
                    Ok(p) => r.fail(format!("active generation {g}: {}", p.join("; "))),
                    Err(e) => r.fail(format!("{e:#}")),
                }
            }
            Some(g) => r.fail(format!("current names missing generation {g}")),
            None => r.warn("no active generation"),
        }
    } else {
        r.warn(format!("{} does not exist", db_root.display()));
    }

    println!("units");
    match units::diff(cfg) {
        Ok(d) if d.is_empty() => r.warn(format!("no templates in {}", cfg.units_dir().display())),
        Ok(d) => {
            for (name, _, st) in d {
                match st {
                    units::UnitStatus::Unchanged => {
                        r.ok(format!("{name} installed and up to date"))
                    }
                    units::UnitStatus::Changed => r.warn(format!(
                        "{name} differs from template (run `service install`)"
                    )),
                    units::UnitStatus::New => r.warn(format!("{name} not installed")),
                }
            }
        }
        Err(e) => r.fail(format!("templates: {e:#}")),
    }

    println!("disk");
    match disk_space(root) {
        Ok((free, total)) => {
            let msg = format!("{} free of {}", human_bytes(free), human_bytes(total));
            if free < 1 << 30 || (total > 0 && free * 10 < total) {
                r.warn(msg);
            } else {
                r.ok(msg);
            }
        }
        Err(e) => r.warn(format!("disk space: {e:#}")),
    }

    println!(
        "\ndoctor: {} ok, {} warning(s), {} failure(s)",
        r.ok, r.warn, r.fail
    );
    r
}
