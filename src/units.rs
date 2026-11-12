//! Unit templates: render `{{...}}` placeholders and install into the systemd directory.

use crate::Ctx;
use crate::config::Config;
use crate::util::{atomic_write, validate_name};
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::Path;

pub const UNIT_EXTENSIONS: &[&str] = &["service", "target", "timer", "socket"];

/// Expand placeholders:
/// `{{deploy_root}}`, `{{current:<p>}}`, `{{data:<p>}}`, `{{config:<p>}}`, `{{run:<p>}}`, `{{logs:<p>}}`.
pub fn render_str(cfg: &Config, input: &str) -> Result<String> {
    let root = cfg.deploy_root.to_string_lossy();
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find("}}")
            .with_context(|| format!("unterminated placeholder near {:?}", &rest[start..]))?;
        let key = after[..end].trim();
        let value = match key.split_once(':') {
            None if key == "deploy_root" => root.to_string(),
            Some((kind, project)) => {
                let project = project.trim();
                validate_name("project in placeholder", project)?;
                let sub = match kind.trim() {
                    "current" => "current",
                    "data" => "data",
                    "config" => "config",
                    "run" => "run",
                    "logs" => "logs",
                    other => bail!("unknown placeholder kind {other:?} in {{{{{key}}}}}"),
                };
                format!("{root}/{sub}/{project}")
            }
            None => bail!("unknown placeholder {{{{{key}}}}}"),
        };
        out.push_str(&value);
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// Render all templates in the units dir: (unit name, content), sorted by name.
pub fn render_all(cfg: &Config) -> Result<Vec<(String, String)>> {
    let dir = cfg.units_dir();
    let rd = fs::read_dir(&dir).with_context(|| format!("read units dir {}", dir.display()))?;
    let mut out = Vec::new();
    for e in rd {
        let e = e?;
        let name = e.file_name().to_string_lossy().into_owned();
        let ext = Path::new(&name)
            .extension()
            .and_then(|x| x.to_str())
            .unwrap_or("");
        if !UNIT_EXTENSIONS.contains(&ext) || !e.file_type()?.is_file() {
            continue;
        }
        validate_name("unit file name", &name)?;
        let text = fs::read_to_string(e.path())
            .with_context(|| format!("read template {}", e.path().display()))?;
        let rendered = render_str(cfg, &text).with_context(|| format!("render {name}"))?;
        out.push((name, rendered));
    }
    out.sort();
    Ok(out)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnitStatus {
    New,
    Changed,
    Unchanged,
}

impl UnitStatus {
    pub fn label(self) -> &'static str {
        match self {
            UnitStatus::New => "new",
            UnitStatus::Changed => "changed",
            UnitStatus::Unchanged => "unchanged",
        }
    }
}

/// Compare rendered templates with what is installed in the systemd dir.
pub fn diff(cfg: &Config) -> Result<Vec<(String, String, UnitStatus)>> {
    let sd = cfg.systemd_dir();
    Ok(render_all(cfg)?
        .into_iter()
        .map(|(name, content)| {
            let st = match fs::read_to_string(sd.join(&name)) {
                Ok(cur) if cur == content => UnitStatus::Unchanged,
                Ok(_) => UnitStatus::Changed,
                Err(_) => UnitStatus::New,
            };
            (name, content, st)
        })
        .collect())
}

/// Render into <deploy_root>/systemd/ only.
pub fn render_to_deploy(ctx: &Ctx) -> Result<Vec<(String, String)>> {
    let rendered = render_all(&ctx.cfg)?;
    let out_dir = ctx.cfg.deploy_root.join("systemd");
    if ctx.dry_run {
        println!(
            "[dry-run] would render {} unit(s) into {}",
            rendered.len(),
            out_dir.display()
        );
        return Ok(rendered);
    }
    fs::create_dir_all(&out_dir)?;
    for (name, content) in &rendered {
        let p = out_dir.join(name);
        if fs::read_to_string(&p).ok().as_deref() != Some(content.as_str()) {
            atomic_write(&p, content.as_bytes(), 0o644)?;
        }
    }
    let names: Vec<&str> = rendered.iter().map(|(n, _)| n.as_str()).collect();
    for e in fs::read_dir(&out_dir)?.flatten() {
        let n = e.file_name().to_string_lossy().into_owned();
        if !n.starts_with('.') && !names.contains(&n.as_str()) {
            println!(
                "  note: {n} in {} has no template (stale?)",
                out_dir.display()
            );
        }
    }
    Ok(rendered)
}

pub fn install(ctx: &Ctx) -> Result<()> {
    let cfg = &ctx.cfg;
    render_to_deploy(ctx)?;
    let sd = cfg.systemd_dir();
    let d = diff(cfg)?;
    if d.is_empty() {
        println!("no unit templates in {}", cfg.units_dir().display());
    }
    let mut changed = 0;
    for (name, content, st) in &d {
        println!("  {:<9} {name}", st.label());
        if *st == UnitStatus::Unchanged {
            continue;
        }
        changed += 1;
        if ctx.dry_run {
            println!("[dry-run] would write {}", sd.join(name).display());
        } else {
            atomic_write(&sd.join(name), content.as_bytes(), 0o644)?;
        }
    }
    println!(
        "units: {changed} changed/new, {} unchanged (installed into {})",
        d.len() - changed,
        sd.display()
    );
    if changed > 0 {
        ctx.sys.daemon_reload()?;
    }
    for u in &cfg.enable {
        if !d.iter().any(|(n, _, _)| n == u) {
            println!("  note: {u} is listed in `enable` but has no template");
        }
        ctx.sys.enable(u)?;
        if !ctx.dry_run {
            println!("  enabled {u}");
        }
    }
    Ok(())
}
