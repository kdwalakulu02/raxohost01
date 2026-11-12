//! raxosentinel signature database generations:
//! `<root>/<generation>/` directories plus a `current` file naming the active generation
//! (same layout raxosentinel uses with `--private-db-root <root> --private-generation <name>`).

use crate::Ctx;
use crate::activation::{self, Target};
use crate::archive::{self, Mapping};
use crate::config::{Config, SENTINEL_DB_SOURCE_DIR};
use crate::release::{Staging, rename_noreplace};
use crate::source;
use crate::state::{InstallRecord, State, TrackKey};
use crate::util::{
    atomic_write_owned, chown_tree, force_remove_dir, fsync_dir, now_rfc3339, resolve_owner,
    set_tree_modes, sha256_file,
};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub const DB_FILE: &str = "database.rsidb";

#[derive(Debug, Deserialize)]
pub struct DbManifest {
    #[serde(default)]
    pub project: Option<String>,
    pub generation: String,
    pub database_file_sha256: String,
}

fn owner(cfg: &Config) -> Result<Option<(u32, u32)>> {
    match cfg.sentineldb.as_ref().and_then(|d| d.owner.as_deref()) {
        Some(o) => resolve_owner(o)
            .with_context(|| format!("sentineldb.owner {o:?}"))
            .map(Some),
        None => Ok(None),
    }
}

/// raxosentinel accepts generation pointers of letters, digits, `_` and `-` (max 120 chars).
pub fn validate_generation(g: &str) -> Result<()> {
    if g.is_empty()
        || g.len() > 120
        || g.starts_with('-')
        || !g
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("invalid generation {g:?} (letters, digits, '_' and '-' only, max 120 chars)");
    }
    Ok(())
}

pub fn generation_dir(cfg: &Config, generation: &str) -> PathBuf {
    cfg.sentineldb_root().join(generation)
}

pub fn installed(cfg: &Config) -> Result<Vec<String>> {
    let root = cfg.sentineldb_root();
    let rd = match fs::read_dir(&root) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e).with_context(|| format!("read {}", root.display())),
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

pub fn active(cfg: &Config) -> Option<String> {
    fs::read_to_string(cfg.sentineldb_root().join("current"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Problems with an installed generation (empty = OK).
pub fn verify(cfg: &Config, generation: &str) -> Result<Vec<String>> {
    validate_generation(generation)?;
    let dir = generation_dir(cfg, generation);
    if !dir.is_dir() {
        bail!(
            "sentinel db generation {generation} is not installed ({})",
            dir.display()
        );
    }
    let mut problems = Vec::new();
    let db = dir.join(DB_FILE);
    if !db.is_file() {
        problems.push(format!("{DB_FILE} missing"));
        return Ok(problems);
    }
    let state = State::load(&cfg.state_file())?;
    match state
        .sentineldb
        .installed
        .get(generation)
        .and_then(|r| r.database_sha256.clone())
    {
        Some(expected) => {
            let actual = sha256_file(&db)?;
            if actual != expected {
                problems.push(format!(
                    "{DB_FILE} checksum mismatch: expected {expected}, got {actual}"
                ));
            }
        }
        None => println!(
            "  note: {generation} was not installed by raxohost; {DB_FILE} checksum not verified"
        ),
    }
    Ok(problems)
}

pub fn install(ctx: &Ctx, generation: &str) -> Result<crate::release::InstallOutcome> {
    use crate::release::InstallOutcome;
    let cfg = &ctx.cfg;
    validate_generation(generation)?;
    let root = cfg.sentineldb_root();
    let final_dir = root.join(generation);
    if fs::symlink_metadata(&final_dir).is_ok() {
        let problems = verify(cfg, generation)?;
        if problems.is_empty() {
            println!("sentinel db {generation}: already installed");
            return Ok(InstallOutcome::AlreadyInstalled);
        }
        bail!(
            "sentinel db {generation} is installed but fails verification (not modifying it):\n  {}",
            problems.join("\n  ")
        );
    }
    let own = owner(cfg)?;
    if ctx.dry_run {
        match source::locate(&cfg.sources, SENTINEL_DB_SOURCE_DIR, generation)? {
            Some(s) => println!(
                "[dry-run] would install sentinel db {generation} from {} into {}",
                s.display(),
                final_dir.display()
            ),
            None => bail!("{SENTINEL_DB_SOURCE_DIR}/{generation} not found in any source"),
        }
        return Ok(InstallOutcome::DryRun);
    }

    if !root.exists() {
        fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        if let Some((u, g)) = own {
            std::os::unix::fs::lchown(&root, Some(u), Some(g))?;
        }
    }
    let staging = Staging(root.join(format!(".staging-{generation}-{}", std::process::id())));
    force_remove_dir(&staging.0)?;
    fs::create_dir(&staging.0)?;
    fs::set_permissions(&staging.0, fs::Permissions::from_mode(0o700))?;

    let bundle = source::fetch_bundle(
        &cfg.sources,
        SENTINEL_DB_SOURCE_DIR,
        generation,
        &staging.0.join("download"),
    )?;
    println!(
        "sentinel db {generation}: fetched from {} (archive sha256 OK)",
        bundle.source
    );
    let manifest: DbManifest =
        serde_json::from_slice(&bundle.manifest_bytes).context("parse db manifest.json")?;
    if let Some(p) = &manifest.project
        && p != SENTINEL_DB_SOURCE_DIR
    {
        bail!("db manifest project is {p:?}, expected {SENTINEL_DB_SOURCE_DIR:?}");
    }
    if manifest.generation != generation {
        bail!(
            "db manifest describes generation {:?}, expected {generation:?}",
            manifest.generation
        );
    }
    let expected = manifest.database_file_sha256.to_ascii_lowercase();

    let tree = staging.0.join("tree");
    fs::create_dir(&tree)?;
    let mut skipped = Vec::new();
    let hashes = archive::extract(&bundle.archive, &tree, |path, _is_dir| {
        match path.strip_prefix(generation) {
            Ok(rel) => Ok(Mapping::Extract(rel.to_path_buf())),
            Err(_) => {
                skipped.push(path.display().to_string());
                Ok(Mapping::Skip)
            }
        }
    })?;
    if hashes.is_empty() {
        bail!("archive contains no {generation}/ directory");
    }
    match hashes.get(Path::new(DB_FILE)) {
        None => bail!("archive has no {generation}/{DB_FILE}"),
        Some(h) if *h != expected => {
            bail!("{DB_FILE} checksum mismatch: manifest {expected}, archive {h}")
        }
        Some(_) => {}
    }
    if !skipped.is_empty() {
        println!(
            "  ignored archive members outside {generation}/: {}",
            skipped.join(", ")
        );
    }
    set_tree_modes(&tree, 0o700, &|_| 0o600)?;
    if let Some((u, g)) = own {
        chown_tree(&tree, u, g)?;
    }
    rename_noreplace(&tree, &final_dir)?;
    fsync_dir(&root)?;
    drop(staging);

    let mut state = State::load(&cfg.state_file())?;
    state.sentineldb.installed.insert(
        generation.to_string(),
        InstallRecord {
            installed_at: now_rfc3339(),
            source: bundle.source.clone(),
            archive_sha256: bundle.archive_sha256.clone(),
            database_sha256: Some(expected),
        },
    );
    state.sentineldb.push("install", generation, None);
    state.save(&cfg.state_file())?;
    println!(
        "sentinel db {generation}: installed {} file(s) into {} ({DB_FILE} sha256 OK)",
        hashes.len(),
        final_dir.display()
    );
    Ok(InstallOutcome::Installed)
}

pub fn activate(ctx: &Ctx, generation: &str, restart: bool, action: &str) -> Result<()> {
    let cfg = &ctx.cfg;
    let problems = verify(cfg, generation)?;
    if !problems.is_empty() {
        bail!(
            "refusing to activate sentinel db {generation}:\n  {}",
            problems.join("\n  ")
        );
    }
    let own = owner(cfg)?;
    let current = cfg.sentineldb_root().join("current");
    let switch = move |g: &str| atomic_write_owned(&current, g.as_bytes(), 0o600, own);
    let target = Target {
        label: "sentinel db".into(),
        policy: cfg.sentineldb_policy(),
        switch: &switch,
        key: TrackKey::SentinelDb,
    };
    activation::activate(ctx, &target, generation, active(cfg), restart, action)
}

pub fn rollback(ctx: &Ctx, restart: bool) -> Result<()> {
    let state = State::load(&ctx.cfg.state_file())?;
    let prev = state
        .sentineldb
        .previous
        .clone()
        .context("sentinel db: no previous generation recorded")?;
    activate(ctx, &prev, restart, "rollback")
}

pub fn available(cfg: &Config) -> Vec<(String, Result<Vec<String>>)> {
    cfg.sources
        .iter()
        .map(|s| {
            (
                s.clone(),
                source::Source::parse(s).and_then(|src| src.list(SENTINEL_DB_SOURCE_DIR)),
            )
        })
        .collect()
}
