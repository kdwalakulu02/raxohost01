//! Safe tar.gz extraction: only regular files and directories, no absolute paths,
//! no `..`, no symlinks/hardlinks/devices, no duplicate entries.

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use tar::EntryType;

pub enum Mapping {
    /// Extract to this path relative to the destination.
    Extract(PathBuf),
    Skip,
}

/// Normalize an archive member path; rejects absolute paths and `..`.
pub fn normalize(p: &Path) -> Result<PathBuf> {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::CurDir => {}
            Component::ParentDir => bail!("path traversal in archive member {:?}", p),
            Component::RootDir | Component::Prefix(_) => {
                bail!("absolute path in archive member {:?}", p)
            }
        }
    }
    Ok(out)
}

/// List normalized member paths and whether they are directories (validating entry types).
pub fn list(archive: &Path) -> Result<Vec<(PathBuf, bool)>> {
    let mut out = Vec::new();
    walk(archive, |path, kind, _| {
        out.push((path.to_path_buf(), kind == Kind::Dir));
        Ok(())
    })?;
    Ok(out)
}

#[derive(PartialEq, Clone, Copy)]
enum Kind {
    Dir,
    File,
}

fn walk(archive: &Path, mut f: impl FnMut(&Path, Kind, &mut dyn Read) -> Result<()>) -> Result<()> {
    let file = File::open(archive).with_context(|| format!("open {}", archive.display()))?;
    let mut ar = tar::Archive::new(GzDecoder::new(std::io::BufReader::new(file)));
    for entry in ar.entries().context("read archive")? {
        let mut entry = entry.context("read archive entry")?;
        let raw = entry.path().context("archive member path")?.into_owned();
        let path = normalize(&raw)?;
        let kind = match entry.header().entry_type() {
            EntryType::Regular | EntryType::Continuous => Kind::File,
            EntryType::Directory => Kind::Dir,
            EntryType::XGlobalHeader | EntryType::XHeader => continue,
            EntryType::Symlink => bail!("symlink in archive not allowed: {:?}", raw),
            EntryType::Link => bail!("hardlink in archive not allowed: {:?}", raw),
            other => bail!("unsupported archive member type {other:?}: {:?}", raw),
        };
        if path.as_os_str().is_empty() {
            if kind == Kind::Dir {
                continue;
            }
            bail!("archive member with empty path");
        }
        f(&path, kind, &mut entry)?;
    }
    Ok(())
}

/// Extract into `dest` (which must exist and be empty/new). `map` decides where each member goes.
/// Returns sha256 of every extracted regular file keyed by destination-relative path.
pub fn extract(
    archive: &Path,
    dest: &Path,
    mut map: impl FnMut(&Path, bool) -> Result<Mapping>,
) -> Result<BTreeMap<PathBuf, String>> {
    let mut hashes = BTreeMap::new();
    walk(archive, |path, kind, reader| {
        let rel = match map(path, kind == Kind::Dir)? {
            Mapping::Skip => return Ok(()),
            Mapping::Extract(r) => normalize(&r)?,
        };
        if rel.as_os_str().is_empty() {
            return Ok(());
        }
        let target = dest.join(&rel);
        if kind == Kind::Dir {
            fs::create_dir_all(&target).with_context(|| format!("mkdir {}", target.display()))?;
            return Ok(());
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
        let mut out = File::create_new(&target)
            .with_context(|| format!("duplicate or unwritable archive member {}", rel.display()))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
            out.write_all(&buf[..n])?;
        }
        out.sync_all()?;
        hashes.insert(rel, hex::encode(h.finalize()));
        Ok(())
    })?;
    Ok(hashes)
}
