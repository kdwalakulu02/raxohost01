//! Small filesystem / hashing helpers shared by all modules.

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn sha256_reader(mut r: impl Read) -> Result<String> {
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = r.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex::encode(h.finalize()))
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let f = File::open(path).with_context(|| format!("open {}", path.display()))?;
    sha256_reader(f).with_context(|| format!("read {}", path.display()))
}

/// Parse a `sha256sum`-style file: `<hex>  <name>` or `<hex> *<name>` per line.
pub fn parse_sha256sums(text: &str) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim_end();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (hash, rest) = line
            .split_once(' ')
            .with_context(|| format!("SHA256SUMS line {}: malformed", i + 1))?;
        let name = rest.trim_start_matches([' ', '*']);
        if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("SHA256SUMS line {}: invalid hash", i + 1);
        }
        if name.is_empty() || name.contains('/') || name.starts_with('.') {
            bail!("SHA256SUMS line {}: invalid file name {name:?}", i + 1);
        }
        out.push((hash.to_ascii_lowercase(), name.to_string()));
    }
    Ok(out)
}

/// Names used for projects, release ids, generations, unit names.
pub fn validate_name(kind: &str, s: &str) -> Result<()> {
    let ok = !s.is_empty()
        && s.len() <= 200
        && !s.starts_with('.')
        && !s.starts_with('-')
        && !s.contains("..")
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '@'));
    if !ok {
        bail!(
            "invalid {kind} {s:?} (allowed: letters, digits, . _ + - @; no leading '.'/'-', no '..')"
        );
    }
    Ok(())
}

/// A relative path made only of normal components (no `..`, no absolute, no empty).
pub fn safe_relative(p: &str) -> Result<PathBuf> {
    let path = Path::new(p);
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            Component::Normal(x) => out.push(x),
            Component::CurDir => {}
            _ => bail!("unsafe path {p:?}"),
        }
    }
    if out.as_os_str().is_empty() {
        bail!("empty path {p:?}");
    }
    Ok(out)
}

pub fn fsync_dir(dir: &Path) -> Result<()> {
    let f = File::open(dir).with_context(|| format!("open dir {}", dir.display()))?;
    f.sync_all().ok();
    Ok(())
}

/// Write `data` to `path` atomically (temp file in the same dir + fsync + rename).
pub fn atomic_write(path: &Path, data: &[u8], mode: u32) -> Result<()> {
    atomic_write_owned(path, data, mode, None)
}

/// Like [`atomic_write`] but chowns the temp file before it is renamed into place.
pub fn atomic_write_owned(
    path: &Path,
    data: &[u8],
    mode: u32,
    owner: Option<(u32, u32)>,
) -> Result<()> {
    let dir = path.parent().context("path has no parent")?;
    let name = path.file_name().context("path has no file name")?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(data)?;
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::fchown(&f, Some(uid), Some(gid))
                .with_context(|| format!("chown {}", tmp.display()))?;
        }
        f.sync_all()?;
    }
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename to {}", path.display()));
    }
    fsync_dir(dir)?;
    Ok(())
}

/// Atomically point symlink `link` at `target` (temp symlink + rename over).
pub fn atomic_symlink(target: &Path, link: &Path) -> Result<()> {
    let dir = link.parent().context("link has no parent")?;
    let name = link.file_name().context("link has no name")?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        name.to_string_lossy(),
        std::process::id()
    ));
    let _ = fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)
        .with_context(|| format!("create symlink {}", tmp.display()))?;
    if let Err(e) = fs::rename(&tmp, link) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("rename symlink over {}", link.display()));
    }
    fsync_dir(dir)?;
    Ok(())
}

/// Recursively make a tree writable by the owner and remove it.
pub fn force_remove_dir(path: &Path) -> Result<()> {
    if fs::symlink_metadata(path).is_err() {
        return Ok(());
    }
    make_writable(path);
    fs::remove_dir_all(path).with_context(|| format!("remove {}", path.display()))
}

fn make_writable(path: &Path) {
    let Ok(md) = fs::symlink_metadata(path) else {
        return;
    };
    if md.is_dir() {
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        if let Ok(rd) = fs::read_dir(path) {
            for e in rd.flatten() {
                make_writable(&e.path());
            }
        }
    }
}

/// Walk a tree returning (relative path, metadata) for every entry (not following symlinks).
pub fn walk(root: &Path) -> Result<Vec<(PathBuf, fs::Metadata)>> {
    let mut out = Vec::new();
    let mut stack = vec![PathBuf::new()];
    while let Some(rel) = stack.pop() {
        let dir = root.join(&rel);
        let mut entries: Vec<_> = fs::read_dir(&dir)
            .with_context(|| format!("read dir {}", dir.display()))?
            .collect::<std::io::Result<_>>()?;
        entries.sort_by_key(|e| e.file_name());
        for e in entries {
            let r = rel.join(e.file_name());
            let md = fs::symlink_metadata(e.path())?;
            if md.is_dir() {
                stack.push(r.clone());
            }
            out.push((r, md));
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

/// Apply modes bottom-up: files get `file_mode(rel)`, dirs get `dir_mode`.
pub fn set_tree_modes(root: &Path, dir_mode: u32, file_mode: &dyn Fn(&Path) -> u32) -> Result<()> {
    let mut entries = walk(root)?;
    entries.reverse();
    for (rel, md) in entries {
        let p = root.join(&rel);
        let mode = if md.is_dir() {
            dir_mode
        } else {
            file_mode(&rel)
        };
        fs::set_permissions(&p, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {}", p.display()))?;
    }
    fs::set_permissions(root, fs::Permissions::from_mode(dir_mode))?;
    Ok(())
}

/// Resolve "user:group" (or "user") into uid/gid.
pub fn resolve_owner(spec: &str) -> Result<(u32, u32)> {
    let (user, group) = match spec.split_once(':') {
        Some((u, g)) => (u, Some(g)),
        None => (spec, None),
    };
    let (uid, user_gid) = lookup_user(user)?;
    let gid = match group {
        Some(g) if !g.is_empty() => lookup_group(g)?,
        _ => user_gid,
    };
    Ok((uid, gid))
}

fn lookup_user(user: &str) -> Result<(u32, u32)> {
    if let Ok(n) = user.parse::<u32>() {
        return Ok((n, n));
    }
    let c = std::ffi::CString::new(user)?;
    // SAFETY: getpwnam returns a pointer to static storage or null; we copy fields immediately.
    let pw = unsafe { libc::getpwnam(c.as_ptr()) };
    if pw.is_null() {
        bail!("unknown user {user:?}");
    }
    // SAFETY: pw is non-null and points to a valid passwd struct.
    unsafe { Ok(((*pw).pw_uid, (*pw).pw_gid)) }
}

fn lookup_group(group: &str) -> Result<u32> {
    if let Ok(n) = group.parse::<u32>() {
        return Ok(n);
    }
    let c = std::ffi::CString::new(group)?;
    // SAFETY: as above for getgrnam.
    let gr = unsafe { libc::getgrnam(c.as_ptr()) };
    if gr.is_null() {
        bail!("unknown group {group:?}");
    }
    // SAFETY: gr is non-null.
    unsafe { Ok((*gr).gr_gid) }
}

pub fn chown_tree(root: &Path, uid: u32, gid: u32) -> Result<()> {
    for (rel, _) in walk(root)? {
        let p = root.join(rel);
        std::os::unix::fs::lchown(&p, Some(uid), Some(gid))
            .with_context(|| format!("chown {}", p.display()))?;
    }
    std::os::unix::fs::lchown(root, Some(uid), Some(gid))
        .with_context(|| format!("chown {}", root.display()))?;
    Ok(())
}

/// RFC 3339 UTC timestamp, second precision.
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    format_rfc3339(secs)
}

pub fn format_rfc3339(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    // Civil-from-days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// Exclusive advisory lock held for the lifetime of the value.
pub struct LockGuard {
    _file: File,
}

pub fn acquire_lock(path: &Path) -> Result<LockGuard> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("open lock file {}", path.display()))?;
    // SAFETY: valid fd owned by `file`.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EWOULDBLOCK) {
            bail!(
                "another raxohost process holds the lock {} — refusing to run concurrently",
                path.display()
            );
        }
        return Err(err).with_context(|| format!("flock {}", path.display()));
    }
    Ok(LockGuard { _file: file })
}

/// Free bytes and total bytes of the filesystem containing `path`.
pub fn disk_space(path: &Path) -> Result<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: c is a valid C string, st is a valid out pointer.
    let rc = unsafe { libc::statvfs(c.as_ptr(), &mut st) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error()).context("statvfs");
    }
    let frsize = st.f_frsize as u64;
    Ok((st.f_bavail as u64 * frsize, st.f_blocks as u64 * frsize))
}

pub fn human_bytes(n: u64) -> String {
    const U: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", U[i])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1_793_771_542), "2026-11-04T05:52:22Z");
    }

    #[test]
    fn names() {
        assert!(validate_name("r", "0.1.0+abc1234").is_ok());
        assert!(validate_name("r", "../x").is_err());
        assert!(validate_name("r", "a/b").is_err());
        assert!(safe_relative("bin/x").is_ok());
        assert!(safe_relative("../x").is_err());
        assert!(safe_relative("/etc/passwd").is_err());
    }
}
