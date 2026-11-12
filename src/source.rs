//! Release sources: local directories or https:// base URLs laid out like `dist/`:
//! `<base>/<project>/<release-id>/{SHA256SUMS,manifest.json,<archive>.tar.gz}`.
//! HTTPS sources may publish `<base>/<project>/index.txt` (one release id per line) for listing.

use crate::util::{parse_sha256sums, sha256_file, validate_name};
use anyhow::{Context, Result, bail};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[derive(Debug, Clone)]
pub enum Source {
    Local(PathBuf),
    Https(String),
}

impl Source {
    pub fn parse(s: &str) -> Result<Source> {
        if s.starts_with("https://") {
            Ok(Source::Https(s.trim_end_matches('/').to_string()))
        } else if s.contains("://") {
            bail!("unsupported source {s:?} (use a local path or https://)")
        } else {
            Ok(Source::Local(PathBuf::from(s)))
        }
    }

    pub fn display(&self) -> String {
        match self {
            Source::Local(p) => p.display().to_string(),
            Source::Https(u) => u.clone(),
        }
    }

    fn url(base: &str, parts: &[&str]) -> String {
        let mut u = base.to_string();
        for p in parts {
            u.push('/');
            u.push_str(&p.replace('%', "%25").replace('+', "%2B"));
        }
        u
    }

    /// Fetch `<base>/<parts...>`; Ok(None) if it does not exist.
    fn get_bytes(&self, parts: &[&str], max: usize) -> Result<Option<Vec<u8>>> {
        match self {
            Source::Local(base) => {
                let p = parts.iter().fold(base.clone(), |acc, x| acc.join(x));
                match fs::read(&p) {
                    Ok(b) if b.len() <= max => Ok(Some(b)),
                    Ok(_) => bail!("{} is unexpectedly large", p.display()),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(e).with_context(|| format!("read {}", p.display())),
                }
            }
            Source::Https(base) => {
                let url = Self::url(base, parts);
                let mut resp = match http_get(&url)? {
                    Some(r) => r,
                    None => return Ok(None),
                };
                let mut v = Vec::new();
                resp.body_mut()
                    .as_reader()
                    .take(max as u64 + 1)
                    .read_to_end(&mut v)
                    .with_context(|| format!("download {url}"))?;
                if v.len() > max {
                    bail!("{url} is unexpectedly large");
                }
                Ok(Some(v))
            }
        }
    }

    /// Copy/download `<base>/<parts...>` into `dest` (must not exist).
    fn get_file(&self, parts: &[&str], dest: &Path) -> Result<()> {
        let mut out =
            File::create_new(dest).with_context(|| format!("create {}", dest.display()))?;
        match self {
            Source::Local(base) => {
                let p = parts.iter().fold(base.clone(), |acc, x| acc.join(x));
                let mut f = File::open(&p).with_context(|| format!("open {}", p.display()))?;
                std::io::copy(&mut f, &mut out).with_context(|| format!("copy {}", p.display()))?;
            }
            Source::Https(base) => {
                let url = Self::url(base, parts);
                let mut resp = http_get(&url)?.with_context(|| format!("{url}: not found"))?;
                std::io::copy(&mut resp.body_mut().as_reader(), &mut out)
                    .with_context(|| format!("download {url}"))?;
            }
        }
        out.flush()?;
        out.sync_all()?;
        Ok(())
    }

    /// Release ids (or generations) published under `<base>/<dir>/`.
    pub fn list(&self, dir: &str) -> Result<Vec<String>> {
        let mut v = match self {
            Source::Local(base) => {
                let d = base.join(dir);
                let rd = match fs::read_dir(&d) {
                    Ok(rd) => rd,
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
                    Err(e) => return Err(e).with_context(|| format!("read {}", d.display())),
                };
                rd.flatten()
                    .filter(|e| e.path().join("SHA256SUMS").is_file())
                    .filter_map(|e| e.file_name().into_string().ok())
                    .collect::<Vec<_>>()
            }
            Source::Https(_) => match self.get_bytes(&[dir, "index.txt"], 1 << 20)? {
                None => bail!("no {dir}/index.txt published (listing unsupported)"),
                Some(b) => String::from_utf8_lossy(&b)
                    .lines()
                    .map(|l| l.trim().to_string())
                    .filter(|l| !l.is_empty() && !l.starts_with('#'))
                    .collect(),
            },
        };
        v.retain(|x| validate_name("release id", x).is_ok());
        v.sort();
        Ok(v)
    }
}

fn http_get(url: &str) -> Result<Option<ureq::http::Response<ureq::Body>>> {
    let agent = ureq::Agent::new_with_config(
        ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(15)))
            .http_status_as_error(false)
            .build(),
    );
    let resp = agent
        .get(url)
        .call()
        .with_context(|| format!("GET {url}"))?;
    match resp.status().as_u16() {
        200 => Ok(Some(resp)),
        404 | 410 => Ok(None),
        c => bail!("GET {url}: HTTP {c}"),
    }
}

/// A verified download of a release (or DB generation) bundle.
#[derive(Debug)]
pub struct Bundle {
    pub source: String,
    pub archive: PathBuf,
    pub archive_sha256: String,
    pub manifest_bytes: Vec<u8>,
    /// Whether manifest.json is covered by SHA256SUMS.
    pub manifest_checksummed: bool,
}

/// First source that publishes `<dir>/<id>/SHA256SUMS`.
pub fn locate(sources: &[String], dir: &str, id: &str) -> Result<Option<Source>> {
    for s in sources {
        let src = Source::parse(s)?;
        let found = match &src {
            Source::Local(b) => b.join(dir).join(id).join("SHA256SUMS").is_file(),
            Source::Https(_) => src.get_bytes(&[dir, id, "SHA256SUMS"], 1 << 20)?.is_some(),
        };
        if found {
            return Ok(Some(src));
        }
    }
    Ok(None)
}

/// Fetch SHA256SUMS, manifest.json and the archive from the first source that has the bundle,
/// verifying checksums. The archive is written into `download_dir`.
pub fn fetch_bundle(
    sources: &[String],
    dir: &str,
    id: &str,
    download_dir: &Path,
) -> Result<Bundle> {
    if sources.is_empty() {
        bail!("no release sources configured");
    }
    let src = locate(sources, dir, id)?.with_context(|| {
        format!(
            "{dir}/{id} not found in any source ({})",
            sources.join(", ")
        )
    })?;
    let sums_text = src
        .get_bytes(&[dir, id, "SHA256SUMS"], 1 << 20)?
        .context("SHA256SUMS disappeared")?;
    let sums = parse_sha256sums(&String::from_utf8_lossy(&sums_text))
        .with_context(|| format!("{}: {dir}/{id}/SHA256SUMS", src.display()))?;
    let archives: Vec<_> = sums
        .iter()
        .filter(|(_, n)| n.ends_with(".tar.gz"))
        .collect();
    let (archive_sha, archive_name) = match archives.as_slice() {
        [one] => (*one).clone(),
        [] => bail!("SHA256SUMS for {dir}/{id} lists no .tar.gz archive"),
        _ => bail!("SHA256SUMS for {dir}/{id} lists several archives"),
    };
    let manifest_bytes = src
        .get_bytes(&[dir, id, "manifest.json"], 16 << 20)?
        .with_context(|| format!("{dir}/{id}/manifest.json missing in {}", src.display()))?;
    let mut manifest_checksummed = false;
    if let Some((h, _)) = sums.iter().find(|(_, n)| n == "manifest.json") {
        let actual = crate::util::sha256_reader(&manifest_bytes[..])?;
        if &actual != h {
            bail!("checksum mismatch for manifest.json: expected {h}, got {actual}");
        }
        manifest_checksummed = true;
    }
    fs::create_dir_all(download_dir)?;
    let archive = download_dir.join(&archive_name);
    src.get_file(&[dir, id, &archive_name], &archive)?;
    let actual = sha256_file(&archive)?;
    if actual != archive_sha {
        bail!("checksum mismatch for {archive_name}: SHA256SUMS says {archive_sha}, got {actual}");
    }
    Ok(Bundle {
        source: src.display(),
        archive,
        archive_sha256: actual,
        manifest_bytes,
        manifest_checksummed,
    })
}
