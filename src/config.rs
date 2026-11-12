//! raxohost.toml configuration.

use crate::health::HealthCheck;
use crate::util::validate_name;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DEFAULT_CONFIG: &str = "/root/store01/deploy01/config/raxohost/raxohost.toml";
pub const SELF_PROJECT: &str = "raxohost";
pub const SENTINEL_PROJECT: &str = "raxosentinel";
pub const SENTINEL_DB_SOURCE_DIR: &str = "raxosentinel-db";

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub deploy_root: PathBuf,
    /// Release source base locations: local directories or https:// URLs laid out like dist/.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Where rendered units are installed (default /etc/systemd/system).
    #[serde(default)]
    pub systemd_dir: Option<PathBuf>,
    /// Unit templates directory (default <deploy_root>/config/raxohost/units).
    #[serde(default)]
    pub units_dir: Option<PathBuf>,
    /// Units to `systemctl enable` after `service install`.
    #[serde(default)]
    pub enable: Vec<String>,
    /// Default number of health check attempts.
    #[serde(default)]
    pub health_retries: Option<u32>,
    /// Default seconds between health check attempts.
    #[serde(default)]
    pub health_interval_secs: Option<u64>,
    #[serde(default)]
    pub projects: BTreeMap<String, ProjectConfig>,
    #[serde(default)]
    pub sentineldb: Option<SentinelDbConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectConfig {
    /// systemd units restarted when a release of this project is activated.
    #[serde(default)]
    pub services: Vec<String>,
    #[serde(default)]
    pub health: Vec<HealthCheck>,
    #[serde(default)]
    pub health_retries: Option<u32>,
    #[serde(default)]
    pub health_interval_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SentinelDbConfig {
    /// Generations root (default <deploy_root>/data/raxosentinel/rsidb).
    #[serde(default)]
    pub root: Option<PathBuf>,
    /// "user:group" applied with chown to installed generations and the `current` file.
    #[serde(default)]
    pub owner: Option<String>,
    /// Units restarted on activation (default: projects.raxosentinel.services).
    #[serde(default)]
    pub services: Option<Vec<String>>,
    /// Health checks after activation (default: projects.raxosentinel.health).
    #[serde(default)]
    pub health: Option<Vec<HealthCheck>>,
}

/// Effective health/restart settings for one activation target.
#[derive(Debug, Clone)]
pub struct ActivationPolicy {
    pub services: Vec<String>,
    pub health: Vec<HealthCheck>,
    pub retries: u32,
    pub interval_secs: u64,
}

impl Config {
    pub fn load(path: &Path) -> Result<Config> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?;
        let mut cfg: Config =
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("/"));
        cfg.sources = cfg
            .sources
            .iter()
            .map(|s| {
                if s.contains("://") || Path::new(s).is_absolute() {
                    s.clone()
                } else {
                    base.join(s).to_string_lossy().into_owned()
                }
            })
            .collect();
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<()> {
        if !self.deploy_root.is_absolute() {
            bail!("deploy_root must be an absolute path");
        }
        for s in &self.sources {
            if s.contains("://") && !s.starts_with("https://") {
                bail!("source {s:?}: only local paths and https:// URLs are supported");
            }
        }
        for (name, p) in &self.projects {
            validate_name("project name", name)?;
            for s in &p.services {
                validate_name("service name", s)?;
            }
        }
        for s in &self.enable {
            validate_name("unit name", s)?;
        }
        if let Some(db) = &self.sentineldb {
            if let Some(o) = &db.owner
                && o.trim().is_empty()
            {
                bail!("sentineldb.owner must not be empty");
            }
            if let Some(r) = &db.root
                && !r.is_absolute()
            {
                bail!("sentineldb.root must be absolute");
            }
        }
        Ok(())
    }

    pub fn systemd_dir(&self) -> PathBuf {
        self.systemd_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/systemd/system"))
    }

    pub fn units_dir(&self) -> PathBuf {
        self.units_dir
            .clone()
            .unwrap_or_else(|| self.deploy_root.join("config/raxohost/units"))
    }

    pub fn releases_dir(&self, project: &str) -> PathBuf {
        self.deploy_root.join("releases").join(project)
    }

    pub fn current_link(&self, project: &str) -> PathBuf {
        self.deploy_root.join("current").join(project)
    }

    pub fn state_dir(&self) -> PathBuf {
        self.deploy_root.join("state")
    }

    pub fn state_file(&self) -> PathBuf {
        self.state_dir().join("raxohost.json")
    }

    pub fn lock_file(&self) -> PathBuf {
        self.state_dir().join("raxohost.lock")
    }

    pub fn sentineldb_root(&self) -> PathBuf {
        self.sentineldb
            .as_ref()
            .and_then(|d| d.root.clone())
            .unwrap_or_else(|| self.deploy_root.join("data/raxosentinel/rsidb"))
    }

    /// Known project or the implicit `raxohost` self project.
    pub fn project(&self, name: &str) -> Result<ProjectConfig> {
        validate_name("project name", name)?;
        match self.projects.get(name) {
            Some(p) => Ok(p.clone()),
            None if name == SELF_PROJECT => Ok(ProjectConfig::default()),
            None => bail!(
                "unknown project {name:?} (configured: {})",
                self.project_names().join(", ")
            ),
        }
    }

    /// Configured projects plus `raxohost` itself.
    pub fn project_names(&self) -> Vec<String> {
        let mut v: Vec<String> = self.projects.keys().cloned().collect();
        if !v.iter().any(|p| p == SELF_PROJECT) {
            v.push(SELF_PROJECT.to_string());
        }
        v
    }

    pub fn project_policy(&self, name: &str) -> Result<ActivationPolicy> {
        let p = self.project(name)?;
        Ok(ActivationPolicy {
            services: p.services,
            health: p.health,
            retries: p
                .health_retries
                .or(self.health_retries)
                .unwrap_or(10)
                .max(1),
            interval_secs: p
                .health_interval_secs
                .or(self.health_interval_secs)
                .unwrap_or(2),
        })
    }

    pub fn sentineldb_policy(&self) -> ActivationPolicy {
        let sentinel = self
            .projects
            .get(SENTINEL_PROJECT)
            .cloned()
            .unwrap_or_default();
        let db = self.sentineldb.clone().unwrap_or_default();
        ActivationPolicy {
            services: db.services.unwrap_or(sentinel.services),
            health: db.health.unwrap_or(sentinel.health),
            retries: sentinel
                .health_retries
                .or(self.health_retries)
                .unwrap_or(10)
                .max(1),
            interval_secs: sentinel
                .health_interval_secs
                .or(self.health_interval_secs)
                .unwrap_or(2),
        }
    }

    /// All services managed through raxohost (deduplicated, config order).
    pub fn all_services(&self) -> Vec<String> {
        let mut v: Vec<String> = Vec::new();
        let db = self.sentineldb.as_ref().and_then(|d| d.services.clone());
        for s in self
            .projects
            .values()
            .flat_map(|p| p.services.iter())
            .chain(db.iter().flatten())
            .chain(self.enable.iter())
        {
            if !v.contains(s) {
                v.push(s.clone());
            }
        }
        v
    }

    /// Expand `{{...}}` placeholders (same syntax as unit templates).
    pub fn expand(&self, s: &str) -> Result<String> {
        crate::units::render_str(self, s)
    }
}
