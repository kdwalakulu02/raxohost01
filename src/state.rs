//! Persistent activation history in <deploy_root>/state/raxohost.json.

use crate::util::{atomic_write, now_rfc3339};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

const HISTORY_MAX: usize = 50;

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct State {
    #[serde(default)]
    pub projects: BTreeMap<String, Track>,
    #[serde(default)]
    pub sentineldb: Track,
}

/// Active/previous tracking for a project or for the sentinel DB generations.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Track {
    #[serde(default)]
    pub active: Option<String>,
    #[serde(default)]
    pub previous: Option<String>,
    #[serde(default)]
    pub activated_at: Option<String>,
    #[serde(default)]
    pub installed: BTreeMap<String, InstallRecord>,
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
}

#[derive(Debug, Clone)]
pub enum TrackKey {
    Project(String),
    SentinelDb,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRecord {
    pub installed_at: String,
    pub source: String,
    pub archive_sha256: String,
    /// Sentinel DB only: expected sha256 of database.rsidb.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoryEntry {
    pub at: String,
    pub action: String,
    pub id: String,
    #[serde(default)]
    pub from: Option<String>,
}

impl State {
    pub fn load(path: &Path) -> Result<State> {
        match std::fs::read(path) {
            Ok(b) => {
                serde_json::from_slice(&b).with_context(|| format!("parse {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        let mut s = serde_json::to_vec_pretty(self)?;
        s.push(b'\n');
        atomic_write(path, &s, 0o644)
    }

    pub fn track_mut(&mut self, key: &TrackKey) -> &mut Track {
        match key {
            TrackKey::Project(p) => self.project_mut(p),
            TrackKey::SentinelDb => &mut self.sentineldb,
        }
    }

    pub fn project_mut(&mut self, p: &str) -> &mut Track {
        self.projects.entry(p.to_string()).or_default()
    }
}

impl Track {
    /// Record that `id` became active (replacing `from`).
    pub fn record_activation(&mut self, action: &str, id: &str, from: Option<String>) {
        let now = now_rfc3339();
        if from.as_deref() != Some(id) {
            self.previous = from.clone();
        }
        self.active = Some(id.to_string());
        self.activated_at = Some(now.clone());
        self.push(action, id, from);
    }

    pub fn push(&mut self, action: &str, id: &str, from: Option<String>) {
        self.history.push(HistoryEntry {
            at: now_rfc3339(),
            action: action.to_string(),
            id: id.to_string(),
            from,
        });
        if self.history.len() > HISTORY_MAX {
            let n = self.history.len() - HISTORY_MAX;
            self.history.drain(..n);
        }
    }
}
