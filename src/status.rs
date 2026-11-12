//! `raxohost status`.

use crate::Ctx;
use crate::config::Config;
use crate::state::State;
use crate::{release, sentineldb};
use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ProjectStatus {
    pub project: String,
    pub active: Option<String>,
    pub previous: Option<String>,
    pub activated_at: Option<String>,
    pub installed: Vec<String>,
    pub services: Vec<ServiceState>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct ServiceState {
    pub unit: String,
    pub state: String,
}

#[derive(Debug, Serialize)]
pub struct DbStatus {
    pub root: String,
    pub active: Option<String>,
    pub previous: Option<String>,
    pub installed: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct Status {
    pub deploy_root: String,
    pub projects: Vec<ProjectStatus>,
    pub sentineldb: DbStatus,
}

pub fn collect(ctx: &Ctx, only: Option<&str>) -> Result<Status> {
    let cfg: &Config = &ctx.cfg;
    let state = State::load(&cfg.state_file())?;
    let mut projects = Vec::new();
    for p in cfg.project_names() {
        if only.is_some_and(|o| o != p) {
            continue;
        }
        let pc = cfg.project(&p)?;
        let installed = release::installed(cfg, &p)?;
        let active = release::active(cfg, &p);
        let track = state.projects.get(&p).cloned().unwrap_or_default();
        let mut warnings = Vec::new();
        if let Some(a) = &active {
            if !installed.contains(a) {
                warnings.push(format!("current/{p} points at missing release {a}"));
            }
            if track.active.as_deref() != Some(a.as_str()) {
                warnings.push("state file disagrees with current symlink".into());
            }
        }
        if p == crate::config::SELF_PROJECT
            && installed.is_empty()
            && !cfg.projects.contains_key(&p)
        {
            continue;
        }
        projects.push(ProjectStatus {
            services: pc
                .services
                .iter()
                .map(|u| ServiceState {
                    unit: u.clone(),
                    state: ctx.sys.is_active(u),
                })
                .collect(),
            project: p,
            active,
            previous: track.previous,
            activated_at: track.activated_at,
            installed,
            warnings,
        });
    }
    Ok(Status {
        deploy_root: cfg.deploy_root.display().to_string(),
        projects,
        sentineldb: DbStatus {
            root: cfg.sentineldb_root().display().to_string(),
            active: sentineldb::active(cfg),
            previous: state.sentineldb.previous.clone(),
            installed: sentineldb::installed(cfg)?,
        },
    })
}

pub fn print(st: &Status) {
    println!("deploy root: {}", st.deploy_root);
    for p in &st.projects {
        println!("\n{}", p.project);
        println!(
            "  active:    {}{}",
            p.active.as_deref().unwrap_or("-"),
            p.activated_at
                .as_deref()
                .map(|t| format!(" (since {t})"))
                .unwrap_or_default()
        );
        println!("  previous:  {}", p.previous.as_deref().unwrap_or("-"));
        println!(
            "  installed: {}",
            if p.installed.is_empty() {
                "-".to_string()
            } else {
                p.installed.join(", ")
            }
        );
        for s in &p.services {
            println!("  service:   {:<32} {}", s.unit, s.state);
        }
        for w in &p.warnings {
            println!("  WARNING:   {w}");
        }
    }
    let db = &st.sentineldb;
    println!("\nsentinel db ({})", db.root);
    println!("  active:    {}", db.active.as_deref().unwrap_or("-"));
    println!("  previous:  {}", db.previous.as_deref().unwrap_or("-"));
    println!(
        "  installed: {}",
        if db.installed.is_empty() {
            "-".to_string()
        } else {
            db.installed.join(", ")
        }
    );
}
