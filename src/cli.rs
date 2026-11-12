//! Command line interface.

use crate::config::{Config, DEFAULT_CONFIG};
use crate::systemd::SystemCtl;
use crate::{Ctx, doctor, health, release, sentineldb, source, status, units};
use anyhow::{Result, bail};
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "raxohost",
    version,
    about = "Host/deployment agent for raxo services"
)]
pub struct Cli {
    /// Config file (default: $RAXOHOST_CONFIG or /root/store01/deploy01/config/raxohost/raxohost.toml)
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    /// Print what would happen without changing anything
    #[arg(long, global = true)]
    pub dry_run: bool,
    /// JSON output (status, release list/available/verify, sentineldb list, health)
    #[arg(long, global = true)]
    pub json: bool,
    #[command(subcommand)]
    pub cmd: Cmd,
}

#[derive(Subcommand, Debug)]
pub enum Cmd {
    /// Active/previous/installed releases, service states, sentinel DB generation
    Status { project: Option<String> },
    /// Manage project releases
    #[command(subcommand)]
    Release(ReleaseCmd),
    /// Install (if needed) and activate a release
    Deploy {
        project: String,
        release_id: String,
        #[command(flatten)]
        r: RestartFlag,
    },
    /// Manage raxosentinel signature database generations
    #[command(subcommand)]
    Sentineldb(DbCmd),
    /// Render/install unit files and wrap systemctl/journalctl
    #[command(subcommand)]
    Service(ServiceCmd),
    /// Run health checks
    Health { project: Option<String> },
    /// Check deploy layout, config, units, symlinks, releases, disk space
    Doctor,
    /// Manage raxohost itself
    #[command(name = "self", subcommand)]
    SelfCmd(SelfCmd),
}

#[derive(Args, Debug)]
pub struct RestartFlag {
    /// Do not restart services (and skip health checks)
    #[arg(long)]
    pub no_restart: bool,
}

#[derive(Subcommand, Debug)]
pub enum ReleaseCmd {
    /// List releases published in the configured sources
    Available { project: Option<String> },
    /// List installed releases
    List { project: Option<String> },
    /// Fetch, verify and unpack a release (never modifies an installed release)
    Install { project: String, release_id: String },
    /// Re-verify installed files against the manifest (default: active release)
    Verify {
        project: String,
        release_id: Option<String>,
    },
    /// Switch current/<project> to a release, restart services, health check, auto-rollback
    Activate {
        project: String,
        release_id: String,
        #[command(flatten)]
        r: RestartFlag,
    },
    /// Re-activate the previous release
    Rollback {
        project: String,
        #[command(flatten)]
        r: RestartFlag,
    },
    /// Remove old releases (never the active or previous one)
    Prune {
        project: String,
        /// Number of most recently installed releases to keep
        #[arg(long)]
        keep: usize,
        /// Actually delete
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum DbCmd {
    /// Fetch, verify and unpack a generation into data/raxosentinel/rsidb/<generation>
    Install { generation: String },
    /// Atomically switch the `current` file, restart sentinel services, health check
    Activate {
        generation: String,
        #[command(flatten)]
        r: RestartFlag,
    },
    /// Re-activate the previous generation
    Rollback {
        #[command(flatten)]
        r: RestartFlag,
    },
    /// List installed generations
    List,
    /// List generations published in the sources
    Available,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCmd {
    /// Render templates into <deploy_root>/systemd and install them into systemd_dir
    Install,
    /// Only render templates into <deploy_root>/systemd and show the diff
    Render,
    Start {
        name: String,
    },
    Stop {
        name: String,
    },
    Restart {
        name: String,
    },
    Status {
        name: String,
    },
    Logs {
        name: String,
        #[arg(short = 'n', long, default_value_t = 100)]
        lines: u32,
        #[arg(short, long)]
        follow: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum SelfCmd {
    /// Install+activate a raxohost release and point <deploy_root>/bin/raxohost at it
    Install { release_id: String },
}

pub fn config_path(cli: &Cli) -> PathBuf {
    cli.config
        .clone()
        .or_else(|| std::env::var_os("RAXOHOST_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG))
}

fn print_json<T: serde::Serialize>(v: &T) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(v)?);
    Ok(())
}

fn projects_or_all(ctx: &Ctx, p: &Option<String>) -> Result<Vec<String>> {
    match p {
        Some(p) => {
            ctx.cfg.project(p)?;
            Ok(vec![p.clone()])
        }
        None => Ok(ctx.cfg.project_names()),
    }
}

fn service_names(ctx: &Ctx, name: &str) -> Result<Vec<String>> {
    if name == "all" {
        let v = ctx.cfg.all_services();
        if v.is_empty() {
            bail!("no services configured");
        }
        Ok(v)
    } else {
        crate::util::validate_name("unit name", name)?;
        Ok(vec![name.to_string()])
    }
}

pub fn main_entry() -> Result<i32> {
    let cli = Cli::parse();
    let path = config_path(&cli);
    let cfg = Config::load(&path)?;
    let ctx = Ctx::new(
        cfg,
        Box::new(SystemCtl {
            dry_run: cli.dry_run,
        }),
        cli.dry_run,
    );
    run(&ctx, &cli, &path)
}

/// Execute a parsed command; returns the process exit code.
pub fn run(ctx: &Ctx, cli: &Cli, config_path: &std::path::Path) -> Result<i32> {
    let json = cli.json;
    match &cli.cmd {
        Cmd::Status { project } => {
            if let Some(p) = project {
                ctx.cfg.project(p)?;
            }
            let st = status::collect(ctx, project.as_deref())?;
            if json {
                print_json(&st)?
            } else {
                status::print(&st)
            }
        }
        Cmd::Release(rc) => match rc {
            ReleaseCmd::Available { project } => {
                let mut out = serde_json::Map::new();
                for p in projects_or_all(ctx, project)? {
                    let mut ids = Vec::new();
                    for s in &ctx.cfg.sources {
                        match source::Source::parse(s).and_then(|src| src.list(&p)) {
                            Ok(v) => {
                                for id in v {
                                    if !json {
                                        println!("{p:<16} {id:<24} {s}");
                                    }
                                    ids.push(serde_json::json!({"release": id, "source": s}));
                                }
                            }
                            Err(e) => eprintln!("warning: {s}: {e:#}"),
                        }
                    }
                    out.insert(p, ids.into());
                }
                if json {
                    print_json(&out)?;
                }
            }
            ReleaseCmd::List { project } => {
                let mut out = serde_json::Map::new();
                for p in projects_or_all(ctx, project)? {
                    let active = release::active(&ctx.cfg, &p);
                    let ids = release::installed(&ctx.cfg, &p)?;
                    if !json {
                        for id in &ids {
                            let mark = if active.as_deref() == Some(id) {
                                "*"
                            } else {
                                " "
                            };
                            println!("{mark} {p:<16} {id}");
                        }
                    }
                    out.insert(p, serde_json::json!({"active": active, "installed": ids}));
                }
                if json {
                    print_json(&out)?;
                }
            }
            ReleaseCmd::Install {
                project,
                release_id,
            } => {
                let _l = ctx.lock()?;
                release::install(ctx, project, release_id)?;
            }
            ReleaseCmd::Verify {
                project,
                release_id,
            } => {
                ctx.cfg.project(project)?;
                let rid = match release_id {
                    Some(r) => r.clone(),
                    None => release::active(&ctx.cfg, project)
                        .ok_or_else(|| anyhow::anyhow!("{project}: no active release"))?,
                };
                let rep = release::verify(&ctx.cfg, project, &rid)?;
                if json {
                    print_json(&rep)?;
                } else if rep.problems.is_empty() {
                    println!("{project} {rid}: OK ({} files verified)", rep.files);
                } else {
                    println!("{project} {rid}: FAILED");
                    for p in &rep.problems {
                        println!("  - {p}");
                    }
                }
                if !rep.problems.is_empty() {
                    return Ok(1);
                }
            }
            ReleaseCmd::Activate {
                project,
                release_id,
                r,
            } => {
                let _l = ctx.lock()?;
                release::activate(ctx, project, release_id, !r.no_restart, "activate")?;
            }
            ReleaseCmd::Rollback { project, r } => {
                let _l = ctx.lock()?;
                ctx.cfg.project(project)?;
                release::rollback(ctx, project, !r.no_restart)?;
            }
            ReleaseCmd::Prune { project, keep, yes } => {
                let _l = ctx.lock()?;
                release::prune(ctx, project, *keep, *yes)?;
            }
        },
        Cmd::Deploy {
            project,
            release_id,
            r,
        } => {
            let _l = ctx.lock()?;
            release::deploy(ctx, project, release_id, !r.no_restart)?;
        }
        Cmd::Sentineldb(dc) => match dc {
            DbCmd::Install { generation } => {
                let _l = ctx.lock()?;
                sentineldb::install(ctx, generation)?;
            }
            DbCmd::Activate { generation, r } => {
                let _l = ctx.lock()?;
                sentineldb::activate(ctx, generation, !r.no_restart, "activate")?;
            }
            DbCmd::Rollback { r } => {
                let _l = ctx.lock()?;
                sentineldb::rollback(ctx, !r.no_restart)?;
            }
            DbCmd::List => {
                let active = sentineldb::active(&ctx.cfg);
                let ids = sentineldb::installed(&ctx.cfg)?;
                if json {
                    print_json(&serde_json::json!({"active": active, "installed": ids}))?;
                } else if ids.is_empty() {
                    println!("no generations in {}", ctx.cfg.sentineldb_root().display());
                } else {
                    for id in ids {
                        let mark = if active.as_deref() == Some(&id) {
                            "*"
                        } else {
                            " "
                        };
                        println!("{mark} {id}");
                    }
                }
            }
            DbCmd::Available => {
                let mut out = Vec::new();
                for (s, r) in sentineldb::available(&ctx.cfg) {
                    match r {
                        Ok(v) => {
                            for g in v {
                                if !json {
                                    println!("{g:<24} {s}");
                                }
                                out.push(serde_json::json!({"generation": g, "source": s}));
                            }
                        }
                        Err(e) => eprintln!("warning: {s}: {e:#}"),
                    }
                }
                if json {
                    print_json(&out)?;
                }
            }
        },
        Cmd::Service(sc) => match sc {
            ServiceCmd::Install => {
                let _l = ctx.lock()?;
                units::install(ctx)?;
            }
            ServiceCmd::Render => {
                let _l = ctx.lock()?;
                units::render_to_deploy(ctx)?;
                for (name, _, st) in units::diff(&ctx.cfg)? {
                    println!("  {:<9} {name}", st.label());
                }
            }
            ServiceCmd::Start { name } => {
                for u in service_names(ctx, name)? {
                    ctx.sys.start(&u)?;
                }
            }
            ServiceCmd::Stop { name } => {
                for u in service_names(ctx, name)? {
                    ctx.sys.stop(&u)?;
                }
            }
            ServiceCmd::Restart { name } => {
                for u in service_names(ctx, name)? {
                    ctx.sys.restart(&u)?;
                }
            }
            ServiceCmd::Status { name } => ctx.sys.status(&service_names(ctx, name)?)?,
            ServiceCmd::Logs {
                name,
                lines,
                follow,
            } => ctx.sys.logs(&service_names(ctx, name)?, *lines, *follow)?,
        },
        Cmd::Health { project } => {
            let mut targets: Vec<(String, crate::config::ActivationPolicy)> = Vec::new();
            for p in projects_or_all(ctx, project)? {
                targets.push((p.clone(), ctx.cfg.project_policy(&p)?));
            }
            if project.is_none()
                && ctx
                    .cfg
                    .sentineldb
                    .as_ref()
                    .is_some_and(|d| d.health.is_some())
            {
                targets.push(("sentinel db".into(), ctx.cfg.sentineldb_policy()));
            }
            let mut failed = 0;
            let mut out = Vec::new();
            for (name, pol) in targets {
                if pol.health.is_empty() {
                    continue;
                }
                let failures = health::run_once(&ctx.cfg, ctx.sys.as_ref(), &pol.health);
                if !json {
                    if failures.is_empty() {
                        println!("{name}: OK ({} check(s))", pol.health.len());
                    } else {
                        println!("{name}: FAILED");
                        for f in &failures {
                            println!("  - {f}");
                        }
                    }
                }
                if !failures.is_empty() {
                    failed += 1;
                }
                out.push(serde_json::json!({"target": name, "ok": failures.is_empty(), "failures": failures}));
            }
            if json {
                print_json(&out)?;
            } else if out.is_empty() {
                println!("no health checks configured");
            }
            if failed > 0 {
                return Ok(1);
            }
        }
        Cmd::Doctor => {
            let r = doctor::run(ctx, config_path);
            if r.fail > 0 {
                return Ok(1);
            }
        }
        Cmd::SelfCmd(SelfCmd::Install { release_id }) => {
            let _l = ctx.lock()?;
            release::self_install(ctx, release_id, true)?;
        }
    }
    Ok(0)
}
