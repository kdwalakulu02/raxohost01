//! raxohost — small synchronous host/deployment agent.

pub mod activation;
pub mod archive;
pub mod cli;
pub mod config;
pub mod doctor;
pub mod health;
pub mod release;
pub mod sentineldb;
pub mod source;
pub mod state;
pub mod status;
pub mod systemd;
pub mod units;
pub mod util;

use config::Config;
use systemd::Systemd;

/// Everything a command needs: config, the systemd abstraction and global flags.
pub struct Ctx {
    pub cfg: Config,
    pub sys: Box<dyn Systemd>,
    pub dry_run: bool,
}

impl Ctx {
    pub fn new(cfg: Config, sys: Box<dyn Systemd>, dry_run: bool) -> Ctx {
        Ctx { cfg, sys, dry_run }
    }

    /// Exclusive lock for mutating commands (no-op in dry-run mode).
    pub fn lock(&self) -> anyhow::Result<Option<util::LockGuard>> {
        if self.dry_run {
            return Ok(None);
        }
        if !self.cfg.deploy_root.is_dir() {
            anyhow::bail!(
                "deploy root {} does not exist",
                self.cfg.deploy_root.display()
            );
        }
        util::acquire_lock(&self.cfg.lock_file()).map(Some)
    }
}
