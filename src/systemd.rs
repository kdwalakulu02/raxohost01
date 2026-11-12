//! All systemctl / journalctl interaction goes through [`Systemd`] so it can be faked in tests.

use anyhow::{Context, Result, bail};
use std::process::{Command, Stdio};

pub trait Systemd {
    /// Output of `systemctl is-active <unit>` (e.g. "active", "inactive", "failed", "unknown").
    fn is_active(&self, unit: &str) -> String;
    fn start(&self, unit: &str) -> Result<()>;
    fn stop(&self, unit: &str) -> Result<()>;
    fn restart(&self, unit: &str) -> Result<()>;
    fn daemon_reload(&self) -> Result<()>;
    fn enable(&self, unit: &str) -> Result<()>;
    /// `systemctl status` passthrough to the terminal.
    fn status(&self, units: &[String]) -> Result<()>;
    /// `journalctl` passthrough to the terminal.
    fn logs(&self, units: &[String], lines: u32, follow: bool) -> Result<()>;
}

/// Real implementation shelling out to systemctl/journalctl.
/// In dry-run mode mutating calls only print what would be executed.
pub struct SystemCtl {
    pub dry_run: bool,
}

impl SystemCtl {
    fn mutate(&self, args: &[&str]) -> Result<()> {
        if self.dry_run {
            println!("[dry-run] would run: systemctl {}", args.join(" "));
            return Ok(());
        }
        let st = Command::new("systemctl")
            .args(args)
            .status()
            .context("failed to execute systemctl")?;
        if !st.success() {
            bail!("systemctl {} failed ({st})", args.join(" "));
        }
        Ok(())
    }
}

impl Systemd for SystemCtl {
    fn is_active(&self, unit: &str) -> String {
        match Command::new("systemctl")
            .args(["is-active", unit])
            .stderr(Stdio::null())
            .output()
        {
            Ok(o) => {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() { "unknown".into() } else { s }
            }
            Err(_) => "unknown (systemctl unavailable)".into(),
        }
    }
    fn start(&self, unit: &str) -> Result<()> {
        self.mutate(&["start", unit])
    }
    fn stop(&self, unit: &str) -> Result<()> {
        self.mutate(&["stop", unit])
    }
    fn restart(&self, unit: &str) -> Result<()> {
        self.mutate(&["restart", unit])
    }
    fn daemon_reload(&self) -> Result<()> {
        self.mutate(&["daemon-reload"])
    }
    fn enable(&self, unit: &str) -> Result<()> {
        self.mutate(&["enable", unit])
    }
    fn status(&self, units: &[String]) -> Result<()> {
        // `systemctl status` exits non-zero for inactive units; that is not an error here.
        Command::new("systemctl")
            .args(["status", "--no-pager"])
            .args(units)
            .status()
            .context("failed to execute systemctl")?;
        Ok(())
    }
    fn logs(&self, units: &[String], lines: u32, follow: bool) -> Result<()> {
        let mut c = Command::new("journalctl");
        c.arg("--no-pager").arg("-n").arg(lines.to_string());
        for u in units {
            c.arg("-u").arg(u);
        }
        if follow {
            c.arg("--follow");
        }
        let st = c.status().context("failed to execute journalctl")?;
        if !st.success() {
            bail!("journalctl failed ({st})");
        }
        Ok(())
    }
}
