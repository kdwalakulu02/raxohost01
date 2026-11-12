//! Health checks run after activation and by `raxohost health`.

use crate::config::{ActivationPolicy, Config};
use crate::systemd::Systemd;
use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::FileTypeExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::Duration;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum HealthCheck {
    /// HTTP(S) GET expecting a 2xx status.
    Http {
        url: String,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
    /// Unix socket exists at path.
    Socket { path: String },
    /// `systemctl is-active <unit>` reports "active".
    Unit { unit: String },
    /// Command (argv, no shell) exits 0. Output is not printed.
    Command {
        argv: Vec<String>,
        #[serde(default)]
        timeout_secs: Option<u64>,
    },
}

impl HealthCheck {
    pub fn describe(&self) -> String {
        match self {
            HealthCheck::Http { url, .. } => format!("http {url}"),
            HealthCheck::Socket { path } => format!("socket {path}"),
            HealthCheck::Unit { unit } => format!("unit {unit}"),
            HealthCheck::Command { argv, .. } => {
                format!("command {}", argv.first().map(String::as_str).unwrap_or(""))
            }
        }
    }

    /// Ok(()) when healthy, Err(reason) otherwise.
    pub fn run(&self, cfg: &Config, sys: &dyn Systemd) -> Result<()> {
        match self {
            HealthCheck::Http { url, timeout_secs } => {
                let url = cfg.expand(url)?;
                let agent = ureq::Agent::new_with_config(
                    ureq::Agent::config_builder()
                        .timeout_global(Some(Duration::from_secs(timeout_secs.unwrap_or(5))))
                        .http_status_as_error(false)
                        .build(),
                );
                let resp = agent.get(&url).call()?;
                let code = resp.status().as_u16();
                if !(200..300).contains(&code) {
                    bail!("HTTP status {code}");
                }
                Ok(())
            }
            HealthCheck::Socket { path } => {
                let path = cfg.expand(path)?;
                match std::fs::metadata(Path::new(&path)) {
                    Ok(md) if md.file_type().is_socket() => Ok(()),
                    Ok(_) => bail!("{path} exists but is not a socket"),
                    Err(_) => bail!("{path} does not exist"),
                }
            }
            HealthCheck::Unit { unit } => {
                let st = sys.is_active(unit);
                if st != "active" {
                    bail!("{unit} is {st}");
                }
                Ok(())
            }
            HealthCheck::Command { argv, timeout_secs } => {
                let argv: Vec<String> =
                    argv.iter().map(|a| cfg.expand(a)).collect::<Result<_>>()?;
                let Some((prog, args)) = argv.split_first() else {
                    bail!("empty argv");
                };
                let mut child = Command::new(prog)
                    .args(args)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .map_err(|e| anyhow::anyhow!("cannot run {prog}: {e}"))?;
                let deadline =
                    std::time::Instant::now() + Duration::from_secs(timeout_secs.unwrap_or(30));
                loop {
                    if let Some(st) = child.try_wait()? {
                        if st.success() {
                            return Ok(());
                        }
                        bail!("exited with {st}");
                    }
                    if std::time::Instant::now() > deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        bail!("timed out");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
}

/// Run all checks once; returns failure descriptions.
pub fn run_once(cfg: &Config, sys: &dyn Systemd, checks: &[HealthCheck]) -> Vec<String> {
    checks
        .iter()
        .filter_map(|c| {
            c.run(cfg, sys)
                .err()
                .map(|e| format!("{}: {e:#}", c.describe()))
        })
        .collect()
}

/// Run checks with retries per the policy. Prints progress. Returns Ok(true) when healthy.
pub fn run_with_retries(cfg: &Config, sys: &dyn Systemd, policy: &ActivationPolicy) -> bool {
    if policy.health.is_empty() {
        println!("  health: no checks configured");
        return true;
    }
    let mut failures = Vec::new();
    for attempt in 1..=policy.retries {
        failures = run_once(cfg, sys, &policy.health);
        if failures.is_empty() {
            println!(
                "  health: OK ({} check(s), attempt {attempt}/{})",
                policy.health.len(),
                policy.retries
            );
            return true;
        }
        if attempt < policy.retries {
            std::thread::sleep(Duration::from_secs(policy.interval_secs));
        }
    }
    println!("  health: FAILED after {} attempt(s)", policy.retries);
    for f in failures {
        println!("    - {f}");
    }
    false
}
