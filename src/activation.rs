//! Shared activate → restart → health check → auto-rollback procedure
//! used by project releases and sentinel DB generations.

use crate::Ctx;
use crate::config::ActivationPolicy;
use crate::health;
use crate::state::{State, TrackKey};
use anyhow::{Result, bail};

pub struct Target<'a> {
    /// Human label, e.g. "raxoemailrust" or "sentinel db".
    pub label: String,
    pub policy: ActivationPolicy,
    /// Atomically point the active pointer at the given id.
    pub switch: &'a dyn Fn(&str) -> Result<()>,
    /// Which tracking record inside the state file.
    pub key: TrackKey,
}

/// Restart services and run health checks. Returns true when everything succeeded.
pub fn restart_and_check(ctx: &Ctx, policy: &ActivationPolicy) -> bool {
    for s in &policy.services {
        match ctx.sys.restart(s) {
            Ok(()) => println!("  restarted {s}"),
            Err(e) => {
                println!("  restart {s} FAILED: {e:#}");
                return false;
            }
        }
    }
    health::run_with_retries(&ctx.cfg, ctx.sys.as_ref(), policy)
}

pub fn activate(
    ctx: &Ctx,
    t: &Target,
    new: &str,
    old: Option<String>,
    restart: bool,
    action: &str,
) -> Result<()> {
    if old.as_deref() == Some(new) {
        println!("{}: {new} is already active", t.label);
        return Ok(());
    }
    if ctx.dry_run {
        println!(
            "[dry-run] would activate {} {new} (currently {})",
            t.label,
            old.as_deref().unwrap_or("none")
        );
        if restart {
            for s in &t.policy.services {
                println!("[dry-run] would restart {s}");
            }
            println!(
                "[dry-run] would run {} health check(s), rolling back on failure",
                t.policy.health.len()
            );
        }
        return Ok(());
    }

    let state_path = ctx.cfg.state_file();
    let mut state = State::load(&state_path)?;
    let snapshot = state.track_mut(&t.key).clone();

    (t.switch)(new)?;
    state
        .track_mut(&t.key)
        .record_activation(action, new, old.clone());
    state.save(&state_path)?;
    println!(
        "{}: activated {new} (previous: {})",
        t.label,
        old.as_deref().unwrap_or("none")
    );

    if !restart {
        println!("  --no-restart: services not restarted, health checks skipped");
        return Ok(());
    }
    if restart_and_check(ctx, &t.policy) {
        return Ok(());
    }

    let Some(old) = old else {
        bail!(
            "{}: activation of {new} failed and there is no previous version to roll back to",
            t.label
        );
    };
    println!("{}: activation failed — rolling back to {old}", t.label);
    (t.switch)(&old)?;
    let track = state.track_mut(&t.key);
    *track = snapshot;
    track.push("auto-rollback", &old, Some(new.to_string()));
    state.save(&state_path)?;
    let healthy = restart_and_check(ctx, &t.policy);
    bail!(
        "{}: {new} failed restart/health checks; automatically rolled back to {old}{}",
        t.label,
        if healthy {
            ""
        } else {
            " (WARNING: rolled-back version is also unhealthy)"
        }
    )
}
