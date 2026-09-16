//! Background status poller.
//!
//! One loop, one HTTP call per tick, conditional on the previous ETag. At the
//! default 30-second interval that is 120 requests per hour against a 5000-per-
//! hour budget, and in the steady state the responses are 304s with no body.
//!
//! Polling rather than webhooks, deliberately: this app runs on a laptop that is
//! frequently asleep, and a webhook needs a publicly reachable endpoint that the
//! app does not have. Missing a poll is harmless here because every value the UI
//! shows is derived from GitHub's own timestamps rather than from a local clock.
//!
//! When the vault is locked this loop still ticks, but it performs no network
//! call at all: without the credential there is nothing to ask about.

use std::time::Duration;

use tauri::Manager;

use super::api::RunLookup;
use crate::state::AppState;

/// Start the poller. Called once during setup.
pub fn spawn(app: tauri::AppHandle) {
    tauri::async_runtime::spawn(async move {
        let mut etag: Option<String> = None;

        loop {
            let interval_secs = {
                let state = app.state::<AppState>();
                refresh(&state, &mut etag).await;
                state.config_snapshot().poll_seconds.clamp(10, 300)
            };
            tokio::time::sleep(Duration::from_secs(interval_secs)).await;
        }
    });
}

/// One refresh cycle.
async fn refresh(state: &AppState, etag: &mut Option<String>) {
    let config = state.config_snapshot();

    let unlocked = state
        .session
        .lock()
        .map(|session| session.is_open())
        .unwrap_or(false);
    if !unlocked {
        set_status(state, |status| {
            status.phase = "locked".into();
            status.remaining_secs = None;
            status.elapsed_secs = None;
        });
        return;
    }

    let Some(slug) = config.repo_slug() else {
        set_status(state, |status| status.phase = "unconfigured".into());
        return;
    };

    // A missing credential is reported as its own phase so the UI can point at
    // the exact fix rather than showing a generic failure.
    let token = match state.secret_copy("GH_PAT") {
        Ok(token) => token,
        Err(_) => {
            set_status(state, |status| status.phase = "no_credential".into());
            return;
        }
    };

    match state.gh.latest_run(&token, &slug, etag.as_deref()).await {
        Ok(RunLookup::NotModified) => {
            let now = nrvault::now_unix();
            set_status(state, |status| {
                status.last_poll_unix = Some(now);
                status.error = None;
                // The countdown is recomputed from the server timestamp on every
                // tick, including ticks that return 304, so it keeps decrementing
                // without needing a fresh body.
                if let Some(started) = status.started_at_unix {
                    let cycle = config.cycle_minutes.saturating_mul(60);
                    let elapsed = now.saturating_sub(started);
                    status.elapsed_secs = Some(elapsed);
                    status.remaining_secs = Some(cycle.saturating_sub(elapsed));
                }
            });
        }
        Ok(RunLookup::Modified(run, fresh_etag)) => {
            *etag = fresh_etag;
            let now = nrvault::now_unix();
            set_status(state, |status| {
                status.last_poll_unix = Some(now);
                status.error = None;
                apply_run(status, run, &config, now);
            });
        }
        Err(err) => {
            let message = err.to_string();
            state.log(format!("[poll] {message}"));
            let now = nrvault::now_unix();
            set_status(state, |status| {
                status.last_poll_unix = Some(now);
                status.error = Some(message);
            });
        }
    }
}

fn apply_run(
    status: &mut crate::state::NodeStatus,
    run: Option<super::api::RunSummary>,
    config: &crate::state::Config,
    now: u64,
) {
    let Some(run) = run else {
        status.phase = "no_runs".into();
        status.run_id = None;
        status.run_url = None;
        status.remaining_secs = None;
        status.elapsed_secs = None;
        return;
    };

    status.phase = run.status.clone();
    status.conclusion = run.conclusion.clone();
    status.run_id = Some(run.id);
    status.run_url = Some(run.html_url.clone());
    status.slot = parse_slot(run.display_title.as_deref());

    match run.started_unix() {
        Some(started) => {
            let cycle = config.cycle_minutes.saturating_mul(60);
            let elapsed = now.saturating_sub(started);
            status.started_at_unix = Some(started);
            status.elapsed_secs = Some(elapsed);
            // A finished run has no remaining lifetime; showing a frozen
            // countdown would imply the node is still serving.
            status.remaining_secs = Some(if run.is_active() {
                cycle.saturating_sub(elapsed)
            } else {
                0
            });
        }
        None => {
            status.started_at_unix = None;
            status.elapsed_secs = None;
            status.remaining_secs = None;
        }
    }
}

/// Which slot a run occupies, taken from its `run-name`.
///
/// `runner.yml` sets `run-name: node-a (cycle)`, which GitHub surfaces as
/// `display_title`. Encoding the slot there is what lets the app dispatch the
/// successor into the *idle* slot, and that alternation is what keeps two nodes
/// from fighting over the same snapshot.
pub fn parse_slot(display_title: Option<&str>) -> String {
    match display_title {
        Some(title) if title.contains("node-b") => "b".into(),
        Some(title) if title.contains("node-a") => "a".into(),
        _ => "?".into(),
    }
}

fn set_status(state: &AppState, mutate: impl FnOnce(&mut crate::state::NodeStatus)) {
    if let Ok(mut status) = state.status.write() {
        mutate(&mut status);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_is_read_from_the_run_name() {
        assert_eq!(parse_slot(Some("node-a (cycle)")), "a");
        assert_eq!(parse_slot(Some("node-b (failover)")), "b");
        assert_eq!(parse_slot(Some("some other run")), "?");
        assert_eq!(parse_slot(None), "?");
    }
}
