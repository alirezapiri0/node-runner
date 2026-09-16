//! Injecting vault credentials into the runner repository.
//!
//! GitHub Actions secrets are **write-only**: the API stores an encrypted value
//! and will never return it, and the UI shows only the name. That is a useful
//! property here -- it means a compromised desktop cannot read back the
//! credentials of a node it does not own, and it means this module cannot
//! accidentally display a secret even if asked to.
//!
//! The consequence for the operator is that "verify" here means "the write was
//! accepted", not "the value round-tripped". The vault remains the only place
//! the value can be read, which is the intended single source of truth.

use serde::Serialize;

use super::api::GhError;
use crate::state::AppState;

/// The credentials the runner workflow expects, with the reason each exists.
///
/// This list is the contract between the desktop app and `runner.yml`. If a
/// workflow references a secret that is not here, the handover will fail at the
/// freeze step -- so both sides are cross-checked in `docs/OPERATIONS.md`.
pub const REQUIRED_SECRETS: &[(&str, &str)] = &[
    (
        "GH_PAT",
        "dispatches the successor run; needs Actions: write on this repository only",
    ),
    (
        "RCLONE_SERVICE_ACCOUNT_JSON",
        "authenticates rclone to the backup folder; never expires because it is not OAuth",
    ),
    (
        "CF_TUNNEL_TOKEN",
        "binds the immutable hostname across node migrations",
    ),
];

#[derive(Debug, Clone, Serialize)]
pub struct SecretReport {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

/// Seal and upload every required credential.
///
/// Ordering matters: the repository public key is fetched once, up front. If the
/// key rotates mid-loop, GitHub rejects the remaining writes with their own
/// error rather than silently storing something sealed to a stale key, so the
/// per-secret report is accurate.
pub async fn inject_required(state: &AppState) -> Result<Vec<SecretReport>, GhError> {
    let config = state.config_snapshot();
    let slug = config.repo_slug().ok_or_else(|| {
        GhError::Config("set the repository owner and name in Settings first".into())
    })?;

    let token = state.secret_copy("GH_PAT").map_err(GhError::Config)?;
    let key = state.gh.repo_public_key(&token, &slug).await?;

    let mut reports = Vec::with_capacity(REQUIRED_SECRETS.len());

    for (name, purpose) in REQUIRED_SECRETS {
        // A missing secret is a reportable outcome, not a hard failure: the
        // operator may legitimately want to inject only some of them.
        let value = match state.secret_copy(name) {
            Ok(value) => value,
            Err(_) => {
                reports.push(SecretReport {
                    name: (*name).into(),
                    ok: false,
                    detail: "not present in the vault".into(),
                });
                continue;
            }
        };

        let sealed = match key.seal(value.as_bytes()) {
            Ok(sealed) => sealed,
            Err(e) => {
                reports.push(SecretReport {
                    name: (*name).into(),
                    ok: false,
                    detail: format!("could not be sealed: {e}"),
                });
                continue;
            }
        };

        match state
            .gh
            .put_secret(&token, &slug, name, &key, sealed.as_str())
            .await
        {
            Ok(()) => reports.push(SecretReport {
                name: (*name).into(),
                ok: true,
                detail: format!("stored — {purpose}"),
            }),
            Err(e) => reports.push(SecretReport {
                name: (*name).into(),
                ok: false,
                detail: e.to_string(),
            }),
        }
    }

    Ok(reports)
}
