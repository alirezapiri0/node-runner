//! Google Drive integration.
//!
//! The desktop app talks to Drive directly over the REST API rather than
//! shelling out to `rclone`. That is a deliberate footprint decision: a bundled
//! `rclone` binary is roughly 50MB, which would make the <5MB portable-binary
//! target impossible on its own. `rclone` stays on the runner, where the
//! payload it moves actually is.
//!
//! What the app reads from Drive:
//!
//! | Object | Purpose |
//! |---|---|
//! | `heartbeat.json` | node liveness, phase, and the tail of the runner log |
//! | `KILLSWITCH.json` | the stop marker the runner checks before handing over |
//! | `snapshots/*` | the backup ledger shown in the dashboard |
//!
//! Everything the app *writes* is a small text file. It never uploads or
//! downloads a snapshot.

pub mod jwt;
pub mod ledger;

#[derive(Debug, thiserror::Error)]
pub enum DriveError {
    #[error("network error talking to Google: {0}")]
    Network(String),

    #[error("Google rejected the credential (HTTP {status}): {detail}")]
    Auth { status: u16, detail: String },

    #[error("Google returned HTTP {status}: {detail}")]
    Api { status: u16, detail: String },

    #[error("unexpected response from Google: {0}")]
    Response(String),

    #[error("Drive is not usable with the current configuration: {0}")]
    Config(String),
}
