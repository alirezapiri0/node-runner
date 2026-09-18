//! Application state.
//!
//! Held in Tauri's managed state and guarded per-field so that a slow network
//! call never blocks a vault operation, and vice versa.
//!
//! # The rule this file exists to enforce
//!
//! An unlocked vault is represented by exactly one thing: the presence of a
//! [`VaultPayload`] inside [`Session`]. There is no second copy, no cached
//! string table, and no way for the UI to reach a value. Locking drops the
//! payload, which zeroizes it (see `nrvault::secret`). Every path that could
//! leave a decrypted secret resident -- auto-lock, explicit lock, panic -- goes
//! through that single field.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

use nrvault::{KdfParams, ProtectorStatus, SecretView, TamperEvent, VaultPayload, VaultStore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::gh::api::GithubClient;

pub const DEFAULT_CYCLE_MINUTES: u64 = 350;
pub const DEFAULT_POLL_SECONDS: u64 = 30;
pub const DEFAULT_AUTO_LOCK_MINUTES: u64 = 15;
pub const LOG_CAPACITY: usize = 500;

/// Non-secret, user-editable configuration, persisted as JSON next to the vault.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// `owner` of the single repository that hosts the runner workflow.
    pub owner: String,
    pub repo: String,
    pub workflow_file: String,
    /// Minutes a node is allowed to serve before handing over. Must stay below
    /// GitHub's six-hour job ceiling; see `docs/OPERATIONS.md`.
    pub cycle_minutes: u64,
    pub poll_seconds: u64,
    pub auto_lock_minutes: u64,
    /// Process match pattern the runner freezes before snapshotting.
    pub workload_pattern: String,
    pub tunnel_hostname: String,
    pub drive_folder_id: String,
    pub backup_retention: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            owner: String::new(),
            repo: String::new(),
            workflow_file: "runner.yml".into(),
            cycle_minutes: DEFAULT_CYCLE_MINUTES,
            poll_seconds: DEFAULT_POLL_SECONDS,
            auto_lock_minutes: DEFAULT_AUTO_LOCK_MINUTES,
            workload_pattern: String::new(),
            tunnel_hostname: String::new(),
            drive_folder_id: String::new(),
            backup_retention: 20,
        }
    }
}

impl Config {
    /// Reject settings that would produce a broken or unsafe cycle.
    ///
    /// The upper bound is the important one: GitHub terminates a job at six
    /// hours, so a cycle longer than that means the handover never runs and the
    /// state is never snapshotted. Ten minutes of margin is reserved for the
    /// freeze, upload and standby acknowledgement.
    pub fn validate(&self) -> Result<(), String> {
        if !self.owner.is_empty() && self.repo.is_empty() {
            return Err("repository name is required when an owner is set".into());
        }
        if self.cycle_minutes < 10 {
            return Err("cycle must be at least 10 minutes".into());
        }
        if self.cycle_minutes > 355 {
            return Err("cycle must be at most 355 minutes: GitHub kills a job at 360, \
                 and the handover needs the remaining margin"
                .into());
        }
        if self.poll_seconds < 10 {
            return Err("poll interval must be at least 10 seconds".into());
        }
        if self.auto_lock_minutes == 0 {
            return Err("auto-lock cannot be disabled".into());
        }
        Ok(())
    }

    pub fn repo_slug(&self) -> Option<String> {
        if self.owner.is_empty() || self.repo.is_empty() {
            None
        } else {
            Some(format!("{}/{}", self.owner, self.repo))
        }
    }
}

/// The single home of decrypted secrets.
#[derive(Default)]
pub struct Session {
    payload: Option<VaultPayload>,
    opened_at: Option<Instant>,
    last_use: Option<Instant>,
}

impl Session {
    pub fn is_open(&self) -> bool {
        self.payload.is_some()
    }

    pub fn open(&mut self, payload: VaultPayload) {
        let now = Instant::now();
        self.payload = Some(payload);
        self.opened_at = Some(now);
        self.last_use = Some(now);
    }

    /// Drop the decrypted payload. The `VaultPayload` Drop impl overwrites every
    /// value before releasing the allocations.
    pub fn lock(&mut self) {
        // Explicit drop for readability: this is the security-relevant line.
        drop(self.payload.take());
        self.opened_at = None;
        self.last_use = None;
    }

    pub fn touch(&mut self) {
        self.last_use = Some(Instant::now());
    }

    pub fn payload(&self) -> Option<&VaultPayload> {
        self.payload.as_ref()
    }

    /// Mutable access, used only by the commands that edit the vault. Callers
    /// must follow a mutation with a save, and must call [`Session::touch`] so
    /// the auto-lock timer reflects the activity.
    pub fn payload_mut(&mut self) -> Option<&mut VaultPayload> {
        self.payload.as_mut()
    }

    pub fn idle_for(&self) -> Option<Duration> {
        self.last_use.map(|t| t.elapsed())
    }

    pub fn opened_for(&self) -> Option<Duration> {
        self.opened_at.map(|t| t.elapsed())
    }
}

/// Buffered log lines with sequence numbers so the UI can tail incrementally.
#[derive(Default)]
pub struct LogBuffer {
    lines: std::collections::VecDeque<(u64, String)>,
    next_seq: u64,
}

impl LogBuffer {
    pub fn push(&mut self, line: impl Into<String>) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        self.lines.push_back((seq, line.into()));
        while self.lines.len() > LOG_CAPACITY {
            self.lines.pop_front();
        }
    }

    pub fn since(&self, seq: u64) -> Vec<(u64, String)> {
        self.lines
            .iter()
            .filter(|(s, _)| *s >= seq)
            .cloned()
            .collect()
    }

    pub fn head_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn clear(&mut self) {
        self.lines.clear();
    }
}

/// Live status of the remote node, refreshed by the poller.
#[derive(Clone, Debug, Default, Serialize)]
pub struct NodeStatus {
    /// `locked`, `unconfigured`, `unknown`, or a GitHub run status.
    pub phase: String,
    /// Slot whose run is currently being observed.
    pub slot: String,
    pub run_id: Option<u64>,
    pub run_url: Option<String>,
    pub started_at_unix: Option<u64>,
    /// Server-derived countdown, so it survives an app restart.
    pub remaining_secs: Option<u64>,
    pub elapsed_secs: Option<u64>,
    pub conclusion: Option<String>,
    /// When set, no successor will be dispatched by the runner.
    pub kill_switch: bool,
    pub last_poll_unix: Option<u64>,
    pub next_poll_secs: Option<u64>,
    pub rate_limit_remaining: Option<u32>,
    pub error: Option<String>,
}

/// Vault status, safe to render before unlocking.
#[derive(Clone, Debug, Serialize)]
pub struct VaultStatus {
    pub exists: bool,
    pub unlocked: bool,
    pub secrets: Vec<SecretView>,
    pub protector: ProtectorStatus,
    /// Whether this platform actually pins secret pages against swap. Reported
    /// separately from `protector` because they are unrelated mechanisms.
    pub swap_protection: bool,
    pub format: Option<String>,
    pub kdf: Option<KdfParams>,
    pub os_wrap: bool,
    pub binding_label: Option<String>,
    pub tamper_strikes: u32,
    pub tamper_log: Vec<TamperEvent>,
    pub rotate_count: u32,
    pub recoverable_from_backup: bool,
    pub unlocked_secs: Option<u64>,
    pub auto_lock_secs: Option<u64>,
}

pub struct AppState {
    pub store: VaultStore,
    pub session: Mutex<Session>,
    pub config: RwLock<Config>,
    pub status: RwLock<NodeStatus>,
    pub logs: Mutex<LogBuffer>,
    pub gh: GithubClient,
    /// Set by the tray "Quit" item so `RunEvent::ExitRequested` lets the process
    /// die instead of keeping it alive in the tray.
    pub quitting: std::sync::atomic::AtomicBool,
    /// When engaged, no handover is dispatched from this app and the runner sees
    /// the marker on Drive. Persisted, so a restart does not silently resume a
    /// loop the user deliberately stopped.
    pub kill_switch: std::sync::atomic::AtomicBool,
    /// Lazily built Drive client, keyed by a fingerprint of the service-account
    /// JSON so that rotating the credential transparently rebuilds it.
    drive: Mutex<Option<(String, std::sync::Arc<crate::drive::ledger::DriveClient>)>>,
}

impl AppState {
    pub fn new() -> Result<Self, String> {
        let store = VaultStore::with_default_dir();
        store.ensure_dir().map_err(|e| e.to_string())?;
        let config = load_config(store.dir()).unwrap_or_default();

        let kill_switch = load_kill_switch(store.dir());

        Ok(Self {
            store,
            session: Mutex::new(Session::default()),
            config: RwLock::new(config),
            status: RwLock::new(NodeStatus {
                phase: "unknown".into(),
                ..Default::default()
            }),
            logs: Mutex::new(LogBuffer::default()),
            gh: GithubClient::new().map_err(|e| e.to_string())?,
            quitting: std::sync::atomic::AtomicBool::new(false),
            kill_switch: std::sync::atomic::AtomicBool::new(kill_switch),
            drive: Mutex::new(None),
        })
    }

    /// Build (or reuse) the Drive client from the vault's service-account key.
    ///
    /// Requires an unlocked vault, which is why a locked app cannot touch Drive
    /// at all: the credential is not merely hidden, it is unavailable.
    pub fn drive(&self) -> Result<std::sync::Arc<crate::drive::ledger::DriveClient>, String> {
        let folder_id = self.config_snapshot().drive_folder_id;
        if folder_id.trim().is_empty() {
            return Err("no Drive folder id configured; see Settings".into());
        }
        let key = self.secret_copy("RCLONE_SERVICE_ACCOUNT_JSON")?;
        let fingerprint = fingerprint(key.as_str());

        {
            let guard = self
                .drive
                .lock()
                .map_err(|_| "drive client slot is poisoned".to_string())?;
            if let Some((cached_fp, client)) = guard.as_ref() {
                if *cached_fp == fingerprint {
                    return Ok(client.clone());
                }
            }
        }

        let client = std::sync::Arc::new(
            crate::drive::ledger::DriveClient::new(key.as_str(), &folder_id)
                .map_err(|e| e.to_string())?,
        );
        let mut guard = self
            .drive
            .lock()
            .map_err(|_| "drive client slot is poisoned".to_string())?;
        *guard = Some((fingerprint, client.clone()));
        Ok(client)
    }

    /// Drop the cached Drive client, and with it its cached access token.
    pub fn forget_drive(&self) {
        if let Ok(mut guard) = self.drive.lock() {
            *guard = None;
        }
    }

    pub fn log(&self, line: impl Into<String>) {
        if let Ok(mut logs) = self.logs.lock() {
            logs.push(line);
        }
    }

    pub fn config_snapshot(&self) -> Config {
        self.config.read().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn status_snapshot(&self) -> NodeStatus {
        self.status.read().map(|s| s.clone()).unwrap_or_default()
    }

    /// Copy one secret out of the vault for a network call.
    ///
    /// This deliberately produces a `Zeroizing<String>` rather than handing out
    /// a borrow: an HTTP call must hold the credential across an `.await`, and a
    /// `MutexGuard` over the session cannot be held there. The copy is scrubbed
    /// when it goes out of scope, but it *is* a second copy in the heap while it
    /// lives -- recorded as an accepted residual in `docs/THREAT_MODEL.md`.
    pub fn secret_copy(&self, name: &str) -> Result<Zeroizing<String>, String> {
        let session = self
            .session
            .lock()
            .map_err(|_| "vault session is poisoned".to_string())?;
        let payload = session
            .payload()
            .ok_or_else(|| "vault is locked".to_string())?;
        let value = payload.get(name).map_err(|e| e.to_string())?;
        Ok(Zeroizing::new(value.to_string()))
    }
}

pub fn config_path(dir: &Path) -> PathBuf {
    dir.join("config.json")
}

pub fn kill_switch_path(dir: &Path) -> PathBuf {
    dir.join("killswitch.json")
}

/// A stable, non-reversible identifier for a credential, used only to notice
/// that it changed. Not a secret and not derived reversibly.
fn fingerprint(value: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    digest[..8].iter().map(|b| format!("{b:02x}")).collect()
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct KillSwitchFile {
    engaged: bool,
}

pub fn load_kill_switch(dir: &Path) -> bool {
    std::fs::read(kill_switch_path(dir))
        .ok()
        .and_then(|raw| serde_json::from_slice::<KillSwitchFile>(&raw).ok())
        .map(|f| f.engaged)
        .unwrap_or(false)
}

pub fn save_kill_switch(dir: &Path, engaged: bool) -> Result<(), String> {
    let bytes =
        serde_json::to_vec_pretty(&KillSwitchFile { engaged }).map_err(|e| e.to_string())?;
    nrvault::atomic::write_atomic(&kill_switch_path(dir), &bytes, false).map_err(|e| e.to_string())
}

pub fn load_config(dir: &Path) -> Option<Config> {
    let raw = std::fs::read(config_path(dir)).ok()?;
    serde_json::from_slice(&raw).ok()
}

pub fn save_config(dir: &Path, config: &Config) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(config).map_err(|e| e.to_string())?;
    nrvault::atomic::write_atomic(&config_path(dir), &bytes, false).map_err(|e| e.to_string())
}
