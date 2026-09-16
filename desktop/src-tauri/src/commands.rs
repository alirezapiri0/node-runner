//! The command surface exposed to the webview.
//!
//! # The rule every command here obeys
//!
//! **No command returns secret material.** `vault_list_secrets` returns names,
//! timestamps and notes -- never values. There is deliberately no
//! `vault_get_secret`, and its absence is a security control rather than an
//! omission: a compromised or socially-engineered frontend cannot exfiltrate the
//! vault because the channel that would carry a plaintext value does not exist.
//! Secrets only ever move *into* the vault, or out of it directly into an HTTP
//! request built in Rust.
//!
//! Consequence for the UI: to let a user confirm a paste landed correctly, the
//! interface shows a fingerprint (length plus a truncated SHA-256) rather than
//! the value. That answers "is this the token I meant" without ever displaying
//! the token.

use nrvault::{KdfParams, Passphrase, SecretView, UnlockRequest, VaultPayload, WrapPolicy};
use serde::Serialize;
use tauri::State;

use crate::drive::ledger::{DriveEntry, Heartbeat};
use crate::gh::api::{successor_slot, DispatchRequest};
use crate::gh::secrets::SecretReport;
use crate::state::{save_config, save_kill_switch, AppState, Config, NodeStatus, VaultStatus};

/// Every command returns `Result<_, String>` with a message that is safe to
/// render. `nrvault`'s errors never contain secret material, so they can be
/// passed through directly.
type CmdResult<T> = Result<T, String>;

// ---------------------------------------------------------------------------
// Vault lifecycle
// ---------------------------------------------------------------------------

fn build_vault_status(state: &AppState) -> VaultStatus {
    let meta = state.store.meta_or_default();

    // Scoped so the session lock is released before any filesystem work.
    let (unlocked, secrets, unlocked_secs, auto_lock_secs) = {
        let opened = state
            .session
            .lock()
            .map(|session| {
                (
                    session.is_open(),
                    session
                        .payload()
                        .map(|payload| payload.views())
                        .unwrap_or_default(),
                    session.opened_for().map(|d| d.as_secs()),
                )
            })
            .unwrap_or((false, Vec::new(), None));
        let auto = state.config_snapshot().auto_lock_minutes.saturating_mul(60);
        (opened.0, opened.1, opened.2, Some(auto))
    };

    // Structure is read from the file, which needs no key. This is what lets the
    // dashboard report vault health before the user has typed anything.
    let (exists, format, kdf, os_wrap, binding_label) = match state.store.load() {
        Ok(vault) => (
            true,
            Some(vault.structural_summary()),
            Some(vault.header.kdf),
            vault.has_os_wrap(),
            vault.binding().map(|b| b.label().to_string()),
        ),
        Err(_) => (state.store.exists(), None, None, false, None),
    };

    VaultStatus {
        exists,
        unlocked,
        secrets,
        protector: nrvault::keywrap::probe_protector(),
        swap_protection: nrvault::swap_protection_available(),
        format,
        kdf,
        os_wrap,
        binding_label,
        tamper_strikes: meta.tamper_strikes,
        tamper_log: meta.tamper_log,
        rotate_count: meta.rotate_count,
        recoverable_from_backup: state.store.recoverable_from_backup(),
        unlocked_secs,
        auto_lock_secs,
    }
}

#[tauri::command]
pub fn vault_status(state: State<'_, AppState>) -> VaultStatus {
    build_vault_status(&state)
}

/// Calibrate the KDF without creating anything, so Settings can show the cost
/// the user's machine will actually pay.
#[tauri::command]
pub async fn vault_calibrate() -> CmdResult<KdfParams> {
    tauri::async_runtime::spawn_blocking(|| nrvault::kdf::calibrate(250))
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn vault_init(
    state: State<'_, AppState>,
    passphrase: String,
    kdf_target_ms: Option<u64>,
) -> CmdResult<VaultStatus> {
    if state.store.exists() {
        return Err("a vault already exists in this location".into());
    }

    let target = kdf_target_ms.unwrap_or(250);
    let dir = state.store.dir().to_path_buf();

    // One blocking unit does the whole job: derive, seal, persist, and re-open.
    // The passphrase is moved in as a `String` and never cloned, so there is
    // exactly one heap copy of it for the duration of the call.
    let (payload, summary) = tauri::async_runtime::spawn_blocking(move || {
        let pass = Passphrase::new(passphrase);
        pass.check_policy()?;
        let store = nrvault::VaultStore::new(dir);

        let policy = WrapPolicy {
            kdf: None,
            aead: nrvault::aead::AeadId::Aes256Gcm,
            os_wrap: nrvault::keywrap::os_available(),
            calibration_target_ms: target,
        };

        let empty = VaultPayload::new(nrvault::now_unix());
        let vault = nrvault::EncryptedVault::seal_secrets(&empty, &pass, &policy)?;

        // Record how long this machine actually took, so Settings can show the
        // real unlock cost rather than the target it was calibrated against.
        let calibrated_ms = nrvault::kdf::time_derive(vault.header.kdf)
            .ok()
            .map(|ms| ms as u64);
        let summary = vault.structural_summary();
        store.save(&vault, calibrated_ms)?;

        // Immediately unlock: the user just proved they know the passphrase, and
        // asking again would only encourage a weaker one.
        let opened = vault.unseal_secrets(&UnlockRequest::passphrase(&pass))?;
        Ok::<_, nrvault::VaultError>((opened, summary))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    if let Ok(mut session) = state.session.lock() {
        session.open(payload);
    }
    state.log(format!("vault created ({summary})"));

    Ok(build_vault_status(&state))
}

#[tauri::command]
pub async fn vault_unlock(
    state: State<'_, AppState>,
    passphrase: String,
) -> CmdResult<VaultStatus> {
    let pass = Passphrase::new(passphrase);
    let store = state.store.dir().to_path_buf();

    let payload = tauri::async_runtime::spawn_blocking(move || {
        let store = nrvault::VaultStore::new(store);
        store.load_and_unseal(&UnlockRequest::passphrase(&pass))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    if let Ok(mut session) = state.session.lock() {
        session.open(payload);
    }
    state.log("vault unlocked with the passphrase");
    Ok(build_vault_status(&state))
}

/// Unlock using the OS-protected key copy: no passphrase required.
///
/// This is what makes the app usable day to day. It is also strictly weaker than
/// the passphrase path, which is why privileged operations (rotation, export,
/// destroy) explicitly refuse to accept it.
#[tauri::command]
pub async fn vault_unlock_os(state: State<'_, AppState>) -> CmdResult<VaultStatus> {
    let store = state.store.dir().to_path_buf();
    let payload = tauri::async_runtime::spawn_blocking(move || {
        let store = nrvault::VaultStore::new(store);
        store.load_and_unseal(&UnlockRequest::os_convenience())
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    if let Ok(mut session) = state.session.lock() {
        session.open(payload);
    }
    state.log("vault unlocked via the OS-protected key");
    Ok(build_vault_status(&state))
}

#[tauri::command]
pub fn vault_lock(state: State<'_, AppState>) -> CmdResult<VaultStatus> {
    if let Ok(mut session) = state.session.lock() {
        session.lock();
    }
    // Drop the cached Drive client too, so its access token does not outlive the
    // unlock it was derived from.
    state.forget_drive();
    state.log("vault locked");
    Ok(build_vault_status(&state))
}

#[tauri::command]
pub fn vault_list_secrets(state: State<'_, AppState>) -> CmdResult<Vec<SecretView>> {
    let session = state
        .session
        .lock()
        .map_err(|_| "vault session is poisoned".to_string())?;
    let payload = session
        .payload()
        .ok_or_else(|| "vault is locked".to_string())?;
    Ok(payload.views())
}

#[tauri::command]
pub fn vault_set_secret(
    state: State<'_, AppState>,
    name: String,
    value: String,
    note: Option<String>,
) -> CmdResult<VaultStatus> {
    // Validate before touching anything: these names become environment variable
    // names on the runner, so a name with shell metacharacters in it would be a
    // command-injection vector rather than a cosmetic problem.
    VaultPayload::validate_name(&name).map_err(|e| e.to_string())?;

    let now = nrvault::now_unix();
    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "vault session is poisoned".to_string())?;
        let payload = session
            .payload_mut()
            .ok_or_else(|| "unlock the vault before changing it".to_string())?;
        payload.set(&name, &value, now);
        if let Some(note) = note.as_deref() {
            payload
                .set_note(&name, Some(note), now)
                .map_err(|e| e.to_string())?;
        }
        session.touch();
    };

    persist_session(&state)?;
    Ok(build_vault_status(&state))
}

#[tauri::command]
pub fn vault_delete_secret(state: State<'_, AppState>, name: String) -> CmdResult<VaultStatus> {
    let now = nrvault::now_unix();
    {
        let mut session = state
            .session
            .lock()
            .map_err(|_| "vault session is poisoned".to_string())?;
        let payload = session
            .payload_mut()
            .ok_or_else(|| "unlock the vault before changing it".to_string())?;
        payload.remove(&name, now).map_err(|e| e.to_string())?;
        session.touch();
    }
    persist_session(&state)?;
    Ok(build_vault_status(&state))
}

/// Re-seal the vault under a new passphrase.
///
/// Requires the current passphrase, not merely an unlocked session. If a stolen
/// laptop is unlocked via the OS path, an attacker must not be able to change the
/// passphrase and lock the owner out.
#[tauri::command]
pub async fn vault_rotate(
    state: State<'_, AppState>,
    current_passphrase: String,
    new_passphrase: String,
    kdf_target_ms: Option<u64>,
) -> CmdResult<VaultStatus> {
    let store = state.store.dir().to_path_buf();
    let target = kdf_target_ms.unwrap_or(250);

    let payload = tauri::async_runtime::spawn_blocking(move || {
        let current = Passphrase::new(current_passphrase);
        let new = Passphrase::new(new_passphrase);
        new.check_policy()?;

        let store = nrvault::VaultStore::new(store);
        let mut vault = store.load()?;

        // Decrypt with the *old* passphrase and re-wrap under a freshly calibrated
        // key. This uses the passphrase path explicitly and never the OS path, so
        // an unlocked session alone cannot change the passphrase.
        let policy = WrapPolicy {
            kdf: None,
            aead: vault.header.aead_id,
            os_wrap: nrvault::keywrap::os_available(),
            calibration_target_ms: target,
        };
        vault.rotate_passphrase(&UnlockRequest::passphrase(&current), &new, &policy)?;
        store.save(&vault, None)?;
        store.note_rotation()?;

        // Re-open under the new passphrase inside the same blocking unit, so the
        // new passphrase never has to be copied out of it.
        vault.unseal_secrets(&UnlockRequest::passphrase(&new))
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    if let Ok(mut session) = state.session.lock() {
        session.open(payload);
    }
    state.log("vault passphrase rotated");
    Ok(build_vault_status(&state))
}

#[tauri::command]
pub fn vault_clear_alerts(state: State<'_, AppState>) -> CmdResult<VaultStatus> {
    state.store.clear_tampers().map_err(|e| e.to_string())?;
    Ok(build_vault_status(&state))
}

/// Destroy the vault. Requires the passphrase because it is irreversible.
#[tauri::command]
pub async fn vault_destroy(
    state: State<'_, AppState>,
    passphrase: String,
) -> CmdResult<VaultStatus> {
    let pass = Passphrase::new(passphrase);
    let store = state.store.dir().to_path_buf();

    tauri::async_runtime::spawn_blocking(move || {
        let store = nrvault::VaultStore::new(store);
        // Prove knowledge of the passphrase before destroying anything.
        store.load_and_unseal(&UnlockRequest::passphrase(&pass))?;
        store.destroy()
    })
    .await
    .map_err(|e| e.to_string())?
    .map_err(|e| e.to_string())?;

    if let Ok(mut session) = state.session.lock() {
        session.lock();
    }
    state.forget_drive();
    state.log("vault destroyed");
    Ok(build_vault_status(&state))
}

/// Re-seal the vault after an in-memory mutation.
///
/// `update_payload` re-encrypts only the payload and recomputes the MAC; the
/// salt, KDF parameters and wrapped DEK are untouched. That is what allows a save
/// to work from a session unlocked through the OS path, with no passphrase
/// prompt for editing a token.
///
/// On a platform with no OS key protector there is no way to reach the DEK
/// without a passphrase, and this app deliberately does not retain passphrases in
/// memory, so writes are refused with an explicit message rather than by keeping
/// a secret alive between calls. The desktop target is Windows, where DPAPI is
/// always available.
fn persist_session(state: &AppState) -> CmdResult<()> {
    let json = {
        let session = state
            .session
            .lock()
            .map_err(|_| "vault session is poisoned".to_string())?;
        let payload = session
            .payload()
            .ok_or_else(|| "vault is locked".to_string())?;
        payload.to_json().map_err(|e| e.to_string())?
    };

    let mut vault = state.store.load().map_err(|e| e.to_string())?;
    if !vault.has_os_wrap() {
        return Err(
            "this vault has no OS-protected key, so it must be re-opened with the passphrase to \
             write changes"
                .into(),
        );
    }

    vault
        .update_payload(json.as_bytes(), &UnlockRequest::os_convenience())
        .map_err(|e| e.to_string())?;
    state.store.save(&vault, None).map_err(|e| e.to_string())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn config_get(state: State<'_, AppState>) -> Config {
    state.config_snapshot()
}

#[tauri::command]
pub fn config_set(state: State<'_, AppState>, config: Config) -> CmdResult<Config> {
    config.validate()?;
    save_config(state.store.dir(), &config)?;
    if let Ok(mut current) = state.config.write() {
        *current = config.clone();
    }
    // A changed folder or credential invalidates the cached Drive client.
    state.forget_drive();
    Ok(config)
}

// ---------------------------------------------------------------------------
// Node control
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn node_status(state: State<'_, AppState>) -> NodeStatus {
    let mut status = state.status_snapshot();
    status.kill_switch = state.kill_switch.load(std::sync::atomic::Ordering::Relaxed);
    status
}

#[derive(Debug, Clone, Serialize)]
pub struct KillSwitchState {
    pub engaged: bool,
    pub drive_marker_written: bool,
    pub detail: String,
}

/// Engage or release the global stop.
///
/// Two effects, and both matter: the local flag stops this app from dispatching
/// anything, and the marker on Drive is what the *running node* checks before it
/// freezes and hands over. Without the second half, stopping the desktop would
/// only blind the operator while the loop continued.
#[tauri::command]
pub async fn node_set_kill_switch(
    state: State<'_, AppState>,
    engaged: bool,
    note: Option<String>,
) -> CmdResult<KillSwitchState> {
    use std::sync::atomic::Ordering;

    state.kill_switch.store(engaged, Ordering::Relaxed);
    save_kill_switch(state.store.dir(), engaged)?;

    let note = note.unwrap_or_else(|| {
        if engaged {
            "engaged from the desktop app".into()
        } else {
            "released from the desktop app".into()
        }
    });

    // Best-effort: the marker needs Drive, which needs an unlocked vault. A
    // failure here is surfaced rather than hidden, because a local-only stop
    // would be a false sense of safety.
    match state.drive() {
        Ok(client) => match client.set_killswitch(engaged, &note).await {
            Ok(()) => Ok(KillSwitchState {
                engaged,
                drive_marker_written: true,
                detail: "stop marker written to Drive; the running node will observe it before handing over".into(),
            }),
            Err(e) => Ok(KillSwitchState {
                engaged,
                drive_marker_written: false,
                detail: format!(
                    "local stop applied, but the Drive marker could not be written: {e}. \
                     The node will keep refreshing until the marker is set."
                ),
            }),
        },
        Err(e) => Ok(KillSwitchState {
            engaged,
            drive_marker_written: false,
            detail: format!("local stop applied; Drive unavailable: {e}"),
        }),
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DispatchReport {
    pub accepted: bool,
    pub target_slot: String,
    pub detail: String,
}

/// Force migration / failover: dispatch a successor now.
///
/// Targets whichever slot is *not* currently running, so the successor can start
/// immediately instead of queueing behind the live node. That alternation is the
/// whole reason two concurrency groups exist in the workflow.
#[tauri::command]
pub async fn node_dispatch(state: State<'_, AppState>) -> CmdResult<DispatchReport> {
    use std::sync::atomic::Ordering;

    if state.kill_switch.load(Ordering::Relaxed) {
        return Err("the stop switch is engaged; release it before dispatching a successor".into());
    }

    let config = state.config_snapshot();
    let slug = config
        .repo_slug()
        .ok_or_else(|| "set the repository owner and name in Settings".to_string())?;
    let token = state.secret_copy("GH_PAT")?;

    // Computed by a tested function rather than inline: the workflow rejects any
    // slot outside `blue|green` with a 422, which is how the a/b spelling this
    // used to send went unnoticed until CI compiled the crate.
    let target_slot = successor_slot(&state.status_snapshot().slot);

    let outcome = state
        .gh
        .dispatch(&DispatchRequest {
            token: token.as_str(),
            slug: slug.as_str(),
            workflow_file: config.workflow_file.as_str(),
            git_ref: "main",
            slot: target_slot,
            commit: "",
            reason: "failover",
        })
        .await
        .map_err(|e| e.to_string())?;

    state.log(format!(
        "dispatched successor into slot {target_slot}: {}",
        outcome.detail
    ));

    Ok(DispatchReport {
        accepted: outcome.accepted,
        target_slot: target_slot.into(),
        detail: outcome.detail,
    })
}

/// Seal and upload the vault's credentials into the runner repository.
#[tauri::command]
pub async fn secrets_inject(state: State<'_, AppState>) -> CmdResult<Vec<SecretReport>> {
    crate::gh::secrets::inject_required(&state)
        .await
        .map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Drive: ledger, heartbeat, and the relayed log tail
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn drive_ledger(state: State<'_, AppState>) -> CmdResult<Vec<DriveEntry>> {
    state
        .drive()?
        .list_snapshots()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn drive_heartbeat(state: State<'_, AppState>) -> CmdResult<Option<Heartbeat>> {
    state.drive()?.heartbeat().await.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Local log tail
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct LogTail {
    pub next_seq: u64,
    pub lines: Vec<String>,
}

/// Incremental local log tail.
///
/// Polling rather than a pushed channel, deliberately: the frontend is
/// dependency-free and talks to the backend over plain `invoke`, so a polled
/// cursor needs no JS-side event plumbing. The cost is one in-process call every
/// couple of seconds with no network involved.
#[tauri::command]
pub fn logs_tail(state: State<'_, AppState>, since: u64) -> LogTail {
    let logs = state.logs.lock();
    match logs.as_ref() {
        Ok(buffer) => LogTail {
            next_seq: buffer.head_seq(),
            lines: buffer
                .since(since)
                .into_iter()
                .map(|(_, line)| line)
                .collect(),
        },
        Err(_) => LogTail {
            next_seq: since,
            lines: Vec::new(),
        },
    }
}

#[tauri::command]
pub fn logs_clear(state: State<'_, AppState>) -> CmdResult<()> {
    state
        .logs
        .lock()
        .map_err(|_| "log buffer is poisoned".to_string())?
        .clear();
    Ok(())
}

// ---------------------------------------------------------------------------
// About / diagnostics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct AppInfo {
    pub version: String,
    pub data_dir: String,
    pub vault_path: String,
    pub swap_protection: bool,
    pub os_protection: bool,
    pub protector_status: String,
    pub secret_fingerprint_helper: bool,
}

#[tauri::command]
pub fn app_info(state: State<'_, AppState>) -> AppInfo {
    AppInfo {
        version: env!("CARGO_PKG_VERSION").to_string(),
        data_dir: state.store.dir().display().to_string(),
        vault_path: state.store.vault_path().display().to_string(),
        swap_protection: nrvault::swap_protection_available(),
        os_protection: nrvault::keywrap::os_available(),
        protector_status: format!("{:?}", nrvault::keywrap::probe_protector()),
        secret_fingerprint_helper: true,
    }
}
