//! Persistence for the sealed vault.
//!
//! Two files live side by side:
//!
//! * `vault.bin` -- the sealed envelope, in the format documented in
//!   [`crate::vault`]. Nothing outside that module knows its layout.
//! * `vault.meta.json` -- non-secret operational metadata: KDF parameters,
//!   calibration timing, OS protector health, and a tamper ledger.
//!
//! The metadata file is deliberately kept separate and non-secret so the UI can
//! report vault health *before* the user types a passphrase. It must never be
//! allowed to grow a field that leaks credential data; `secret_names` is
//! conspicuously absent for that reason.
//!
//! # Location
//!
//! `%LOCALAPPDATA%\NodeRunner` on Windows, **not** `%APPDATA%`. The roaming
//! profile replicates to other machines, and a DPAPI-wrapped blob cannot be
//! unwrapped anywhere except the profile that produced it -- so a roaming vault
//! would present as "corrupt" on every other machine the user signs into.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::atomic;
use crate::errors::{Result, VaultError};
use crate::kdf::KdfParams;
use crate::keywrap::{self, ProtectorStatus, TpmBinding};
use crate::secret::VaultPayload;
use crate::vault::{EncryptedVault, UnlockRequest};

pub const META_SCHEMA: u32 = 1;
const MAX_TAMPER_LOG: usize = 10;

/// One recorded integrity failure.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TamperEvent {
    pub at_unix: u64,
    /// Non-secret description, e.g. "mac mismatch on load".
    pub detail: String,
}

/// Non-secret vault metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VaultMeta {
    pub schema: u32,
    pub format_version: u16,
    pub aead: String,
    pub kdf: KdfParams,
    pub kdf_calibrated_ms: Option<u64>,
    pub os_wrap: Option<TpmBinding>,
    pub protector: ProtectorStatus,
    pub created_at_unix: u64,
    pub updated_at_unix: u64,
    pub last_unlock_at_unix: Option<u64>,
    /// Number of times the wrapped DEK has been re-keyed.
    pub rotate_count: u32,
    /// Cumulative integrity failures. Non-zero means "investigate", and the UI
    /// shows a persistent banner until it is explicitly cleared.
    pub tamper_strikes: u32,
    pub tamper_log: Vec<TamperEvent>,
    /// SHA-256 of the envelope as written by the last successful seal.
    ///
    /// Non-secret by construction (see `EncryptedVault::envelope_fingerprint`).
    /// Its only job is to let an unlock failure be attributed correctly: file
    /// changed versus passphrase mistyped.
    pub envelope_fingerprint: Option<String>,
}

impl VaultMeta {
    pub fn new(kdf: KdfParams, now_unix: u64) -> Self {
        Self {
            schema: META_SCHEMA,
            format_version: crate::vault::FORMAT_VERSION,
            aead: "AES-256-GCM".into(),
            kdf,
            kdf_calibrated_ms: None,
            os_wrap: None,
            protector: ProtectorStatus::Unsupported,
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
            last_unlock_at_unix: None,
            rotate_count: 0,
            tamper_strikes: 0,
            tamper_log: Vec::new(),
            envelope_fingerprint: None,
        }
    }
}

/// Filesystem-backed vault.
pub struct VaultStore {
    dir: PathBuf,
}

impl VaultStore {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    /// The production location for this user.
    pub fn default_dir() -> PathBuf {
        #[cfg(windows)]
        {
            if let Some(p) = std::env::var_os("LOCALAPPDATA") {
                return PathBuf::from(p).join("NodeRunner");
            }
        }
        if let Some(p) = std::env::var_os("XDG_DATA_HOME") {
            return PathBuf::from(p).join("noderunner");
        }
        if let Some(p) = std::env::var_os("HOME") {
            return PathBuf::from(p).join(".local/share/noderunner");
        }
        std::env::temp_dir().join("noderunner")
    }

    pub fn with_default_dir() -> Self {
        Self::new(Self::default_dir())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn vault_path(&self) -> PathBuf {
        self.dir.join("vault.bin")
    }

    pub fn meta_path(&self) -> PathBuf {
        self.dir.join("vault.meta.json")
    }

    pub fn backup_path(&self) -> PathBuf {
        atomic::backup_path(&self.vault_path())
    }

    pub fn exists(&self) -> bool {
        self.vault_path().exists()
    }

    /// True when the primary file is unreadable but the previous generation is
    /// still present. Never tell the user "no vault" in this state.
    pub fn recoverable_from_backup(&self) -> bool {
        !self.vault_path().exists() && self.backup_path().exists()
    }

    pub fn ensure_dir(&self) -> Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        Ok(())
    }

    // -- sealed vault -------------------------------------------------------

    /// Persist the envelope and refresh the metadata in one step.
    pub fn save(&self, vault: &EncryptedVault, calibrated_ms: Option<u64>) -> Result<()> {
        self.ensure_dir()?;
        atomic::write_atomic(&self.vault_path(), &vault.to_bytes(), true)?;

        let mut meta = self
            .meta()
            .unwrap_or_else(|_| VaultMeta::new(vault.header.kdf, crate::now_unix()));
        meta.format_version = vault.header.version;
        meta.aead = vault.header.aead_id.name().to_string();
        meta.kdf = vault.header.kdf;
        meta.os_wrap = vault.binding();
        meta.protector = keywrap::probe_protector();
        meta.envelope_fingerprint = Some(vault.envelope_fingerprint());
        if calibrated_ms.is_some() {
            meta.kdf_calibrated_ms = calibrated_ms;
        }
        meta.updated_at_unix = crate::now_unix();
        self.write_meta(&meta)
    }

    pub fn load(&self) -> Result<EncryptedVault> {
        let bytes = atomic::read(&self.vault_path())?;
        EncryptedVault::from_bytes(&bytes)
    }

    /// Open the previous generation. Used when the primary fails structurally.
    pub fn load_backup(&self) -> Result<EncryptedVault> {
        let bytes = atomic::read(&self.backup_path())?;
        EncryptedVault::from_bytes(&bytes)
    }

    /// Load, unseal, and record the unlock in the metadata.
    ///
    /// When an unlock fails, the two possible causes are attributed using the
    /// recorded fingerprint rather than guessed:
    ///
    /// * file unchanged  -> a mistyped passphrase; no alarm, no ledger entry
    /// * file changed    -> reported as tampering in the ledger
    pub fn load_and_unseal(&self, req: &UnlockRequest<'_>) -> Result<VaultPayload> {
        let vault = self.load()?;
        match vault.unseal_secrets(req) {
            Ok(payload) => {
                self.note_unlock();
                Ok(payload)
            }
            Err(VaultError::Integrity) => {
                // Authenticity was proven and the payload still would not open.
                // Unambiguous: record it unconditionally.
                let _ = self.record_tamper("authenticated envelope failed to open");
                Err(VaultError::Integrity)
            }
            Err(VaultError::Auth) => {
                if self.envelope_changed_since_seal(&vault) == Some(true) {
                    let _ = self.record_tamper("envelope changed since it was last sealed");
                }
                // Returned either way: the caller cannot act differently, and
                // telling the user which case it is comes from the ledger.
                Err(VaultError::Auth)
            }
            Err(e) => Err(e),
        }
    }

    /// Whether the envelope differs from what was recorded at seal time.
    ///
    /// `None` means no fingerprint has been recorded (a vault written before
    /// this field existed), in which case no attribution is possible.
    pub fn envelope_changed_since_seal(&self, vault: &EncryptedVault) -> Option<bool> {
        let recorded = self.meta().ok()?.envelope_fingerprint?;
        Some(recorded != vault.envelope_fingerprint())
    }

    // -- metadata -----------------------------------------------------------

    pub fn meta(&self) -> Result<VaultMeta> {
        let bytes = atomic::read(&self.meta_path())?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub fn write_meta(&self, meta: &VaultMeta) -> Result<()> {
        self.ensure_dir()?;
        let bytes = serde_json::to_vec_pretty(meta)?;
        atomic::write_atomic(&self.meta_path(), &bytes, false)
    }

    /// Metadata, or a freshly synthesised default if the file is missing or
    /// unreadable. The UI should still render.
    pub fn meta_or_default(&self) -> VaultMeta {
        self.meta()
            .unwrap_or_else(|_| VaultMeta::new(KdfParams::preferred(), crate::now_unix()))
    }

    fn note_unlock(&self) {
        let mut meta = self.meta_or_default();
        meta.last_unlock_at_unix = Some(crate::now_unix());
        if keywrap::os_available() {
            meta.protector = keywrap::probe_protector();
        }
        let _ = self.write_meta(&meta);
    }

    /// Record an integrity failure and return the new strike count.
    pub fn record_tamper(&self, detail: &str) -> Result<u32> {
        let mut meta = self.meta_or_default();
        meta.tamper_strikes = meta.tamper_strikes.saturating_add(1);
        meta.updated_at_unix = crate::now_unix();
        meta.tamper_log.insert(
            0,
            TamperEvent {
                at_unix: crate::now_unix(),
                detail: detail.to_string(),
            },
        );
        meta.tamper_log.truncate(MAX_TAMPER_LOG);
        let strikes = meta.tamper_strikes;
        self.write_meta(&meta)?;
        Ok(strikes)
    }

    pub fn clear_tampers(&self) -> Result<()> {
        let mut meta = self.meta_or_default();
        meta.tamper_strikes = 0;
        meta.tamper_log.clear();
        self.write_meta(&meta)
    }

    pub fn note_rotation(&self) -> Result<()> {
        let mut meta = self.meta_or_default();
        meta.rotate_count = meta.rotate_count.saturating_add(1);
        meta.updated_at_unix = crate::now_unix();
        self.write_meta(&meta)
    }

    /// Destroy the vault and its metadata.
    ///
    /// This is the real erasure mechanism in this design: crypto-erase. Once the
    /// wrapped DEK is gone, the payload ciphertext is unrecoverable regardless
    /// of what remains in the filesystem's free blocks.
    pub fn destroy(&self) -> Result<()> {
        atomic::wipe(&self.vault_path())?;
        atomic::wipe(&self.backup_path())?;
        atomic::wipe(&atomic::tmp_path(&self.vault_path()))?;
        atomic::wipe(&self.meta_path())?;
        Ok(())
    }
}

impl std::fmt::Debug for VaultStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultStore")
            .field("dir", &self.dir)
            .field("exists", &self.exists())
            .finish()
    }
}
