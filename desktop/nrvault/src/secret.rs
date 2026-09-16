//! Secret-bearing newtypes.
//!
//! Every type here follows the same contract:
//!
//! * `Debug` is hand-written and prints `[redacted]`. A derived `Debug` on a
//!   secret type is the single most likely real-world leak in a Rust codebase,
//!   because a stray `tracing::debug!(?secret)` or an `unwrap()` panic message
//!   will happily print the value.
//! * The type is not `Clone` unless cloning is genuinely required, so secrets
//!   do not multiply across the heap.
//! * `Drop` actively overwrites the allocation rather than relying on the
//!   allocator to do the right thing.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::errors::{Result, VaultError};

/// Minimum accepted master password length.
///
/// A length floor is a blunt instrument, but it is the only password-strength
/// signal we can evaluate locally without shipping a wordlist-sized estimator
/// (zxcvbn and friends are hundreds of KB, which the <5MB budget cannot absorb).
pub const MIN_PASSPHRASE_LEN: usize = 12;

/// A master password. Held as `Zeroizing<String>` so the heap allocation is
/// scrubbed on drop.
pub struct Passphrase(Zeroizing<String>);

impl Passphrase {
    pub fn new(s: impl Into<String>) -> Self {
        Self(Zeroizing::new(s.into()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Borrow the plaintext. Named `expose` on purpose: every call site should
    /// be obvious in review.
    pub fn expose(&self) -> &str {
        self.0.as_str()
    }

    /// Enforce the passphrase policy at *creation* time, never at unlock time.
    ///
    /// Rejecting weak passphrases on unlock would lock users out of vaults they
    /// already created, so the policy is only applied when a new passphrase is
    /// being established.
    pub fn check_policy(&self) -> Result<()> {
        let s = self.expose();
        if s.chars().count() < MIN_PASSPHRASE_LEN {
            return Err(VaultError::WeakPassphrase(format!(
                "must be at least {MIN_PASSPHRASE_LEN} characters"
            )));
        }
        let classes = [
            s.chars().any(|c| c.is_ascii_lowercase()),
            s.chars().any(|c| c.is_ascii_uppercase()),
            s.chars().any(|c| c.is_ascii_digit()),
            s.chars().any(|c| !c.is_ascii_alphanumeric()),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if classes < 2 {
            return Err(VaultError::WeakPassphrase(
                "use at least two of: lowercase, uppercase, digits, symbols".into(),
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase([redacted])")
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        // Zeroizing<String> already handles this; kept explicit so the
        // invariant is visible without chasing the wrapper.
        self.0.zeroize();
    }
}

/// One credential plus provenance metadata.
///
/// Deliberately **not** `Clone`: nothing in this codebase should be making
/// copies of credential material.
#[derive(Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SecretEntry {
    pub value: String,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub rotated_at_unix: Option<u64>,
    #[serde(default)]
    pub note: Option<String>,
}

impl fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretEntry")
            .field("value", &"[redacted]")
            .field("created_at_unix", &self.created_at_unix)
            .field("rotated_at_unix", &self.rotated_at_unix)
            .field("note", &self.note)
            .finish()
    }
}

/// A metadata-only projection safe to hand to the UI.
///
/// This is the type the Tauri layer returns from `vault_list_secrets`. The
/// frontend has no command that can read a secret *value* back out, so this
/// struct is the only shape credential metadata ever takes on the IPC boundary.
#[derive(Debug, Clone, Serialize)]
pub struct SecretView {
    pub name: String,
    pub created_at_unix: u64,
    pub rotated_at_unix: Option<u64>,
    pub note: Option<String>,
}

/// The decrypted vault contents.
#[derive(Serialize, Deserialize, Default)]
pub struct VaultPayload {
    pub schema: u32,
    pub secrets: BTreeMap<String, SecretEntry>,
    #[serde(default)]
    pub created_at_unix: u64,
    #[serde(default)]
    pub updated_at_unix: u64,
}

impl VaultPayload {
    pub const SCHEMA: u32 = 1;

    pub fn new(now_unix: u64) -> Self {
        Self {
            schema: Self::SCHEMA,
            secrets: BTreeMap::new(),
            created_at_unix: now_unix,
            updated_at_unix: now_unix,
        }
    }

    /// Secret names are constrained to an allowlist charset because they are
    /// used to build environment variable names on the runner. Allowing
    /// arbitrary bytes here would let a vault entry smuggle shell metacharacters
    /// into `lifecycle.sh`.
    pub fn validate_name(name: &str) -> Result<()> {
        if name.is_empty() || name.len() > 64 {
            return Err(VaultError::InvalidSecretName(name.to_string()));
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(VaultError::InvalidSecretName(format!(
                "{name:?} (use A-Z, 0-9 and _ only)"
            )));
        }
        Ok(())
    }

    pub fn set(&mut self, name: &str, value: &str, now_unix: u64) {
        let entry = self
            .secrets
            .entry(name.to_string())
            .or_insert_with(|| SecretEntry {
                value: String::new(),
                created_at_unix: now_unix,
                rotated_at_unix: None,
                note: None,
            });
        if !entry.value.is_empty() {
            entry.rotated_at_unix = Some(now_unix);
        }
        entry.value.zeroize();
        entry.value = value.to_string();
        if entry.created_at_unix == 0 {
            entry.created_at_unix = now_unix;
        }
        self.touch(now_unix);
    }

    pub fn set_note(&mut self, name: &str, note: Option<&str>, now_unix: u64) -> Result<()> {
        let entry = self
            .secrets
            .get_mut(name)
            .ok_or_else(|| VaultError::UnknownSecret(name.to_string()))?;
        entry.note = note.map(|s| s.to_string());
        self.touch(now_unix);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<&str> {
        self.secrets
            .get(name)
            .map(|e| e.value.as_str())
            .ok_or_else(|| VaultError::UnknownSecret(name.to_string()))
    }

    pub fn remove(&mut self, name: &str, now_unix: u64) -> Result<()> {
        let mut entry = self
            .secrets
            .remove(name)
            .ok_or_else(|| VaultError::UnknownSecret(name.to_string()))?;
        // Overwrite before the allocation is released.
        entry.value.zeroize();
        self.touch(now_unix);
        Ok(())
    }

    pub fn touch(&mut self, now_unix: u64) {
        self.updated_at_unix = now_unix;
    }

    pub fn names(&self) -> Vec<&str> {
        self.secrets.keys().map(String::as_str).collect()
    }

    /// Metadata-only view for the UI. Never includes values.
    pub fn views(&self) -> Vec<SecretView> {
        self.secrets
            .iter()
            .map(|(name, e)| SecretView {
                name: name.clone(),
                created_at_unix: e.created_at_unix,
                rotated_at_unix: e.rotated_at_unix,
                note: e.note.clone(),
            })
            .collect()
    }

    /// Canonical serialization.
    ///
    /// `BTreeMap` guarantees key order, so the same logical vault always
    /// serializes to the same bytes. That determinism is what lets the tests
    /// assert on ciphertext stability and makes the encrypted blob reproducible
    /// given a fixed DEK/nonce.
    pub fn to_json(&self) -> Result<Zeroizing<String>> {
        Ok(Zeroizing::new(serde_json::to_string(self)?))
    }

    pub fn from_json(raw: &[u8]) -> Result<Self> {
        let payload: Self =
            serde_json::from_slice(raw).map_err(|e| VaultError::Payload(e.to_string()))?;
        if payload.schema != Self::SCHEMA {
            return Err(VaultError::Unsupported(format!(
                "payload schema {} (expected {})",
                payload.schema,
                Self::SCHEMA
            )));
        }
        Ok(payload)
    }
}

impl fmt::Debug for VaultPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VaultPayload")
            .field("schema", &self.schema)
            .field("secret_names", &self.names())
            .field("created_at_unix", &self.created_at_unix)
            .field("updated_at_unix", &self.updated_at_unix)
            .finish()
    }
}

impl Drop for VaultPayload {
    fn drop(&mut self) {
        for entry in self.secrets.values_mut() {
            entry.value.zeroize();
            if let Some(note) = entry.note.as_mut() {
                note.zeroize();
            }
        }
        self.secrets.clear();
    }
}
