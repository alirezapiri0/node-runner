//! Typed errors for the vault.
//!
//! Two rules hold across this crate:
//!
//! 1. No error message ever embeds secret material. The variants carry
//!    identifiers, lengths and algorithm names only.
//! 2. `unseal*` never panics on hostile input. Every parse step is bounds
//!    checked and returns a variant below, so a fuzz target can assert
//!    "typed error for arbitrary bytes" (see `fuzz/fuzz_targets/unseal.rs`).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    // ---- structural (checked BEFORE any key derivation work) ----
    #[error("vault is structurally invalid: {0}")]
    Format(String),

    #[error("unsupported vault format: {0}")]
    Unsupported(String),

    // ---- authenticated (checked with key material in hand) ----
    /// Authenticity **was** established and the contents still could not be
    /// opened. This is unambiguous corruption or tampering.
    #[error("integrity check failed: the vault file is corrupt or has been modified")]
    Integrity,

    /// The key material did not authenticate this file. Read the variant
    /// documentation on [`VaultError::is_authentication_failure`] before showing
    /// this to a user.
    #[error(
        "authentication failed: the passphrase is incorrect, or the vault file has been modified"
    )]
    Auth,

    #[error("no usable unlock method: {0}")]
    NoUnlockMethod(String),

    #[error("this operation requires the passphrase and will not use the OS convenience path")]
    PassphraseRequired,

    // ---- policy ----
    #[error("master password rejected: {0}")]
    WeakPassphrase(String),

    #[error("invalid KDF parameters: {0}")]
    KdfParams(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    // ---- OS protection ----
    #[error("OS key protection unavailable on this platform: {0}")]
    OsProtectionUnavailable(String),

    #[error("OS key protection failed: {0}")]
    OsProtection(String),

    #[error("secure memory operation failed: {0}")]
    SecureMemory(String),

    // ---- payload ----
    #[error("vault payload is not valid JSON: {0}")]
    Payload(String),

    #[error("no secret named {0:?} is present in the vault")]
    UnknownSecret(String),

    #[error("secret name is not allowed: {0}")]
    InvalidSecretName(String),

    // ---- plumbing ----
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;

impl VaultError {
    /// True when the failure is `Auth`.
    ///
    /// This variant carries a deliberate ambiguity that cannot be engineered
    /// away: a wrong passphrase derives a wrong MAC key, and a modified file
    /// fails the same MAC check. The two are the same computation, so they
    /// produce the same error. That is the property that makes the MAC
    /// meaningful -- if they were distinguishable, the vault would leak
    /// information about the key to an attacker who can modify the file.
    ///
    /// Callers that need to tell them apart must use a signal that does not
    /// depend on the passphrase, namely
    /// [`crate::VaultStore::header_changed_since_seal`].
    pub fn is_authentication_failure(&self) -> bool {
        matches!(self, Self::Auth)
    }

    /// True when authenticity was proven and the content still failed to open:
    /// definite corruption or tampering, never a mistyped passphrase.
    pub fn is_definite_tamper(&self) -> bool {
        matches!(self, Self::Integrity)
    }
}
