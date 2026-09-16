//! `nrvault` -- the credential engine for Node Runner.
//!
//! This crate is the entire security boundary. It has no UI dependencies, no
//! async runtime and no network code, so it can be audited, fuzzed and tested in
//! isolation from the Tauri application that uses it.
//!
//! # Threat model in one paragraph
//!
//! The vault protects credentials at rest against offline theft of the machine,
//! its backups, or a copied vault file; against another user account on the same
//! box; and against silent file modification. It does **not** defend against
//! malware already executing as the current user -- DPAPI will unwrap for such
//! code and the decrypted payload lives in this process's address space while
//! in use. See `docs/THREAT_MODEL.md` for the full breakdown, including the
//! residual gaps this design accepts (IPC-side copies of the passphrase,
//! crash dumps, and swap on platforms without page locking).

pub mod aead;
pub mod atomic;
pub mod errors;
pub mod kdf;
pub mod keywrap;
pub mod lockmem;
pub mod sealbox;
pub mod secret;
pub mod store;
pub mod vault;

pub use errors::{Result, VaultError};
pub use kdf::KdfParams;
pub use keywrap::{ProtectorStatus, TpmBinding};
pub use sealbox::RepositoryKey;
pub use secret::{Passphrase, SecretEntry, SecretView, VaultPayload, MIN_PASSPHRASE_LEN};
pub use store::{TamperEvent, VaultMeta, VaultStore};
pub use vault::{EncryptedVault, Header, UnlockRequest, WrapPolicy};

/// Seconds since the Unix epoch.
///
/// Deliberately dependency-free: pulling in a datetime crate for this would
/// cost more binary than the entire crypto stack.
pub fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Apply process-wide hardening. Call once, as early as possible in `main`.
///
/// * widens the working-set quota so page locking is not refused under pressure
/// * suppresses WER crash dialogs, because a dump taken while the payload is
///   decrypted contains the key material in the clear
///
/// Failures are returned rather than ignored, but a caller may reasonably log
/// and continue: neither is required for correctness, only for defence in depth.
pub fn harden_process() -> Result<()> {
    lockmem::harden_process()?;
    lockmem::enable_process_memory_lock()?;
    Ok(())
}

/// Whether this platform actually pins secret pages (i.e. protects against
/// swap). Reported by the UI so the claim is never overstated.
pub const fn swap_protection_available() -> bool {
    lockmem::secure_memory_supported()
}
