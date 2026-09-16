//! Key derivation: Argon2id, then HKDF-SHA256 domain separation.
//!
//! # Key separation
//!
//! Argon2id produces 32 bytes of output. It is tempting to use those directly as
//! the AES key. This module does not: the output is treated as input keying
//! material and expanded through HKDF before use, so the raw KDF output is never
//! an encryption key and two keys are never derived from the same input for two
//! different purposes.
//!
//! # Why the MAC key comes from the DEK, not from the passphrase
//!
//! There are two candidate sources for the vault's HMAC key: the passphrase-
//! derived key, or the data encryption key. This module uses the DEK, and the
//! reasoning is worth recording because the alternative is tempting.
//!
//! Deriving the MAC key from the passphrase would allow integrity to be checked
//! slightly earlier -- before the DEK is unwrapped. That is a marginal benefit,
//! because the DEK unwrap is itself an authenticated AEAD operation, so an
//! attacker still cannot get us to act on chosen ciphertext.
//!
//! Deriving it from the DEK costs almost nothing and buys three things:
//!
//! 1. The OS-protected unlock path gains a real integrity check. Without it,
//!    that path had only the payload's own AEAD tag.
//! 2. A wrong passphrase and a modified payload become **distinguishable**: the
//!    former fails the DEK unwrap, the latter fails the MAC. Users get an
//!    accurate error instead of one message covering both causes.
//! 3. Saving is possible from a convenience-unlocked session, because writing
//!    re-encrypts the payload and so needs to recompute the MAC -- which needs a
//!    key that both unlock paths can reach.
//!
//! # Parameter agility
//!
//! The cost parameters are read from the vault header, not hard-coded. That is
//! what allows a vault created with yesterday's parameters to keep opening after
//! today's are raised. `unseal` reports whether the stored parameters are below
//! the current policy so the caller can transparently re-seal.
//!
//! # Bounds on accepted parameters
//!
//! Parsing hostile parameters is a denial-of-service risk in both directions: a
//! tiny `m_cost` downgrades the KDF, and a gigantic one makes the app allocate
//! gigabytes before it can tell the file is bogus. Both ends are bounded, and
//! the bound is checked *before* any allocation happens.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::errors::{Result, VaultError};
use crate::lockmem::LockedBuf;
use crate::secret::Passphrase;

pub const OMK_LEN: usize = 32;
pub const SALT_LEN: usize = 32;

/// A per-installation KDF salt. Random at seal time and stored in the header,
/// so two installations sealing the same passphrase derive different keys.
pub type Salt = [u8; SALT_LEN];

/// Distinct HKDF labels. Changing either is a format break.
pub const HKDF_INFO_WRAP: &[u8] = b"nr-vault/wrap/v1";
pub const HKDF_INFO_MAC: &[u8] = b"nr-vault/mac/v1";

/// Reject vaults specifying a weaker KDF than this -- a downgrade guard.
pub const MIN_ACCEPTED_M_COST_KIB: u32 = 8 * 1024; // 8 MiB
/// Reject vaults specifying more than this -- an allocation-bomb guard.
pub const MAX_ACCEPTED_M_COST_KIB: u32 = 1024 * 1024; // 1 GiB
pub const MAX_ACCEPTED_T_COST: u32 = 16;
pub const MAX_ACCEPTED_P_COST: u8 = 8;

/// Highest cost this build will *create* with, regardless of calibration.
pub const MAX_GENERATED_M_COST_KIB: u32 = 256 * 1024; // 256 MiB
/// Lowest cost this build will *create* with.
pub const MIN_GENERATED_M_COST_KIB: u32 = 19 * 1024; // 19 MiB, OWASP floor

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u8,
}

impl KdfParams {
    /// OWASP's preferred configuration for a memory-hard, GPU/ASIC-resistant
    /// derivation: 64 MiB of memory, 3 passes.
    pub const fn preferred() -> Self {
        Self {
            m_cost_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 1,
        }
    }

    /// Still acceptable, used for interactive unlocks on constrained machines.
    pub const fn floor() -> Self {
        Self {
            m_cost_kib: 19 * 1024,
            t_cost: 2,
            p_cost: 1,
        }
    }

    /// Bounds for parameters we are willing to *create*.
    pub fn validate_for_creation(&self) -> Result<()> {
        if self.m_cost_kib < MIN_GENERATED_M_COST_KIB {
            return Err(VaultError::KdfParams(format!(
                "memory cost {} KiB is below the {} KiB floor",
                self.m_cost_kib, MIN_GENERATED_M_COST_KIB
            )));
        }
        if self.m_cost_kib > MAX_GENERATED_M_COST_KIB {
            return Err(VaultError::KdfParams(format!(
                "memory cost {} KiB exceeds the {} KiB ceiling",
                self.m_cost_kib, MAX_GENERATED_M_COST_KIB
            )));
        }
        self.validate_accepted()
    }

    /// Bounds for parameters we are willing to *honour* from an existing vault.
    /// Wider than creation bounds so future builds with higher settings still
    /// open, but tight enough to refuse an allocation bomb.
    pub fn validate_accepted(&self) -> Result<()> {
        if self.m_cost_kib < MIN_ACCEPTED_M_COST_KIB || self.m_cost_kib > MAX_ACCEPTED_M_COST_KIB {
            return Err(VaultError::KdfParams(format!(
                "memory cost {} KiB outside accepted range [{}, {}]",
                self.m_cost_kib, MIN_ACCEPTED_M_COST_KIB, MAX_ACCEPTED_M_COST_KIB
            )));
        }
        if self.t_cost == 0 || self.t_cost > MAX_ACCEPTED_T_COST {
            return Err(VaultError::KdfParams(format!(
                "time cost {} outside accepted range [1, {}]",
                self.t_cost, MAX_ACCEPTED_T_COST
            )));
        }
        if self.p_cost == 0 || self.p_cost > MAX_ACCEPTED_P_COST {
            return Err(VaultError::KdfParams(format!(
                "parallelism {} outside accepted range [1, {}]",
                self.p_cost, MAX_ACCEPTED_P_COST
            )));
        }
        // Argon2 itself requires m_cost >= 8 * p_cost.
        if self.m_cost_kib < 8 * self.p_cost as u32 {
            return Err(VaultError::KdfParams(
                "memory cost must be at least 8x parallelism".into(),
            ));
        }
        Ok(())
    }

    /// True when this vault was sealed with parameters below current policy.
    pub fn is_below(&self, policy: &KdfParams) -> bool {
        self.m_cost_kib < policy.m_cost_kib
            || self.t_cost < policy.t_cost
            || self.p_cost < policy.p_cost
    }
}

/// Derive the key-wrapping key from the passphrase.
///
/// The intermediate Argon2id output lives in a pinned, zeroizing buffer and is
/// dropped (and thus scrubbed) before this function returns. The returned key
/// wraps the DEK; it is never used for anything else.
pub fn derive_wrap_key(pass: &Passphrase, salt: &Salt, params: KdfParams) -> Result<LockedBuf> {
    params.validate_accepted()?;

    let argon_params = Params::new(
        params.m_cost_kib,
        params.t_cost,
        params.p_cost as u32,
        Some(OMK_LEN),
    )
    .map_err(|e| VaultError::KdfParams(e.to_string()))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon_params);

    let mut okm = LockedBuf::zeroed(OMK_LEN);
    argon
        .hash_password_into(pass.as_bytes(), salt, okm.as_mut_slice())
        .map_err(|e| VaultError::Kdf(e.to_string()))?;

    let hk = Hkdf::<Sha256>::new(Some(salt), okm.as_slice());
    let mut wrap_key = LockedBuf::zeroed(32);
    hk.expand(HKDF_INFO_WRAP, wrap_key.as_mut_slice())
        .map_err(|_| VaultError::Kdf("hkdf expand(wrap) failed".into()))?;

    // `okm` is dropped here: pages unlocked, bytes overwritten.
    Ok(wrap_key)
}

/// Derive the vault's MAC key from the data encryption key.
///
/// Reaching this requires the DEK, which requires either the passphrase or the
/// OS-protected copy -- so it is available on both unlock paths, which is the
/// point. See the module documentation for why this is preferred over deriving
/// it from the passphrase.
pub fn mac_key_from_dek(dek: &[u8; 32], salt: &Salt) -> Result<LockedBuf> {
    let hk = Hkdf::<Sha256>::new(Some(salt), dek);
    let mut mac_key = LockedBuf::zeroed(32);
    hk.expand(HKDF_INFO_MAC, mac_key.as_mut_slice())
        .map_err(|_| VaultError::Kdf("hkdf expand(mac) failed".into()))?;
    Ok(mac_key)
}

/// Time a single derivation, in milliseconds. Callers use the result to report
/// the unlock cost to the user and to record it in the vault metadata.
pub fn time_derive(params: KdfParams) -> Result<u128> {
    let salt = [0x5au8; SALT_LEN];
    let pass = Passphrase::new("nr-vault-calibration-probe");
    let start = std::time::Instant::now();
    let _key = derive_wrap_key(&pass, &salt, params)?;
    Ok(start.elapsed().as_millis())
}

/// Pick the strongest parameters that stay within `target_ms` on this machine.
///
/// Runs once at vault creation and the result is recorded in the vault metadata,
/// so the cost is paid a single time rather than on every unlock.
pub fn calibrate(target_ms: u64) -> Result<KdfParams> {
    let mut best = KdfParams::floor();
    let mut m = MIN_GENERATED_M_COST_KIB;

    while m <= MAX_GENERATED_M_COST_KIB {
        let candidate = KdfParams {
            m_cost_kib: m,
            t_cost: best.t_cost,
            p_cost: best.p_cost,
        };
        let elapsed = time_derive(candidate)?;
        if elapsed <= target_ms as u128 {
            best = candidate;
            m = m.saturating_mul(2);
        } else {
            break;
        }
    }

    // If even the floor is slower than the target, the floor is still the
    // floor: a fast machine should not talk us below the security minimum.
    Ok(best)
}
