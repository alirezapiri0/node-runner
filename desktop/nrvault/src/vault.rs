//! The encrypted vault envelope.
//!
//! # File layout
//!
//! ```text
//! offset  size  field
//!      0     8  magic "NRVAULT1"
//!      8     2  format version (u16 LE)
//!     10     1  kdf id (1 = Argon2id)
//!     11     1  aead id (1 = AES-256-GCM, 2 = XChaCha20-Poly1305)
//!     12     4  memory cost KiB (u32 LE)
//!     16     4  time cost (u32 LE)
//!     20     1  parallelism
//!     21    32  salt
//!     53    12  nonce for the KEK wrap
//!     65    24  nonce for the payload (12 used by GCM, 24 by XChaCha)
//!     89     3  flags
//!     92     4  length of the OS-protected blob (u32 LE)
//!     96     4  reserved (must be zero)
//!    100   ...  OS-protected DEK blob        (dpapi_len bytes)
//!     ..    48  DEK wrapped under the KEK    (32 ciphertext + 16 tag)
//!     ..   ...  payload ciphertext           (plaintext + 16 tag)
//!     ..    32  HMAC-SHA256 over everything above
//! ```
//!
//! # Key hierarchy
//!
//! ```text
//! passphrase --Argon2id(salt, m, t, p)--> IKM --HKDF--> wrap_key, mac_key
//! wrap_key   --AES-256-GCM------------> wrapped_dek_pass      (this file)
//! random DEK --DPAPI------------------> dpapi_blob            (this file)
//! DEK        --AEAD(payload, aad)-----> payload_ct            (this file)
//! mac_key    --HMAC-SHA256-----------> mac                    (this file)
//! ```
//!
//! The DEK is random, never derived from the passphrase. Consequences worth
//! stating because they drive the design:
//!
//! * Rotating the passphrase re-wraps a 32-byte key; it does not re-encrypt
//!   the payload for key-rotation reasons.
//! * The passphrase and DPAPI paths are independent. Losing either one still
//!   leaves the other, and the OS path degrades to "ask for the passphrase"
//!   rather than "vault lost".
//! * A fresh random DEK per seal keeps the per-key message count far below the
//!   AEAD's birthday bound, so nonce reuse cannot become a practical concern.
//!
//! # Validation ordering
//!
//! Opening a vault performs three checks in a fixed order, and the order is what
//! makes the error variants meaningful:
//!
//! 1. **Structural** ([`EncryptedVault::from_bytes`]) runs before any key
//!    derivation. Magic, version, algorithm ids, length fields, flag/reserved
//!    canonical form and the KDF parameter bounds are all checked here, so a
//!    truncated or malformed file costs microseconds and allocates nothing.
//! 2. **DEK unwrap**, which is an authenticated AEAD operation. A failure means
//!    the supplied credential did not produce the wrapping key, and is reported
//!    as [`VaultError::Auth`]. No attacker-controlled data has been interpreted
//!    at this point: the output of a failed AEAD open is discarded.
//! 3. **MAC verification** over the entire file, followed by payload decryption.
//!    Both run only once the DEK is in hand, and both report
//!    [`VaultError::Integrity`] on failure.
//!
//! The resulting error semantics are worth stating plainly, because they are
//! what the UI shows a user:
//!
//! | Symptom | Variant | Meaning |
//! |---|---|---|
//! | wrong passphrase | `Auth` | the credential is wrong |
//! | edited header | `Auth` | the AAD changed, so the DEK will not unwrap |
//! | edited payload or OS blob | `Integrity` | the credential is right, the file is not |
//! | truncated / bad magic | `Format` | not a vault file at all |
//!
//! The one ambiguity left is that header tampering and a wrong passphrase look
//! the same. That cannot be resolved with key material; it is resolved with
//! [`EncryptedVault::envelope_fingerprint`], which the store records at seal
//! time and compares on failure.

use std::fmt;

use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::aead::{self, AeadId, KEK_NONCE_LEN, NONCE_FIELD_LEN, TAG_LEN};
use crate::errors::{Result, VaultError};
use crate::kdf::{self, KdfParams, Salt, SALT_LEN};
use crate::keywrap::{self, TpmBinding};
use crate::lockmem::LockedBuf;
use crate::secret::{Passphrase, VaultPayload};

pub const MAGIC: [u8; 8] = *b"NRVAULT1";
pub const FORMAT_VERSION: u16 = 1;
pub const KDF_ID_ARGON2ID: u8 = 1;

pub const FIXED_HEADER_LEN: usize = 100;
pub const FLAGS_LEN: usize = 3;
pub const RESERVED_LEN: usize = 4;
pub const DEK_LEN: usize = 32;
/// 32-byte ciphertext plus the 16-byte GCM tag.
pub const WRAPPED_DEK_LEN: usize = DEK_LEN + TAG_LEN;
pub const MAC_LEN: usize = 32;

/// Flag bit 0: an OS-protected copy of the DEK is present.
pub const FLAG_OS_WRAP: u8 = 0x01;

/// Sanity ceiling on the OS blob. A DPAPI blob for 32 bytes is a few hundred
/// bytes; anything larger means the header is lying.
pub const MAX_DPAPI_BLOB_LEN: u32 = 4096;

/// Byte range of the payload nonce inside the fixed header.
///
/// Named because it is the one field deliberately excluded from the KEK wrap's
/// associated data -- see [`kek_aad`].
const NONCE_DEK_OFFSET: usize = 65;
const NONCE_DEK_RANGE: std::ops::Range<usize> =
    NONCE_DEK_OFFSET..NONCE_DEK_OFFSET + NONCE_FIELD_LEN;

/// Minimum viable file: header + wrapped DEK + an empty-but-tagged payload + MAC.
pub const MIN_FILE_LEN: usize = FIXED_HEADER_LEN + WRAPPED_DEK_LEN + TAG_LEN + MAC_LEN;

/// How a vault should be sealed.
#[derive(Clone, Copy, Debug)]
pub struct WrapPolicy {
    /// `None` calibrates against `calibration_target_ms` on this machine.
    pub kdf: Option<KdfParams>,
    pub aead: AeadId,
    /// Also produce a DPAPI-wrapped copy of the DEK for convenience unlock.
    /// Errors on platforms without an OS protector rather than silently
    /// downgrading -- a silent downgrade would be invisible in the UI.
    pub os_wrap: bool,
    pub calibration_target_ms: u64,
}

impl Default for WrapPolicy {
    fn default() -> Self {
        Self {
            kdf: None,
            aead: AeadId::Aes256Gcm,
            os_wrap: keywrap::os_available(),
            calibration_target_ms: 250,
        }
    }
}

impl WrapPolicy {
    /// No OS wrap. Used on non-Windows platforms and by the test suite so the
    /// crypto path is exercised independently of machine state.
    pub const fn portable() -> Self {
        Self {
            kdf: None,
            aead: AeadId::Aes256Gcm,
            os_wrap: false,
            calibration_target_ms: 250,
        }
    }

    /// Fixed, cheap-but-still-legal parameters for tests: the cheapest cost that
    /// `validate_for_creation` accepts, with a single pass. This keeps the suite
    /// to a few milliseconds per derivation without ever constructing a vault
    /// whose parameters the production path would reject.
    pub const fn test_fast() -> Self {
        Self {
            kdf: Some(KdfParams {
                m_cost_kib: kdf::MIN_GENERATED_M_COST_KIB,
                t_cost: 1,
                p_cost: 1,
            }),
            aead: AeadId::Aes256Gcm,
            os_wrap: false,
            calibration_target_ms: 1,
        }
    }
}

/// Which credential to open a vault with.
#[derive(Clone, Copy)]
pub struct UnlockRequest<'a> {
    pub passphrase: Option<&'a Passphrase>,
    /// Permit the OS-protected DEK path. Callers performing privileged
    /// operations should leave this false so that a live, unlocked session
    /// cannot be used to re-wrap or export the vault without the passphrase.
    pub allow_os: bool,
}

impl<'a> UnlockRequest<'a> {
    /// Passphrase only. The safe default.
    pub fn passphrase(pass: &'a Passphrase) -> Self {
        Self {
            passphrase: Some(pass),
            allow_os: false,
        }
    }

    /// OS-protected DEK only, for convenience unlock on this machine.
    pub fn os_convenience() -> Self {
        Self {
            passphrase: None,
            allow_os: true,
        }
    }

    /// Passphrase first, OS path as fallback.
    pub fn either(pass: &'a Passphrase) -> Self {
        Self {
            passphrase: Some(pass),
            allow_os: true,
        }
    }
}

impl std::fmt::Debug for UnlockRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockRequest")
            .field(
                "passphrase",
                &self.passphrase.map(|_| "[redacted]").unwrap_or("none"),
            )
            .field("allow_os", &self.allow_os)
            .finish()
    }
}

/// Result of a successful unseal.
pub struct Unsealed {
    pub plaintext: Zeroizing<Vec<u8>>,
    /// True when the OS-protected DEK was used, i.e. no passphrase was supplied.
    pub used_os_path: bool,
}

impl std::fmt::Debug for Unsealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unsealed")
            .field("plaintext", &"[redacted]")
            .field("used_os_path", &self.used_os_path)
            .finish()
    }
}

/// The parsed fixed-size header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version: u16,
    pub kdf_id: u8,
    pub aead_id: AeadId,
    pub kdf: KdfParams,
    pub salt: Salt,
    pub nonce_kek: [u8; KEK_NONCE_LEN],
    pub nonce_dek: [u8; NONCE_FIELD_LEN],
    pub flags: [u8; FLAGS_LEN],
    pub dpapi_len: u32,
    pub reserved: [u8; RESERVED_LEN],
}

impl Header {
    pub fn has_os_wrap(&self) -> bool {
        self.flags[0] & FLAG_OS_WRAP != 0
    }

    pub fn to_bytes(&self) -> [u8; FIXED_HEADER_LEN] {
        let mut b = [0u8; FIXED_HEADER_LEN];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..10].copy_from_slice(&self.version.to_le_bytes());
        b[10] = self.kdf_id;
        b[11] = self.aead_id.to_u8();
        b[12..16].copy_from_slice(&self.kdf.m_cost_kib.to_le_bytes());
        b[16..20].copy_from_slice(&self.kdf.t_cost.to_le_bytes());
        b[20] = self.kdf.p_cost;
        b[21..53].copy_from_slice(&self.salt);
        b[53..65].copy_from_slice(&self.nonce_kek);
        b[65..89].copy_from_slice(&self.nonce_dek);
        b[89..92].copy_from_slice(&self.flags);
        b[92..96].copy_from_slice(&self.dpapi_len.to_le_bytes());
        b[96..100].copy_from_slice(&self.reserved);
        b
    }

    /// Strict parse. Every rejection here happens before any KDF work.
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        if b.len() != FIXED_HEADER_LEN {
            return Err(VaultError::Format(format!(
                "header must be {FIXED_HEADER_LEN} bytes, found {}",
                b.len()
            )));
        }
        if b[0..8] != MAGIC {
            return Err(VaultError::Format("bad magic; not a vault file".into()));
        }

        let version = u16::from_le_bytes([b[8], b[9]]);
        if version != FORMAT_VERSION {
            return Err(VaultError::Unsupported(format!(
                "format version {version} (this build writes and reads {FORMAT_VERSION})"
            )));
        }

        let kdf_id = b[10];
        if kdf_id != KDF_ID_ARGON2ID {
            return Err(VaultError::Unsupported(format!("kdf id {kdf_id}")));
        }

        let aead_id = AeadId::from_u8(b[11])?;

        let kdf = KdfParams {
            m_cost_kib: u32::from_le_bytes([b[12], b[13], b[14], b[15]]),
            t_cost: u32::from_le_bytes([b[16], b[17], b[18], b[19]]),
            p_cost: b[20],
        };
        // Bounded *before* the allocator sees it: a hostile header must not be
        // able to make us reserve a gigabyte.
        kdf.validate_accepted()?;

        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&b[21..53]);
        let mut nonce_kek = [0u8; KEK_NONCE_LEN];
        nonce_kek.copy_from_slice(&b[53..65]);
        let mut nonce_dek = [0u8; NONCE_FIELD_LEN];
        nonce_dek.copy_from_slice(&b[65..89]);

        let mut flags = [0u8; FLAGS_LEN];
        flags.copy_from_slice(&b[89..92]);
        // Only bit 0 is defined. Reject unknown bits rather than ignoring them,
        // so a future format cannot be silently misinterpreted by an old build.
        if flags[1] != 0 || flags[2] != 0 {
            return Err(VaultError::Unsupported(
                "unknown feature flags set in the header".into(),
            ));
        }

        let dpapi_len = u32::from_le_bytes([b[92], b[93], b[94], b[95]]);
        if dpapi_len > MAX_DPAPI_BLOB_LEN {
            return Err(VaultError::Format(format!(
                "declared OS blob length {dpapi_len} exceeds {MAX_DPAPI_BLOB_LEN}"
            )));
        }

        let mut reserved = [0u8; RESERVED_LEN];
        reserved.copy_from_slice(&b[96..100]);
        if reserved != [0u8; RESERVED_LEN] {
            return Err(VaultError::Format(
                "reserved header bytes are non-zero (non-canonical file)".into(),
            ));
        }

        let has_os_wrap = flags[0] & FLAG_OS_WRAP != 0;
        if has_os_wrap != (dpapi_len > 0) {
            return Err(VaultError::Format(
                "OS-wrap flag disagrees with the declared blob length (non-canonical file)".into(),
            ));
        }

        Ok(Self {
            version,
            kdf_id,
            aead_id,
            kdf,
            salt,
            nonce_kek,
            nonce_dek,
            flags,
            dpapi_len,
            reserved,
        })
    }
}

/// A complete sealed vault, held in memory.
#[derive(Clone)]
pub struct EncryptedVault {
    pub header: Header,
    pub dpapi_blob: Vec<u8>,
    pub wrapped_dek_pass: Vec<u8>,
    pub payload_ct: Vec<u8>,
    pub mac: [u8; MAC_LEN],
}

impl EncryptedVault {
    // -- construction --------------------------------------------------------

    /// Seal raw bytes under a passphrase.
    pub fn seal_raw(raw: &[u8], pass: &Passphrase, policy: &WrapPolicy) -> Result<Self> {
        let kdf = resolve_kdf(policy)?;
        let mut dek = LockedBuf::zeroed(DEK_LEN);
        OsRng.fill_bytes(dek.as_mut_slice());
        Self::build(raw, &dek, pass, policy, kdf)
    }

    /// Seal a structured payload under a passphrase.
    pub fn seal_secrets(
        payload: &VaultPayload,
        pass: &Passphrase,
        policy: &WrapPolicy,
    ) -> Result<Self> {
        let json = payload.to_json()?;
        Self::seal_raw(json.as_bytes(), pass, policy)
    }

    /// The assembly step, with the DEK supplied. Used both by `seal_raw` and by
    /// DEK-preserving rotation.
    fn build(
        raw: &[u8],
        dek: &LockedBuf,
        pass: &Passphrase,
        policy: &WrapPolicy,
        kdf: KdfParams,
    ) -> Result<Self> {
        let salt: Salt = random_array();
        let nonce_kek: [u8; KEK_NONCE_LEN] = random_array();
        let nonce_dek: [u8; NONCE_FIELD_LEN] = random_array();

        let dpapi_blob = if policy.os_wrap {
            if !keywrap::os_available() {
                return Err(VaultError::OsProtectionUnavailable(format!(
                    "OS key wrapping requested on {}",
                    std::env::consts::OS
                )));
            }
            keywrap::os_wrap(dek.as_slice(), &salt)?
        } else {
            Vec::new()
        };

        let mut flags = [0u8; FLAGS_LEN];
        if !dpapi_blob.is_empty() {
            flags[0] |= FLAG_OS_WRAP;
        }

        let header = Header {
            version: FORMAT_VERSION,
            kdf_id: KDF_ID_ARGON2ID,
            aead_id: policy.aead,
            kdf,
            salt,
            nonce_kek,
            nonce_dek,
            flags,
            dpapi_len: dpapi_blob.len() as u32,
            reserved: [0u8; RESERVED_LEN],
        };

        let header_bytes = header.to_bytes();
        let wrap_key = kdf::derive_wrap_key(pass, &salt, kdf)?;

        // The KEK wrap authenticates the header, minus the payload nonce -- see
        // `kek_aad` for why that one field is excluded. It is the earliest point
        // at which a tampered salt, parameter set or KEK nonce can be detected.
        let wrapped = aead::wrap_gcm(
            wrap_key.as_array32()?,
            &nonce_kek,
            &kek_aad(&header),
            dek.as_slice(),
        )?;
        if wrapped.len() != WRAPPED_DEK_LEN {
            return Err(VaultError::Format(format!(
                "wrapped DEK is {} bytes, expected {WRAPPED_DEK_LEN}",
                wrapped.len()
            )));
        }

        // The payload binds the header AND both wrap blobs as AAD, so no blob
        // can be swapped, reordered or downgraded without breaking the tag.
        let aad = Self::compose_aad(&header_bytes, &dpapi_blob, &wrapped);

        let payload_ct = aead::encrypt(policy.aead, dek.as_array32()?, &nonce_dek, &aad, raw)?;

        let mut vault = Self {
            header,
            dpapi_blob,
            wrapped_dek_pass: wrapped,
            payload_ct,
            mac: [0u8; MAC_LEN],
        };
        // The MAC key comes from the DEK, so both unlock paths can recompute it.
        let mac_key = kdf::mac_key_from_dek(dek.as_array32()?, &salt)?;
        vault.mac = compute_mac(mac_key.as_array32()?, &vault.bytes_before_mac())?;
        Ok(vault)
    }

    // -- opening ------------------------------------------------------------

    /// Open the vault and return the raw plaintext.
    pub fn unseal_raw(&self, req: &UnlockRequest<'_>) -> Result<Unsealed> {
        // The passphrase is consumed by `open_dek`, so only its presence matters
        // here.
        if req.passphrase.is_some() {
            // Step 1: unwrap the DEK. Authenticated, so a wrong passphrase is
            // caught here and reported as Auth rather than being conflated with
            // file damage. A failure output is discarded by the AEAD, so nothing
            // attacker-chosen has been interpreted.
            let dek = self.open_dek(req)?;

            // Step 2: integrity over the entire file. This is only reachable
            // because the MAC key is derived from the DEK, which is why a wrong
            // passphrase can no longer masquerade as tampering.
            self.verify_with_dek(&dek)?;

            // Step 3: only now does any plaintext exist.
            let plaintext = self.decrypt_payload(&dek)?;

            return Ok(Unsealed {
                plaintext,
                used_os_path: false,
            });
        }

        if req.allow_os {
            if self.dpapi_blob.is_empty() || !self.header.has_os_wrap() {
                return Err(VaultError::NoUnlockMethod(
                    "this vault has no OS-protected key; the passphrase is required".into(),
                ));
            }
            let dek = keywrap::os_unwrap(&self.dpapi_blob, &self.header.salt)?;

            // The OS path gets the same integrity check as the passphrase path.
            // It did not have one when the MAC key came from the passphrase, so
            // this is a genuine improvement rather than a refactor.
            self.verify_with_dek(&dek)?;

            let plaintext = self.decrypt_payload(&dek)?;

            return Ok(Unsealed {
                plaintext,
                used_os_path: true,
            });
        }

        Err(VaultError::NoUnlockMethod(
            "unlock request supplied neither a passphrase nor OS fallback permission".into(),
        ))
    }

    /// Open a structured payload.
    pub fn unseal_secrets(&self, req: &UnlockRequest<'_>) -> Result<VaultPayload> {
        let unsealed = self.unseal_raw(req)?;
        // `plaintext` zeroizes when this scope ends, including on the error path.
        VaultPayload::from_json(unsealed.plaintext.as_slice())
    }

    /// Guarantee a structured payload's key material has rotated.
    pub fn rotate_passphrase(
        &mut self,
        unlock: &UnlockRequest<'_>,
        new_pass: &Passphrase,
        policy: &WrapPolicy,
    ) -> Result<()> {
        self.reseal(unlock, new_pass, policy, false)
    }

    /// Full rekey: new DEK, new salt, new nonces, new payload ciphertext.
    pub fn rekey(
        &mut self,
        unlock: &UnlockRequest<'_>,
        new_pass: &Passphrase,
        policy: &WrapPolicy,
    ) -> Result<()> {
        self.reseal(unlock, new_pass, policy, true)
    }

    /// Re-seal under `new_pass`.
    ///
    /// Both variants re-encrypt the payload, because the header is bound into
    /// the payload's AAD and any change to the salt or KEK nonce changes the
    /// header. The payload is at most a few KB, so this costs nothing.
    pub fn reseal(
        &mut self,
        unlock: &UnlockRequest<'_>,
        new_pass: &Passphrase,
        policy: &WrapPolicy,
        fresh_dek: bool,
    ) -> Result<()> {
        let unsealed = self.unseal_raw(unlock)?;
        let rebuilt = if fresh_dek {
            Self::seal_raw(unsealed.plaintext.as_slice(), new_pass, policy)?
        } else {
            let kdf = match policy.kdf {
                Some(p) => {
                    p.validate_for_creation()?;
                    p
                }
                None => self.header.kdf,
            };
            let dek = self.open_dek(unlock)?;
            Self::build(unsealed.plaintext.as_slice(), &dek, new_pass, policy, kdf)?
        };
        *self = rebuilt;
        Ok(())
    }

    /// Recover the DEK with whichever credential is available.
    ///
    /// Public because it is the mechanism behind [`Self::update_payload`], and
    /// because knowing *which* unlock paths a vault supports is legitimately
    /// useful to a caller.
    pub fn open_dek(&self, req: &UnlockRequest<'_>) -> Result<LockedBuf> {
        if let Some(pass) = req.passphrase {
            let wrap_key = kdf::derive_wrap_key(pass, &self.header.salt, self.header.kdf)?;
            let dek_bytes = aead::unwrap_gcm(
                wrap_key.as_array32()?,
                &self.header.nonce_kek,
                &kek_aad(&self.header),
                &self.wrapped_dek_pass,
            )
            .map_err(|_| VaultError::Auth)?;
            return Ok(LockedBuf::copy_from(dek_bytes.as_slice()));
        }
        if req.allow_os && !self.dpapi_blob.is_empty() {
            return keywrap::os_unwrap(&self.dpapi_blob, &self.header.salt);
        }
        Err(VaultError::NoUnlockMethod("no usable credential".into()))
    }

    /// Verify the whole file's MAC using a DEK that has already been unwrapped.
    fn verify_with_dek(&self, dek: &LockedBuf) -> Result<()> {
        let mac_key = kdf::mac_key_from_dek(dek.as_array32()?, &self.header.salt)?;
        self.verify_mac(mac_key.as_array32()?)
    }

    fn decrypt_payload(&self, dek: &LockedBuf) -> Result<Zeroizing<Vec<u8>>> {
        aead::decrypt(
            self.header.aead_id,
            dek.as_array32()?,
            &self.header.nonce_dek,
            &self.aad_bytes(),
            &self.payload_ct,
        )
        .map_err(|_| VaultError::Integrity)
    }

    /// Re-encrypt the payload with the existing key material. This is the write
    /// path for any change to the vault's contents.
    ///
    /// Only three things change: the payload nonce, the payload ciphertext and
    /// the MAC. The salt, the KDF parameters and the wrapped DEK are untouched,
    /// which is what allows a write from a session that was unlocked through the
    /// OS path -- the user is not asked for their passphrase to edit a token.
    ///
    /// A fresh random nonce is generated on every call. Reusing a nonce under
    /// the same key is the one mistake that breaks GCM catastrophically (it leaks
    /// the XOR of the plaintexts and, with two messages, the authentication
    /// subkey), so this is not an optimisation point.
    pub fn update_payload(&mut self, raw: &[u8], unlock: &UnlockRequest<'_>) -> Result<()> {
        let dek = self.open_dek(unlock)?;

        let nonce_dek: [u8; NONCE_FIELD_LEN] = random_array();
        self.header.nonce_dek = nonce_dek;

        // The nonce lives inside the AAD, so the header has to be updated before
        // the new ciphertext is produced -- otherwise the AAD would describe the
        // previous nonce.
        self.payload_ct = aead::encrypt(
            self.header.aead_id,
            dek.as_array32()?,
            &nonce_dek,
            &self.aad_bytes(),
            raw,
        )?;

        let mac_key = kdf::mac_key_from_dek(dek.as_array32()?, &self.header.salt)?;
        self.mac = compute_mac(mac_key.as_array32()?, &self.bytes_before_mac())?;
        Ok(())
    }

    // -- integrity ----------------------------------------------------------

    /// Constant-time HMAC verification over the whole serialized file.
    pub fn verify_mac(&self, mac_key: &[u8; MAC_LEN]) -> Result<()> {
        let expected = self.mac;
        let actual = compute_mac(mac_key, &self.bytes_before_mac())?;
        // `subtle` is pulled in transitively by the AEAD crates; compare with an
        // explicit constant-time loop rather than relying on `==` on arrays.
        if subtle::ConstantTimeEq::ct_eq(actual.as_slice(), expected.as_slice()).unwrap_u8() != 1 {
            return Err(VaultError::Integrity);
        }
        Ok(())
    }

    /// True when this vault was sealed with weaker parameters than `policy`.
    /// The caller can then transparently re-seal on a successful unlock.
    pub fn kdf_is_below(&self, policy: &KdfParams) -> bool {
        self.header.kdf.is_below(policy)
    }

    pub fn has_os_wrap(&self) -> bool {
        self.header.has_os_wrap()
    }

    pub fn binding(&self) -> Option<TpmBinding> {
        if self.header.has_os_wrap() {
            Some(TpmBinding::UserProfileScope)
        } else {
            None
        }
    }

    pub fn payload_plaintext_len(&self) -> Option<usize> {
        self.payload_ct.len().checked_sub(TAG_LEN)
    }

    /// A non-secret fingerprint of the entire envelope, computable without any
    /// key material.
    ///
    /// This exists to break the ambiguity inherent in [`VaultError::Auth`]. The
    /// store records this value at seal time and compares it when an unlock
    /// fails, so the app can tell "you mistyped your passphrase" (file
    /// unchanged) from "this file changed since I wrote it" (fingerprint
    /// differs) -- a discrimination no key-dependent check can make, because a
    /// wrong passphrase and a modified file are the same computation.
    ///
    /// It reveals nothing: it is a hash of bytes already stored in the clear
    /// inside `vault.bin`, and the vault's confidentiality rests on the AEAD,
    /// not on this value being secret.
    ///
    /// It is explicitly **not** a security boundary. An attacker who edits the
    /// vault can edit the metadata to match. It detects accidental corruption
    /// and naive tampering, and it is documented as exactly that rather than
    /// being described as an integrity control.
    pub fn envelope_fingerprint(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.to_bytes());
        hex(&hasher.finalize())
    }

    /// Non-secret description of the envelope, safe for logs and the UI.
    pub fn structural_summary(&self) -> String {
        format!(
            "v{} {} kdf=Argon2id(m={}KiB,t={},p={}) os_wrap={} payload={}B",
            self.header.version,
            self.header.aead_id.name(),
            self.header.kdf.m_cost_kib,
            self.header.kdf.t_cost,
            self.header.kdf.p_cost,
            if self.header.has_os_wrap() {
                "yes"
            } else {
                "no"
            },
            self.payload_plaintext_len().unwrap_or(0),
        )
    }

    // -- serialization ------------------------------------------------------

    fn compose_aad(header_bytes: &[u8], dpapi_blob: &[u8], wrapped: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(header_bytes.len() + dpapi_blob.len() + wrapped.len());
        aad.extend_from_slice(header_bytes);
        aad.extend_from_slice(dpapi_blob);
        aad.extend_from_slice(wrapped);
        aad
    }

    fn aad_bytes(&self) -> Vec<u8> {
        Self::compose_aad(
            &self.header.to_bytes(),
            &self.dpapi_blob,
            &self.wrapped_dek_pass,
        )
    }

    fn bytes_before_mac(&self) -> Vec<u8> {
        let mut out = self.aad_bytes();
        out.extend_from_slice(&self.payload_ct);
        out
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.bytes_before_mac();
        out.extend_from_slice(&self.mac);
        out
    }

    /// Strict parse. Rejects anything non-canonical so a future format cannot
    /// be misread by this build.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MIN_FILE_LEN {
            return Err(VaultError::Format(format!(
                "file is {} bytes; a vault is at least {MIN_FILE_LEN}",
                bytes.len()
            )));
        }

        let header = Header::from_bytes(&bytes[..FIXED_HEADER_LEN])?;
        let dpapi_len = header.dpapi_len as usize;

        // Checked arithmetic: dpapi_len is already bounded, but the sum still
        // must not be trusted implicitly.
        let after_dpapi = FIXED_HEADER_LEN
            .checked_add(dpapi_len)
            .ok_or_else(|| VaultError::Format("length overflow".into()))?;
        let after_wrap = after_dpapi
            .checked_add(WRAPPED_DEK_LEN)
            .ok_or_else(|| VaultError::Format("length overflow".into()))?;
        let payload_end = bytes
            .len()
            .checked_sub(MAC_LEN)
            .ok_or_else(|| VaultError::Format("file shorter than its MAC".into()))?;

        if after_wrap >= payload_end {
            return Err(VaultError::Format(format!(
                "declared OS blob length {dpapi_len} does not fit in a {}-byte file",
                bytes.len()
            )));
        }

        let dpapi_blob = bytes[FIXED_HEADER_LEN..after_dpapi].to_vec();
        let wrapped_dek_pass = bytes[after_dpapi..after_wrap].to_vec();
        let payload_ct = bytes[after_wrap..payload_end].to_vec();

        if payload_ct.len() < TAG_LEN {
            return Err(VaultError::Format(
                "payload is shorter than its authentication tag".into(),
            ));
        }

        let mut mac = [0u8; MAC_LEN];
        mac.copy_from_slice(&bytes[payload_end..]);

        Ok(Self {
            header,
            dpapi_blob,
            wrapped_dek_pass,
            payload_ct,
            mac,
        })
    }
}

impl fmt::Debug for EncryptedVault {
    /// Hand-written so the debug output is a structural description rather than
    /// a dump of ciphertext bytes -- and so that adding a plaintext-bearing field
    /// to this struct in future cannot silently start printing it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedVault")
            .field("summary", &self.structural_summary())
            .field("envelope_fingerprint", &self.envelope_fingerprint())
            .field("os_blob_len", &self.dpapi_blob.len())
            .field("wrapped_dek_len", &self.wrapped_dek_pass.len())
            .field("payload_ct_len", &self.payload_ct.len())
            .field("mac", &"[32 bytes]")
            .finish()
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 0x0f) as usize] as char);
    }
    out
}

/// Associated data for the KEK wrap: the header with the payload-nonce field
/// zeroed out.
///
/// Excluding exactly one field is a deliberate design decision. Because the
/// payload nonce sits in the header, and the header is the KEK wrap's AAD,
/// re-encrypting the payload would otherwise change the AAD and invalidate the
/// wrapped DEK -- forcing a passphrase prompt on every write. Zeroing the field
/// means a save can rotate the payload nonce freely.
///
/// Nothing is weakened by the exclusion. The nonce is authenticated twice over:
/// it is part of the payload's own AAD, and the whole file is covered by the
/// file-level HMAC. What the KEK wrap's AAD protects -- the salt, the KDF
/// parameters, the algorithm identifiers and the KEK nonce -- is untouched.
fn kek_aad(header: &Header) -> [u8; FIXED_HEADER_LEN] {
    let mut bytes = header.to_bytes();
    bytes[NONCE_DEK_RANGE].fill(0);
    bytes
}

fn resolve_kdf(policy: &WrapPolicy) -> Result<KdfParams> {
    match policy.kdf {
        Some(p) => {
            p.validate_for_creation()?;
            Ok(p)
        }
        None => kdf::calibrate(policy.calibration_target_ms),
    }
}

fn compute_mac(mac_key: &[u8; MAC_LEN], data: &[u8]) -> Result<[u8; MAC_LEN]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(mac_key)
        .map_err(|e| VaultError::Kdf(format!("hmac key init: {e}")))?;
    mac.update(data);
    let out = mac.finalize().into_bytes();
    let mut arr = [0u8; MAC_LEN];
    arr.copy_from_slice(&out);
    Ok(arr)
}

fn random_array<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}
