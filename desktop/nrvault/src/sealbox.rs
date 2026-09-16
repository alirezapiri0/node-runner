//! Sealed boxes: libsodium-compatible `crypto_box_seal`.
//!
//! GitHub's Actions Secrets API does not accept plaintext. Each repository
//! publishes an X25519 public key, and every secret must be submitted as a
//! **sealed box** -- an anonymous, authenticated, one-way encryption to that key.
//! There is no nonce management and no sender key to agree on, which is what
//! makes it safe to use in a one-shot API call.
//!
//! # Why this lives in the security crate
//!
//! It is a cryptographic primitive with an interoperability requirement, so it
//! belongs behind the same review and test boundary as the vault rather than
//! inline in a UI command handler. It also means the construction below is
//! exercised by CI rather than only at the moment a user clicks a button.
//!
//! # Construction
//!
//! ```text
//! ephemeral_sk <- random 32 bytes
//! ephemeral_pk  = X25519_base(ephemeral_sk)
//! nonce         = BLAKE2b-24(ephemeral_pk || recipient_pk)
//! shared        = X25519(ephemeral_sk, recipient_sk)
//! key           = HSalsa20(shared, zero)          <- via SalsaBox::new
//! ciphertext    = XSalsa20-Poly1305(key, nonce, plaintext)
//! output        = ephemeral_pk || ciphertext
//! ```
//!
//! Output is therefore exactly `48 + plaintext.len()` bytes (32-byte ephemeral
//! key plus a 16-byte Poly1305 tag), and the nonce is never transmitted because
//! the recipient can recompute it. `crypto_box` implements this construction
//! directly, and the length assertion in the test suite is what keeps it pinned:
//! a non-libsodium-compatible construction would not produce a 48-byte overhead.
//!
//! # Verification status
//!
//! The round trip, the 48-byte overhead, tamper rejection and recipient binding
//! are all covered by tests. What those tests **cannot** prove is agreement with
//! libsodium byte-for-byte against GitHub's live endpoint, because that needs a
//! real repository and a credential. `docs/SECURITY.md` records this as the one
//! place where interoperability rests on the construction matching the
//! specification rather than on an executed exchange, and recommends the
//! `gh secret set` path (which uses GitHub's own implementation) for first-time
//! setup.

use base64ct::{Base64, Encoding};
use crypto_box::{PublicKey, SecretKey, SEALBYTES};
use rand_core::OsRng;
use zeroize::Zeroizing;

use crate::errors::{Result, VaultError};

/// Bytes added to the plaintext length by sealing: 32-byte ephemeral public key
/// plus a 16-byte authentication tag.
pub const SEALED_OVERHEAD: usize = SEALBYTES;

/// A repository's signing key, as returned by
/// `GET /repos/{owner}/{repo}/actions/secrets/public-key`.
///
/// `key_id` must be echoed back on the write request; GitHub rejects a value
/// sealed to a key that has since been rotated, which is exactly the behaviour
/// we want (it fails loudly rather than silently storing something unusable).
#[derive(Clone)]
pub struct RepositoryKey {
    pub key_id: String,
    public_key: PublicKey,
}

impl RepositoryKey {
    /// Parse the base64 public key from the API response.
    pub fn from_base64(key_id: impl Into<String>, key_b64: &str) -> Result<Self> {
        let raw = Base64::decode_vec(key_b64.trim()).map_err(|e| {
            VaultError::Format(format!("repository public key is not valid base64: {e}"))
        })?;
        let bytes: [u8; 32] = raw.try_into().map_err(|v: Vec<u8>| {
            VaultError::Format(format!(
                "repository public key must be 32 bytes, found {}",
                v.len()
            ))
        })?;
        Ok(Self {
            key_id: key_id.into(),
            public_key: PublicKey::from(bytes),
        })
    }

    /// Seal `plaintext` to this repository and return the base64 value to put in
    /// the `encrypted_value` field.
    ///
    /// The return is a `Zeroizing<String>` because, although it is ciphertext,
    /// it is ciphertext of a credential and there is no reason to leave copies
    /// of it lying around in the heap.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Zeroizing<String>> {
        let sealed = self
            .public_key
            .seal(&mut OsRng, plaintext)
            .map_err(|_| VaultError::Kdf("sealing to the repository key failed".into()))?;

        debug_assert_eq!(sealed.len(), plaintext.len() + SEALED_OVERHEAD);
        Ok(Zeroizing::new(Base64::encode_string(&sealed)))
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key.to_bytes()
    }
}

impl std::fmt::Debug for RepositoryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepositoryKey")
            .field("key_id", &self.key_id)
            .field("public_key", &"<32 bytes>")
            .finish()
    }
}

/// Generate a keypair. The test suite uses this to stand in for GitHub; nothing
/// in production generates recipient keys, because they belong to the repository.
pub fn generate_keypair() -> (SecretKey, PublicKey) {
    let secret = SecretKey::generate(&mut OsRng);
    let public = secret.public_key();
    (secret, public)
}

/// Open a sealed box. Used by the round-trip tests, and by the recovery tool if
/// a vault ever needs to be moved between repositories.
pub fn unseal(recipient: &SecretKey, sealed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    recipient
        .unseal(sealed)
        .map(Zeroizing::new)
        .map_err(|_| VaultError::Auth)
}

/// Decode the base64 form produced by [`RepositoryKey::seal`].
pub fn decode_sealed(b64: &str) -> Result<Zeroizing<Vec<u8>>> {
    Base64::decode_vec(b64.trim())
        .map(Zeroizing::new)
        .map_err(|e| VaultError::Format(format!("sealed box is not valid base64: {e}")))
}
