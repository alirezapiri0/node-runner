//! Authenticated encryption.
//!
//! The payload cipher is selectable and recorded in the vault header, so a
//! future migration (say, to a nonce-misuse-resistant mode) is a read-path
//! change rather than a breaking format change.
//!
//! Nonce policy: the caller supplies a 24-byte buffer of `OsRng` output. AES-GCM
//! uses the first 12 bytes (its native width); XChaCha20-Poly1305 uses all 24.
//! **No nonce is ever derived from a counter or reused**, and because a fresh
//! random DEK is generated on every seal, the 2^32-message-per-key GCM safety
//! bound is structurally unreachable rather than merely unlikely.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use zeroize::Zeroizing;

use crate::errors::{Result, VaultError};

/// Width of the nonce field stored in the vault header. Wide enough for the
/// widest supported cipher so the header layout never has to change.
pub const NONCE_FIELD_LEN: usize = 24;

/// Nonce width for the KEK wrap, which is fixed to AES-256-GCM.
pub const KEK_NONCE_LEN: usize = 12;

/// Authentication tag width for both ciphers.
pub const TAG_LEN: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadId {
    Aes256Gcm = 1,
    XChaCha20Poly1305 = 2,
}

impl AeadId {
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    pub fn from_u8(v: u8) -> Result<Self> {
        match v {
            1 => Ok(Self::Aes256Gcm),
            2 => Ok(Self::XChaCha20Poly1305),
            other => Err(VaultError::Unsupported(format!("unknown aead id {other}"))),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::XChaCha20Poly1305 => "XChaCha20-Poly1305",
        }
    }

    pub fn nonce_len(self) -> usize {
        match self {
            Self::Aes256Gcm => 12,
            Self::XChaCha20Poly1305 => 24,
        }
    }
}

/// Encrypt `plaintext` under `key` with `aad` bound into the tag.
pub fn encrypt(
    id: AeadId,
    key: &[u8; 32],
    nonce: &[u8; NONCE_FIELD_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let n = &nonce[..id.nonce_len()];
    match id {
        AeadId::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| VaultError::Kdf(format!("aes key init: {e}")))?;
            cipher
                .encrypt(
                    n.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::Auth)
        }
        AeadId::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| VaultError::Kdf(format!("chacha key init: {e}")))?;
            cipher
                .encrypt(
                    n.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::Auth)
        }
    }
}

/// Decrypt and verify. Returns a buffer that zeroizes on drop.
pub fn decrypt(
    id: AeadId,
    key: &[u8; 32],
    nonce: &[u8; NONCE_FIELD_LEN],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let n = &nonce[..id.nonce_len()];
    let out = match id {
        AeadId::Aes256Gcm => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|e| VaultError::Kdf(format!("aes key init: {e}")))?;
            cipher
                .decrypt(
                    n.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::Auth)?
        }
        AeadId::XChaCha20Poly1305 => {
            let cipher = XChaCha20Poly1305::new_from_slice(key)
                .map_err(|e| VaultError::Kdf(format!("chacha key init: {e}")))?;
            cipher
                .decrypt(
                    n.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| VaultError::Auth)?
        }
    };
    Ok(Zeroizing::new(out))
}

/// AES-256-GCM with a 12-byte nonce. Used for the KEK->DEK wrap, whose width
/// is fixed by the format so it does not need to follow `aead_id`.
pub fn wrap_gcm(
    key: &[u8; 32],
    nonce: &[u8; KEK_NONCE_LEN],
    aad: &[u8],
    pt: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Kdf(format!("aes key init: {e}")))?;
    cipher
        .encrypt(nonce.into(), Payload { msg: pt, aad })
        .map_err(|_| VaultError::Auth)
}

pub fn unwrap_gcm(
    key: &[u8; 32],
    nonce: &[u8; KEK_NONCE_LEN],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| VaultError::Kdf(format!("aes key init: {e}")))?;
    let out = cipher
        .decrypt(nonce.into(), Payload { msg: ct, aad })
        .map_err(|_| VaultError::Auth)?;
    Ok(Zeroizing::new(out))
}
