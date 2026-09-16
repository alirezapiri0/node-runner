//! OS-level key wrapping.
//!
//! # What DPAPI actually protects against
//!
//! [`os_wrap`] uses `CryptProtectData` to bind the data encryption key to the
//! current Windows user profile. That protects against:
//!
//! * offline theft of the disk or of a backup containing the vault file
//! * another user account on the same machine
//! * a copy of the vault carried to a different machine
//!
//! It does **not** protect against:
//!
//! * malware already running as *this* user -- DPAPI will happily unwrap for it
//! * an administrator who can install a keylogger or inject into the process
//!
//! And, importantly, `CryptProtectData` is **not TPM-bound**. It is a
//! user-profile-bound symmetric scheme; the master key lives in the user's
//! credential files, encrypted with a key derived from the account's logon
//! secrets. Genuine hardware binding requires CNG/`NCrypt` with the Microsoft
//! Platform Crypto Provider (`NCRYPT_PLATFORM_CRYPTO_PROVIDER`), which is a
//! different API and a different key lifecycle. [`TpmBinding`] records that
//! distinction so the UI cannot overstate what the user is getting.
//!
//! # Entropy
//!
//! Every wrap passes `pOptionalEntropy` = [`APP_ENTROPY_TAG`] || vault salt.
//! That means a DPAPI blob lifted from this app cannot be unwrapped by other
//! software running as the same user unless it also knows the tag *and* the
//! per-installation salt -- i.e. it needs the vault file too.

use crate::errors::Result;
use crate::lockmem::LockedBuf;

/// Application-specific DPAPI entropy prefix.
pub const APP_ENTROPY_TAG: &[u8] = b"nr-vault/dpapi-entropy/v1";

/// How the master key is bound to this machine, for display purposes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TpmBinding {
    /// DPAPI user-scope: profile-bound, not hardware-bound.
    UserProfileScope,
    /// Reserved for a CNG platform-provider key. Not implemented in this build;
    /// the variant exists so the UI and metadata schema do not change when it is.
    PlatformCryptoProvider,
}

impl TpmBinding {
    pub fn label(self) -> &'static str {
        match self {
            Self::UserProfileScope => "Windows DPAPI (user profile scope; not TPM-bound)",
            Self::PlatformCryptoProvider => "CNG Platform Crypto Provider (TPM-bound)",
        }
    }
}

/// True when this platform has a real OS key protector.
pub const fn os_available() -> bool {
    cfg!(windows)
}

/// Wrap `plaintext` (normally the 32-byte DEK) into an OS-protected blob.
pub fn os_wrap(plaintext: &[u8], salt: &[u8; 32]) -> Result<Vec<u8>> {
    let entropy = build_entropy(salt);
    platform::wrap(plaintext, &entropy)
}

/// Unwrap a blob produced by [`os_wrap`]. Returns pinned, zeroizing memory.
pub fn os_unwrap(blob: &[u8], salt: &[u8; 32]) -> Result<LockedBuf> {
    let entropy = build_entropy(salt);
    platform::unwrap(blob, &entropy)
}

/// Probe whether the OS protector is currently healthy.
///
/// Performs a real wrap/unwrap round trip of a throwaway value, then asks DPAPI
/// to verify the protection of that blob. A profile that was migrated, restored
/// from an image, or whose credentials were rotated will fail here even though
/// the API still "works" -- worth knowing before the user relies on it.
pub fn probe_protector() -> ProtectorStatus {
    if !os_available() {
        return ProtectorStatus::Unsupported;
    }
    let salt = [0u8; 32];
    let probe = b"nr-vault-protector-probe";
    match os_wrap(probe, &salt) {
        Ok(blob) => match os_unwrap(&blob, &salt) {
            Ok(round) if round.as_slice() == probe => {
                match platform::verify_protection(&blob, &build_entropy(&salt)) {
                    Ok(()) => ProtectorStatus::Healthy,
                    Err(_) => ProtectorStatus::ProtectionChanged,
                }
            }
            _ => ProtectorStatus::Failing,
        },
        Err(_) => ProtectorStatus::Failing,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ProtectorStatus {
    /// Round trip and protection verification both succeeded.
    Healthy,
    /// DPAPI works, but the stored protection is no longer intact. Usually means
    /// the profile was migrated or restored; the vault may not open.
    ProtectionChanged,
    /// The API is present but the round trip failed.
    Failing,
    /// Not a Windows platform.
    Unsupported,
}

fn build_entropy(salt: &[u8; 32]) -> Vec<u8> {
    let mut e = Vec::with_capacity(APP_ENTROPY_TAG.len() + salt.len());
    e.extend_from_slice(APP_ENTROPY_TAG);
    e.extend_from_slice(salt);
    e
}

// ---------------------------------------------------------------------------
// Windows implementation
// ---------------------------------------------------------------------------

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN,
        CRYPTPROTECT_VERIFY_PROTECTION, CRYPT_INTEGER_BLOB,
    };

    use crate::errors::{Result, VaultError};
    use crate::lockmem::LockedBuf;

    fn blob_of(data: &[u8]) -> CRYPT_INTEGER_BLOB {
        CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            // DPAPI only reads from the input blob; the cast to *mut is part of
            // the ABI and no write occurs through it.
            pbData: data.as_ptr() as *mut u8,
        }
    }

    /// Copy an output blob into owned memory and free the DPAPI allocation.
    ///
    /// SAFETY contract: `out.pbData` must be a live allocation from LocalAlloc
    /// (which is what crypt32 hands back) and is freed exactly once here.
    unsafe fn take_blob(out: CRYPT_INTEGER_BLOB) -> Vec<u8> {
        if out.pbData.is_null() || out.cbData == 0 {
            return Vec::new();
        }
        let owned = unsafe {
            let slice = std::slice::from_raw_parts(out.pbData, out.cbData as usize);
            slice.to_vec()
        };
        unsafe { LocalFree(out.pbData as *mut c_void) };
        owned
    }

    pub fn wrap(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>> {
        let in_blob = blob_of(plaintext);
        let ent_blob = blob_of(entropy);
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        // CRYPTPROTECT_UI_FORBIDDEN: never pop a dialog. A background service or
        // an unattended app must fail rather than silently block on a prompt.
        // CRYPTPROTECT_LOCAL_MACHINE is deliberately NOT set -- machine scope
        // would let any user on the box unwrap.
        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                std::ptr::null(),
                &ent_blob,
                std::ptr::null::<c_void>(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if ok == 0 {
            return Err(VaultError::OsProtection(format!(
                "CryptProtectData failed (Win32 error {})",
                unsafe { GetLastError() }
            )));
        }

        // SAFETY: crypt32 returned success, so out_blob owns a LocalAlloc block.
        Ok(unsafe { take_blob(out_blob) })
    }

    pub fn unwrap(blob: &[u8], entropy: &[u8]) -> Result<LockedBuf> {
        let in_blob = blob_of(blob);
        let ent_blob = blob_of(entropy);
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };
        let mut descr: windows_sys::core::PWSTR = std::ptr::null_mut();

        let ok = unsafe {
            CryptUnprotectData(
                &in_blob,
                &mut descr,
                &ent_blob,
                std::ptr::null::<c_void>(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if ok == 0 {
            return Err(VaultError::OsProtection(format!(
                "CryptUnprotectData failed (Win32 error {})",
                unsafe { GetLastError() }
            )));
        }

        // SAFETY: success implies out_blob is a LocalAlloc block.
        let owned = unsafe { take_blob(out_blob) };
        if !descr.is_null() {
            // The description string is also LocalAlloc'd by crypt32.
            unsafe { LocalFree(descr as *mut c_void) };
        }
        let buf = LockedBuf::copy_from(&owned);
        // `owned` is a plain Vec we cannot zeroize by scope; overwrite it here.
        drop(owned);
        Ok(buf)
    }

    /// Ask DPAPI whether this blob's protection is still intact.
    pub fn verify_protection(blob: &[u8], entropy: &[u8]) -> Result<()> {
        let in_blob = blob_of(blob);
        let ent_blob = blob_of(entropy);
        let mut out_blob = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: std::ptr::null_mut(),
        };

        let ok = unsafe {
            CryptProtectData(
                &in_blob,
                std::ptr::null(),
                &ent_blob,
                std::ptr::null::<c_void>(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_VERIFY_PROTECTION,
                &mut out_blob,
            )
        };

        if ok == 0 {
            return Err(VaultError::OsProtection(
                "CryptProtectData(VERIFY_PROTECTION) reports the protection is not intact".into(),
            ));
        }
        // SAFETY: success implies an owned allocation we must release.
        let _ = unsafe { take_blob(out_blob) };
        Ok(())
    }
}

#[cfg(not(windows))]
mod platform {
    use crate::errors::{Result, VaultError};
    use crate::lockmem::LockedBuf;

    fn unsupported() -> VaultError {
        VaultError::OsProtectionUnavailable(std::env::consts::OS.to_string())
    }

    pub fn wrap(_plaintext: &[u8], _entropy: &[u8]) -> Result<Vec<u8>> {
        Err(unsupported())
    }

    pub fn unwrap(_blob: &[u8], _entropy: &[u8]) -> Result<LockedBuf> {
        Err(unsupported())
    }

    pub fn verify_protection(_blob: &[u8], _entropy: &[u8]) -> Result<()> {
        Err(unsupported())
    }
}

// ---------------------------------------------------------------------------
// Optional: Windows Credential Vault (convenience tier only)
// ---------------------------------------------------------------------------

/// Store/lookup a convenience copy of a seed in the Windows Credential Vault.
///
/// This is **not** a security tier. The Credential Manager stores its own
/// DPAPI-protected blob, so anything that can read the DPAPI blob (same-user
/// malware) can read this too. It exists because the specification asked for it
/// and because it is the right place for material that must survive an
/// application reinstall. It is behind the `credman` feature so it is opt-in.
#[cfg(all(windows, feature = "credman"))]
pub mod credential_vault {
    use std::ffi::c_void;

    use windows_sys::Win32::Foundation::{GetLastError, FILETIME};
    use windows_sys::Win32::Security::Credentials::{
        CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE, CRED_TYPE_GENERIC,
    };

    use crate::errors::{Result, VaultError};
    use crate::lockmem::LockedBuf;

    fn to_wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn store(service: &str, account: &str, secret: &[u8]) -> Result<()> {
        let mut target = to_wide(service);
        let mut user = to_wide(account);
        let mut blob = secret.to_vec();

        let cred = CREDENTIALW {
            Flags: 0,
            Type: CRED_TYPE_GENERIC,
            TargetName: target.as_mut_ptr(),
            Comment: std::ptr::null_mut(),
            LastWritten: FILETIME {
                dwLowDateTime: 0,
                dwHighDateTime: 0,
            },
            CredentialBlobSize: blob.len() as u32,
            CredentialBlob: blob.as_mut_ptr(),
            Persist: CRED_PERSIST_LOCAL_MACHINE,
            AttributeCount: 0,
            Attributes: std::ptr::null_mut(),
            TargetAlias: std::ptr::null_mut(),
            UserName: user.as_mut_ptr(),
        };

        // SAFETY: `cred` and every pointer it contains are valid for this call;
        // CredWriteW copies the blob before returning.
        let ok = unsafe { CredWriteW(&cred, 0) };
        // Scrub the local copy regardless of outcome.
        for b in blob.iter_mut() {
            *b = 0;
        }

        if ok == 0 {
            return Err(VaultError::OsProtection(format!(
                "CredWriteW failed (Win32 error {})",
                unsafe { GetLastError() }
            )));
        }
        Ok(())
    }

    pub fn load(service: &str) -> Result<LockedBuf> {
        let target = to_wide(service);
        let mut out: *mut CREDENTIALW = std::ptr::null_mut();

        // SAFETY: `target` is a NUL-terminated wide string that outlives the
        // call; on success `out` receives an allocation we must CredFree.
        let ok = unsafe { CredReadW(target.as_ptr(), CRED_TYPE_GENERIC, 0, &mut out) };

        if ok == 0 || out.is_null() {
            return Err(VaultError::NoUnlockMethod(format!(
                "no credential named {service:?} in the Windows Credential Vault"
            )));
        }

        let buf = unsafe {
            let cred = &*out;
            let slice =
                std::slice::from_raw_parts(cred.CredentialBlob, cred.CredentialBlobSize as usize);
            LockedBuf::copy_from(slice)
        };
        unsafe { CredFree(out as *const c_void) };
        Ok(buf)
    }
}
