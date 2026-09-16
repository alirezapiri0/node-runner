//! Memory hygiene: two *different* mechanisms that are routinely conflated.
//!
//! * **Zeroization** (`zeroize`) overwrites an allocation when it is dropped.
//!   It protects against secrets lingering in freed heap memory and in a heap
//!   dump. It does **not** stop the OS from writing the page to `pagefile.sys`
//!   while the secret is still live.
//! * **Locking** (`VirtualLock`) pins the pages so the OS cannot page them out.
//!   This is the actual anti-swap control. It is a *process*-level facility and
//!   is best-effort: it can fail under memory pressure or when the process
//!   working-set quota is too small, which is why [`enable_process_memory_lock`]
//!   runs at startup to widen the quota.
//!
//! Both are used here, and the distinction is preserved in the API so nobody
//! later "simplifies" one away believing the other covers it.

use std::fmt;

use zeroize::Zeroize;

use crate::errors::{Result, VaultError};

/// A fixed-size, zeroizing, optionally page-locked byte buffer.
///
/// Backed by `Box<[u8]>` rather than `Vec<u8>` deliberately: a `Box<[u8]>` has
/// no spare capacity and cannot reallocate, so the address handed to
/// `VirtualLock` stays valid for the buffer's entire lifetime. Locking a `Vec`
/// and then pushing to it would silently invalidate the lock.
pub struct LockedBuf {
    data: Box<[u8]>,
    locked: bool,
}

impl LockedBuf {
    pub fn zeroed(len: usize) -> Self {
        let data = vec![0u8; len].into_boxed_slice();
        let locked = lock_region(data.as_ptr(), data.len());
        Self { data, locked }
    }

    pub fn copy_from(src: &[u8]) -> Self {
        let mut data = src.to_vec().into_boxed_slice();
        let locked = lock_region(data.as_ptr(), data.len());
        if !locked {
            // Still zeroize-on-drop; just not pinned. The caller can surface
            // this via `is_locked()` if it wants to warn the user.
            data.zeroize();
            data.copy_from_slice(src);
        }
        Self { data, locked }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// True when the pages are actually pinned against paging.
    pub fn is_locked(&self) -> bool {
        self.locked
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Borrow as a 32-byte key, with a checked conversion instead of a panic.
    pub fn as_array32(&self) -> Result<&[u8; 32]> {
        self.as_slice().try_into().map_err(|_| {
            VaultError::SecureMemory(format!("expected 32 bytes, found {}", self.len()))
        })
    }

    /// Release the page lock early (e.g. once a key has been rotated out),
    /// while keeping the buffer zeroizing on drop.
    pub fn unlock(&mut self) {
        if self.locked {
            unlock_region(self.data.as_ptr(), self.data.len());
            self.locked = false;
        }
    }
}

impl Drop for LockedBuf {
    fn drop(&mut self) {
        if self.locked {
            unlock_region(self.data.as_ptr(), self.data.len());
        }
        self.data.zeroize();
    }
}

impl fmt::Debug for LockedBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LockedBuf([redacted; {} bytes, pinned={}])",
            self.data.len(),
            self.locked
        )
    }
}

/// True when the platform implements page locking.
pub const fn secure_memory_supported() -> bool {
    cfg!(windows)
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------

#[cfg(windows)]
fn lock_region(ptr: *const u8, len: usize) -> bool {
    use windows_sys::Win32::System::Memory::VirtualLock;
    if len == 0 {
        return false;
    }
    // SAFETY: `ptr`/`len` describe a live allocation owned by the caller, and
    // the boxed slice is never reallocated for the life of the buffer.
    unsafe { VirtualLock(ptr as *const core::ffi::c_void, len) != 0 }
}

#[cfg(windows)]
fn unlock_region(ptr: *const u8, len: usize) {
    use windows_sys::Win32::System::Memory::VirtualUnlock;
    if len == 0 {
        return;
    }
    // SAFETY: symmetric with `lock_region`; failure here is intentionally
    // ignored because the allocation is about to be zeroized and freed anyway.
    unsafe {
        VirtualUnlock(ptr as *const core::ffi::c_void, len);
    }
}

/// Raise the process's minimum working set so `VirtualLock` has a quota to
/// draw from. Without this, locking can fail once the process exceeds its
/// default quota, which is exactly when secrets are most likely to be paged.
///
/// `QUOTA_LIMITS_HARDWS_MIN_ENABLE` makes the minimum a hard requirement, which
/// is what stops the trim-and-swap path.
#[cfg(windows)]
pub fn enable_process_memory_lock() -> Result<()> {
    // Note the split: the working-set APIs live under `System::Memory` in
    // windows-sys even though the documentation groups them with processes.
    use windows_sys::Win32::System::Memory::{
        SetProcessWorkingSetSizeEx, QUOTA_LIMITS_HARDWS_MIN_ENABLE,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    const MIN_WORKING_SET: usize = 64 * 1024 * 1024;
    // SAFETY: pseudo-handle, valid for the calling process; no ownership taken.
    let ok = unsafe {
        SetProcessWorkingSetSizeEx(
            GetCurrentProcess(),
            MIN_WORKING_SET,
            usize::MAX,
            QUOTA_LIMITS_HARDWS_MIN_ENABLE,
        )
    };
    if ok == 0 {
        return Err(VaultError::SecureMemory(
            "SetProcessWorkingSetSizeEx failed; page locking may be refused under pressure".into(),
        ));
    }
    Ok(())
}

/// Suppress the Windows Error Reporting fault dialog for this process.
///
/// Crash dumps are a real exfiltration path for a vault: a minidump taken
/// while the payload is decrypted contains the key material in the clear.
/// Combined with `panic = "abort"` this keeps those dumps from being produced.
#[cfg(windows)]
pub fn harden_process() -> Result<()> {
    use windows_sys::Win32::System::Diagnostics::Debug::{SetErrorMode, SEM_NOGPFAULTERRORBOX};
    // SAFETY: process-wide mode flag, no pointers involved.
    unsafe {
        SetErrorMode(SEM_NOGPFAULTERRORBOX);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Non-Windows (CI on Linux, and the fuzz/audit toolchain)
// ---------------------------------------------------------------------------

#[cfg(not(windows))]
fn lock_region(_ptr: *const u8, _len: usize) -> bool {
    false
}

#[cfg(not(windows))]
fn unlock_region(_ptr: *const u8, _len: usize) {}

#[cfg(not(windows))]
pub fn enable_process_memory_lock() -> Result<()> {
    Ok(())
}

#[cfg(not(windows))]
pub fn harden_process() -> Result<()> {
    Ok(())
}
