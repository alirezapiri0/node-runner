//! Durable file operations for the vault.
//!
//! The vault is the one file whose corruption is unrecoverable, so writes go
//! through a temp-file-plus-rename sequence with an fsync in between. A crash
//! at any point leaves either the old vault or the new one, never a half-written
//! file.
//!
//! Note on `wipe`: overwriting a file is a weak erasure guarantee on SSDs,
//! where wear levelling and TRIM can preserve the original blocks. The real
//! guarantee here is **crypto-erase** -- the vault is useless without its DEK,
//! so destroying the wrap material destroys the data. `wipe` is defence in
//! depth, not the primary mechanism.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::errors::Result;

/// Write `data` to `path` atomically.
///
/// 1. write to `<path>.tmp` and `sync_all` it
/// 2. optionally copy the existing file to `<path>.bak`
/// 3. rename the temp file over the target
///
/// `std::fs::rename` maps to `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` on
/// Windows and `rename(2)` elsewhere, both of which are atomic with respect to
/// other observers.
pub fn write_atomic(path: &Path, data: &[u8], keep_backup: bool) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let tmp = tmp_path(path);
    {
        let mut f = fs::File::create(&tmp)?;
        restrict_permissions(&tmp)?;
        f.write_all(data)?;
        f.flush()?;
        // Durability: without this the rename can be reordered ahead of the
        // data blocks, and a power loss leaves an empty file under the real name.
        f.sync_all()?;
    }

    if keep_backup && path.exists() {
        let bak = backup_path(path);
        fs::copy(path, &bak)?;
        if let Ok(f) = fs::File::open(&bak) {
            let _ = f.sync_all();
        }
    }

    fs::rename(&tmp, path)?;
    Ok(())
}

pub fn read(path: &Path) -> Result<Vec<u8>> {
    Ok(fs::read(path)?)
}

pub fn tmp_path(path: &Path) -> PathBuf {
    with_suffix(path, ".tmp")
}

pub fn backup_path(path: &Path) -> PathBuf {
    with_suffix(path, ".bak")
}

fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut s = path.as_os_str().to_os_string();
    s.push(suffix);
    PathBuf::from(s)
}

/// Overwrite then delete. See the module note on why this is not a strong
/// erasure guarantee by itself.
pub fn wipe(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let len = fs::metadata(path)?.len() as usize;
    if len > 0 {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; len.min(64 * 1024)];
            let mut written = 0usize;
            while written < len {
                let n = zeros.len().min(len - written);
                if f.write_all(&zeros[..n]).is_err() {
                    break;
                }
                written += n;
            }
            let _ = f.flush();
            let _ = f.sync_all();
        }
    }
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Best-effort owner-only permissions.
///
/// On Unix this is `0o600`. On Windows new files under `%LOCALAPPDATA%` already
/// inherit a user-only DACL, and tightening it further would require building a
/// security descriptor -- which is noted in SECURITY.md as an accepted residual
/// rather than silently skipped.
pub fn restrict_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}
