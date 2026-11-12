//! Non-Windows fallback: the guard API as cheap no-ops.
//!
//! Other file systems have no NTFS/WOF compression to work around, so these
//! functions behave like their `std` counterparts. Everything else in this crate
//! (queries, decompression, `tune`) is Windows-only.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;

use crate::CompressionKind;

pub(crate) fn open_uncompressed_with(opts: &OpenOptions, path: &Path) -> io::Result<File> {
    opts.open(path)
}

/// No-op on this platform.
pub fn preallocate(_file: &File, _size: u64) -> io::Result<()> {
    Ok(())
}

/// Creates (or truncates) a file – on this platform simply `File::create`.
///
/// ```no_run
/// use std::io::Write;
/// let mut f = ntfs_unthrottle::create_uncompressed("out/archive.bin")?;
/// f.write_all(b"...")?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn create_uncompressed<P: AsRef<Path>>(path: P) -> io::Result<File> {
    File::create(path)
}

/// No-op on this platform.
pub fn disable_compression(_file: &File) -> io::Result<()> {
    Ok(())
}

/// Same as `std::fs::create_dir_all` on this platform.
pub fn create_dir_all_uncompressed<P: AsRef<Path>>(path: P) -> io::Result<()> {
    fs::create_dir_all(path)
}

/// No-op on this platform; always `Ok(false)` (nothing was cleared).
pub fn clear_dir_compression<P: AsRef<Path>>(_dir: P) -> io::Result<bool> {
    Ok(false)
}

/// Always `Ok(None)` for existing paths; errors (e.g. "not found") are passed through.
pub fn compression_kind<P: AsRef<Path>>(path: P) -> io::Result<Option<CompressionKind>> {
    fs::metadata(path).map(|_| None)
}

/// Always `Ok(None)` on this platform.
pub fn compression_kind_of(_file: &File) -> io::Result<Option<CompressionKind>> {
    Ok(None)
}
