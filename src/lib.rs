//! Low-level building blocks to detect and remove NTFS (LZNT1) and WOF
//! (CompactOS) compression.
//!
//! The functions are intentionally small so they can be embedded directly into
//! your own unpackers/converters:
//!
//! - [`create_uncompressed`] – create a file that is never NTFS-compressed,
//!   even inside a compressed folder (best-effort, no extra I/O on normal folders).
//! - [`create_uncompressed_with_size`] – same as [`create_uncompressed`], plus
//!   best-effort contiguous cluster pre-allocation (NTFS & ReFS).
//! - [`UncompressedOpenOptions`] – extension trait for [`std::fs::OpenOptions`]
//!   supporting `.create_new(true)`, `.append(true)`, custom Windows flags, etc.
//! - [`create_dir_all_uncompressed`] – like `std::fs::create_dir_all`, but keeps
//!   the created folder tree free of the inherited compression flag.
//! - [`compression_kind`] – is a file LZNT1- or WOF-compressed?
//!
//! # Features
//!
//! - `cli` (default): the `ntfs-unthrottle` command-line tool and its dependencies.
//! - `tune` (enabled by `cli`): the `tune` module with volume/drive diagnostics.
//!
//! Library users only need `windows-sys`:
//!
//! ```toml
//! ntfs-unthrottle = { version = "0.8", default-features = false }
//! ```
//!
//! # Platforms
//!
//! The full API is Windows-only. On other platforms the guard functions
//! ([`create_uncompressed`], [`create_uncompressed_with_size`],
//! [`UncompressedOpenOptions`], [`preallocate`], [`disable_compression`],
//! [`create_dir_all_uncompressed`], [`clear_dir_compression`],
//! [`compression_kind`], [`compression_kind_of`]) are
//! available as cheap no-ops, so callers need no `cfg` switches of their own.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::Path;

#[cfg(windows)]
mod win;
#[cfg(windows)]
pub use win::*;
#[cfg(all(windows, feature = "tune"))]
pub(crate) use win::{ioctl, is_unsupported};

#[cfg(not(windows))]
mod portable;
#[cfg(not(windows))]
pub use portable::*;

#[cfg(all(windows, feature = "tune"))]
pub mod tune;

// ---------------------------------------------------------------------------
// Extension trait & platform-independent wrappers
// ---------------------------------------------------------------------------

/// Extension trait for [`std::fs::OpenOptions`] to open or create files without
/// NTFS compression (and optionally pre-allocate contiguous clusters).
///
/// ```no_run
/// use std::fs::OpenOptions;
/// use ntfs_unthrottle::UncompressedOpenOptions;
///
/// let file = OpenOptions::new()
///     .write(true)
///     .create_new(true)
///     .open_uncompressed_with_size("D:/out/payload.bin", 64 * 1024 * 1024)?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub trait UncompressedOpenOptions {
    /// Opens/creates `path` with these options and clears inherited
    /// `FILE_ATTRIBUTE_COMPRESSED` before writing (best-effort on Windows).
    fn open_uncompressed<P: AsRef<Path>>(&self, path: P) -> io::Result<File>;

    /// Like [`open_uncompressed`](Self::open_uncompressed), plus best-effort
    /// contiguous cluster pre-allocation via [`preallocate`] (NTFS & ReFS).
    fn open_uncompressed_with_size<P: AsRef<Path>>(&self, path: P, size: u64) -> io::Result<File>;
}

impl UncompressedOpenOptions for OpenOptions {
    fn open_uncompressed<P: AsRef<Path>>(&self, path: P) -> io::Result<File> {
        #[cfg(windows)]
        {
            win::open_uncompressed_with(self, path.as_ref())
        }
        #[cfg(not(windows))]
        {
            portable::open_uncompressed_with(self, path.as_ref())
        }
    }

    fn open_uncompressed_with_size<P: AsRef<Path>>(&self, path: P, size: u64) -> io::Result<File> {
        let file = self.open_uncompressed(path)?;
        let _ = preallocate(&file, size);
        Ok(file)
    }
}

/// Like [`create_uncompressed`], plus best-effort contiguous cluster
/// pre-allocation for `size` bytes (on Windows via `FileAllocationInfo`,
/// covering both NTFS and ReFS / Dev Drives).
pub fn create_uncompressed_with_size<P: AsRef<Path>>(path: P, size: u64) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    opts.open_uncompressed_with_size(path, size)
}

// ---------------------------------------------------------------------------
// Platform-neutral types
// ---------------------------------------------------------------------------

/// Algorithm of a WOF compression (`compact /exe:…`, CompactOS, CompactGUI).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WofAlgorithm {
    Xpress4K,
    Xpress8K,
    Xpress16K,
    Lzx,
    Unknown(u32),
}

impl fmt::Display for WofAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Xpress4K => f.write_str("XPRESS4K"),
            Self::Xpress8K => f.write_str("XPRESS8K"),
            Self::Xpress16K => f.write_str("XPRESS16K"),
            Self::Lzx => f.write_str("LZX"),
            Self::Unknown(n) => write!(f, "WOF#{n}"),
        }
    }
}

/// Kind of transparent compression of a file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionKind {
    /// Classic NTFS compression (`FILE_ATTRIBUTE_COMPRESSED`, blue arrows).
    Lznt1,
    /// Windows Overlay Filter – without a visible attribute.
    Wof(WofAlgorithm),
}

impl fmt::Display for CompressionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Lznt1 => f.write_str("LZNT1"),
            Self::Wof(a) => write!(f, "WOF/{a}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Platform-neutral helpers
// ---------------------------------------------------------------------------

/// Strips the `\\?\` prefix for display (`\\?\UNC\srv\x` → `\\srv\x`).
pub fn display_path(path: &Path) -> String {
    let s = path.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{rest}")
    } else if let Some(rest) = s.strip_prefix(r"\\?\") {
        rest.to_string()
    } else {
        s.into_owned()
    }
}

/// Is `path` a virtual hard disk (`.vhd`, `.vhdx`, `.avhdx`)?
pub fn is_virtual_disk(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "vhd" | "vhdx" | "avhdx"))
}
