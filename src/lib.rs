//! Low-level building blocks to detect and remove NTFS (LZNT1) and WOF
//! (CompactOS) compression.
//!
//! The functions are intentionally small so they can be embedded directly into
//! your own unpackers/converters, see [`create_uncompressed`].

#[cfg(not(windows))]
compile_error!("ntfs-unthrottle only supports Windows (NTFS).");

use std::ffi::c_void;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};

use windows_sys::Win32::Foundation::{
    GetLastError, ERROR_ACCESS_DENIED, ERROR_DISK_FULL, ERROR_FILE_SYSTEM_LIMITATION,
    ERROR_HANDLE_EOF, ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_LOCK_VIOLATION,
    ERROR_MORE_DATA, ERROR_NOT_SUPPORTED, ERROR_OBJECT_NOT_EXTERNALLY_BACKED,
    ERROR_SHARING_VIOLATION, ERROR_USER_MAPPED_FILE, HANDLE, NO_ERROR, SetLastError,
};
use windows_sys::Win32::Storage::FileSystem::{
    GetCompressedFileSizeW, GetDiskFreeSpaceExW, GetFileAttributesW, GetFileInformationByHandle,
    GetVolumeInformationW, GetVolumePathNameW, BY_HANDLE_FILE_INFORMATION, SetFileAttributesW, COMPRESSION_FORMAT_NONE, FILE_ATTRIBUTE_COMPRESSED,
    FILE_ATTRIBUTE_READONLY, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_PROVIDER_COMPRESSION_LZX, FILE_PROVIDER_COMPRESSION_XPRESS16K,
    FILE_PROVIDER_COMPRESSION_XPRESS4K, FILE_PROVIDER_COMPRESSION_XPRESS8K, FILE_WRITE_DATA,
    INVALID_FILE_ATTRIBUTES, WOF_PROVIDER_FILE,
};
use windows_sys::Win32::System::Ioctl::{
    FILE_PROVIDER_EXTERNAL_INFO_V1, FSCTL_DELETE_EXTERNAL_BACKING, FSCTL_GET_EXTERNAL_BACKING,
    FSCTL_GET_RETRIEVAL_POINTERS, FSCTL_SET_COMPRESSION, WOF_EXTERNAL_INFO,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

pub mod tune;

/// `FILE_FILE_COMPRESSION` from winnt.h (avoids the SystemServices feature).
const FILE_FILE_COMPRESSION: u32 = 0x0000_0010;

// ---------------------------------------------------------------------------
// Types
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

impl WofAlgorithm {
    fn from_raw(raw: u32) -> Self {
        match raw {
            FILE_PROVIDER_COMPRESSION_XPRESS4K => Self::Xpress4K,
            FILE_PROVIDER_COMPRESSION_XPRESS8K => Self::Xpress8K,
            FILE_PROVIDER_COMPRESSION_XPRESS16K => Self::Xpress16K,
            FILE_PROVIDER_COMPRESSION_LZX => Self::Lzx,
            other => Self::Unknown(other),
        }
    }
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

/// Information about the volume a path resides on.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Root of the volume or mount point, e.g. `C:\`.
    pub root: PathBuf,
    /// File system, e.g. `NTFS`, `ReFS`, `exFAT`.
    pub fs_name: String,
    /// Does the file system support file-based compression?
    pub supports_compression: bool,
    /// Free space available to the current user, in bytes.
    pub free_bytes: u64,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// NUL-terminated UTF-16 string for Win32 calls.
pub fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

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

fn raw_handle(file: &File) -> HANDLE {
    file.as_raw_handle() as HANDLE
}

/// Thin wrapper around `DeviceIoControl`; returns the number of bytes returned.
///
/// # Safety
/// `input`/`output` must be valid for the given lengths.
unsafe fn ioctl(
    file: &File,
    code: u32,
    input: *const c_void,
    input_len: u32,
    output: *mut c_void,
    output_len: u32,
) -> io::Result<u32> {
    let mut returned = 0u32;
    let ok = DeviceIoControl(
        raw_handle(file),
        code,
        input,
        input_len,
        output,
        output_len,
        &mut returned,
        null_mut(),
    );
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(returned)
    }
}

fn os_code(err: &io::Error) -> Option<u32> {
    err.raw_os_error().map(|c| c as u32)
}

/// Errors meaning "the file system/driver cannot do this" (FAT, exFAT, ReFS, no wof.sys).
fn is_unsupported(err: &io::Error) -> bool {
    matches!(
        os_code(err),
        Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER)
    )
}

/// Opens a handle for querying metadata only (no data access, no locking).
pub fn open_for_query(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// Per its IOCTL definition, `FSCTL_SET_COMPRESSION` requires `FILE_READ_DATA | FILE_WRITE_DATA`.
fn open_for_modify(path: &Path, is_dir: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.access_mode(FILE_READ_DATA | FILE_WRITE_DATA)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    if is_dir {
        // On Windows, directory handles only exist with backup semantics.
        opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    opts.open(path)
}

// ---------------------------------------------------------------------------
// Queries
// ---------------------------------------------------------------------------

/// Space actually allocated on disk (`GetCompressedFileSizeW`).
/// Works for LZNT1, WOF and sparse files.
pub fn physical_size(path: &Path) -> io::Result<u64> {
    let wide = to_wide(path);
    let mut high = 0u32;
    // Otherwise GetLastError below could return a stale error from an earlier call.
    // SAFETY: only sets the thread-local error value.
    unsafe { SetLastError(NO_ERROR) };
    // SAFETY: wide is NUL-terminated, high is a valid pointer.
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
    if low == u32::MAX {
        // u32::MAX can also be a valid low part → GetLastError decides.
        let err = unsafe { GetLastError() };
        if err != NO_ERROR {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
    }
    Ok((u64::from(high) << 32) | u64::from(low))
}

/// Returns the WOF algorithm if the file is WOF-compressed.
/// WIM-backed files (WIMBoot) are intentionally ignored.
pub fn wof_algorithm(path: &Path) -> io::Result<Option<WofAlgorithm>> {
    wof_algorithm_of(&open_for_query(path)?)
}

/// Like [`wof_algorithm`], but on an already opened handle.
pub fn wof_algorithm_of(file: &File) -> io::Result<Option<WofAlgorithm>> {
    #[repr(C)]
    struct Buf {
        wof: WOF_EXTERNAL_INFO,
        file: FILE_PROVIDER_EXTERNAL_INFO_V1,
    }
    // SAFETY: plain POD structs, zero initialization is valid.
    let mut buf: Buf = unsafe { std::mem::zeroed() };
    let res = unsafe {
        ioctl(
            file,
            FSCTL_GET_EXTERNAL_BACKING,
            null(),
            0,
            &mut buf as *mut Buf as *mut c_void,
            std::mem::size_of::<Buf>() as u32,
        )
    };
    match res {
        Ok(_) if buf.wof.Provider == WOF_PROVIDER_FILE => {
            Ok(Some(WofAlgorithm::from_raw(buf.file.Algorithm)))
        }
        Ok(_) => Ok(None),
        Err(e) if os_code(&e) == Some(ERROR_OBJECT_NOT_EXTERNALLY_BACKED) || is_unsupported(&e) => {
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

/// Number of physically contiguous fragments of a file
/// (`FSCTL_GET_RETRIEVAL_POINTERS`). For LZNT1 files typically
/// "one fragment per 64 KiB compression unit" – the actual bottleneck.
pub fn fragment_count(path: &Path) -> io::Result<u64> {
    fragment_count_of(&open_for_query(path)?)
}

/// Like [`fragment_count`], but on an already opened handle.
pub fn fragment_count_of(file: &File) -> io::Result<u64> {

    // Layout of RETRIEVAL_POINTERS_BUFFER:
    //   u32 ExtentCount, (4 bytes padding), i64 StartingVcn,
    //   [ { i64 NextVcn, i64 Lcn } ; ExtentCount ]
    const BUF_WORDS: usize = 8 * 1024; // 64 KiB, 8-byte aligned
    let mut buf = vec![0i64; BUF_WORDS];
    let mut start_vcn: i64 = 0;
    let mut fragments = 0u64;
    let mut last_lcn_end: Option<i64> = None;

    loop {
        let res = unsafe {
            ioctl(
                file,
                FSCTL_GET_RETRIEVAL_POINTERS,
                &start_vcn as *const i64 as *const c_void,
                8,
                buf.as_mut_ptr() as *mut c_void,
                (BUF_WORDS * 8) as u32,
            )
        };
        let more = match res {
            Ok(_) => false,
            Err(e) if os_code(&e) == Some(ERROR_MORE_DATA) => true,
            // Resident (very small) or empty files have no extents.
            Err(e) if os_code(&e) == Some(ERROR_HANDLE_EOF) => return Ok(0),
            Err(e) => return Err(e),
        };

        let count = (buf[0] as u64 & 0xFFFF_FFFF) as usize;
        let mut vcn = buf[1];
        let max_extents = (BUF_WORDS - 2) / 2;
        for i in 0..count.min(max_extents) {
            let next_vcn = buf[2 + i * 2];
            let lcn = buf[3 + i * 2];
            let len = next_vcn - vcn;
            if lcn != -1 {
                // Skip sparse holes (lcn == -1); only real jumps count.
                if last_lcn_end != Some(lcn) {
                    fragments += 1;
                }
                last_lcn_end = Some(lcn + len);
            }
            vcn = next_vcn;
        }
        if !more || count == 0 {
            break;
        }
        start_vcn = vcn;
    }
    Ok(fragments)
}

/// Unique identity of a file on a volume – hardlinks share it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub volume_serial: u32,
    /// 64-bit file index (MFT reference on NTFS).
    pub index: u64,
    /// Number of hardlinks (names) of this file.
    pub links: u32,
}

impl FileIdentity {
    /// Key for duplicate detection (without the link count).
    pub fn key(&self) -> (u32, u64) {
        (self.volume_serial, self.index)
    }
}

/// Volume serial number, file index and link count of an open handle.
pub fn file_identity_of(file: &File) -> io::Result<FileIdentity> {
    // SAFETY: plain POD struct, zero initialization is valid.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle, pointer to a sufficiently large struct.
    if unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        links: info.nNumberOfLinks,
    })
}

/// Determines volume root, file system and free space for a path.
pub fn volume_info(path: &Path) -> io::Result<VolumeInfo> {
    let wide = to_wide(path);
    let mut root = vec![0u16; 1024];
    // SAFETY: valid buffer, length in characters.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let root_len = root.iter().position(|&c| c == 0).unwrap_or(root.len());
    root.truncate(root_len + 1); // incl. NUL

    let mut fs_name = vec![0u16; 64];
    let mut fs_flags = 0u32;
    // SAFETY: all pointers are valid or null.
    let ok = unsafe {
        GetVolumeInformationW(
            root.as_ptr(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut fs_flags,
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    let fs_len = fs_name.iter().position(|&c| c == 0).unwrap_or(fs_name.len());

    let mut free = 0u64;
    // SAFETY: root is NUL-terminated.
    if unsafe { GetDiskFreeSpaceExW(root.as_ptr(), &mut free, null_mut(), null_mut()) } == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(VolumeInfo {
        root: PathBuf::from(std::ffi::OsString::from_wide(&root[..root_len])),
        fs_name: String::from_utf16_lossy(&fs_name[..fs_len]),
        supports_compression: fs_flags & FILE_FILE_COMPRESSION != 0,
        free_bytes: free,
    })
}

/// Raw file attributes (`GetFileAttributesW`).
pub fn file_attributes(path: &Path) -> io::Result<u32> {
    let wide = to_wide(path);
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        Err(io::Error::last_os_error())
    } else {
        Ok(attrs)
    }
}

/// Is `path` the root of the system drive (`sysdrive`, e.g. `C:`)?
/// Recognizes `C:\` as well as `\\?\C:\`.
pub fn is_system_drive_root(path: &Path, sysdrive: &str) -> bool {
    if path.parent().is_some() {
        return false;
    }
    let shown = display_path(path);
    let a = shown.trim_end_matches('\\');
    !a.is_empty() && a.eq_ignore_ascii_case(sysdrive.trim_end_matches('\\'))
}

/// All ancestor folders (excluding `path` itself) that carry the compression flag.
/// New *subfolders* there keep inheriting the flag. The drive root (e.g. `E:\`)
/// counts as well – except on the system drive, where the flag is Windows' business.
pub fn compressed_ancestors(path: &Path) -> Vec<PathBuf> {
    let sysdrive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    path.ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
        .filter(|p| !is_system_drive_root(p, &sysdrive))
        .filter(|p| file_attributes(p).is_ok_and(|a| a & FILE_ATTRIBUTE_COMPRESSED != 0))
        .map(Path::to_path_buf)
        .collect()
}

// ---------------------------------------------------------------------------
// Modifications
// ---------------------------------------------------------------------------

/// Clears the read-only attribute for the lifetime of the guard and restores
/// it in `Drop` – even on errors/panics.
pub struct ReadonlyGuard {
    wide: Vec<u16>,
    restore: bool,
}

impl ReadonlyGuard {
    pub fn clear(path: &Path) -> io::Result<Self> {
        let wide = to_wide(path);
        let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
        if attrs == INVALID_FILE_ATTRIBUTES {
            return Err(io::Error::last_os_error());
        }
        if attrs & FILE_ATTRIBUTE_READONLY == 0 {
            return Ok(Self { wide, restore: false });
        }
        if unsafe { SetFileAttributesW(wide.as_ptr(), attrs & !FILE_ATTRIBUTE_READONLY) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { wide, restore: true })
    }
}

impl Drop for ReadonlyGuard {
    fn drop(&mut self) {
        if !self.restore {
            return;
        }
        unsafe {
            let cur = GetFileAttributesW(self.wide.as_ptr());
            if cur != INVALID_FILE_ATTRIBUTES {
                SetFileAttributesW(self.wide.as_ptr(), cur | FILE_ATTRIBUTE_READONLY);
            }
        }
    }
}

/// Raw `FSCTL_SET_COMPRESSION(COMPRESSION_FORMAT_NONE)` without error suppression.
/// For already compressed files the call blocks until NTFS has rewritten all
/// compression units uncompressed.
fn set_compression_none(file: &File) -> io::Result<()> {
    let format: u16 = COMPRESSION_FORMAT_NONE;
    // SAFETY: input buffer is valid for the given length.
    unsafe {
        ioctl(
            file,
            FSCTL_SET_COMPRESSION,
            &format as *const u16 as *const c_void,
            std::mem::size_of::<u16>() as u32,
            null_mut(),
            0,
        )
    }
    .map(|_| ())
}

/// Disables NTFS compression on an open handle – intended for **newly created**
/// files (see [`create_uncompressed`]).
/// The handle needs read **and** write access. On file systems without
/// compression (FAT, exFAT, ReFS) this is a no-op: "not supported" and
/// `ERROR_INVALID_PARAMETER` are intentionally ignored there.
///
/// To decompress existing files use [`remove_ntfs_compression`] – it reports
/// every error.
pub fn disable_compression(file: &File) -> io::Result<()> {
    match set_compression_none(file) {
        Err(e) if is_unsupported(&e) => Ok(()),
        other => other,
    }
}

/// Removes the NTFS compression of a file or the inheritance flag of a folder.
///
/// Unlike [`disable_compression`], nothing is swallowed here: the item verifiably
/// carries `FILE_ATTRIBUTE_COMPRESSED`, so every error is real (e.g. a sparse
/// conflict). Afterwards it verifies that the attribute is really gone.
pub fn remove_ntfs_compression(path: &Path, is_dir: bool) -> io::Result<()> {
    let _ro = if is_dir { None } else { Some(ReadonlyGuard::clear(path)?) };
    set_compression_none(&open_for_modify(path, is_dir)?)?;
    if file_attributes(path)? & FILE_ATTRIBUTE_COMPRESSED != 0 {
        return Err(io::Error::other(
            "compression still active after FSCTL_SET_COMPRESSION",
        ));
    }
    Ok(())
}

/// Removes a WOF compression (the file is decompressed in the process).
pub fn remove_wof_compression(path: &Path) -> io::Result<()> {
    let _ro = ReadonlyGuard::clear(path)?;
    let file = open_for_modify(path, false)?;
    match unsafe { ioctl(&file, FSCTL_DELETE_EXTERNAL_BACKING, null(), 0, null_mut(), 0) } {
        Ok(_) => Ok(()),
        // wof.sys decompresses the file but then passes the FSCTL on to NTFS,
        // which answers "not externally backed". Check the target state instead
        // of trusting the return value.
        Err(e) if os_code(&e) == Some(ERROR_OBJECT_NOT_EXTERNALLY_BACKED) => {
            match wof_algorithm_of(&file)? {
                None => Ok(()),
                Some(_) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// Removes the given kind of compression.
pub fn remove_compression(path: &Path, kind: CompressionKind) -> io::Result<()> {
    match kind {
        CompressionKind::Lznt1 => remove_ntfs_compression(path, false),
        CompressionKind::Wof(_) => remove_wof_compression(path),
    }
}

/// Creates (or truncates) a file and disables compression **before** any data
/// is written – costs < 1 ms and protects your own tools against a compressed
/// target folder.
///
/// ```no_run
/// use std::io::Write;
/// let mut f = ntfs_unthrottle::create_uncompressed("D:/out/archive.bin".as_ref())?;
/// f.write_all(b"...")?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn create_uncompressed(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true) // required: FSCTL_SET_COMPRESSION checks FILE_READ_DATA
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    disable_compression(&file)?;
    Ok(file)
}

// ---------------------------------------------------------------------------
// Error messages
// ---------------------------------------------------------------------------

/// Common Windows errors with a user-friendly explanation (see [`error_hint`]).
/// Lets callers render their own (e.g. localized) messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorHint {
    /// File is opened/locked by another process (sharing/lock violation, mapped file).
    Locked,
    /// Access denied (ACL, system file, missing elevation).
    AccessDenied,
    /// Disk full.
    DiskFull,
    /// `ERROR_FILE_SYSTEM_LIMITATION`: file too fragmented.
    FileSystemLimitation,
    /// `ERROR_INVALID_PARAMETER`: NTFS rejects the change (cluster > 4 KiB, sparse conflict).
    InvalidParameter,
}

/// Classifies `err` into a well-known [`ErrorHint`]; `None` for anything else.
pub fn error_hint(err: &io::Error) -> Option<ErrorHint> {
    match os_code(err)? {
        ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION | ERROR_USER_MAPPED_FILE => Some(ErrorHint::Locked),
        ERROR_ACCESS_DENIED => Some(ErrorHint::AccessDenied),
        ERROR_DISK_FULL => Some(ErrorHint::DiskFull),
        ERROR_FILE_SYSTEM_LIMITATION => Some(ErrorHint::FileSystemLimitation),
        ERROR_INVALID_PARAMETER => Some(ErrorHint::InvalidParameter),
        _ => None,
    }
}

/// Is `path` a virtual hard disk (`.vhd`, `.vhdx`, `.avhdx`)?
pub fn is_virtual_disk(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "vhd" | "vhdx" | "avhdx"))
}

/// Translates common Windows errors into understandable hints (English).
pub fn describe_error(err: &io::Error) -> String {
    match error_hint(err) {
        Some(ErrorHint::Locked) => "file is opened/locked by another process".into(),
        Some(ErrorHint::AccessDenied) => {
            "access denied (ACL/system file – try running the terminal as administrator)".into()
        }
        Some(ErrorHint::DiskFull) => "disk full".into(),
        Some(ErrorHint::FileSystemLimitation) => {
            "NTFS limit reached: file is too fragmented (defragment it first)".into()
        }
        Some(ErrorHint::InvalidParameter) => {
            "NTFS rejects the change (invalid parameter – e.g. cluster > 4 KiB or sparse conflict)"
                .into()
        }
        None => err.to_string(),
    }
}

/// Like [`describe_error`], but adds hints matching the file
/// (e.g. for virtual hard disks `.vhd`/`.vhdx`).
pub fn describe_error_at(err: &io::Error, path: &Path) -> String {
    let base = describe_error(err);
    if !is_virtual_disk(path) {
        return base;
    }
    match error_hint(err) {
        Some(ErrorHint::Locked) => {
            format!("{base} – for .vhdx stop the VM, run `wsl --shutdown` or close Docker")
        }
        Some(ErrorHint::FileSystemLimitation) => {
            format!("{base} – for .vhdx use `Optimize-VHD` or copy the file instead")
        }
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_drive_root_detection() {
        assert!(is_system_drive_root(Path::new(r"C:\"), "C:"));
        assert!(is_system_drive_root(Path::new(r"\\?\C:\"), "c:"));
        assert!(!is_system_drive_root(Path::new(r"E:\"), "C:"));
        assert!(!is_system_drive_root(Path::new(r"\\?\E:\"), "C:"));
        assert!(!is_system_drive_root(Path::new(r"C:\Windows"), "C:"));
    }

    #[test]
    fn describe_error_at_adds_vhdx_hints() {
        let share = io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION as i32);
        let limit = io::Error::from_raw_os_error(ERROR_FILE_SYSTEM_LIMITATION as i32);
        let vhdx = Path::new(r"E:\VMs\disk.VHDX");
        assert!(describe_error_at(&share, vhdx).contains("wsl --shutdown"));
        assert!(describe_error_at(&limit, vhdx).contains("Optimize-VHD"));
        assert!(describe_error_at(&limit, vhdx).contains("defragment"));
        // Other files: unchanged
        let bin = Path::new(r"E:\Games\data.bin");
        assert_eq!(describe_error_at(&share, bin), describe_error(&share));
        assert_eq!(describe_error_at(&limit, bin), describe_error(&limit));
    }

    #[test]
    fn invalid_parameter_tolerated_only_for_new_files() {
        let e = io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32);
        // Tolerated only via disable_compression (create_uncompressed) …
        assert!(is_unsupported(&e));
        // … when decompressing it is reported – with an understandable text.
        assert!(describe_error(&e).contains("NTFS rejects"));
    }

    #[test]
    fn error_hint_classification() {
        let hint = |c: u32| error_hint(&io::Error::from_raw_os_error(c as i32));
        assert_eq!(hint(ERROR_SHARING_VIOLATION), Some(ErrorHint::Locked));
        assert_eq!(hint(ERROR_USER_MAPPED_FILE), Some(ErrorHint::Locked));
        assert_eq!(hint(ERROR_ACCESS_DENIED), Some(ErrorHint::AccessDenied));
        assert_eq!(hint(ERROR_MORE_DATA), None);
        assert_eq!(error_hint(&io::Error::other("x")), None);
        assert!(is_virtual_disk(Path::new(r"E:\a.AVHDX")));
        assert!(!is_virtual_disk(Path::new(r"E:\a.vmdk")));
    }

    #[test]
    fn file_identity_matches_for_hardlinks() {
        let dir = std::env::temp_dir().join(format!("ntfs-unthrottle-hl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.bin");
        let b = dir.join("b.bin");
        std::fs::write(&a, b"x").unwrap();
        let _ = std::fs::remove_file(&b);
        let linked = std::fs::hard_link(&a, &b).is_ok();
        let ia = file_identity_of(&open_for_query(&a).unwrap()).unwrap();
        if linked {
            let ib = file_identity_of(&open_for_query(&b).unwrap()).unwrap();
            assert_eq!(ia.key(), ib.key());
            assert_eq!(ia.links, 2);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
