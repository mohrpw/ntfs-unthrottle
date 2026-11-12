//! Windows implementation (re-exported from the crate root).

use std::ffi::c_void;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
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
    BY_HANDLE_FILE_INFORMATION, COMPRESSION_FORMAT_NONE, FILE_ALLOCATION_INFO,
    FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_READONLY,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_PROVIDER_COMPRESSION_LZX, FILE_PROVIDER_COMPRESSION_XPRESS16K,
    FILE_PROVIDER_COMPRESSION_XPRESS4K, FILE_PROVIDER_COMPRESSION_XPRESS8K, FILE_READ_ATTRIBUTES,
    FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_WRITE_DATA,
    FileAllocationInfo, GetCompressedFileSizeW, GetDiskFreeSpaceExW, GetFileAttributesW,
    GetFileInformationByHandle, GetVolumeInformationW, GetVolumePathNameW,
    INVALID_FILE_ATTRIBUTES, SetFileAttributesW, SetFileInformationByHandle, WOF_PROVIDER_FILE,
};
use windows_sys::Win32::System::Ioctl::{
    FILE_PROVIDER_EXTERNAL_INFO_V1, FSCTL_DELETE_EXTERNAL_BACKING, FSCTL_GET_EXTERNAL_BACKING,
    FSCTL_GET_RETRIEVAL_POINTERS, FSCTL_SET_COMPRESSION, WOF_EXTERNAL_INFO,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::{display_path, is_virtual_disk, CompressionKind, WofAlgorithm};

/// `FILE_FILE_COMPRESSION` from winnt.h (avoids the SystemServices feature).
const FILE_FILE_COMPRESSION: u32 = 0x0000_0010;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

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

fn raw_handle(file: &File) -> HANDLE {
    file.as_raw_handle() as HANDLE
}

/// Thin wrapper around `DeviceIoControl`; returns the number of bytes returned.
///
/// # Safety
/// `input`/`output` must be valid for the given lengths.
pub(crate) unsafe fn ioctl(
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
pub(crate) fn is_unsupported(err: &io::Error) -> bool {
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
        // Never follow directory symlinks/junctions onto external targets.
        opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT);
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

fn by_handle_file_info(file: &File) -> io::Result<BY_HANDLE_FILE_INFORMATION> {
    // SAFETY: plain POD struct, zero initialization is valid.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: valid handle, pointer to a sufficiently large struct.
    if unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(info)
}

/// Volume serial number, file index and link count of an open handle.
pub fn file_identity_of(file: &File) -> io::Result<FileIdentity> {
    let info = by_handle_file_info(file)?;
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        links: info.nNumberOfLinks,
    })
}

/// File attributes of an already open handle (`GetFileInformationByHandle`).
pub fn file_attributes_of(file: &File) -> io::Result<u32> {
    Ok(by_handle_file_info(file)?.dwFileAttributes)
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

fn clear_compression_and_verify(file: &File) -> io::Result<()> {
    set_compression_none(file)?;
    if file_attributes_of(file)? & FILE_ATTRIBUTE_COMPRESSED != 0 {
        return Err(io::Error::other(
            "compression still active after FSCTL_SET_COMPRESSION",
        ));
    }
    Ok(())
}

/// Removes the NTFS compression of a file or the inheritance flag of a folder.
///
/// Unlike [`disable_compression`], nothing is swallowed here: the item verifiably
/// carries `FILE_ATTRIBUTE_COMPRESSED`, so every error is real (e.g. a sparse
/// conflict). Afterwards it verifies that the attribute is really gone.
pub fn remove_ntfs_compression(path: &Path, is_dir: bool) -> io::Result<()> {
    let _ro = if is_dir { None } else { Some(ReadonlyGuard::clear(path)?) };
    let file = open_for_modify(path, is_dir)?;
    if is_dir && file_attributes_of(&file)? & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "refusing to modify reparse point directory",
        ));
    }
    clear_compression_and_verify(&file)
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

pub(crate) fn open_uncompressed_with(opts: &OpenOptions, path: &Path) -> io::Result<File> {
    let file = match opts.clone().read(true).open(path) {
        Ok(f) => f,
        // Without FILE_READ_DATA the FSCTL cannot succeed: just open/create with caller options.
        Err(e) if os_code(&e) == Some(ERROR_ACCESS_DENIED) => return opts.open(path),
        Err(e) => return Err(e),
    };
    if has_compressed_attr(&file) {
        // Best-effort, see create_uncompressed / UncompressedOpenOptions.
        let _ = disable_compression(&file);
    }
    Ok(file)
}

/// Reserves contiguous disk clusters for `file` (`SetFileInformationByHandle`
/// with `FileAllocationInfo`) without changing the logical file size (`EOF`).
///
/// Works on both NTFS and ReFS (Dev Drive). Unlike `set_len`, interrupted
/// sequential writes do not leave a fake zero-padded file of `size` bytes, and
/// existing files that are already `>= size` (e.g. opened with `.append(true)`)
/// are never truncated. `size == 0` is a no-op.
pub fn preallocate(file: &File, size: u64) -> io::Result<()> {
    if size == 0 {
        return Ok(());
    }
    let alloc = i64::try_from(size)
        .map_err(|_| io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32))?;
    if file.metadata()?.len() >= size {
        return Ok(());
    }
    let info = FILE_ALLOCATION_INFO { AllocationSize: alloc };
    // SAFETY: `file` is a valid handle and `info` is a plain POD struct matching FileAllocationInfo.
    let ok = unsafe {
        SetFileInformationByHandle(
            raw_handle(file),
            FileAllocationInfo,
            (&info as *const FILE_ALLOCATION_INFO).cast(),
            std::mem::size_of::<FILE_ALLOCATION_INFO>() as u32,
        )
    };
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Creates (or truncates) a file and disables NTFS compression **before** any
/// data is written – protects your own tools against a compressed target folder.
///
/// - **Zero overhead on normal folders:** the compression attribute is read from
///   the already open handle; `FSCTL_SET_COMPRESSION` is only issued if the new
///   file actually inherited `FILE_ATTRIBUTE_COMPRESSED`.
/// - **Best-effort:** if disabling the compression fails (e.g. a file system
///   filter rejects the FSCTL), the error is ignored and the file is still
///   returned. Only errors while opening/creating the file are reported. Use
///   [`disable_compression`] on the handle if you need to see that error.
/// - The handle is opened with read **and** write access (the FSCTL requires
///   `FILE_READ_DATA`). If read access is denied, the file is created
///   write-only instead and **no** attempt is made to disable compression.
///
/// ```no_run
/// use std::io::Write;
/// let mut f = ntfs_unthrottle::create_uncompressed("D:/out/archive.bin")?;
/// f.write_all(b"...")?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn create_uncompressed<P: AsRef<Path>>(path: P) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    open_uncompressed_with(&opts, path.as_ref())
}

/// Does the open file carry `FILE_ATTRIBUTE_COMPRESSED`? Unknown → `true`,
/// so that the guard is attempted when in doubt.
fn has_compressed_attr(file: &File) -> bool {
    file.metadata()
        .map(|m| m.file_attributes() & FILE_ATTRIBUTE_COMPRESSED != 0)
        .unwrap_or(true)
}

/// Clears the compression flag of a folder if it is set, so that files and
/// subfolders created there afterwards are no longer compressed. Existing
/// files inside are not touched. Returns `Ok(true)` if the flag was cleared,
/// `Ok(false)` if it was not set (or if `dir` is a symlink/junction/reparse point).
pub fn clear_dir_compression<P: AsRef<Path>>(dir: P) -> io::Result<bool> {
    let dir = dir.as_ref();
    let pre = file_attributes(dir)?;
    if pre & FILE_ATTRIBUTE_REPARSE_POINT != 0 || pre & FILE_ATTRIBUTE_COMPRESSED == 0 {
        return Ok(false);
    }
    // Re-check directly on the handle opened with FILE_FLAG_OPEN_REPARSE_POINT
    // so a concurrent swap to a junction/symlink cannot affect an external target.
    let file = open_for_modify(dir, true)?;
    let attrs = file_attributes_of(&file)?;
    if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 || attrs & FILE_ATTRIBUTE_COMPRESSED == 0 {
        return Ok(false);
    }
    clear_compression_and_verify(&file)?;
    Ok(true)
}

/// Like [`std::fs::create_dir_all`], but keeps the created folders free of an
/// inherited compression flag.
///
/// - Every folder created by this call and the target folder `path` itself
///   (even if it already existed) get their compression flag cleared.
/// - Already existing folders **above** `path` are left untouched, as is a
///   volume root (e.g. `E:\`) passed as `path`.
/// - Clearing the flag is **best-effort** (like [`create_uncompressed`]): only
///   errors while creating folders are reported.
pub fn create_dir_all_uncompressed<P: AsRef<Path>>(path: P) -> io::Result<()> {
    let path = path.as_ref();
    if path.as_os_str().is_empty() {
        // Same error as std.
        return fs::create_dir_all(path);
    }
    // Missing folders, deepest first. `symlink_metadata` instead of `exists`: on
    // permission/I/O errors or dangling junctions an existing entry must not be treated as new.
    let missing: Vec<&Path> = path
        .ancestors()
        .take_while(|p| {
            !p.as_os_str().is_empty()
                && matches!(fs::symlink_metadata(p), Err(e) if e.kind() == io::ErrorKind::NotFound)
        })
        .collect();
    for dir in missing.iter().rev() {
        match fs::create_dir(dir) {
            Ok(()) => {
                // After the first created folder is cleared, deeper ones no longer
                // inherit the flag – the attribute check makes this nearly free.
                let _ = clear_dir_compression(dir);
            }
            // Created concurrently by someone else: not ours, leave it alone.
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists && dir.is_dir() => {}
            Err(e) => return Err(e),
        }
    }
    // Always also the target itself – even if it already existed.
    // (`parent()` is `None` only for volume roots such as `E:\` or `\\srv\share\`.)
    if path.parent().is_some() {
        let _ = clear_dir_compression(path);
    }
    Ok(())
}

/// Kind of compression of a file or folder (`None` = uncompressed).
/// For folders, [`CompressionKind::Lznt1`] means the inheritance flag is set.
/// Symlinks are followed.
pub fn compression_kind<P: AsRef<Path>>(path: P) -> io::Result<Option<CompressionKind>> {
    compression_kind_of(&open_for_query(path.as_ref())?)
}

/// Like [`compression_kind`], but on an already opened handle
/// (needs `FILE_READ_ATTRIBUTES`, e.g. from [`open_for_query`]).
pub fn compression_kind_of(file: &File) -> io::Result<Option<CompressionKind>> {
    let attrs = file.metadata()?.file_attributes();
    if attrs & FILE_ATTRIBUTE_COMPRESSED != 0 {
        return Ok(Some(CompressionKind::Lznt1));
    }
    if attrs & FILE_ATTRIBUTE_DIRECTORY != 0 {
        return Ok(None);
    }
    Ok(wof_algorithm_of(file)?.map(CompressionKind::Wof))
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

    /// Fresh temp folder for a test; removed again by `Drop`.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir()
                .join(format!("ntfs-unthrottle-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn is_compressed(path: &Path) -> bool {
        file_attributes(path).unwrap() & FILE_ATTRIBUTE_COMPRESSED != 0
    }

    /// Temp folder with the compression flag set, or `None` if the temp volume
    /// does not support NTFS compression (test is skipped then).
    fn compressed_temp_dir(tag: &str) -> Option<TempDir> {
        use windows_sys::Win32::Storage::FileSystem::COMPRESSION_FORMAT_DEFAULT;
        let dir = TempDir::new(tag);
        if !volume_info(&dir.0).ok()?.supports_compression {
            return None;
        }
        let format: u16 = COMPRESSION_FORMAT_DEFAULT;
        let handle = open_for_modify(&dir.0, true).ok()?;
        // SAFETY: input buffer is valid for the given length.
        unsafe {
            ioctl(
                &handle,
                FSCTL_SET_COMPRESSION,
                &format as *const u16 as *const c_void,
                std::mem::size_of::<u16>() as u32,
                null_mut(),
                0,
            )
        }
        .ok()?;
        is_compressed(&dir.0).then_some(dir)
    }

    #[test]
    fn create_uncompressed_accepts_path_like_args() {
        let dir = TempDir::new("args");
        let s = dir.0.join("a.bin").to_string_lossy().into_owned();
        create_uncompressed(s.as_str()).unwrap();
        create_uncompressed(&s).unwrap();
        create_uncompressed(dir.0.join("b.bin")).unwrap();
        create_uncompressed(dir.0.join("c.bin").as_path()).unwrap();
        // Normal folder: stays uncompressed, nothing to do.
        assert!(!is_compressed(&dir.0.join("b.bin")));
        assert_eq!(compression_kind(dir.0.join("b.bin")).unwrap(), None);
    }

    #[test]
    fn create_uncompressed_in_compressed_dir() {
        let Some(dir) = compressed_temp_dir("cu") else { return };
        use std::io::Write;
        let path = dir.0.join("out.bin");
        let mut f = create_uncompressed(&path).unwrap();
        f.write_all(&[0u8; 256 * 1024]).unwrap();
        drop(f);
        assert!(!is_compressed(&path));
        // Truncating an existing compressed file also clears the flag.
        let plain = dir.0.join("plain.bin");
        fs::write(&plain, b"x").unwrap();
        assert_eq!(compression_kind(&plain).unwrap(), Some(CompressionKind::Lznt1));
        create_uncompressed(&plain).unwrap();
        assert_eq!(compression_kind(&plain).unwrap(), None);
        // Folder with the flag reports LZNT1 (inheritance flag).
        assert_eq!(compression_kind(&dir.0).unwrap(), Some(CompressionKind::Lznt1));
    }

    #[test]
    fn create_dir_all_uncompressed_clears_new_dirs_only() {
        let Some(dir) = compressed_temp_dir("cda") else { return };
        let deep = dir.0.join("a").join("b").join("c");
        create_dir_all_uncompressed(&deep).unwrap();
        for p in [dir.0.join("a"), dir.0.join("a").join("b"), deep.clone()] {
            assert!(!is_compressed(&p), "{} still compressed", p.display());
        }
        assert!(is_compressed(&dir.0), "existing ancestor must not be touched");
        // Idempotent.
        create_dir_all_uncompressed(&deep).unwrap();
    }

    #[test]
    fn create_dir_all_uncompressed_clears_existing_target() {
        let Some(dir) = compressed_temp_dir("cdx") else { return };
        let target = dir.0.join("x");
        fs::create_dir(&target).unwrap();
        assert!(is_compressed(&target), "new folder should inherit the flag");
        create_dir_all_uncompressed(&target).unwrap();
        assert!(!is_compressed(&target));
        assert!(is_compressed(&dir.0));
    }

    #[test]
    fn create_dir_all_uncompressed_empty_path_behaves_like_std() {
        // std currently returns Ok(()) for "" – whatever it does, we must match it.
        let std_res = fs::create_dir_all("").map_err(|e| e.kind());
        assert_eq!(create_dir_all_uncompressed("").map_err(|e| e.kind()), std_res);
    }

    #[test]
    fn compressed_temp_dir_available() {
        // Not an assertion: documents in the test output whether the
        // compression tests above actually ran on this machine.
        let ran = compressed_temp_dir("probe").is_some();
        println!("compressed temp dir available: {ran}");
    }

    #[test]
    fn clear_dir_compression_reports_change() {
        let plain = TempDir::new("cdc");
        assert!(!clear_dir_compression(&plain.0).unwrap());
        let Some(dir) = compressed_temp_dir("cdc2") else { return };
        assert!(clear_dir_compression(&dir.0).unwrap());
        assert!(!is_compressed(&dir.0));
    }

    #[test]
    fn clear_dir_compression_does_not_follow_junctions() {
        let Some(target) = compressed_temp_dir("junc-target") else { return };
        let parent = TempDir::new("junc-parent");
        let link = parent.0.join("link");
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&link)
            .arg(&target.0)
            .output();
        let Ok(out) = status else { return };
        if !out.status.success() {
            return;
        }
        assert!(!clear_dir_compression(&link).unwrap());
        create_dir_all_uncompressed(&link).unwrap();
        // Target outside the junction path must retain its compression flag.
        assert!(is_compressed(&target.0));
        // remove_ntfs_compression must refuse a directory reparse point.
        assert!(remove_ntfs_compression(&link, true).is_err());
        assert!(is_compressed(&target.0));
        let _ = fs::remove_dir(&link);
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

    #[test]
    fn open_options_ext_supports_create_new_and_custom_flags() {
        use crate::UncompressedOpenOptions;
        use std::io::Write;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_SEQUENTIAL_SCAN;

        let Some(dir) = compressed_temp_dir("ext") else { return };
        let path = dir.0.join("unique.bin");

        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_SEQUENTIAL_SCAN)
            .open_uncompressed(&path)
            .unwrap();
        f.write_all(b"hello").unwrap();
        drop(f);
        assert!(!is_compressed(&path));

        // create_new must fail if the file already exists without overwriting it.
        let err = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open_uncompressed(&path)
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&path).unwrap(), b"hello");
    }

    #[test]
    fn preallocate_and_create_with_size_preserve_existing_data() {
        use crate::{create_uncompressed_with_size, UncompressedOpenOptions};
        use std::io::Write;

        let dir = TempDir::new("prealloc");
        let p = dir.0.join("sized.bin");
        let mut f = create_uncompressed_with_size(&p, 256 * 1024).unwrap();
        // FileAllocationInfo must NOT change logical EOF before writing.
        assert_eq!(f.metadata().unwrap().len(), 0);
        f.write_all(&[0xABu8; 8192]).unwrap();
        drop(f);
        assert_eq!(fs::metadata(&p).unwrap().len(), 8192);
        assert_eq!(compression_kind(&p).unwrap(), None);

        // Append with size < existing_len and size == 0 must NEVER truncate existing bytes.
        let mut f_small = OpenOptions::new()
            .write(true)
            .append(true)
            .open_uncompressed_with_size(&p, 1024)
            .unwrap();
        assert_eq!(f_small.metadata().unwrap().len(), 8192);
        preallocate(&f_small, 0).unwrap();
        assert_eq!(f_small.metadata().unwrap().len(), 8192);
        f_small.write_all(b"tail").unwrap();
        drop(f_small);
        let data = fs::read(&p).unwrap();
        assert_eq!(data.len(), 8192 + 4);
        assert!(data.ends_with(b"tail"));

        // Values > i64::MAX must be rejected cleanly with ERROR_INVALID_PARAMETER.
        let ro = OpenOptions::new().read(true).open(&p).unwrap();
        let err = preallocate(&ro, u64::MAX).unwrap_err();
        assert_eq!(os_code(&err), Some(ERROR_INVALID_PARAMETER));
    }

    #[test]
    fn create_uncompressed_with_size_in_compressed_dir() {
        use crate::create_uncompressed_with_size;
        use std::io::Write;

        let Some(dir) = compressed_temp_dir("cuws") else { return };
        let path = dir.0.join("pre.bin");
        let mut f = create_uncompressed_with_size(&path, 128 * 1024).unwrap();
        f.write_all(&[1u8; 128 * 1024]).unwrap();
        drop(f);
        assert!(!is_compressed(&path));
        assert_eq!(fs::metadata(&path).unwrap().len(), 128 * 1024);
    }
}
