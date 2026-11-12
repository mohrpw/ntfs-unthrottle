//! Read-only queries for the optimizer (`--optimize`): storage device, MFT,
//! 8.3 short names and the global NTFS switches from the registry.
//!
//! Nothing is modified here – fixes intentionally run visibly via `fsutil`,
//! so every step is traceable and can be reverted with built-in Windows tools.

use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io;
use std::mem::size_of;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::ERROR_SUCCESS;
use windows_sys::Win32::Globalization::{MultiByteToWideChar, CP_OEMCP};
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeNameForVolumeMountPointW, BusTypeAta, BusTypeFileBackedVirtual, BusTypeNvme,
    BusTypeRAID, BusTypeSas, BusTypeSata, BusTypeScsi, BusTypeSd, BusTypeSpaces, BusTypeUsb,
    BusTypeVirtual, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_NO_BUFFERING, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, StorageDeviceSeekPenaltyProperty,
    StorageDeviceTrimProperty, DEVICE_SEEK_PENALTY_DESCRIPTOR, DEVICE_TRIM_DESCRIPTOR,
    FILE_FS_PERSISTENT_VOLUME_INFORMATION, FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_IS_VOLUME_DIRTY,
    FSCTL_QUERY_PERSISTENT_VOLUME_STATE, IOCTL_STORAGE_QUERY_PROPERTY, NTFS_VOLUME_DATA_BUFFER,
    FSBPIO_INFL_None, FSBPIO_INFL_SKIP_STORAGE_STACK_QUERY, FSBPIO_OUTFL_COMPATIBLE_STORAGE_DRIVER,
    FSCTL_MANAGE_BYPASS_IO, FS_BPIO_INPUT, FS_BPIO_OP_QUERY, FS_BPIO_OUTPUT, FS_BPIO_RESULTS,
    PERSISTENT_VOLUME_STATE_DEV_VOLUME, PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
    PERSISTENT_VOLUME_STATE_TRUSTED_VOLUME, STORAGE_DEVICE_DESCRIPTOR, STORAGE_PROPERTY_ID,
    STORAGE_PROPERTY_QUERY,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_QWORD};

use crate::{file_attributes, ioctl, is_unsupported, to_wide};

const VOLUME_IS_DIRTY: u32 = 0x1;

/// Bus type and kind of the storage device below a volume.
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub product: Option<String>,
    pub bus: Option<&'static str>,
    /// `Some(true)` = HDD (head movement), `Some(false)` = SSD.
    pub seek_penalty: Option<bool>,
    pub trim_supported: Option<bool>,
}

/// Excerpt from `NTFS_VOLUME_DATA_BUFFER`.
#[derive(Debug, Clone, Copy)]
pub struct NtfsData {
    pub bytes_per_cluster: u32,
    pub bytes_per_record: u32,
    pub mft_valid_length: u64,
    pub mft_zone_bytes: u64,
    pub total_bytes: u64,
    pub free_bytes: u64,
}

impl NtfsData {
    /// Number of records the MFT already occupies space for.
    pub fn mft_records(&self) -> u64 {
        self.mft_valid_length / u64::from(self.bytes_per_record.max(1))
    }
}

/// `\\?\Volume{GUID}` (without trailing backslash) – opens the volume itself.
fn volume_device(root: &Path) -> io::Result<PathBuf> {
    let mut wide = to_wide(root);
    // The API requires a trailing backslash.
    if wide.len() >= 2 && wide[wide.len() - 2] != u16::from(b'\\') {
        wide.insert(wide.len() - 1, u16::from(b'\\'));
    }
    let mut buf = [0u16; 64];
    // SAFETY: valid buffer, length in characters.
    if unsafe { GetVolumeNameForVolumeMountPointW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..len]);
    Ok(PathBuf::from(s.trim_end_matches('\\')))
}

/// Volume handle without data access – sufficient for device queries, even without admin.
fn open_volume(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(volume_device(root)?)
}

fn open_root_dir_meta(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
}

fn open_root_dir(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
}

/// Like [`open_root_dir`], but unbuffered: NTFS rejects BypassIO queries on
/// handles for cached I/O ("Handles opened for cached IO not supported").
fn open_root_dir_uncached(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_NO_BUFFERING)
        .open(root)
}

fn storage_query(vol: &File, id: STORAGE_PROPERTY_ID, out: &mut [u8]) -> io::Result<u32> {
    let query = STORAGE_PROPERTY_QUERY {
        PropertyId: id,
        QueryType: PropertyStandardQuery,
        AdditionalParameters: [0],
    };
    // SAFETY: input/output buffers are valid for the given lengths.
    unsafe {
        ioctl(
            vol,
            IOCTL_STORAGE_QUERY_PROPERTY,
            (&query as *const STORAGE_PROPERTY_QUERY).cast(),
            size_of::<STORAGE_PROPERTY_QUERY>() as u32,
            out.as_mut_ptr().cast(),
            out.len() as u32,
        )
    }
}

fn bus_name(bus: i32) -> &'static str {
    match bus {
        x if x == BusTypeNvme => "NVMe",
        x if x == BusTypeSata => "SATA",
        x if x == BusTypeAta => "ATA",
        x if x == BusTypeUsb => "USB",
        x if x == BusTypeSas => "SAS",
        x if x == BusTypeScsi => "SCSI",
        x if x == BusTypeRAID => "RAID",
        x if x == BusTypeSd => "SD card",
        x if x == BusTypeSpaces => "Storage Spaces",
        x if x == BusTypeVirtual || x == BusTypeFileBackedVirtual => "virtual",
        _ => "unknown",
    }
}

/// Bus type (NVMe/SATA/USB …), SSD/HDD and TRIM capability.
///
/// `bus` is a stable English identifier (`NVMe`, `SATA`, `USB`, `SD card`,
/// `Storage Spaces`, `virtual`, `unknown`, …) suitable for comparisons.
pub fn device_info(root: &Path) -> io::Result<DeviceInfo> {
    let vol = open_volume(root)?;
    let mut info = DeviceInfo::default();

    let mut buf = vec![0u8; 1024];
    if let Ok(n) = storage_query(&vol, StorageDeviceProperty, &mut buf) {
        if n as usize >= size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            // SAFETY: the buffer is large enough; read_unaligned because of Vec<u8>.
            let d: STORAGE_DEVICE_DESCRIPTOR = unsafe { buf.as_ptr().cast::<STORAGE_DEVICE_DESCRIPTOR>().read_unaligned() };
            info.bus = Some(bus_name(d.BusType));
            let cstr = |off: u32| -> Option<String> {
                let off = off as usize;
                if off == 0 || off >= n as usize {
                    return None;
                }
                let end = buf[off..n as usize].iter().position(|&b| b == 0)? + off;
                let s = String::from_utf8_lossy(&buf[off..end]).trim().to_string();
                (!s.is_empty()).then_some(s)
            };
            info.product = match (cstr(d.VendorIdOffset), cstr(d.ProductIdOffset)) {
                (Some(v), Some(p)) => Some(format!("{v} {p}")),
                (v, p) => p.or(v),
            };
        }
    }

    let mut sp = [0u8; size_of::<DEVICE_SEEK_PENALTY_DESCRIPTOR>()];
    if storage_query(&vol, StorageDeviceSeekPenaltyProperty, &mut sp).is_ok() {
        // SAFETY: the buffer has exactly the struct size.
        let d: DEVICE_SEEK_PENALTY_DESCRIPTOR = unsafe { sp.as_ptr().cast::<DEVICE_SEEK_PENALTY_DESCRIPTOR>().read_unaligned() };
        info.seek_penalty = Some(d.IncursSeekPenalty != 0);
    }

    let mut tr = [0u8; size_of::<DEVICE_TRIM_DESCRIPTOR>()];
    if storage_query(&vol, StorageDeviceTrimProperty, &mut tr).is_ok() {
        // SAFETY: the buffer has exactly the struct size.
        let d: DEVICE_TRIM_DESCRIPTOR = unsafe { tr.as_ptr().cast::<DEVICE_TRIM_DESCRIPTOR>().read_unaligned() };
        info.trim_supported = Some(d.TrimEnabled != 0);
    }
    Ok(info)
}

/// MFT size, MFT zone, cluster size. Usually requires administrator rights.
pub fn ntfs_data(root: &Path) -> io::Result<NtfsData> {
    let vol = open_volume(root)?;
    // SAFETY: plain POD struct.
    let mut d: NTFS_VOLUME_DATA_BUFFER = unsafe { std::mem::zeroed() };
    // SAFETY: valid output buffer.
    unsafe {
        ioctl(
            &vol,
            FSCTL_GET_NTFS_VOLUME_DATA,
            std::ptr::null(),
            0,
            (&mut d as *mut NTFS_VOLUME_DATA_BUFFER).cast::<c_void>(),
            size_of::<NTFS_VOLUME_DATA_BUFFER>() as u32,
        )?;
    }
    let cluster = u64::from(d.BytesPerCluster);
    Ok(NtfsData {
        bytes_per_cluster: d.BytesPerCluster,
        bytes_per_record: d.BytesPerFileRecordSegment,
        mft_valid_length: d.MftValidDataLength as u64,
        mft_zone_bytes: (d.MftZoneEnd - d.MftZoneStart).max(0) as u64 * cluster,
        total_bytes: d.TotalClusters as u64 * cluster,
        free_bytes: d.FreeClusters as u64 * cluster,
    })
}

fn query_persistent_volume_state(handle: &File, mask: u32) -> io::Result<u32> {
    let input = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
        VolumeFlags: 0,
        FlagMask: mask,
        Version: 1,
        Reserved: 0,
    };
    let mut out = input;
    // SAFETY: input/output are valid structs.
    unsafe {
        ioctl(
            handle,
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
            (&input as *const FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>() as u32,
            (&mut out as *mut FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>() as u32,
        )?;
    }
    Ok(out.VolumeFlags)
}

/// Is 8.3 short name creation disabled for this volume (volume flag)?
pub fn short_names_disabled_on_volume(root: &Path) -> io::Result<bool> {
    let dir = open_root_dir(root)?;
    let flags = query_persistent_volume_state(&dir, PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED)?;
    Ok(flags & PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED != 0)
}

/// Windows 11 Dev Drive status of a volume (via `FSCTL_QUERY_PERSISTENT_VOLUME_STATE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DevDriveInfo {
    pub is_dev_drive: bool,
    /// `true` if the Dev Drive is marked trusted (Defender asynchronous performance mode).
    pub is_trusted: bool,
}

/// Decodes `PERSISTENT_VOLUME_STATE_*` flags into [`DevDriveInfo`].
pub fn classify_dev_drive(flags: u32) -> DevDriveInfo {
    DevDriveInfo {
        is_dev_drive: flags & PERSISTENT_VOLUME_STATE_DEV_VOLUME != 0,
        is_trusted: flags & PERSISTENT_VOLUME_STATE_TRUSTED_VOLUME != 0,
    }
}

/// Queries whether `root` is a Windows 11 Dev Drive and whether it is trusted.
/// Opens the volume/root handle with `DesiredAccess = 0` so non-admin callers
/// succeed wherever the file system driver permits metadata-only queries.
pub fn dev_drive_info(root: &Path) -> io::Result<DevDriveInfo> {
    let handle = open_volume(root).or_else(|_| open_root_dir_meta(root))?;
    let mask = PERSISTENT_VOLUME_STATE_DEV_VOLUME | PERSISTENT_VOLUME_STATE_TRUSTED_VOLUME;
    let flags = query_persistent_volume_state(&handle, mask)?;
    Ok(classify_dev_drive(flags))
}

/// Is the dirty bit set (chkdsk pending at next boot)?
pub fn volume_dirty(root: &Path) -> io::Result<bool> {
    let vol = open_volume(root)?;
    let mut flags = 0u32;
    // SAFETY: valid output buffer.
    unsafe {
        ioctl(
            &vol,
            FSCTL_IS_VOLUME_DIRTY,
            std::ptr::null(),
            0,
            (&mut flags as *mut u32).cast(),
            4,
        )?;
    }
    Ok(flags & VOLUME_IS_DIRTY != 0)
}

/// DWORD/QWORD value from `HKLM\<subkey>`.
fn reg_u64(subkey: &str, name: &str) -> Option<u64> {
    let key = to_wide(Path::new(subkey));
    let val = to_wide(Path::new(name));
    let mut data = 0u64;
    let mut len = 8u32;
    // SAFETY: valid buffer, length in bytes.
    let rc = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            val.as_ptr(),
            RRF_RT_REG_DWORD | RRF_RT_REG_QWORD,
            null_mut(),
            (&mut data as *mut u64).cast(),
            &mut len,
        )
    };
    (rc == ERROR_SUCCESS).then_some(data)
}

/// DWORD/QWORD (Windows stores some switches as QWORD) from `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`.
pub fn filesystem_reg_value(name: &str) -> Option<u64> {
    reg_u64(r"SYSTEM\CurrentControlSet\Control\FileSystem", name)
}

/// Read-only Windows Search Indexer state for a volume root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IndexerStatus {
    /// `Some(true)` if `FILE_ATTRIBUTE_NOT_CONTENT_INDEXED` is set on the volume root.
    pub root_not_indexed: Option<bool>,
    /// `Some(true)` if the `WSearch` service startup type is `Disabled` (`Start == 4`).
    pub service_disabled: Option<bool>,
}

/// Queries the Windows Search service startup state and root `NOT_CONTENT_INDEXED` attribute.
pub fn indexer_status(root: &Path) -> IndexerStatus {
    const SERVICE_DISABLED: u64 = 4;
    let root_not_indexed = file_attributes(root)
        .ok()
        .map(|a| a & FILE_ATTRIBUTE_NOT_CONTENT_INDEXED != 0);
    let service_disabled =
        reg_u64(r"SYSTEM\CurrentControlSet\Services\WSearch", "Start").map(|v| v == SERVICE_DISABLED);
    IndexerStatus { root_not_indexed, service_disabled }
}

// ---------------------------------------------------------------------------
// BypassIO (Windows 11, NTFS)
// ---------------------------------------------------------------------------

/// Result of the BypassIO diagnosis of a volume (only `FS_BPIO_OP_QUERY`, changes nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BypassIoStatus {
    /// No driver vetoes. `storage_compatible`: the storage driver
    /// (e.g. `stornvme.sys`) reports BypassIO support.
    Active { storage_compatible: bool },
    /// The filter stack is clear, but the volume/storage stack vetoes
    /// (e.g. `fvevol.sys` with BitLocker, non-NVMe drivers).
    Partial { driver: String, status: u32, reason: String },
    /// A minifilter in the file system filter stack blocks BypassIO.
    Blocked { driver: String, status: u32, reason: String },
    /// `FSCTL_MANAGE_BYPASS_IO` is not supported (Windows 10, older build).
    Unavailable,
}

/// UTF-16 field with a length in characters; not necessarily NUL-terminated.
fn wide_field(buf: &[u16], len_chars: u16) -> String {
    let s = &buf[..usize::from(len_chars).min(buf.len())];
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end]).trim().to_string()
}

/// Evaluates the results of both queries: `filter` (filter stack only, with
/// `FSBPIO_INFL_SKIP_STORAGE_STACK_QUERY`) and `full` (complete stack).
/// A veto is indicated by `OpStatus != 0`.
pub fn classify_bypass_io(filter: &FS_BPIO_RESULTS, full: &FS_BPIO_RESULTS, full_out_flags: i32) -> BypassIoStatus {
    let details = |r: &FS_BPIO_RESULTS| {
        (
            wide_field(&r.FailingDriverName, r.FailingDriverNameLen),
            r.OpStatus,
            wide_field(&r.FailureReason, r.FailureReasonLen),
        )
    };
    if filter.OpStatus != 0 {
        let (driver, status, reason) = details(filter);
        BypassIoStatus::Blocked { driver, status, reason }
    } else if full.OpStatus != 0 {
        let (driver, status, reason) = details(full);
        BypassIoStatus::Partial { driver, status, reason }
    } else {
        BypassIoStatus::Active {
            storage_compatible: full_out_flags & FSBPIO_OUTFL_COMPATIBLE_STORAGE_DRIVER != 0,
        }
    }
}

/// A single `FS_BPIO_OP_QUERY` query. `FS_BPIO_INPUT` has no version/size fields –
/// sizes are conveyed via the buffer lengths of `DeviceIoControl`.
fn bpio_query(dir: &File, in_flags: i32) -> io::Result<(FS_BPIO_RESULTS, i32)> {
    let input = FS_BPIO_INPUT {
        Operation: FS_BPIO_OP_QUERY,
        InFlags: in_flags,
        Reserved1: 0,
        Reserved2: 0,
    };
    // SAFETY: plain POD struct, zero initialization is valid.
    let mut out: FS_BPIO_OUTPUT = unsafe { std::mem::zeroed() };
    // SAFETY: input/output are valid structs of the given size.
    let returned = unsafe {
        ioctl(
            dir,
            FSCTL_MANAGE_BYPASS_IO,
            (&input as *const FS_BPIO_INPUT).cast(),
            size_of::<FS_BPIO_INPUT>() as u32,
            (&mut out as *mut FS_BPIO_OUTPUT).cast(),
            size_of::<FS_BPIO_OUTPUT>() as u32,
        )?
    };
    let need = std::mem::offset_of!(FS_BPIO_OUTPUT, Anonymous) + size_of::<FS_BPIO_RESULTS>();
    if (returned as usize) < need {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("BypassIO: incomplete response ({returned} of {need} bytes)"),
        ));
    }
    // SAFETY: for FS_BPIO_OP_QUERY the union field `Query` is populated.
    Ok((unsafe { out.Anonymous.Query }, out.OutFlags))
}

/// BypassIO status of a volume – read-only query on the root directory
/// (per Microsoft, `FS_BPIO_OP_QUERY` is allowed on directory and volume handles
/// and needs no administrator rights).
pub fn bypass_io_status(root: &Path) -> io::Result<BypassIoStatus> {
    let dir = open_root_dir_uncached(root)?;
    let filter = match bpio_query(&dir, FSBPIO_INFL_SKIP_STORAGE_STACK_QUERY) {
        Ok((r, _)) => r,
        Err(e) if is_unsupported(&e) => return Ok(BypassIoStatus::Unavailable),
        Err(e) => return Err(e),
    };
    let (full, flags) = bpio_query(&dir, FSBPIO_INFL_None)?;
    Ok(classify_bypass_io(&filter, &full, flags))
}

// ---------------------------------------------------------------------------
// ReFS TRIM, fsutil output
// ---------------------------------------------------------------------------

/// Converts console output (OEM code page, e.g. CP850) into a string –
/// otherwise non-ASCII characters in fsutil messages become `�`.
pub fn decode_oem(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let len = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    // SAFETY: first query the length, then write into a sufficiently large buffer.
    let n = unsafe { MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, null_mut(), 0) };
    if n <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    let mut wide = vec![0u16; n as usize];
    let n = unsafe { MultiByteToWideChar(CP_OEMCP, 0, bytes.as_ptr(), len, wide.as_mut_ptr(), n) };
    if n <= 0 {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    String::from_utf16_lossy(&wide[..n as usize])
}

/// Parses `fsutil behavior query DisableDeleteNotify`. The prefix
/// `ReFS DisableDeleteNotify = N` is identical in all Windows languages, only the
/// rest is localized. `Some(true)` = TRIM disabled. "Not set" → `None`.
pub fn parse_refs_ddn(out: &str) -> Option<bool> {
    let line = out
        .lines()
        .map(str::trim)
        .find(|l| l.to_ascii_lowercase().starts_with("refs disabledeletenotify"))?;
    let value = line["ReFS DisableDeleteNotify".len()..].trim_start().strip_prefix('=')?;
    let digit = value.trim_start().chars().next()?.to_digit(10)?;
    Some(digit != 0)
}

/// Is TRIM globally disabled for ReFS (Dev Drives)? Checks the registry first
/// (`RefsDisableDeleteNotification`); if the value is missing, `fsutil` (read-only).
pub fn refs_trim_disabled() -> Option<bool> {
    if let Some(v) = filesystem_reg_value("RefsDisableDeleteNotification") {
        return Some(v != 0);
    }
    let out = std::process::Command::new("fsutil")
        .args(["behavior", "query", "DisableDeleteNotify", "ReFS"])
        .output()
        .ok()?;
    parse_refs_ddn(&decode_oem(&out.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn results(status: u32, driver: &str, reason: &str) -> FS_BPIO_RESULTS {
        // SAFETY: plain POD struct.
        let mut r: FS_BPIO_RESULTS = unsafe { std::mem::zeroed() };
        r.OpStatus = status;
        for (i, c) in driver.encode_utf16().enumerate() {
            r.FailingDriverName[i] = c;
        }
        r.FailingDriverNameLen = driver.encode_utf16().count() as u16;
        for (i, c) in reason.encode_utf16().enumerate() {
            r.FailureReason[i] = c;
        }
        r.FailureReasonLen = reason.encode_utf16().count() as u16;
        r
    }

    const VETO: u32 = 0xC000_00BB; // STATUS_NOT_SUPPORTED

    #[test]
    fn bypass_io_active() {
        let ok = results(0, "", "");
        assert_eq!(
            classify_bypass_io(&ok, &ok, FSBPIO_OUTFL_COMPATIBLE_STORAGE_DRIVER),
            BypassIoStatus::Active { storage_compatible: true }
        );
        assert_eq!(classify_bypass_io(&ok, &ok, 0), BypassIoStatus::Active { storage_compatible: false });
    }

    #[test]
    fn bypass_io_partial_volume_stack() {
        let ok = results(0, "", "");
        let bl = results(VETO, "fvevol.sys", "BitLocker Drive Encryption is enabled.");
        assert_eq!(
            classify_bypass_io(&ok, &bl, 0),
            BypassIoStatus::Partial {
                driver: "fvevol.sys".into(),
                status: VETO,
                reason: "BitLocker Drive Encryption is enabled.".into()
            }
        );
    }

    #[test]
    fn bypass_io_blocked_by_filter_wins() {
        let wof = results(VETO, "wof.sys", "The specified minifilter does not support bypass IO.");
        let BypassIoStatus::Blocked { driver, .. } = classify_bypass_io(&wof, &wof, 0) else {
            panic!("expected Blocked");
        };
        assert_eq!(driver, "wof.sys");
    }

    #[test]
    fn wide_field_is_bounded_and_not_nul_dependent() {
        let r = results(VETO, "abc.sys", "");
        // Length shorter than content → only that many characters
        assert_eq!(wide_field(&r.FailingDriverName, 3), "abc");
        // Length larger than buffer → capped, trailing NULs ignored
        assert_eq!(wide_field(&r.FailingDriverName, 999), "abc.sys");
        // Full buffer without NUL
        let full = [u16::from(b'x'); 32];
        assert_eq!(wide_field(&full, 32).len(), 32);
    }

    #[test]
    fn refs_ddn_parsing() {
        let de = "NTFS DisableDeleteNotify = 0  (TRIM-Vorgänge dürfen gesendet werden)\r\n\
                  ReFS DisableDeleteNotify = 1  (TRIM-Vorgänge sind deaktiviert)\r\n";
        assert_eq!(parse_refs_ddn(de), Some(true));
        let en = "ReFS DisableDeleteNotify = 0  (Allows TRIM operations to be sent to the storage device)";
        assert_eq!(parse_refs_ddn(en), Some(false));
        assert_eq!(parse_refs_ddn("ReFS DisableDeleteNotify is not currently set"), None);
        assert_eq!(parse_refs_ddn("NTFS DisableDeleteNotify = 1"), None);
        assert_eq!(parse_refs_ddn(""), None);
    }

    #[test]
    fn decode_oem_ascii_roundtrip() {
        assert_eq!(decode_oem(b""), "");
        assert_eq!(decode_oem(b"ReFS DisableDeleteNotify = 0"), "ReFS DisableDeleteNotify = 0");
    }

    #[test]
    fn classify_dev_drive_flags() {
        assert_eq!(classify_dev_drive(0), DevDriveInfo { is_dev_drive: false, is_trusted: false });
        assert_eq!(
            classify_dev_drive(PERSISTENT_VOLUME_STATE_DEV_VOLUME),
            DevDriveInfo { is_dev_drive: true, is_trusted: false }
        );
        assert_eq!(
            classify_dev_drive(PERSISTENT_VOLUME_STATE_DEV_VOLUME | PERSISTENT_VOLUME_STATE_TRUSTED_VOLUME),
            DevDriveInfo { is_dev_drive: true, is_trusted: true }
        );
    }

    #[test]
    fn dev_drive_and_indexer_probes_do_not_panic() {
        let sys = PathBuf::from(format!("{}\\", std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into())));
        // On NTFS/ReFS volumes this should either return Ok(...) or an OS error (e.g. unsupported/access denied).
        let _ = dev_drive_info(&sys);
        let idx = indexer_status(&sys);
        assert!(idx.root_not_indexed.is_some());
    }
}
