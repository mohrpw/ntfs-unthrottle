//! Nur-Lese-Abfragen für den Optimierer (`--optimize`): Datenträger, MFT,
//! 8.3-Kurznamen und die globalen NTFS-Schalter aus der Registry.
//!
//! Hier wird nichts verändert – Korrekturen laufen bewusst sichtbar über
//! `fsutil`, damit jeder Schritt nachvollziehbar und mit Windows-Bordmitteln
//! rückgängig zu machen ist.

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
    BusTypeVirtual, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_NO_BUFFERING, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, StorageDeviceSeekPenaltyProperty,
    StorageDeviceTrimProperty, DEVICE_SEEK_PENALTY_DESCRIPTOR, DEVICE_TRIM_DESCRIPTOR,
    FILE_FS_PERSISTENT_VOLUME_INFORMATION, FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_IS_VOLUME_DIRTY,
    FSCTL_QUERY_PERSISTENT_VOLUME_STATE, IOCTL_STORAGE_QUERY_PROPERTY, NTFS_VOLUME_DATA_BUFFER,
    FSBPIO_INFL_None, FSBPIO_INFL_SKIP_STORAGE_STACK_QUERY, FSBPIO_OUTFL_COMPATIBLE_STORAGE_DRIVER,
    FSCTL_MANAGE_BYPASS_IO, FS_BPIO_INPUT, FS_BPIO_OP_QUERY, FS_BPIO_OUTPUT, FS_BPIO_RESULTS,
    PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_PROPERTY_ID, STORAGE_PROPERTY_QUERY,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_QWORD};

use crate::{ioctl, is_unsupported, to_wide};

const VOLUME_IS_DIRTY: u32 = 0x1;

/// Anbindung und Art des Datenträgers unter einem Volume.
#[derive(Debug, Clone, Default)]
pub struct DeviceInfo {
    pub product: Option<String>,
    pub bus: Option<&'static str>,
    /// `Some(true)` = HDD (Kopfbewegung), `Some(false)` = SSD.
    pub seek_penalty: Option<bool>,
    pub trim_supported: Option<bool>,
}

/// Auszug aus `NTFS_VOLUME_DATA_BUFFER`.
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
    /// Anzahl der Datensätze, für die die MFT bereits Platz belegt.
    pub fn mft_records(&self) -> u64 {
        self.mft_valid_length / u64::from(self.bytes_per_record.max(1))
    }
}

/// `\\?\Volume{GUID}` (ohne abschließenden Backslash) – öffnet das Volume selbst.
fn volume_device(root: &Path) -> io::Result<PathBuf> {
    let mut wide = to_wide(root);
    // Die API verlangt einen abschließenden Backslash.
    if wide.len() >= 2 && wide[wide.len() - 2] != u16::from(b'\\') {
        wide.insert(wide.len() - 1, u16::from(b'\\'));
    }
    let mut buf = [0u16; 64];
    // SAFETY: Puffer gültig, Länge in Zeichen.
    if unsafe { GetVolumeNameForVolumeMountPointW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) }
        == 0
    {
        return Err(io::Error::last_os_error());
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let s = String::from_utf16_lossy(&buf[..len]);
    Ok(PathBuf::from(s.trim_end_matches('\\')))
}

/// Volume-Handle ohne Datenzugriff – reicht für Geräte-Abfragen, auch ohne Admin.
fn open_volume(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(0)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(volume_device(root)?)
}

fn open_root_dir(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(root)
}

/// Wie [`open_root_dir`], aber ungepuffert: NTFS lehnt BypassIO-Abfragen auf
/// Handles für gecachte I/O ab („Handles opened for cached IO not supported“).
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
    // SAFETY: Ein-/Ausgabepuffer gültig für die angegebenen Längen.
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
        x if x == BusTypeSd => "SD-Karte",
        x if x == BusTypeSpaces => "Speicherplätze",
        x if x == BusTypeVirtual || x == BusTypeFileBackedVirtual => "virtuell",
        _ => "unbekannt",
    }
}

/// Anbindung (NVMe/SATA/USB …), SSD/HDD und TRIM-Fähigkeit.
pub fn device_info(root: &Path) -> io::Result<DeviceInfo> {
    let vol = open_volume(root)?;
    let mut info = DeviceInfo::default();

    let mut buf = vec![0u8; 1024];
    if let Ok(n) = storage_query(&vol, StorageDeviceProperty, &mut buf) {
        if n as usize >= size_of::<STORAGE_DEVICE_DESCRIPTOR>() {
            // SAFETY: Puffer ist groß genug; read_unaligned wegen Vec<u8>.
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
        // SAFETY: Puffer hat exakt Strukturgröße.
        let d: DEVICE_SEEK_PENALTY_DESCRIPTOR = unsafe { sp.as_ptr().cast::<DEVICE_SEEK_PENALTY_DESCRIPTOR>().read_unaligned() };
        info.seek_penalty = Some(d.IncursSeekPenalty != 0);
    }

    let mut tr = [0u8; size_of::<DEVICE_TRIM_DESCRIPTOR>()];
    if storage_query(&vol, StorageDeviceTrimProperty, &mut tr).is_ok() {
        // SAFETY: Puffer hat exakt Strukturgröße.
        let d: DEVICE_TRIM_DESCRIPTOR = unsafe { tr.as_ptr().cast::<DEVICE_TRIM_DESCRIPTOR>().read_unaligned() };
        info.trim_supported = Some(d.TrimEnabled != 0);
    }
    Ok(info)
}

/// MFT-Größe, MFT-Zone, Clustergröße. Braucht meist Administratorrechte.
pub fn ntfs_data(root: &Path) -> io::Result<NtfsData> {
    let vol = open_volume(root)?;
    // SAFETY: reine POD-Struktur.
    let mut d: NTFS_VOLUME_DATA_BUFFER = unsafe { std::mem::zeroed() };
    // SAFETY: Ausgabepuffer gültig.
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

/// Ist die 8.3-Kurznamen-Erzeugung für dieses Volume abgeschaltet (Volume-Flag)?
pub fn short_names_disabled_on_volume(root: &Path) -> io::Result<bool> {
    let dir = open_root_dir(root)?;
    let input = FILE_FS_PERSISTENT_VOLUME_INFORMATION {
        VolumeFlags: 0,
        FlagMask: PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED,
        Version: 1,
        Reserved: 0,
    };
    let mut out = input;
    // SAFETY: Ein-/Ausgabe sind gültige Strukturen.
    unsafe {
        ioctl(
            &dir,
            FSCTL_QUERY_PERSISTENT_VOLUME_STATE,
            (&input as *const FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>() as u32,
            (&mut out as *mut FILE_FS_PERSISTENT_VOLUME_INFORMATION).cast(),
            size_of::<FILE_FS_PERSISTENT_VOLUME_INFORMATION>() as u32,
        )?;
    }
    Ok(out.VolumeFlags & PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED != 0)
}

/// Dirty-Bit gesetzt (chkdsk beim nächsten Start ausstehend)?
pub fn volume_dirty(root: &Path) -> io::Result<bool> {
    let vol = open_volume(root)?;
    let mut flags = 0u32;
    // SAFETY: Ausgabepuffer gültig.
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

/// DWORD/QWORD (Windows speichert manche Schalter als QWORD) aus `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`.
pub fn filesystem_reg_value(name: &str) -> Option<u64> {
    let key = to_wide(Path::new(r"SYSTEM\CurrentControlSet\Control\FileSystem"));
    let val = to_wide(Path::new(name));
    let mut data = 0u64;
    let mut len = 8u32;
    // SAFETY: Puffer gültig, Länge in Bytes.
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

// ---------------------------------------------------------------------------
// BypassIO (Windows 11, NTFS)
// ---------------------------------------------------------------------------

/// Ergebnis der BypassIO-Diagnose eines Volumes (nur `FS_BPIO_OP_QUERY`, ändert nichts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BypassIoStatus {
    /// Kein Treiber legt ein Veto ein. `storage_compatible`: Speichertreiber
    /// (z. B. `stornvme.sys`) meldet BypassIO-Fähigkeit.
    Active { storage_compatible: bool },
    /// Filter-Stack ist frei, aber Volume-/Speicher-Stack legt ein Veto ein
    /// (z. B. `fvevol.sys` bei BitLocker, nicht-NVMe-Treiber).
    Partial { driver: String, status: u32, reason: String },
    /// Ein Minifilter im Dateisystem-Filter-Stack blockiert BypassIO.
    Blocked { driver: String, status: u32, reason: String },
    /// `FSCTL_MANAGE_BYPASS_IO` wird nicht unterstützt (Windows 10, älterer Build).
    Unavailable,
}

/// UTF-16-Feld mit Längenangabe in Zeichen; nicht zwingend NUL-terminiert.
fn wide_field(buf: &[u16], len_chars: u16) -> String {
    let s = &buf[..usize::from(len_chars).min(buf.len())];
    let end = s.iter().position(|&c| c == 0).unwrap_or(s.len());
    String::from_utf16_lossy(&s[..end]).trim().to_string()
}

/// Bewertet die Ergebnisse der beiden Abfragen: `filter` (nur Filter-Stack, mit
/// `FSBPIO_INFL_SKIP_STORAGE_STACK_QUERY`) und `full` (kompletter Stack).
/// Ein Veto erkennt man an `OpStatus != 0`.
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

/// Eine `FS_BPIO_OP_QUERY`-Abfrage. `FS_BPIO_INPUT` hat keine Version-/Size-Felder –
/// die Größen laufen über die Pufferlängen von `DeviceIoControl`.
fn bpio_query(dir: &File, in_flags: i32) -> io::Result<(FS_BPIO_RESULTS, i32)> {
    let input = FS_BPIO_INPUT {
        Operation: FS_BPIO_OP_QUERY,
        InFlags: in_flags,
        Reserved1: 0,
        Reserved2: 0,
    };
    // SAFETY: reine POD-Struktur, Nullinitialisierung ist gültig.
    let mut out: FS_BPIO_OUTPUT = unsafe { std::mem::zeroed() };
    // SAFETY: Ein-/Ausgabe sind gültige Strukturen der angegebenen Größe.
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
            format!("BypassIO: unvollständige Antwort ({returned} von {need} Bytes)"),
        ));
    }
    // SAFETY: Bei FS_BPIO_OP_QUERY ist das Union-Feld `Query` belegt.
    Ok((unsafe { out.Anonymous.Query }, out.OutFlags))
}

/// BypassIO-Status eines Volumes – reine Lese-Abfrage auf dem Root-Verzeichnis
/// (`FS_BPIO_OP_QUERY` ist laut Microsoft auf Verzeichnis- und Volume-Handles erlaubt,
/// braucht keine Administratorrechte).
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
// ReFS-TRIM, fsutil-Ausgaben
// ---------------------------------------------------------------------------

/// Konsolenausgabe (OEM-Codepage, z. B. CP850) in einen String umwandeln –
/// sonst werden Umlaute aus fsutil-Meldungen zu `�`.
pub fn decode_oem(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return String::new();
    }
    let len = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    // SAFETY: Erst Länge erfragen, dann in ausreichend großen Puffer schreiben.
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

/// Wertet `fsutil behavior query DisableDeleteNotify` aus. Der Präfix
/// `ReFS DisableDeleteNotify = N` ist in allen Sprachen gleich, nur der Rest ist
/// lokalisiert. `Some(true)` = TRIM deaktiviert. „Nicht gesetzt“ → `None`.
pub fn parse_refs_ddn(out: &str) -> Option<bool> {
    let line = out
        .lines()
        .map(str::trim)
        .find(|l| l.to_ascii_lowercase().starts_with("refs disabledeletenotify"))?;
    let value = line["ReFS DisableDeleteNotify".len()..].trim_start().strip_prefix('=')?;
    let digit = value.trim_start().chars().next()?.to_digit(10)?;
    Some(digit != 0)
}

/// Ist TRIM für ReFS (Dev Drives) global abgeschaltet? Zuerst die Registry
/// (`RefsDisableDeleteNotification`), fehlt der Wert, `fsutil` (nur Lesen).
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
        // SAFETY: reine POD-Struktur.
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
            panic!("erwartet Blocked");
        };
        assert_eq!(driver, "wof.sys");
    }

    #[test]
    fn wide_field_is_bounded_and_not_nul_dependent() {
        let r = results(VETO, "abc.sys", "");
        // Länge kürzer als Inhalt → nur so viele Zeichen
        assert_eq!(wide_field(&r.FailingDriverName, 3), "abc");
        // Länge größer als Puffer → gekappt, abschließende NULs ignoriert
        assert_eq!(wide_field(&r.FailingDriverName, 999), "abc.sys");
        // Voller Puffer ohne NUL
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
}
