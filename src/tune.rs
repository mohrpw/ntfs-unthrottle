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
use windows_sys::Win32::Storage::FileSystem::{
    GetVolumeNameForVolumeMountPointW, BusTypeAta, BusTypeFileBackedVirtual, BusTypeNvme,
    BusTypeRAID, BusTypeSas, BusTypeSata, BusTypeScsi, BusTypeSd, BusTypeSpaces, BusTypeUsb,
    BusTypeVirtual, FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Ioctl::{
    PropertyStandardQuery, StorageDeviceProperty, StorageDeviceSeekPenaltyProperty,
    StorageDeviceTrimProperty, DEVICE_SEEK_PENALTY_DESCRIPTOR, DEVICE_TRIM_DESCRIPTOR,
    FILE_FS_PERSISTENT_VOLUME_INFORMATION, FSCTL_GET_NTFS_VOLUME_DATA, FSCTL_IS_VOLUME_DIRTY,
    FSCTL_QUERY_PERSISTENT_VOLUME_STATE, IOCTL_STORAGE_QUERY_PROPERTY, NTFS_VOLUME_DATA_BUFFER,
    PERSISTENT_VOLUME_STATE_SHORT_NAME_CREATION_DISABLED, STORAGE_DEVICE_DESCRIPTOR,
    STORAGE_PROPERTY_ID, STORAGE_PROPERTY_QUERY,
};
use windows_sys::Win32::System::Registry::{RegGetValueW, HKEY_LOCAL_MACHINE, RRF_RT_REG_DWORD, RRF_RT_REG_QWORD};

use crate::{ioctl, to_wide};

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
