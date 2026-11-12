//! Low-Level-Bausteine, um NTFS- (LZNT1) und WOF-Komprimierung (CompactOS) zu
//! erkennen und zu entfernen.
//!
//! Die Funktionen sind bewusst klein gehalten, damit sie sich auch direkt in
//! eigene Entpacker/Konverter einbinden lassen, siehe [`create_uncompressed`].

#[cfg(not(windows))]
compile_error!("ntfs-unthrottle unterstützt ausschließlich Windows (NTFS).");

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

/// `FILE_FILE_COMPRESSION` aus winnt.h (spart das SystemServices-Feature).
const FILE_FILE_COMPRESSION: u32 = 0x0000_0010;

// ---------------------------------------------------------------------------
// Typen
// ---------------------------------------------------------------------------

/// Algorithmus einer WOF-Komprimierung (`compact /exe:…`, CompactOS, CompactGUI).
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

/// Art der transparenten Komprimierung einer Datei.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompressionKind {
    /// Klassische NTFS-Komprimierung (`FILE_ATTRIBUTE_COMPRESSED`, blaue Pfeile).
    Lznt1,
    /// Windows Overlay Filter – ohne sichtbares Attribut.
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

/// Informationen zum Volume, auf dem ein Pfad liegt.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// Wurzel des Volumes bzw. Mount-Punkts, z. B. `C:\`.
    pub root: PathBuf,
    /// Dateisystem, z. B. `NTFS`, `ReFS`, `exFAT`.
    pub fs_name: String,
    /// Unterstützt das Dateisystem dateibasierte Komprimierung?
    pub supports_compression: bool,
    /// Für den aktuellen Benutzer verfügbarer freier Platz in Bytes.
    pub free_bytes: u64,
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------

/// Null-terminierter UTF-16-String für Win32-Aufrufe.
pub fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(std::iter::once(0)).collect()
}

/// Entfernt das `\\?\`-Präfix für die Anzeige (`\\?\UNC\srv\x` → `\\srv\x`).
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

/// Dünner Wrapper um `DeviceIoControl`; liefert die Anzahl zurückgegebener Bytes.
///
/// # Safety
/// `input`/`output` müssen für die angegebenen Längen gültig sein.
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

/// Fehler, die bedeuten: „Dateisystem/Treiber kann das nicht“ (FAT, exFAT, ReFS, kein wof.sys).
fn is_unsupported(err: &io::Error) -> bool {
    matches!(
        os_code(err),
        Some(ERROR_INVALID_FUNCTION | ERROR_NOT_SUPPORTED | ERROR_INVALID_PARAMETER)
    )
}

/// Öffnet ein Handle nur zum Abfragen von Metadaten (kein Daten-Zugriff, kein Sperren).
pub fn open_for_query(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

/// `FSCTL_SET_COMPRESSION` verlangt laut IOCTL-Definition `FILE_READ_DATA | FILE_WRITE_DATA`.
fn open_for_modify(path: &Path, is_dir: bool) -> io::Result<File> {
    let mut opts = OpenOptions::new();
    opts.access_mode(FILE_READ_DATA | FILE_WRITE_DATA)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    if is_dir {
        // Verzeichnis-Handles gibt es unter Windows nur mit Backup-Semantik.
        opts.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    opts.open(path)
}

// ---------------------------------------------------------------------------
// Abfragen
// ---------------------------------------------------------------------------

/// Tatsächlich belegter Platz auf dem Datenträger (`GetCompressedFileSizeW`).
/// Funktioniert für LZNT1, WOF und Sparse-Dateien.
pub fn physical_size(path: &Path) -> io::Result<u64> {
    let wide = to_wide(path);
    let mut high = 0u32;
    // Sonst könnte GetLastError unten einen veralteten Fehler eines früheren Aufrufs liefern.
    // SAFETY: setzt nur den Thread-lokalen Fehlerwert.
    unsafe { SetLastError(NO_ERROR) };
    // SAFETY: wide ist null-terminiert, high ein gültiger Zeiger.
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
    if low == u32::MAX {
        // u32::MAX kann auch ein gültiger Low-Teil sein → GetLastError entscheidet.
        let err = unsafe { GetLastError() };
        if err != NO_ERROR {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
    }
    Ok((u64::from(high) << 32) | u64::from(low))
}

/// Liefert den WOF-Algorithmus, falls die Datei per WOF komprimiert ist.
/// WIM-gestützte Dateien (WIMBoot) werden bewusst ignoriert.
pub fn wof_algorithm(path: &Path) -> io::Result<Option<WofAlgorithm>> {
    wof_algorithm_of(&open_for_query(path)?)
}

/// Wie [`wof_algorithm`], aber auf einem bereits geöffneten Handle.
pub fn wof_algorithm_of(file: &File) -> io::Result<Option<WofAlgorithm>> {
    #[repr(C)]
    struct Buf {
        wof: WOF_EXTERNAL_INFO,
        file: FILE_PROVIDER_EXTERNAL_INFO_V1,
    }
    // SAFETY: reine POD-Structs, Nullinitialisierung ist gültig.
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

/// Anzahl physisch zusammenhängender Fragmente einer Datei
/// (`FSCTL_GET_RETRIEVAL_POINTERS`). Bei LZNT1-Dateien typischerweise
/// „ein Fragment pro 64-KiB-Compression-Unit“ – der eigentliche Bremsklotz.
pub fn fragment_count(path: &Path) -> io::Result<u64> {
    fragment_count_of(&open_for_query(path)?)
}

/// Wie [`fragment_count`], aber auf einem bereits geöffneten Handle.
pub fn fragment_count_of(file: &File) -> io::Result<u64> {

    // Layout RETRIEVAL_POINTERS_BUFFER:
    //   u32 ExtentCount, (4 Byte Padding), i64 StartingVcn,
    //   [ { i64 NextVcn, i64 Lcn } ; ExtentCount ]
    const BUF_WORDS: usize = 8 * 1024; // 64 KiB, 8-Byte-ausgerichtet
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
            // Residente (sehr kleine) oder leere Dateien besitzen keine Extents.
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
                // Sparse-Lücken (lcn == -1) überspringen; nur echte Sprünge zählen.
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

/// Eindeutige Identität einer Datei auf einem Volume – Hardlinks teilen sie.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentity {
    pub volume_serial: u32,
    /// 64-Bit-Dateiindex (MFT-Referenz bei NTFS).
    pub index: u64,
    /// Anzahl der Hardlinks (Namen) dieser Datei.
    pub links: u32,
}

impl FileIdentity {
    /// Schlüssel für die Duplikat-Erkennung (ohne Link-Anzahl).
    pub fn key(&self) -> (u32, u64) {
        (self.volume_serial, self.index)
    }
}

/// Volume-Seriennummer, Dateiindex und Link-Anzahl eines offenen Handles.
pub fn file_identity_of(file: &File) -> io::Result<FileIdentity> {
    // SAFETY: reine POD-Struktur, Nullinitialisierung ist gültig.
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: Handle gültig, Zeiger auf ausreichend große Struktur.
    if unsafe { GetFileInformationByHandle(raw_handle(file), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(FileIdentity {
        volume_serial: info.dwVolumeSerialNumber,
        index: (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        links: info.nNumberOfLinks,
    })
}

/// Volume-Wurzel, Dateisystem und freien Platz für einen Pfad ermitteln.
pub fn volume_info(path: &Path) -> io::Result<VolumeInfo> {
    let wide = to_wide(path);
    let mut root = vec![0u16; 1024];
    // SAFETY: Puffer gültig, Länge in Zeichen.
    if unsafe { GetVolumePathNameW(wide.as_ptr(), root.as_mut_ptr(), root.len() as u32) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let root_len = root.iter().position(|&c| c == 0).unwrap_or(root.len());
    root.truncate(root_len + 1); // inkl. Null

    let mut fs_name = vec![0u16; 64];
    let mut fs_flags = 0u32;
    // SAFETY: alle Zeiger gültig oder null.
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
    // SAFETY: root ist null-terminiert.
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

/// Rohe Dateiattribute (`GetFileAttributesW`).
pub fn file_attributes(path: &Path) -> io::Result<u32> {
    let wide = to_wide(path);
    let attrs = unsafe { GetFileAttributesW(wide.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        Err(io::Error::last_os_error())
    } else {
        Ok(attrs)
    }
}

/// Ist `path` die Wurzel des Systemlaufwerks (`sysdrive`, z. B. `C:`)?
/// Erkennt `C:\` ebenso wie `\\?\C:\`.
pub fn is_system_drive_root(path: &Path, sysdrive: &str) -> bool {
    if path.parent().is_some() {
        return false;
    }
    let shown = display_path(path);
    let a = shown.trim_end_matches('\\');
    !a.is_empty() && a.eq_ignore_ascii_case(sysdrive.trim_end_matches('\\'))
}

/// Alle übergeordneten Ordner (ohne `path` selbst), die das Komprimierungsflag tragen.
/// Neue *Unterordner* dort erben das Flag weiterhin. Die Laufwerkswurzel (z. B. `E:\`)
/// zählt mit – außer beim Systemlaufwerk, dort ist das Flag Sache von Windows.
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
// Änderungen
// ---------------------------------------------------------------------------

/// Nimmt den Schreibschutz für die Lebensdauer des Guards heraus und stellt
/// ihn im `Drop` wieder her – auch bei Fehlern/Panics.
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

/// Roher `FSCTL_SET_COMPRESSION(COMPRESSION_FORMAT_NONE)` ohne Fehlerunterdrückung.
/// Bei bereits komprimierten Dateien blockiert der Aufruf, bis NTFS alle
/// Compression-Units unkomprimiert neu geschrieben hat.
fn set_compression_none(file: &File) -> io::Result<()> {
    let format: u16 = COMPRESSION_FORMAT_NONE;
    // SAFETY: Eingabepuffer gültig für die angegebene Länge.
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

/// Schaltet die NTFS-Komprimierung auf einem offenen Handle ab – gedacht für
/// **neu angelegte** Dateien (siehe [`create_uncompressed`]).
/// Das Handle braucht Lese- **und** Schreibzugriff. Auf Dateisystemen ohne
/// Komprimierung (FAT, exFAT, ReFS) ist das ein No-op: „nicht unterstützt“ und
/// `ERROR_INVALID_PARAMETER` werden dort bewusst ignoriert.
///
/// Zum Entpacken bestehender Dateien [`remove_ntfs_compression`] verwenden – das
/// meldet jeden Fehler.
pub fn disable_compression(file: &File) -> io::Result<()> {
    match set_compression_none(file) {
        Err(e) if is_unsupported(&e) => Ok(()),
        other => other,
    }
}

/// Entfernt die NTFS-Komprimierung einer Datei oder das Vererbungsflag eines Ordners.
///
/// Anders als [`disable_compression`] wird hier nichts verschluckt: Das Element trägt
/// nachweislich `FILE_ATTRIBUTE_COMPRESSED`, jeder Fehler ist also echt (z. B.
/// Sparse-Konflikt). Danach wird geprüft, dass das Attribut wirklich weg ist.
pub fn remove_ntfs_compression(path: &Path, is_dir: bool) -> io::Result<()> {
    let _ro = if is_dir { None } else { Some(ReadonlyGuard::clear(path)?) };
    set_compression_none(&open_for_modify(path, is_dir)?)?;
    if file_attributes(path)? & FILE_ATTRIBUTE_COMPRESSED != 0 {
        return Err(io::Error::other(
            "Komprimierung nach FSCTL_SET_COMPRESSION weiterhin aktiv",
        ));
    }
    Ok(())
}

/// Entfernt eine WOF-Komprimierung (die Datei wird dabei entpackt).
pub fn remove_wof_compression(path: &Path) -> io::Result<()> {
    let _ro = ReadonlyGuard::clear(path)?;
    let file = open_for_modify(path, false)?;
    match unsafe { ioctl(&file, FSCTL_DELETE_EXTERNAL_BACKING, null(), 0, null_mut(), 0) } {
        Ok(_) => Ok(()),
        // wof.sys entpackt die Datei, reicht das FSCTL danach aber an NTFS weiter,
        // das mit „nicht extern gesichert“ antwortet. Zielzustand prüfen statt
        // dem Rückgabewert zu glauben.
        Err(e) if os_code(&e) == Some(ERROR_OBJECT_NOT_EXTERNALLY_BACKED) => {
            match wof_algorithm_of(&file)? {
                None => Ok(()),
                Some(_) => Err(e),
            }
        }
        Err(e) => Err(e),
    }
}

/// Entfernt die angegebene Komprimierungsart.
pub fn remove_compression(path: &Path, kind: CompressionKind) -> io::Result<()> {
    match kind {
        CompressionKind::Lznt1 => remove_ntfs_compression(path, false),
        CompressionKind::Wof(_) => remove_wof_compression(path),
    }
}

/// Legt eine Datei an (bzw. leert sie) und schaltet die Komprimierung ab,
/// **bevor** Daten geschrieben werden – kostet < 1 ms und schützt eigene Tools
/// vor einem komprimierten Zielordner.
///
/// ```no_run
/// use std::io::Write;
/// let mut f = ntfs_unthrottle::create_uncompressed("D:/out/game.xci".as_ref())?;
/// f.write_all(b"...")?;
/// # Ok::<(), std::io::Error>(())
/// ```
pub fn create_uncompressed(path: &Path) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true) // nötig: FSCTL_SET_COMPRESSION prüft FILE_READ_DATA
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    disable_compression(&file)?;
    Ok(file)
}

// ---------------------------------------------------------------------------
// Fehlertexte
// ---------------------------------------------------------------------------

/// Übersetzt häufige Windows-Fehler in verständliche Hinweise.
pub fn describe_error(err: &io::Error) -> String {
    match os_code(err) {
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION | ERROR_USER_MAPPED_FILE) => {
            "Datei ist von einem anderen Prozess geöffnet/gesperrt".into()
        }
        Some(ERROR_ACCESS_DENIED) => {
            "Zugriff verweigert (ACL/Systemdatei – ggf. Terminal als Administrator starten)".into()
        }
        Some(ERROR_DISK_FULL) => "Datenträger voll".into(),
        Some(ERROR_FILE_SYSTEM_LIMITATION) => {
            "NTFS-Grenze erreicht: Datei zu stark fragmentiert (vorher defragmentieren)".into()
        }
        Some(ERROR_INVALID_PARAMETER) => {
            "NTFS lehnt die Änderung ab (ungültiger Parameter – z. B. Cluster > 4 KiB oder Sparse-Konflikt)"
                .into()
        }
        _ => err.to_string(),
    }
}

/// Wie [`describe_error`], ergänzt aber Hinweise passend zur Datei
/// (z. B. bei virtuellen Festplatten `.vhd`/`.vhdx`).
pub fn describe_error_at(err: &io::Error, path: &Path) -> String {
    let base = describe_error(err);
    let is_vhd = path
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| matches!(e.to_ascii_lowercase().as_str(), "vhd" | "vhdx" | "avhdx"));
    if !is_vhd {
        return base;
    }
    match os_code(err) {
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION | ERROR_USER_MAPPED_FILE) => {
            format!("{base} – bei .vhdx ggf. VM beenden, `wsl --shutdown` ausführen bzw. Docker schließen")
        }
        Some(ERROR_FILE_SYSTEM_LIMITATION) => {
            format!("{base} – bei .vhdx alternativ `Optimize-VHD` oder die Datei umkopieren")
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
        assert!(describe_error_at(&limit, vhdx).contains("defragmentieren"));
        // Andere Dateien: unverändert
        let bin = Path::new(r"E:\Games\data.bin");
        assert_eq!(describe_error_at(&share, bin), describe_error(&share));
        assert_eq!(describe_error_at(&limit, bin), describe_error(&limit));
    }

    #[test]
    fn invalid_parameter_tolerated_only_for_new_files() {
        let e = io::Error::from_raw_os_error(ERROR_INVALID_PARAMETER as i32);
        // Tolerant nur über disable_compression (create_uncompressed) …
        assert!(is_unsupported(&e));
        // … beim Entpacken wird er gemeldet – mit verständlichem Text.
        assert!(describe_error(&e).contains("NTFS lehnt"));
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
