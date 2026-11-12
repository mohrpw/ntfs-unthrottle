use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::ExitCode;
use std::time::{Duration, Instant};

mod optimize;

use clap::Parser;
use console::style;
use humansize::{format_size, BINARY};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

use ntfs_unthrottle::{
    compressed_ancestors, describe_error_at, display_path, file_identity_of, fragment_count,
    fragment_count_of, open_for_query, physical_size, remove_compression, remove_ntfs_compression,
    volume_info, wof_algorithm_of, CompressionKind, VolumeInfo, WofAlgorithm,
};
use ntfs_unthrottle::tune::{device_info, DeviceInfo};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT,
};

/// Platzhalter von OneDrive & Co. – würde ein Öffnen mit Schreibzugriff herunterladen.
const CLOUD_ATTRS: u32 =
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN;

/// Bekannte Formate mit hoher Entropie (bereits komprimiert oder verschlüsselt).
const HIGH_ENTROPY_EXTS: &[&str] = &[
    // Switch-Dumps / Container
    "xci", "xcz", "nsp", "nsz", "nca", "ncz",
    // Archive
    "zip", "7z", "rar", "zst", "gz", "xz", "bz2", "lz4", "cab", "msi",
    // Medien
    "mp4", "mkv", "webm", "mov", "avi", "mp3", "flac", "ogg", "opus", "jpg", "jpeg", "png", "webp", "heic",
    // Images & Spiele-Container
    "iso", "chd", "rvz", "wbfs", "cso", "pak", "ucas", "utoc", "bundle", "vpk",
    // Verschlüsselte Container
    "hc", "tc", "vc", "kdbx", "gpg",
];

/// --recommended: Formate mit vielen (Random-)Schreibzugriffen. Komprimierung
/// zerstückelt sie stark (bis ERROR_FILE_SYSTEM_LIMITATION) – immer entpacken.
const WRITE_HEAVY_EXTS: &[&str] = &[
    // VM-Images & Snapshots
    "vhd", "vhdx", "avhdx", "vmdk", "vdi", "qcow2", "vmem", "vmsn", "vmss", "nvram",
    // Datenbanken
    "db", "db-wal", "db-shm", "sqlite", "sqlite3", "mdf", "ldf", "ndf", "edb", "ibd",
    "mdb", "accdb", "ldb", "pst", "ost",
    // Unfertige Downloads (werden blockweise in zufälliger Reihenfolge geschrieben)
    "part", "partial", "crdownload", "!qb", "!ut", "aria2",
];

/// --recommended: Build-/Tooling-Ordner mit vielen kleinen, ständig neu
/// geschriebenen Dateien – darin wird alles entpackt, unabhängig von Größe/Quote.
/// Diese Namen sind eindeutig genug, um ohne weitere Prüfung zu gelten.
const BUILD_DIRS: &[&str] = &[
    "node_modules", ".git", ".vs", ".idea", "__pycache__", ".venv", "venv",
    ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".gradle", ".next", ".nuxt",
    ".turbo", ".parcel-cache", ".angular", ".svelte-kit", ".cargo",
    ".rustup", ".nuget", ".m2", "go-build", "ccache", ".ccache",
];

/// Projekt-Marker (Dateien oder Ordner, `*.ext` = beliebiger Name mit Endung).
const PROJECT_MARKERS: &[&str] = &[
    "package.json", "Cargo.toml", "pyproject.toml", "CMakeLists.txt", "Makefile", ".git", "*.sln",
];

/// Generische Namen, die auch in Spielordnern vorkommen (`Spiel\dist`, `Spiel\build`).
/// Sie zählen nur, wenn der direkte Elternordner einen passenden Projekt-Marker enthält.
const GENERIC_BUILD_DIRS: &[(&str, &[&str])] = &[
    ("build", PROJECT_MARKERS),
    ("dist", PROJECT_MARKERS),
    ("target", &["Cargo.toml", "pom.xml"]),
    ("obj", &["*.csproj", "*.vcxproj", "*.fsproj", "*.vbproj", "*.sln"]),
];

fn has_ext(path: &Path, list: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| list.contains(&e.to_ascii_lowercase().as_str()))
}

/// Enthält `dir` einen der `markers`? (Groß-/Kleinschreibung egal.)
fn is_project_dir(dir: &Path, markers: &[&str]) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else { return false };
    rd.flatten().any(|e| {
        let name = fold(&e.file_name());
        markers.iter().any(|m| match m.strip_prefix('*') {
            Some(ext) => name.len() > ext.len() && name.ends_with(&ext.to_lowercase()),
            None => name == m.to_lowercase(),
        })
    })
}

/// Liegt `path` unterhalb eines Build-/Tooling-Ordners? Geprüft werden nur der
/// Scan-Root `root` und Ordner darunter – nicht, was darüber liegt
/// (`E:\target\Spiele` als Scan-Pfad macht nicht alles zum Build-Ordner).
/// `cache` merkt sich das Marker-Ergebnis je generischem Ordner.
fn in_build_dir(path: &Path, root: &Path, cache: &mut HashMap<PathBuf, bool>) -> bool {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if !dir.starts_with(root) {
            break;
        }
        if let Some(name) = dir.file_name() {
            let n = fold(name);
            if BUILD_DIRS.contains(&n.as_str()) {
                return true;
            }
            if let Some((_, markers)) = GENERIC_BUILD_DIRS.iter().find(|(g, _)| *g == n) {
                let hit = *cache
                    .entry(dir.to_path_buf())
                    .or_insert_with(|| dir.parent().is_some_and(|p| is_project_dir(p, markers)));
                if hit {
                    return true;
                }
            }
        }
        if dir == root {
            break;
        }
        cur = dir.parent();
    }
    false
}

const EXIT_FOUND: u8 = 2;
const EXIT_PARTIAL: u8 = 3;

#[derive(Parser, Debug)]
#[command(
    name = "ntfs-unthrottle",
    version,
    about = "Beseitigt unsichtbare I/O-Bremsen durch transparente NTFS-/WOF-Komprimierung.",
    after_help = "Exit-Codes: 0 = nichts zu tun/alles behoben, 1 = Fehler, \
                  2 = Dry-Run hat Kandidaten gefunden, 3 = einzelne Elemente schlugen fehl."
)]
struct Cli {
    /// Zu prüfende Ordner oder Dateien
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Änderungen tatsächlich anwenden (ohne: reine Analyse)
    #[arg(short, long)]
    fix: bool,

    /// Keine Sicherheitsabfrage (für Skripte)
    #[arg(short, long, requires = "fix")]
    yes: bool,

    /// Mindestgröße für Dateien in MiB
    #[arg(long, value_name = "MiB", default_value_t = 16)]
    min_size: u64,

    /// Physische Größe in % der logischen, ab der eine Komprimierung als nutzlos gilt
    #[arg(long, value_name = "PROZENT", default_value_t = 90.0, value_parser = parse_percent)]
    threshold: f64,

    /// Jede komprimierte Datei ab Mindestgröße erfassen (Endung/Quote egal)
    #[arg(long, conflicts_with = "recommended")]
    all: bool,

    /// Empfohlene Auswahl: wie Standard, zusätzlich immer VM-Images, Datenbanken,
    /// unfertige Downloads, alles in Build-Ordnern (node_modules, target, .git, …)
    /// sowie WOF-Dateien in DirectStorage-Spielen auf NVMe
    #[arg(long, visible_alias = "recommend")]
    recommended: bool,

    /// Komprimierungsflag von Ordnern NICHT entfernen
    #[arg(long)]
    keep_dir_flags: bool,

    /// WOF-/CompactOS-Erkennung überspringen (spart ein Öffnen pro großer Datei)
    #[arg(long)]
    no_wof: bool,

    /// Fragmentanzahl nicht ermitteln
    #[arg(long)]
    no_fragments: bool,

    /// Alle Kandidaten und Ordner auflisten statt nur der größten
    #[arg(short, long)]
    verbose: bool,

    /// Optimierer: Datenträger, MFT, 8.3-Namen, Last-Access, TRIM der Volumes prüfen
    /// (mit --fix sichere Korrekturen per fsutil anwenden). Scannt keine Dateien.
    #[arg(long)]
    optimize: bool,

    /// Ausschließen: Name (z. B. node_modules – greift überall) oder Pfad (z. B. E:\Backup).
    /// Mehrfach angebbar. Systemordner sind immer geschützt.
    #[arg(short = 'x', long = "exclude", value_name = "NAME|PFAD")]
    exclude: Vec<String>,
}

// Poka-Yoke: Diese Listen sind absichtlich NICHT abschaltbar. Sie greifen
// beim Durchlaufen, für direkt angegebene Pfade und für alles darunter.

/// Geschützte Systemordner – egal in welcher Tiefe.
const PROTECTED_ANYWHERE: &[&str] = &[
    "$recycle.bin",              // Papierkorb
    "system volume information", // Schattenkopien, Wiederherstellungspunkte, Indexer
    "config.msi",                // Windows-Installer-Rollback
    "windowsapps",               // Store-Apps (TrustedInstaller, signierte Pakete)
    "wpsystem",                  // Store-App-Daten auf Zweitlaufwerken
    "wudownloadcache",           // Windows-Update-Cache
    "$winreagent",
    "$windows.~bt",
    "$windows.~ws",
    "$sysreset",
    "$getcurrent",
    "msocache",                  // Office-Installationsquelle
];

/// Geschützt, wenn direkt in der Laufwerkswurzel.
const PROTECTED_AT_ROOT: &[&str] = &[
    "windows", "recovery", "boot", "efi", "bootmgr", "pagefile.sys", "swapfile.sys",
    "hiberfil.sys", "dumpstack.log", "dumpstack.log.tmp", "boottel.dat",
];

/// Auffangnetz für Unbekanntes: Was in der Laufwerkswurzel versteckt UND System ist,
/// gehört Windows.
const HIDDEN_SYSTEM: u32 = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;

/// Liegt `path` direkt in einer Laufwerkswurzel? (`\\?\E:\` hat selbst kein Parent.)
fn is_at_volume_root(path: &Path) -> bool {
    path.parent().is_some_and(|p| p.parent().is_none())
}

/// Prüft nur das letzte Element von `path`. `attrs` = Dateiattribute, falls bekannt.
fn protected_reason(path: &Path, attrs: Option<u32>) -> Option<&'static str> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if PROTECTED_ANYWHERE.contains(&name.as_str()) {
        return Some("Systemordner");
    }
    if is_at_volume_root(path) {
        if PROTECTED_AT_ROOT.contains(&name.as_str()) {
            return Some("Systemdatei/-ordner in der Laufwerkswurzel");
        }
        if attrs.is_some_and(|a| a & HIDDEN_SYSTEM == HIDDEN_SYSTEM) {
            return Some("versteckt + System in der Laufwerkswurzel");
        }
    }
    None
}

/// Prüft `path` und alle übergeordneten Elemente – für direkt angegebene Pfade.
fn protected_path(path: &Path) -> Option<(PathBuf, &'static str)> {
    path.ancestors().find_map(|p| {
        let attrs = ntfs_unthrottle::file_attributes(p).ok();
        protected_reason(p, attrs).map(|why| (p.to_path_buf(), why))
    })
}

struct Excludes {
    names: Vec<String>,
    paths: Vec<String>,
}

impl Excludes {
    fn new(cli: &Cli) -> io::Result<Self> {
        let mut names = Vec::new();
        let mut paths = Vec::new();
        for x in &cli.exclude {
            if x.contains(['\\', '/', ':']) {
                let c = match std::fs::canonicalize(x) {
                    Ok(c) => c,
                    // Was es nicht gibt, kann auch nicht gescannt werden – kein Grund abzubrechen.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        println!(
                            "{} --exclude {x}: existiert nicht – ignoriert.",
                            style("ℹ").blue().bold()
                        );
                        continue;
                    }
                    Err(e) => return Err(io::Error::new(e.kind(), format!("--exclude {x}: {e}"))),
                };
                paths.push(c.to_string_lossy().to_lowercase());
            } else {
                names.push(x.to_lowercase());
            }
        }
        Ok(Self { names, paths })
    }

    fn matches(&self, path: &Path, attrs: Option<u32>) -> bool {
        if protected_reason(path, attrs).is_some() {
            return true;
        }
        let Some(name) = path.file_name() else { return false };
        let name = name.to_string_lossy().to_lowercase();
        if self.names.contains(&name) {
            return true;
        }
        if !self.paths.is_empty() {
            let p = path.to_string_lossy().to_lowercase();
            return self.paths.iter().any(|x| {
                p == *x || (p.starts_with(x.as_str()) && (x.ends_with('\\') || p[x.len()..].starts_with('\\')))
            });
        }
        false
    }
}

fn parse_percent(s: &str) -> Result<f64, String> {
    let v: f64 = s.trim_end_matches('%').parse().map_err(|_| format!("keine Zahl: {s}"))?;
    if (0.0..=100.0).contains(&v) {
        Ok(v)
    } else {
        Err("muss zwischen 0 und 100 liegen".into())
    }
}

#[derive(Debug, Clone, Copy)]
enum Reason {
    Extension,
    LowSavings,
    WriteHeavy,
    BuildDir,
    DirectStorage,
    Forced,
}

impl Reason {
    fn label(self) -> &'static str {
        match self {
            Reason::Extension => "Endung",
            Reason::LowSavings => "kaum Ersparnis",
            Reason::WriteHeavy => "Schreiblast",
            Reason::BuildDir => "Build-Ordner",
            Reason::DirectStorage => "DirectStorage",
            Reason::Forced => "--all",
        }
    }
}

struct Candidate {
    /// Index des Scan-Pfads (für die Volume-Zuordnung).
    root: usize,
    path: PathBuf,
    logical: u64,
    physical: u64,
    kind: CompressionKind,
    reason: Reason,
    fragments: Option<u64>,
}

impl Candidate {
    fn ratio(&self) -> f64 {
        ratio(self.physical, self.logical)
    }
}

#[derive(Default)]
struct Scan {
    dirs: Vec<PathBuf>,
    files: Vec<Candidate>,
    entries: u64,
    errors: u64,
    cloud_skipped: u64,
    excluded: Vec<PathBuf>,
    kept_files: u64,
    kept_bytes_saved: u64,
    small_compressed: u64,
    /// Bereits erfasste Dateien mit mehreren Hardlinks: (Volume-Serial, Dateiindex).
    seen_links: HashSet<(u32, u64)>,
    hardlink_dupes: u64,
    /// Marker-Ergebnis je generischem Build-Ordner (`build`, `dist`, …).
    build_cache: HashMap<PathBuf, bool>,
    /// Ordner mit `dstorage.dll`/`dstoragecore.dll` (Scan-Root-Index, Ordner).
    ds_dll_dirs: Vec<(usize, PathBuf)>,
    /// Behaltene WOF-Dateien (≥ --min-size) für die Speichermedium-Regeln.
    /// `reason` ist nur ein Platzhalter – gesetzt wird er erst beim Verschieben.
    kept_wof: Vec<Candidate>,
}

/// Volume und Datenträger eines Scan-Roots – einmal ermittelt.
#[derive(Default)]
struct RootInfo {
    vol: Option<VolumeInfo>,
    dev: Option<DeviceInfo>,
}

impl RootInfo {
    fn new(root: &Path) -> Self {
        // device_info braucht die Volume-Wurzel bzw. den Mount-Punkt –
        // auf einem Unterordner (E:\Games) schlüge es still fehl.
        let vol = volume_info(root).ok();
        let dev = vol.as_ref().and_then(|v| device_info(&v.root).ok());
        Self { vol, dev }
    }

    fn vol_root(&self) -> Option<&Path> {
        self.vol.as_ref().map(|v| v.root.as_path())
    }

    /// WOF (`wof.sys`) gibt es nur auf NTFS – unabhängig von `supports_compression`
    /// (NTFS mit Clustern > 4 KiB kann kein LZNT1, WOF aber schon).
    /// Unbekanntes Volume → sicherheitshalber prüfen.
    fn wof_possible(&self) -> bool {
        self.vol.as_ref().is_none_or(|v| v.fs_name.eq_ignore_ascii_case("NTFS"))
    }

    /// Nur echtes NVMe – RAID, Speicherplätze, USB-Gehäuse zählen nicht (kein BypassIO).
    fn is_nvme(&self) -> bool {
        self.dev.as_ref().is_some_and(|d| d.bus == Some("NVMe"))
    }
}

// --- Pfadvergleiche (NTFS ist case-insensitiv) ------------------------------

/// Komponentenname normiert (Unicode-Kleinschreibung, damit auch `Übung` = `übung`).
fn fold(s: &std::ffi::OsStr) -> String {
    s.to_string_lossy().to_lowercase()
}

/// Pfad als normierte Komponentenliste. `\\?\C:\x` und `C:\x` ergeben dasselbe.
fn norm(p: &Path) -> Vec<String> {
    p.components()
        .filter_map(|c| match c {
            Component::Prefix(pre) => Some(match pre.kind() {
                Prefix::Disk(d) | Prefix::VerbatimDisk(d) => {
                    format!("{}:", char::from(d).to_ascii_lowercase())
                }
                Prefix::UNC(s, sh) | Prefix::VerbatimUNC(s, sh) => {
                    format!(r"\\{}\{}", fold(s), fold(sh))
                }
                _ => fold(pre.as_os_str()),
            }),
            Component::Normal(n) => Some(fold(n)),
            _ => None,
        })
        .collect()
}

/// Liegt `path` in `base` (oder ist es selbst)? Vergleich je Komponente,
/// also `SpielAB` liegt nicht in `SpielA`.
fn under(path: &Path, base: &Path) -> bool {
    let (p, b) = (norm(path), norm(base));
    p.len() >= b.len() && p[..b.len()] == b[..]
}

fn same_path(a: &Path, b: &Path) -> bool {
    norm(a) == norm(b)
}

/// Vergleicht einen Komponentennamen mit einem bereits kleingeschriebenen Namen.
fn comp_eq(a: &std::ffi::OsStr, lower: &str) -> bool {
    fold(a) == lower
}

/// Entfernt Pfade, die in einem anderen (oder demselben) Pfad enthalten sind.
/// Liefert die behaltenen und die verworfenen Pfade (mit dem enthaltenden Pfad).
fn dedup_roots(mut roots: Vec<PathBuf>) -> (Vec<PathBuf>, Vec<(PathBuf, PathBuf)>) {
    roots.sort_by_key(|p| p.components().count());
    let mut kept: Vec<PathBuf> = Vec::new();
    let mut dropped = Vec::new();
    for r in roots {
        match kept.iter().find(|k| under(&r, k)) {
            Some(k) => dropped.push((r, k.clone())),
            None => kept.push(r),
        }
    }
    (kept, dropped)
}

// --- DirectStorage-Erkennung -----------------------------------------------

/// Spiele müssen DirectStorage selbst mitbringen – die Namen sind fest.
const DS_DLLS: &[&str] = &["dstorage.dll", "dstoragecore.dll"];

/// Ordner von Spielbibliotheken (kleingeschrieben); der Ordner danach ist das Spiel.
const LIBRARY_MARKERS: &[&[&str]] = &[
    &["steamapps", "common"],
    &["xboxgames"],
    &["epic games"],
    &["gog games"],
    &["gog galaxy", "games"],
    &["ea games"],
    &["ubisoft game launcher", "games"],
];

/// Engine-/Binär-Unterordner, über die vom DLL-Ordner zum Spiel-Root aufgestiegen wird.
const ENGINE_DIRS: &[&str] = &[
    "binaries", "win64", "win32", "wingdk", "x64", "x86", "x86_64", "arm64", "bin", "bin64",
    "shipping", "retail", "windows", "windowsnoeditor", "redist", "thirdparty", "directstorage",
    "engine", "plugins", "content",
];

/// Volume-Wurzel oder Mount-Punkt erreicht?
fn is_vol_root(cur: &Path, vol_root: Option<&Path>) -> bool {
    cur.file_name().is_none() || vol_root.is_some_and(|vr| same_path(cur, vr))
}

/// Endet `p` mit genau diesen (kleingeschriebenen) Komponenten?
fn ends_with_names(p: &Path, names: &[&str]) -> bool {
    let comps: Vec<_> = p
        .components()
        .filter_map(|c| match c {
            Component::Normal(n) => Some(n),
            _ => None,
        })
        .collect();
    comps.len() >= names.len()
        && comps[comps.len() - names.len()..].iter().zip(names).all(|(a, b)| comp_eq(a, b))
}

/// Leitet aus dem Ordner einer DirectStorage-DLL den Spiel-Ordner ab – reine
/// Pfadlogik. `None`, wenn die DLL direkt in einer Volume-Wurzel liegt.
fn ds_game_root(dll_dir: &Path, vol_root: Option<&Path>) -> Option<PathBuf> {
    if is_vol_root(dll_dir, vol_root) {
        return None;
    }
    // 1. Bekannte Bibliothek: erster Ordner nach dem Marker.
    for a in dll_dir.ancestors() {
        if is_vol_root(a, vol_root) {
            break;
        }
        let Some(parent) = a.parent() else { break };
        if LIBRARY_MARKERS.iter().any(|m| ends_with_names(parent, m)) {
            return Some(a.to_path_buf());
        }
    }
    // 2. Über Engine-Ordner hochsteigen.
    let mut cur = dll_dir;
    let mut last: Option<String> = None;
    while !is_vol_root(cur, vol_root) {
        let Some(name) = cur.file_name().map(fold) else { break };
        let unity_data = last.as_deref() == Some("plugins") && name.ends_with("_data");
        if !ENGINE_DIRS.contains(&name.as_str()) && !unity_data {
            break;
        }
        let Some(parent) = cur.parent() else { break };
        cur = parent;
        last = Some(name);
    }
    // UE: Spiel\Spiel\Binaries\Win64 → Spiel (umfasst auch Spiel\Engine).
    if last.is_some() && !is_vol_root(cur, vol_root) {
        if let (Some(name), Some(parent)) = (cur.file_name(), cur.parent()) {
            if !is_vol_root(parent, vol_root)
                && parent.file_name().is_some_and(|pn| fold(pn) == fold(name))
            {
                cur = parent;
            }
        }
    }
    // 3. Nie ein ganzes Volume markieren.
    if is_vol_root(cur, vol_root) {
        return Some(dll_dir.to_path_buf());
    }
    Some(cur.to_path_buf())
}

/// Ergebnisse der Speichermedium-Regeln für den Report.
#[derive(Default)]
struct StorageNotes {
    /// Ohne --recommended: (Spiel-Root, Dateien, Bytes logisch), die komprimiert bleiben.
    ds_kept: Vec<(PathBuf, u64, u64)>,
    /// Mit --recommended: (Spiel-Root, Dateien), die zum Entpacken vorgemerkt wurden.
    ds_moved: Vec<(PathBuf, u64)>,
    /// NVMe-Hinweis je Volume.
    nvme_heavy: Vec<NvmeHeavy>,
}

/// Viel LZX/XPRESS16K auf einem NVMe-Volume (ohne DirectStorage-Treffer).
struct NvmeHeavy {
    vol: PathBuf,
    total: u64,
    /// Bis zu 3 größte Ordner (voller Pfad) mit Bytes.
    dirs: Vec<(PathBuf, u64)>,
}

impl StorageNotes {
    fn any_hint(&self) -> bool {
        !self.ds_kept.is_empty() || !self.nvme_heavy.is_empty()
    }
}

/// Ab so viel LZX/XPRESS16K pro NVMe-Volume gibt es einen Hinweis.
const NVME_HEAVY_WOF_BYTES: u64 = 1024 * 1024 * 1024;

/// Ordner für den NVMe-Hinweis: erste Ebene unterhalb des Scan-Roots,
/// bzw. der Scan-Root selbst, wenn die Datei direkt darin liegt.
fn group_dir(root: &Path, path: &Path) -> PathBuf {
    let rel = path.strip_prefix(root).unwrap_or(Path::new(""));
    match rel.parent() {
        Some(p) if !p.as_os_str().is_empty() => match rel.components().next() {
            Some(c) => root.join(c),
            None => root.to_path_buf(),
        },
        _ => root.to_path_buf(),
    }
}

/// Wendet die DirectStorage-/NVMe-Regeln auf die behaltenen WOF-Dateien an.
/// Muss vor `check_free_space` laufen, damit verschobene Dateien mitzählen.
fn apply_storage_rules(cli: &Cli, scan: &mut Scan, roots: &[PathBuf], infos: &[RootInfo]) -> StorageNotes {
    let mut notes = StorageNotes::default();

    // Spiel-Roots aller Scan-Pfade, äußere gewinnen.
    let found: Vec<PathBuf> = scan
        .ds_dll_dirs
        .iter()
        .filter_map(|(i, dir)| ds_game_root(dir, infos[*i].vol_root()))
        .collect();
    let (games, _) = dedup_roots(found);
    let games_norm: Vec<Vec<String>> = games.iter().map(|g| norm(g)).collect();
    let game_of = |p: &Path| {
        let n = norm(p);
        games_norm.iter().position(|g| n.len() >= g.len() && n[..g.len()] == g[..])
    };

    let mut per_game = vec![(0u64, 0u64); games.len()];
    // Volume (normiert) → (Volume-Pfad, Summe, Bytes je Ordner)
    type Heavy = (PathBuf, u64, BTreeMap<PathBuf, u64>);
    let mut heavy: BTreeMap<Vec<String>, Heavy> = BTreeMap::new();
    let mut moved = false;

    for mut f in std::mem::take(&mut scan.kept_wof) {
        let info = &infos[f.root];
        if !info.is_nvme() {
            continue;
        }
        if let Some(g) = game_of(&f.path) {
            per_game[g].0 += 1;
            per_game[g].1 += f.logical;
            if cli.recommended {
                scan.kept_files = scan.kept_files.saturating_sub(1);
                scan.kept_bytes_saved =
                    scan.kept_bytes_saved.saturating_sub(f.logical.saturating_sub(f.physical));
                f.reason = Reason::DirectStorage;
                scan.files.push(f);
                moved = true;
            }
            continue;
        }
        if matches!(f.kind, CompressionKind::Wof(WofAlgorithm::Lzx | WofAlgorithm::Xpress16K)) {
            let Some(vol) = info.vol_root() else { continue };
            let e = heavy.entry(norm(vol)).or_insert_with(|| (vol.to_path_buf(), 0, BTreeMap::new()));
            e.1 += f.logical;
            *e.2.entry(group_dir(&roots[f.root], &f.path)).or_default() += f.logical;
        }
    }

    for (g, (n, bytes)) in games.into_iter().zip(per_game) {
        if n == 0 {
            continue;
        }
        if cli.recommended {
            notes.ds_moved.push((g, n));
        } else {
            notes.ds_kept.push((g, n, bytes));
        }
    }
    for (_, (vol, total, dirs)) in heavy {
        if total <= NVME_HEAVY_WOF_BYTES {
            continue;
        }
        let mut dirs: Vec<(PathBuf, u64)> = dirs.into_iter().collect();
        dirs.sort_by_key(|(_, b)| std::cmp::Reverse(*b));
        dirs.truncate(3);
        notes.nvme_heavy.push(NvmeHeavy { vol, total, dirs });
    }
    if moved {
        scan.files.sort_by_key(|f| std::cmp::Reverse(f.logical));
    }
    notes
}

fn ratio(physical: u64, logical: u64) -> f64 {
    if logical == 0 {
        100.0
    } else {
        physical as f64 / logical as f64 * 100.0
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{} {}", style("✖").red().bold(), e);
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> io::Result<ExitCode> {
    if cli.optimize {
        return optimize::run(&cli.paths, cli.fix, cli.yes);
    }
    // Kanonische \\?\-Pfade: damit funktionieren auch Pfade > 260 Zeichen mit
    // den rohen Win32-Aufrufen.
    let mut roots = Vec::new();
    for p in &cli.paths {
        // Poka-Yoke: direkt angegebene Systempfade (oder Pfade darin) ablehnen –
        // zuerst rein am Namen, weil canonicalize bei gesperrten Systempfaden
        // (System Volume Information, pagefile.sys) schon selbst scheitert.
        let abs = std::path::absolute(p).unwrap_or_else(|_| p.clone());
        let canon = std::fs::canonicalize(p);
        let check = canon.as_deref().unwrap_or(&abs);
        if let Some((hit, why)) = protected_path(&abs).or_else(|| protected_path(check)) {
            eprintln!(
                "{} Übersprungen: {} – geschützt ({}: {}).",
                style("⛔").red().bold(),
                display_path(&abs),
                why,
                display_path(&hit)
            );
            continue;
        }
        roots.push(canon.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?);
    }
    if roots.is_empty() {
        return Err(io::Error::other("Keine bearbeitbaren Pfade übrig."));
    }
    // Überlappende Pfade nur einmal scannen – sonst doppelte Kandidaten,
    // doppelter Platzbedarf und doppeltes Entpacken.
    let (roots, dropped) = dedup_roots(roots);
    for (inner, outer) in &dropped {
        println!(
            "{} {} ist in {} enthalten – wird nicht doppelt gescannt.",
            style("ℹ").blue().bold(),
            display_path(inner),
            display_path(outer)
        );
    }
    let infos: Vec<RootInfo> = roots.iter().map(|r| RootInfo::new(r)).collect();

    // --- Phase 1: Scan ----------------------------------------------------
    println!("{} Scanne {} Pfad(e)", style("[1/3]").bold().cyan(), roots.len());
    for (root, info) in roots.iter().zip(&infos) {
        println!("      {}", style(display_path(root)).underlined());
        report_volume(info);
    }

    let started = Instant::now();
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::with_template("{spinner:.cyan} {pos} Einträge geprüft  {wide_msg:.dim}")
            .unwrap(),
    );
    spinner.enable_steady_tick(Duration::from_millis(100));

    let excludes = Excludes::new(cli)?;
    let mut scan = Scan::default();
    for (i, (root, info)) in roots.iter().zip(&infos).enumerate() {
        scan_tree(cli, i, root, info, &excludes, &mut scan, &spinner);
    }
    spinner.finish_and_clear();
    scan.files.sort_by_key(|f| std::cmp::Reverse(f.logical));

    // --- Phase 2: Auswertung ----------------------------------------------
    let notes = apply_storage_rules(cli, &mut scan, &roots, &infos);
    print_report(cli, &scan, &notes, started.elapsed());

    let ancestors: Vec<PathBuf> = {
        let mut v: Vec<PathBuf> = roots.iter().flat_map(|r| compressed_ancestors(r)).collect();
        v.sort();
        v.dedup();
        v
    };
    if !ancestors.is_empty() {
        println!(
            "\n  {} Übergeordnete Ordner tragen ebenfalls das Flag (neue Unterordner dort erben es):",
            style("⚠").yellow().bold()
        );
        for a in &ancestors {
            if a.parent().is_none() {
                // Laufwerkswurzel: wird bewusst nicht automatisch geändert.
                println!(
                    "      {}  {}",
                    display_path(a),
                    style(format!(
                        "(Laufwerkswurzel – nur das Flag entfernen: compact /u {})",
                        display_path(a)
                    ))
                    .dim()
                );
            } else {
                println!("      {}", display_path(a));
            }
        }
    }

    let dirs_todo = if cli.keep_dir_flags { 0 } else { scan.dirs.len() };
    if dirs_todo == 0 && scan.files.is_empty() {
        println!(
            "\n{} Keine kontraproduktive Komprimierung gefunden{}.",
            style("✔").green().bold(),
            if notes.any_hint() { " (Hinweise oben beachten)" } else { "" }
        );
        return Ok(ExitCode::SUCCESS);
    }

    if !cli.fix {
        println!(
            "\n{} Nur Analyse. Mit {} wird die Komprimierung entfernt.",
            style("ℹ").blue().bold(),
            style("--fix").yellow().bold()
        );
        return Ok(ExitCode::from(EXIT_FOUND));
    }

    print!("\n  Prüfe freien Platz …");
    io::stdout().flush()?;
    check_free_space(&roots, &scan.files)?;
    println!(" ok");

    let prompt = format!(
        "\n{}\n{} ",
        style("─".repeat(60)).yellow(),
        style(format!(
            "▶ {} Datei(en) und {} Ordner jetzt entpacken? [j/N]:",
            scan.files.len(),
            dirs_todo
        ))
        .yellow()
        .bold()
    );
    if !cli.yes && !confirm(&prompt)? {
        println!("Abgebrochen.");
        return Ok(ExitCode::SUCCESS);
    }

    // --- Phase 3: Bereinigung --------------------------------------------
    println!("\n{} Bereinige …", style("[3/3]").bold().cyan());
    let mut failed: Vec<(PathBuf, String)> = Vec::new();
    let mut fixed_dirs = 0usize;

    // Zuerst die Ordner: neue Dateien erben ab sofort nichts mehr.
    if dirs_todo > 0 {
        let pb = ProgressBar::new(dirs_todo as u64);
        pb.set_style(
            ProgressStyle::with_template("  Ordner  [{bar:30.cyan/blue}] {pos}/{len}").unwrap(),
        );
        for dir in &scan.dirs {
            match remove_ntfs_compression(dir, true) {
                Ok(()) => fixed_dirs += 1,
                Err(e) => failed.push((dir.clone(), describe_error_at(&e, dir))),
            }
            pb.inc(1);
        }
        pb.finish();
    }

    // Dateien bewusst sequenziell: NTFS schreibt jede Datei synchron neu.
    let mut fixed_files = 0usize;
    let mut freed_fragments = 0u64;
    if !scan.files.is_empty() {
        let total: u64 = scan.files.iter().map(|f| f.logical).sum();
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(
                "  Dateien [{bar:30.green/white}] {bytes}/{total_bytes} {bytes_per_sec} ETA {eta}  {wide_msg:.dim}",
            )
            .unwrap()
            .progress_chars("=> "),
        );
        pb.enable_steady_tick(Duration::from_millis(200));
        for f in &scan.files {
            pb.set_message(file_name(&f.path));
            match remove_compression(&f.path, f.kind) {
                Ok(()) => {
                    fixed_files += 1;
                    if let (Some(before), Ok(after)) = (f.fragments, fragment_count(&f.path)) {
                        freed_fragments += before.saturating_sub(after);
                    }
                }
                Err(e) => failed.push((f.path.clone(), describe_error_at(&e, &f.path))),
            }
            pb.inc(f.logical);
        }
        pb.finish_and_clear();
    }

    // --- Abschluss ----------------------------------------------------------
    println!("\n{}", style("=== Ergebnis ===").bold());
    if dirs_todo > 0 {
        println!("  {} Ordner-Flags entfernt: {}/{}", style("✔").green(), fixed_dirs, dirs_todo);
    }
    println!(
        "  {} Dateien entpackt:      {}/{}",
        style("✔").green(),
        fixed_files,
        scan.files.len()
    );
    if freed_fragments > 0 {
        println!("  {} Fragmente abgebaut:    {}", style("✔").green(), freed_fragments);
    }

    if failed.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "\n  {} {} Element(e) konnten nicht geändert werden:",
        style("⚠").yellow().bold(),
        failed.len()
    );
    let shown = if cli.verbose { failed.len() } else { 10 };
    for (p, why) in failed.iter().take(shown) {
        println!("    - {}: {}", display_path(p), style(why).red());
    }
    if failed.len() > shown {
        println!("    … und {} weitere (-v zeigt alle)", failed.len() - shown);
    }
    Ok(ExitCode::from(EXIT_PARTIAL))
}

fn scan_tree(
    cli: &Cli,
    root_idx: usize,
    root: &Path,
    info: &RootInfo,
    excludes: &Excludes,
    scan: &mut Scan,
    spinner: &ProgressBar,
) {
    let min_bytes = cli.min_size.saturating_mul(1024 * 1024);
    // Auf exFAT/FAT/ReFS gibt es kein wof.sys – dort keine FSCTL-Abfragen pro Datei.
    let skip_wof = cli.no_wof || !info.wof_possible();

    // filter_entry verhindert auch das Absteigen in ausgeschlossene Ordner.
    let excluded = std::cell::RefCell::new(Vec::new());
    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        let attrs = e.metadata().ok().map(|m| m.file_attributes());
        let hit = e.depth() > 0 && excludes.matches(e.path(), attrs);
        if hit {
            excluded.borrow_mut().push(e.path().to_path_buf());
        }
        !hit
    });

    for entry in walker {
        scan.entries += 1;
        if scan.entries % 512 == 0 {
            spinner.set_position(scan.entries);
        }
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                scan.errors += 1;
                continue;
            }
        };
        // Auf Windows kommen die Metadaten aus den FindNextFile-Daten → kein extra Syscall.
        let meta = match entry.metadata() {
            Ok(m) => m,
            Err(_) => {
                scan.errors += 1;
                continue;
            }
        };
        let attrs = meta.file_attributes();
        if attrs & CLOUD_ATTRS != 0 {
            scan.cloud_skipped += 1;
            continue;
        }
        // Junctions, Symlinks, Dedup-Dateien usw. nicht anfassen.
        // (WOF-Dateien zeigen dieses Attribut nicht – wof.sys blendet es aus.)
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            continue;
        }
        let ntfs_compressed = attrs & FILE_ATTRIBUTE_COMPRESSED != 0;

        if meta.is_dir() {
            if ntfs_compressed {
                scan.dirs.push(entry.into_path());
            }
            continue;
        }

        let path = entry.path();
        // DirectStorage-DLLs sind klein – deshalb vor dem Größenfilter. Kein Syscall:
        // nur der Name. Ausgewertet wird nach dem Walk (Reihenfolge ist beliebig).
        if let (Some(name), Some(parent)) = (path.file_name(), path.parent()) {
            if DS_DLLS.iter().any(|d| comp_eq(name, d))
                && scan.ds_dll_dirs.last().is_none_or(|(_, p)| p != parent)
            {
                scan.ds_dll_dirs.push((root_idx, parent.to_path_buf()));
            }
        }
        let logical = meta.len();
        let small = logical < min_bytes;
        // Unter --min-size zählt nur LZNT1 (Attribut, kostenlos): sonst müsste jede
        // kleine Datei (node_modules, .git …) für die WOF-Abfrage geöffnet werden.
        if small && !ntfs_compressed {
            continue;
        }
        let write_heavy = cli.recommended && has_ext(path, WRITE_HEAVY_EXTS);
        let build_dir =
            cli.recommended && !write_heavy && in_build_dir(path, root, &mut scan.build_cache);
        if small && !write_heavy && !build_dir {
            scan.small_compressed += 1;
            continue;
        }

        // Ein Handle für WOF-Abfrage, Hardlink-Identität und Fragmente.
        let handle = open_for_query(path).ok();
        let kind = if ntfs_compressed {
            CompressionKind::Lznt1
        } else if skip_wof {
            continue;
        } else {
            match handle.as_ref().map(wof_algorithm_of) {
                Some(Ok(Some(alg))) => CompressionKind::Wof(alg),
                Some(Ok(None)) => continue,
                _ => {
                    scan.errors += 1;
                    continue;
                }
            }
        };

        // Hardlinks (z. B. Mod-Manager-Staging ↔ Spielordner) nur einmal erfassen –
        // sonst doppelt gezählt, doppelt im Platzbedarf und doppelt entpackt.
        if let Some(id) = handle.as_ref().and_then(|h| file_identity_of(h).ok()) {
            if id.links > 1 && !scan.seen_links.insert(id.key()) {
                scan.hardlink_dupes += 1;
                continue;
            }
        }

        let physical = physical_size(path).unwrap_or(logical);
        let r = ratio(physical, logical);
        let known_ext = has_ext(path, HIGH_ENTROPY_EXTS);

        // WOF ist für lese-lastige Daten (Spiele) oft sinnvoll – dort zählt nur
        // die tatsächliche Quote. Bei LZNT1 kostet jeder Schreibzugriff, daher
        // reicht auch die Endung.
        let reason = if write_heavy {
            Some(Reason::WriteHeavy)
        } else if build_dir {
            Some(Reason::BuildDir)
        } else if r >= cli.threshold {
            Some(Reason::LowSavings)
        } else if known_ext && kind == CompressionKind::Lznt1 {
            Some(Reason::Extension)
        } else if cli.all {
            Some(Reason::Forced)
        } else {
            None
        };

        match reason {
            Some(reason) => {
                spinner.set_message(display_path(path));
                // Bei WOF liegen die Daten im Stream ::WofCompressedData – die
                // Extents des (sparse) Hauptstreams wären bedeutungslos.
                let fragments = if cli.no_fragments || kind != CompressionKind::Lznt1 {
                    None
                } else {
                    match &handle {
                        Some(h) => fragment_count_of(h).ok(),
                        None => fragment_count(path).ok(),
                    }
                };
                scan.files.push(Candidate {
                    root: root_idx,
                    path: path.to_path_buf(),
                    logical,
                    physical,
                    kind,
                    reason,
                    fragments,
                });
            }
            None => {
                scan.kept_files += 1;
                scan.kept_bytes_saved += logical.saturating_sub(physical);
                // WOF unter --min-size bleibt bewusst außen vor: sonst müsste jede
                // kleine Datei für FSCTL_GET_EXTERNAL_BACKING geöffnet werden.
                if let CompressionKind::Wof(_) = kind {
                    scan.kept_wof.push(Candidate {
                        root: root_idx,
                        path: path.to_path_buf(),
                        logical,
                        physical,
                        kind,
                        reason: Reason::DirectStorage,
                        fragments: None,
                    });
                }
            }
        }
    }
    scan.excluded.extend(excluded.into_inner());
}

fn report_volume(info: &RootInfo) {
    match &info.vol {
        Some(v) if !v.fs_name.eq_ignore_ascii_case("NTFS") => println!(
            "      {} Dateisystem {}: WOF/CompactOS gibt es nur auf NTFS – WOF-Prüfung entfällt{}.",
            style("ℹ").blue(),
            v.fs_name,
            if v.supports_compression { "" } else { ", Datei-Komprimierung ebenfalls nicht unterstützt" }
        ),
        Some(v) if !v.supports_compression => println!(
            "      {} NTFS mit Clustern > 4 KiB: klassische NTFS-Komprimierung ist dort nicht möglich, \
             WOF/CompactOS wird trotzdem geprüft.",
            style("ℹ").blue()
        ),
        Some(_) => {}
        None => println!("      {} Volume-Info nicht lesbar", style("⚠").yellow()),
    }
    if let Some(d) = &info.dev {
        let kind = match d.seek_penalty {
            Some(true) => "HDD",
            Some(false) => "SSD",
            None => "Datenträger",
        };
        let bus = d.bus.map(|b| format!("{b}-")).unwrap_or_default();
        let product = d.product.as_deref().map(|p| format!(" ({p})")).unwrap_or_default();
        println!("      {}", style(format!("Datenträger: {bus}{kind}{product}")).dim());
    }
}

/// ⚠/ℹ-Blöcke der Speichermedium-Regeln (nach der Übersicht).
fn print_storage_notes(notes: &StorageNotes) {
    for (g, n, bytes) in &notes.ds_kept {
        println!(
            "\n  {} DirectStorage erkannt: {}",
            style("⚠").yellow().bold(),
            style(display_path(g)).bold()
        );
        println!(
            "      {} WOF-Datei(en) ({}) bleiben komprimiert. Auf NVMe verhindert WOF den",
            n,
            format_size(*bytes, BINARY)
        );
        println!("      BypassIO-Pfad (Windows 11) und bremst die Dekompression.");
        println!(
            "      Entpacken: {}  (alles im Spiel: ntfs-unthrottle \"{}\" --all --fix)",
            style("--recommended").yellow(),
            display_path(g)
        );
    }
    for NvmeHeavy { vol, total, dirs } in &notes.nvme_heavy {
        println!(
            "\n  {} NVMe {}: {} in LZX/XPRESS16K-Dateien bleiben komprimiert. Auf schnellen",
            style("ℹ").blue().bold(),
            display_path(vol),
            format_size(*total, BINARY)
        );
        println!("      NVMe-SSDs kann die Dekompression langsamer sein als die Rohleserate.");
        println!("      Wem Ladezeit wichtiger ist als Platz: ntfs-unthrottle \"<Ordner>\" --all --fix");
        for (d, b) in dirs {
            println!("        {:>10}  {}", format_size(*b, BINARY), display_path(d));
        }
    }
}

fn print_report(cli: &Cli, scan: &Scan, notes: &StorageNotes, took: Duration) {
    let logical: u64 = scan.files.iter().map(|f| f.logical).sum();
    let physical: u64 = scan.files.iter().map(|f| f.physical).sum();

    println!(
        "\n{} Analyse ({} Einträge in {:.1} s)",
        style("[2/3]").bold().cyan(),
        scan.entries,
        took.as_secs_f64()
    );
    println!(
        "  • Komprimierte Ordner (Vererbung):  {}{}",
        style(scan.dirs.len()).yellow().bold(),
        if cli.keep_dir_flags { "  (--keep-dir-flags: bleiben)" } else { "" }
    );
    println!("  • Ausgebremste Dateien:             {}", style(scan.files.len()).yellow().bold());
    if !scan.files.is_empty() {
        println!(
            "  • Datenvolumen:                     {} logisch / {} physisch",
            format_size(logical, BINARY),
            format_size(physical, BINARY)
        );
        println!(
            "  • Zusätzlicher Platzbedarf:         {}",
            style(format_size(logical.saturating_sub(physical), BINARY)).bold()
        );
    }
    if scan.kept_files > 0 {
        println!(
            "  • Sinnvoll komprimiert (bleibt):    {} Dateien, sparen {}",
            scan.kept_files,
            format_size(scan.kept_bytes_saved, BINARY)
        );
    }
    // Bewusst außerhalb von `kept_files > 0`: Hat --recommended alle WOF-Dateien
    // verschoben, ist kept_files 0 – die Zeile soll trotzdem erscheinen.
    for (g, n) in &notes.ds_moved {
        println!(
            "  • DirectStorage erkannt:            {} – {} WOF-Datei(en) werden entpackt",
            display_path(g),
            n
        );
    }
    if scan.small_compressed > 0 {
        println!(
            "  • Komprimiert, aber < {} MiB:        {} (ignoriert)",
            cli.min_size, scan.small_compressed
        );
        if !cli.recommended && !cli.all {
            println!(
                "    {}",
                style("Tipp: --recommended erfasst Build-Ordner, VM-Images & Datenbanken auch darunter.")
                    .dim()
            );
        }
    }
    if scan.hardlink_dupes > 0 {
        println!("  • Hardlink-Duplikate übersprungen:  {}", scan.hardlink_dupes);
    }
    if scan.cloud_skipped > 0 {
        println!("  • Cloud-Platzhalter übersprungen:   {}", scan.cloud_skipped);
    }
    if !scan.excluded.is_empty() {
        let names: Vec<String> = scan
            .excluded
            .iter()
            .take(if cli.verbose { usize::MAX } else { 6 })
            .map(|p| display_path(p))
            .collect();
        let more = scan.excluded.len().saturating_sub(names.len());
        println!(
            "  • Ausgeschlossen:                   {}{}",
            names.join(", "),
            if more > 0 { format!(" … (+{more})") } else { String::new() }
        );
    }
    if scan.errors > 0 {
        println!("  • Nicht lesbare Pfade:              {}", style(scan.errors).dim());
    }
    print_storage_notes(notes);

    if !scan.files.is_empty() {
        let shown = if cli.verbose { scan.files.len() } else { 10 };
        println!("\n  {:>10}  {:>6}  {:<15} {:>9}  {:<14} Pfad", "Größe", "phys.", "Art", "Fragm.", "Grund");
        for f in scan.files.iter().take(shown) {
            println!(
                "  {:>10}  {:>5.1}%  {:<15} {:>9}  {:<14} {}",
                format_size(f.logical, BINARY),
                f.ratio(),
                f.kind.to_string(),
                f.fragments.map_or_else(|| "–".into(), |n| n.to_string()),
                f.reason.label(),
                display_path(&f.path)
            );
        }
        if scan.files.len() > shown {
            println!("  … und {} weitere (-v zeigt alle)", scan.files.len() - shown);
        }
    }

    if cli.verbose && !scan.dirs.is_empty() {
        println!("\n  Komprimierte Ordner:");
        for d in &scan.dirs {
            println!("    {}", display_path(d));
        }
    }
}

/// Prüft je Volume, ob genug Platz zum Entpacken frei ist (+ 256 MiB bzw. 1 % Puffer).
/// Das Volume wird einmal je Scan-Pfad ermittelt (Junctions/Mount-Punkte
/// werden beim Scan nicht verfolgt, alle Dateien eines Pfads liegen also darauf).
fn check_free_space(roots: &[PathBuf], files: &[Candidate]) -> io::Result<()> {
    let vols: Vec<Option<VolumeInfo>> = roots.iter().map(|r| volume_info(r).ok()).collect();
    let mut need: BTreeMap<PathBuf, (u64, Option<VolumeInfo>)> = BTreeMap::new();
    for f in files {
        let Some(v) = &vols[f.root] else { continue };
        let e = need.entry(v.root.clone()).or_insert((0, Some(v.clone())));
        e.0 += f.logical.saturating_sub(f.physical);
    }
    for (root, (bytes, info)) in need {
        let Some(info) = info else { continue };
        let margin = (256 * 1024 * 1024).max(bytes / 100);
        if info.free_bytes < bytes + margin {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                format!(
                    "Nicht genug Platz auf {}: frei {}, benötigt inkl. Puffer {}",
                    display_path(&root),
                    format_size(info.free_bytes, BINARY),
                    format_size(bytes + margin, BINARY)
                ),
            ));
        }
    }
    Ok(())
}

fn confirm(prompt: &str) -> io::Result<bool> {
    if !io::stdin().is_terminal() {
        return Err(io::Error::other(
            "Keine interaktive Konsole – zum Bestätigen --yes angeben.",
        ));
    }
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(matches!(input.trim().to_ascii_lowercase().as_str(), "j" | "ja" | "y" | "yes"))
}

fn file_name(p: &Path) -> String {
    p.file_name().unwrap_or_default().to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    fn game(dll_dir: &str, vol: Option<&str>) -> Option<PathBuf> {
        ds_game_root(Path::new(dll_dir), vol.map(Path::new))
    }

    #[test]
    fn game_root_steam_marker() {
        assert_eq!(
            game(r"E:\SteamLibrary\steamapps\common\Spiel\Engine\Binaries\ThirdParty\Win64", None),
            Some(p(r"E:\SteamLibrary\steamapps\common\Spiel"))
        );
        // Groß-/Kleinschreibung egal
        assert_eq!(
            game(r"E:\SteamApps\Common\Spiel\bin", None),
            Some(p(r"E:\SteamApps\Common\Spiel"))
        );
    }

    #[test]
    fn game_root_other_launchers() {
        assert_eq!(game(r"D:\EA Games\Spiel\Data\Win64", None), Some(p(r"D:\EA Games\Spiel")));
        assert_eq!(
            game(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Spiel\bin", None),
            Some(p(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Spiel"))
        );
        assert_eq!(game(r"D:\GOG Galaxy\Games\Spiel", None), Some(p(r"D:\GOG Galaxy\Games\Spiel")));
        assert_eq!(game(r"D:\XboxGames\Spiel\Content", None), Some(p(r"D:\XboxGames\Spiel")));
    }

    #[test]
    fn game_root_unreal() {
        assert_eq!(game(r"E:\Games\Spiel\Spiel\Binaries\Win64", None), Some(p(r"E:\Games\Spiel")));
        assert_eq!(
            game(r"E:\Games\Spiel\Engine\Binaries\ThirdParty\DirectStorage\Win64", None),
            Some(p(r"E:\Games\Spiel"))
        );
        // Ohne Engine-Ordner kein UE-Doppelordner-Sprung
        assert_eq!(game(r"E:\Games\Spiel\Spiel", None), Some(p(r"E:\Games\Spiel\Spiel")));
    }

    #[test]
    fn game_root_content_dir() {
        // MS-Store/XboxGames-artig ohne Marker
        assert_eq!(game(r"E:\Games\Spiel\Content", None), Some(p(r"E:\Games\Spiel")));
        assert_eq!(game(r"E:\Games\Spiel\Content\bin", None), Some(p(r"E:\Games\Spiel")));
    }

    /// Temporärer Ordner, der beim Drop gelöscht wird.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir()
                .join(format!("ntfs-unthrottle-test-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Self(d)
        }

        fn file(&self, rel: &str) -> PathBuf {
            let f = self.0.join(rel);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(&f, b"x").unwrap();
            f
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn build(path: &Path, root: &Path) -> bool {
        in_build_dir(path, root, &mut HashMap::new())
    }

    #[test]
    fn build_dir_generic_needs_project_marker() {
        let t = TempDir::new("marker");
        // Echtes Projekt: package.json neben dist
        t.file(r"proj\package.json");
        let js = t.file(r"proj\dist\a.js");
        assert!(build(&js, &t.0));
        // Spielordner ohne Marker: dist/build zählen nicht
        let pak = t.file(r"Games\Titel\dist\a.pak");
        assert!(!build(&pak, &t.0));
        let bin = t.file(r"Games\Titel\build\data\x.bin");
        assert!(!build(&bin, &t.0));
        // .sln-Marker (Endung, Groß-/Kleinschreibung egal)
        t.file(r"vs\Loesung.SLN");
        assert!(build(&t.file(r"vs\build\out.dll"), &t.0));
        // target nur mit Cargo.toml, nicht mit package.json
        t.file(r"rs\Cargo.toml");
        assert!(build(&t.file(r"rs\target\debug\x.rlib"), &t.0));
        t.file(r"web\package.json");
        assert!(!build(&t.file(r"web\target\x"), &t.0));
        // Spezifische Namen ohne Marker
        assert!(build(&t.file(r"Games\Titel\node_modules\m\i.js"), &t.0));
    }

    #[test]
    fn build_dir_ignores_folders_above_scan_root() {
        let t = TempDir::new("above");
        let f = t.file(r"node_modules\Spiele\Titel\a.pak");
        // Scan-Root liegt UNTER node_modules → nicht als Build-Ordner werten
        assert!(!build(&f, &t.0.join(r"node_modules\Spiele")));
        // Scan-Root ist der Build-Ordner selbst → zählt
        assert!(build(&f, &t.0.join("node_modules")));
    }

    #[test]
    fn game_root_unity() {
        assert_eq!(
            game(r"E:\Games\Spiel\Spiel_Data\Plugins\x86_64", None),
            Some(p(r"E:\Games\Spiel"))
        );
        // _Data nur direkt über Plugins
        assert_eq!(game(r"E:\Games\Spiel\Foo_Data\bin", None), Some(p(r"E:\Games\Spiel\Foo_Data")));
    }

    #[test]
    fn game_root_volume_guards() {
        // DLL direkt in der Wurzel → nichts markieren
        assert_eq!(game(r"E:\", None), None);
        // Aufstieg bis zur Wurzel → DLL-Ordner selbst
        assert_eq!(game(r"E:\Binaries", None), Some(p(r"E:\Binaries")));
        // Mount-Punkt ohne Laufwerksbuchstaben
        assert_eq!(game(r"C:\Games\Binaries", Some(r"C:\Games\")), Some(p(r"C:\Games\Binaries")));
        assert_eq!(game(r"C:\Games", Some(r"C:\Games")), None);
        // Verbatim-Präfix vs. Volume-Wurzel ohne Präfix
        assert_eq!(
            game(r"\\?\C:\Games\Binaries", Some(r"C:\Games\")),
            Some(p(r"\\?\C:\Games\Binaries"))
        );
        assert_eq!(
            game(r"\\?\E:\Games\Spiel\Binaries\Win64", Some(r"E:\")),
            Some(p(r"\\?\E:\Games\Spiel"))
        );
    }

    #[test]
    fn game_root_marker_edge_cases() {
        // DLL direkt im Marker-Ordner → Regel 2, Ordner selbst
        assert_eq!(game(r"E:\steamapps\common", None), Some(p(r"E:\steamapps\common")));
        // Kein Substring-Treffer
        assert_eq!(
            game(r"E:\backup_steamapps_common_old\Spiel\bin", None),
            Some(p(r"E:\backup_steamapps_common_old\Spiel"))
        );
        assert_eq!(
            game(r"E:\My SteamApps Backup\common\Spiel\bin", None),
            Some(p(r"E:\My SteamApps Backup\common\Spiel"))
        );
    }

    #[test]
    fn under_is_component_wise_and_case_insensitive() {
        assert!(under(Path::new(r"E:\Games\SpielA\x.bin"), Path::new(r"e:\games\spiela")));
        assert!(under(Path::new(r"E:\Spiele\Übung\a"), Path::new(r"e:\spiele\übung")));
        assert!(under(Path::new(r"\\?\E:\Games\SpielA"), Path::new(r"E:\Games")));
        assert!(!under(Path::new(r"E:\Games\SpielAB\x"), Path::new(r"E:\Games\SpielA")));
        assert!(!under(Path::new(r"E:\Games"), Path::new(r"E:\Games\SpielA")));
        assert!(!under(Path::new(r"F:\Games\SpielA"), Path::new(r"E:\Games")));
    }

    #[test]
    fn dedup_roots_drops_contained_paths() {
        let (kept, dropped) = dedup_roots(vec![p(r"E:\Games\SpielA"), p(r"E:\Games")]);
        assert_eq!(kept, vec![p(r"E:\Games")]);
        assert_eq!(dropped, vec![(p(r"E:\Games\SpielA"), p(r"E:\Games"))]);

        let (kept, _) = dedup_roots(vec![p(r"E:\Games"), p(r"E:\Games")]);
        assert_eq!(kept, vec![p(r"E:\Games")]);

        let (kept, _) = dedup_roots(vec![p(r"E:\games"), p(r"E:\Games\x")]);
        assert_eq!(kept, vec![p(r"E:\games")]);

        let (kept, _) = dedup_roots(vec![p(r"E:\Games\SpielA"), p(r"E:\Games\SpielAB")]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn group_dir_uses_full_path() {
        assert_eq!(
            group_dir(Path::new(r"E:\Games"), Path::new(r"E:\Games\SpielB\data\a.bin")),
            p(r"E:\Games\SpielB")
        );
        // Datei direkt im Scan-Root → Scan-Root selbst
        assert_eq!(
            group_dir(Path::new(r"E:\Games\SpielB"), Path::new(r"E:\Games\SpielB\a.bin")),
            p(r"E:\Games\SpielB")
        );
        // Scan-Root ist die Datei selbst
        assert_eq!(group_dir(Path::new(r"E:\a.bin"), Path::new(r"E:\a.bin")), p(r"E:\a.bin"));
        // Zwei Scan-Roots mit gleichnamigem Unterordner bleiben getrennt
        assert_ne!(
            group_dir(Path::new(r"E:\Games"), Path::new(r"E:\Games\Shared\a")),
            group_dir(Path::new(r"E:\Backup"), Path::new(r"E:\Backup\Shared\a"))
        );
    }
}
