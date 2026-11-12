#[cfg(not(windows))]
compile_error!(
    "the ntfs-unthrottle CLI only supports Windows – use the library with default-features = false"
);

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::ExitCode;
use std::time::{Duration, Instant};

mod i18n;
mod optimize;

use clap::Parser;
use console::style;
use humansize::{format_size, BINARY};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

use i18n::{tr, LangChoice};
use ntfs_unthrottle::{
    compressed_ancestors, display_path, file_identity_of, fragment_count,
    fragment_count_of, open_for_query, physical_size, remove_compression, remove_ntfs_compression,
    volume_info, wof_algorithm_of, CompressionKind, VolumeInfo, WofAlgorithm,
};
use ntfs_unthrottle::tune::{device_info, DeviceInfo};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS,
    FILE_ATTRIBUTE_RECALL_ON_OPEN, FILE_ATTRIBUTE_REPARSE_POINT,
};

/// Placeholders of OneDrive & co. – opening them with write access would download them.
const CLOUD_ATTRS: u32 =
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN;

/// Known high-entropy formats (already compressed or encrypted).
const HIGH_ENTROPY_EXTS: &[&str] = &[
    // Compressed / encrypted binary containers
    "xci", "xcz", "nsp", "nsz", "nca", "ncz",
    // Archives
    "zip", "7z", "rar", "zst", "gz", "xz", "bz2", "lz4", "cab", "msi",
    // Media
    "mp4", "mkv", "webm", "mov", "avi", "mp3", "flac", "ogg", "opus", "jpg", "jpeg", "png", "webp", "heic",
    // Disk images & game asset containers
    "iso", "chd", "rvz", "wbfs", "cso", "pak", "ucas", "utoc", "bundle", "vpk",
    // Encrypted containers
    "hc", "tc", "vc", "kdbx", "gpg",
];

/// --recommended: formats with many (random) writes. Compression fragments
/// them heavily (up to ERROR_FILE_SYSTEM_LIMITATION) – always decompress.
const WRITE_HEAVY_EXTS: &[&str] = &[
    // VM images & snapshots
    "vhd", "vhdx", "avhdx", "vmdk", "vdi", "qcow2", "vmem", "vmsn", "vmss", "nvram",
    // Databases
    "db", "db-wal", "db-shm", "sqlite", "sqlite3", "mdf", "ldf", "ndf", "edb", "ibd",
    "mdb", "accdb", "ldb", "pst", "ost",
    // Incomplete downloads (written block by block in random order)
    "part", "partial", "crdownload", "!qb", "!ut", "aria2",
];

/// --recommended: build/tooling folders with many small, constantly rewritten
/// files – everything inside is decompressed, regardless of size/ratio.
/// These names are unambiguous enough to count without further checks.
const BUILD_DIRS: &[&str] = &[
    "node_modules", ".git", ".vs", ".idea", "__pycache__", ".venv", "venv",
    ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".gradle", ".next", ".nuxt",
    ".turbo", ".parcel-cache", ".angular", ".svelte-kit", ".cargo",
    ".rustup", ".nuget", ".m2", "go-build", "ccache", ".ccache",
];

/// Project markers (files or folders, `*.ext` = any name with that extension).
const PROJECT_MARKERS: &[&str] = &[
    "package.json", "Cargo.toml", "pyproject.toml", "CMakeLists.txt", "Makefile", ".git", "*.sln",
];

/// Generic names that also occur in game folders (`Game\dist`, `Game\build`).
/// They only count if the direct parent folder contains a matching project marker.
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

/// Does `dir` contain one of the `markers`? (Case-insensitive.)
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

/// Is `path` located below a build/tooling folder? Only the scan root `root`
/// and folders below it are checked – not what lies above
/// (`E:\target\Games` as scan path does not turn everything into a build folder).
/// `cache` remembers the marker result per generic folder.
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
    about = "Removes invisible I/O bottlenecks caused by transparent NTFS/WOF compression.",
    after_help = "Exit codes: 0 = nothing to do/all fixed, 1 = error, \
                  2 = dry-run found candidates, 3 = some items failed."
)]
struct Cli {
    /// Folders or files to check
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,

    /// Actually apply changes (without: analysis only)
    #[arg(short, long)]
    fix: bool,

    /// Skip the confirmation prompt (for scripts)
    #[arg(short, long, requires = "fix")]
    yes: bool,

    /// Minimum file size in MiB
    #[arg(long, value_name = "MiB", default_value_t = 16)]
    min_size: u64,

    /// Physical size in % of the logical size from which compression counts as useless
    #[arg(long, value_name = "PERCENT", default_value_t = 90.0, value_parser = parse_percent)]
    threshold: f64,

    /// Include every compressed file from the minimum size on (extension/ratio irrelevant)
    #[arg(long, conflicts_with = "recommended")]
    all: bool,

    /// Recommended selection: like the default, plus always VM images, databases,
    /// incomplete downloads, everything in build folders (node_modules, target, .git, …)
    /// and WOF files in DirectStorage games on NVMe
    #[arg(long, visible_alias = "recommend")]
    recommended: bool,

    /// Do NOT clear the compression flag of folders
    #[arg(long)]
    keep_dir_flags: bool,

    /// Skip WOF/CompactOS detection (saves one open per large file)
    #[arg(long)]
    no_wof: bool,

    /// Do not determine the fragment count
    #[arg(long)]
    no_fragments: bool,

    /// List all candidates and folders instead of only the largest
    #[arg(short, long)]
    verbose: bool,

    /// Optimizer: check storage device, MFT, 8.3 names, last access and TRIM of the volumes
    /// (with --fix, apply safe fixes via fsutil). Does not scan files.
    #[arg(long)]
    optimize: bool,

    /// Exclude: name (e.g. node_modules – matches at any depth) or path (e.g. E:\Backup).
    /// Repeatable. System folders are always protected.
    #[arg(short = 'x', long = "exclude", value_name = "NAME|PATH")]
    exclude: Vec<String>,

    /// Output language of runtime messages (auto = LC_ALL/LC_MESSAGES/LANG,
    /// then the Windows UI language). --help is always English.
    #[arg(long, value_enum, value_name = "LANG", default_value_t = LangChoice::Auto)]
    lang: LangChoice,
}

// Poka-yoke: these lists are intentionally NOT configurable. They apply while
// walking, to directly given paths and to everything below them.

/// Protected system folders – at any depth.
const PROTECTED_ANYWHERE: &[&str] = &[
    "$recycle.bin",              // Recycle bin
    "system volume information", // Shadow copies, restore points, indexer
    "config.msi",                // Windows Installer rollback
    "windowsapps",               // Store apps (TrustedInstaller, signed packages)
    "wpsystem",                  // Store app data on secondary drives
    "wudownloadcache",           // Windows Update cache
    "$winreagent",
    "$windows.~bt",
    "$windows.~ws",
    "$sysreset",
    "$getcurrent",
    "msocache",                  // Office installation source
];

/// Protected when located directly in the drive root.
const PROTECTED_AT_ROOT: &[&str] = &[
    "windows", "recovery", "boot", "efi", "bootmgr", "pagefile.sys", "swapfile.sys",
    "hiberfil.sys", "dumpstack.log", "dumpstack.log.tmp", "boottel.dat",
];

/// Safety net for the unknown: whatever is hidden AND system in the drive root
/// belongs to Windows.
const HIDDEN_SYSTEM: u32 = FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM;

/// Why a path is protected (localized in `i18n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protected {
    SystemFolder,
    RootSystemItem,
    RootHiddenSystem,
}

/// Is `path` located directly in a drive root? (`\\?\E:\` itself has no parent.)
fn is_at_volume_root(path: &Path) -> bool {
    path.parent().is_some_and(|p| p.parent().is_none())
}

/// Checks only the last component of `path`. `attrs` = file attributes, if known.
fn protected_reason(path: &Path, attrs: Option<u32>) -> Option<Protected> {
    let name = path.file_name()?.to_string_lossy().to_lowercase();
    if PROTECTED_ANYWHERE.contains(&name.as_str()) {
        return Some(Protected::SystemFolder);
    }
    if is_at_volume_root(path) {
        if PROTECTED_AT_ROOT.contains(&name.as_str()) {
            return Some(Protected::RootSystemItem);
        }
        if attrs.is_some_and(|a| a & HIDDEN_SYSTEM == HIDDEN_SYSTEM) {
            return Some(Protected::RootHiddenSystem);
        }
    }
    None
}

/// Checks `path` and all of its ancestors – for directly given paths.
fn protected_path(path: &Path) -> Option<(PathBuf, Protected)> {
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
                    // What does not exist cannot be scanned either – no reason to abort.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        println!("{} {}", style("ℹ").blue().bold(), tr().exclude_missing(x));
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
    let v: f64 = s.trim_end_matches('%').parse().map_err(|_| format!("not a number: {s}"))?;
    if (0.0..=100.0).contains(&v) {
        Ok(v)
    } else {
        Err("must be between 0 and 100".into())
    }
}

/// Why a file is selected for decompression (localized in `i18n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    Extension,
    LowSavings,
    WriteHeavy,
    BuildDir,
    DirectStorage,
    Forced,
}

struct Candidate {
    /// Index of the scan path (for the volume mapping).
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
    /// Already recorded files with multiple hardlinks: (volume serial, file index).
    seen_links: HashSet<(u32, u64)>,
    hardlink_dupes: u64,
    /// Marker result per generic build folder (`build`, `dist`, …).
    build_cache: HashMap<PathBuf, bool>,
    /// Folders containing `dstorage.dll`/`dstoragecore.dll` (scan root index, folder).
    ds_dll_dirs: Vec<(usize, PathBuf)>,
    /// Kept WOF files (≥ --min-size) for the storage media rules.
    /// `reason` is only a placeholder – it is set when the file is moved.
    kept_wof: Vec<Candidate>,
}

/// Volume and storage device of a scan root – determined once.
#[derive(Default)]
struct RootInfo {
    vol: Option<VolumeInfo>,
    dev: Option<DeviceInfo>,
}

impl RootInfo {
    fn new(root: &Path) -> Self {
        // device_info needs the volume root or mount point –
        // on a subfolder (E:\Games) it would silently fail.
        let vol = volume_info(root).ok();
        let dev = vol.as_ref().and_then(|v| device_info(&v.root).ok());
        Self { vol, dev }
    }

    fn vol_root(&self) -> Option<&Path> {
        self.vol.as_ref().map(|v| v.root.as_path())
    }

    /// WOF (`wof.sys`) only exists on NTFS – independent of `supports_compression`
    /// (NTFS with clusters > 4 KiB cannot do LZNT1, but WOF works).
    /// Unknown volume → check to be safe.
    fn wof_possible(&self) -> bool {
        self.vol.as_ref().is_none_or(|v| v.fs_name.eq_ignore_ascii_case("NTFS"))
    }

    /// Only real NVMe – RAID, Storage Spaces, USB enclosures do not count (no BypassIO).
    fn is_nvme(&self) -> bool {
        self.dev.as_ref().is_some_and(|d| d.bus == Some("NVMe"))
    }
}

// --- Path comparisons (NTFS is case-insensitive) ----------------------------

/// Normalized component name (Unicode lowercase, so `Übung` = `übung` as well).
fn fold(s: &std::ffi::OsStr) -> String {
    s.to_string_lossy().to_lowercase()
}

/// Path as a normalized component list. `\\?\C:\x` and `C:\x` yield the same.
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

/// Is `path` inside `base` (or `base` itself)? Compared per component,
/// so `GameAB` is not inside `GameA`.
fn under(path: &Path, base: &Path) -> bool {
    let (p, b) = (norm(path), norm(base));
    p.len() >= b.len() && p[..b.len()] == b[..]
}

fn same_path(a: &Path, b: &Path) -> bool {
    norm(a) == norm(b)
}

/// Compares a component name with an already lowercased name.
fn comp_eq(a: &std::ffi::OsStr, lower: &str) -> bool {
    fold(a) == lower
}

/// Removes paths contained in another (or the same) path.
/// Returns the kept and the dropped paths (together with the containing path).
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

// --- DirectStorage detection -----------------------------------------------

/// Games have to ship DirectStorage themselves – the names are fixed.
const DS_DLLS: &[&str] = &["dstorage.dll", "dstoragecore.dll"];

/// Folders of game libraries (lowercase); the folder after them is the game.
const LIBRARY_MARKERS: &[&[&str]] = &[
    &["steamapps", "common"],
    &["xboxgames"],
    &["epic games"],
    &["gog games"],
    &["gog galaxy", "games"],
    &["ea games"],
    &["ubisoft game launcher", "games"],
];

/// Engine/binary subfolders used to climb from the DLL folder to the game root.
const ENGINE_DIRS: &[&str] = &[
    "binaries", "win64", "win32", "wingdk", "x64", "x86", "x86_64", "arm64", "bin", "bin64",
    "shipping", "retail", "windows", "windowsnoeditor", "redist", "thirdparty", "directstorage",
    "engine", "plugins", "content",
];

/// Volume root or mount point reached?
fn is_vol_root(cur: &Path, vol_root: Option<&Path>) -> bool {
    cur.file_name().is_none() || vol_root.is_some_and(|vr| same_path(cur, vr))
}

/// Does `p` end with exactly these (lowercase) components?
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

/// Derives the game folder from the folder of a DirectStorage DLL – pure
/// path logic. `None` if the DLL lies directly in a volume root.
fn ds_game_root(dll_dir: &Path, vol_root: Option<&Path>) -> Option<PathBuf> {
    if is_vol_root(dll_dir, vol_root) {
        return None;
    }
    // 1. Known library: first folder after the marker.
    for a in dll_dir.ancestors() {
        if is_vol_root(a, vol_root) {
            break;
        }
        let Some(parent) = a.parent() else { break };
        if LIBRARY_MARKERS.iter().any(|m| ends_with_names(parent, m)) {
            return Some(a.to_path_buf());
        }
    }
    // 2. Climb up through engine folders.
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
    // UE: Game\Game\Binaries\Win64 → Game (also covers Game\Engine).
    if last.is_some() && !is_vol_root(cur, vol_root) {
        if let (Some(name), Some(parent)) = (cur.file_name(), cur.parent()) {
            if !is_vol_root(parent, vol_root)
                && parent.file_name().is_some_and(|pn| fold(pn) == fold(name))
            {
                cur = parent;
            }
        }
    }
    // 3. Never mark an entire volume.
    if is_vol_root(cur, vol_root) {
        return Some(dll_dir.to_path_buf());
    }
    Some(cur.to_path_buf())
}

/// Results of the storage media rules for the report.
#[derive(Default)]
struct StorageNotes {
    /// Without --recommended: (game root, files, logical bytes) that stay compressed.
    ds_kept: Vec<(PathBuf, u64, u64)>,
    /// With --recommended: (game root, files) scheduled for decompression.
    ds_moved: Vec<(PathBuf, u64)>,
    /// NVMe hint per volume.
    nvme_heavy: Vec<NvmeHeavy>,
}

/// Lots of LZX/XPRESS16K on an NVMe volume (without DirectStorage hits).
struct NvmeHeavy {
    vol: PathBuf,
    total: u64,
    /// Up to 3 largest folders (full path) with bytes.
    dirs: Vec<(PathBuf, u64)>,
}

impl StorageNotes {
    fn any_hint(&self) -> bool {
        !self.ds_kept.is_empty() || !self.nvme_heavy.is_empty()
    }
}

/// From this much LZX/XPRESS16K per NVMe volume on, a hint is shown.
const NVME_HEAVY_WOF_BYTES: u64 = 1024 * 1024 * 1024;

/// Folder for the NVMe hint: first level below the scan root,
/// or the scan root itself if the file lies directly in it.
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

/// Applies the DirectStorage/NVMe rules to the kept WOF files.
/// Must run before `check_free_space` so that moved files are counted.
fn apply_storage_rules(cli: &Cli, scan: &mut Scan, roots: &[PathBuf], infos: &[RootInfo]) -> StorageNotes {
    let mut notes = StorageNotes::default();

    // Game roots of all scan paths, outer ones win.
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
    // Volume (normalized) → (volume path, total, bytes per folder)
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
    i18n::init(i18n::detect(cli.lang));
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
    let l = tr();
    // Canonical \\?\ paths: this way paths > 260 characters also work with
    // the raw Win32 calls.
    let mut roots = Vec::new();
    for p in &cli.paths {
        // Poka-yoke: reject directly given system paths (or paths inside them) –
        // first purely by name, because canonicalize already fails on locked
        // system paths (System Volume Information, pagefile.sys).
        let abs = std::path::absolute(p).unwrap_or_else(|_| p.clone());
        let canon = std::fs::canonicalize(p);
        let check = canon.as_deref().unwrap_or(&abs);
        if let Some((hit, why)) = protected_path(&abs).or_else(|| protected_path(check)) {
            eprintln!(
                "{} {}",
                style("⛔").red().bold(),
                l.skipped_protected(display_path(&abs), l.protected(why), display_path(&hit))
            );
            continue;
        }
        roots.push(canon.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?);
    }
    if roots.is_empty() {
        return Err(io::Error::other(l.no_paths_left()));
    }
    // Scan overlapping paths only once – otherwise duplicate candidates,
    // duplicate space requirements and duplicate decompression.
    let (roots, dropped) = dedup_roots(roots);
    for (inner, outer) in &dropped {
        println!(
            "{} {}",
            style("ℹ").blue().bold(),
            l.root_contained(display_path(inner), display_path(outer))
        );
    }
    let infos: Vec<RootInfo> = roots.iter().map(|r| RootInfo::new(r)).collect();

    // --- Phase 1: scan ----------------------------------------------------
    println!("{} {}", style("[1/3]").bold().cyan(), l.scanning_paths(roots.len()));
    for (root, info) in roots.iter().zip(&infos) {
        println!("      {}", style(display_path(root)).underlined());
        report_volume(info);
    }

    let started = Instant::now();
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(ProgressStyle::with_template(l.spinner_template()).unwrap());
    spinner.enable_steady_tick(Duration::from_millis(100));

    let excludes = Excludes::new(cli)?;
    let mut scan = Scan::default();
    for (i, (root, info)) in roots.iter().zip(&infos).enumerate() {
        scan_tree(cli, i, root, info, &excludes, &mut scan, &spinner);
    }
    spinner.finish_and_clear();
    scan.files.sort_by_key(|f| std::cmp::Reverse(f.logical));

    // --- Phase 2: evaluation ----------------------------------------------
    let notes = apply_storage_rules(cli, &mut scan, &roots, &infos);
    print_report(cli, &scan, &notes, started.elapsed());

    let ancestors: Vec<PathBuf> = {
        let mut v: Vec<PathBuf> = roots.iter().flat_map(|r| compressed_ancestors(r)).collect();
        v.sort();
        v.dedup();
        v
    };
    if !ancestors.is_empty() {
        println!("\n  {} {}", style("⚠").yellow().bold(), l.ancestors_flagged());
        for a in &ancestors {
            if a.parent().is_none() {
                // Drive root: intentionally not changed automatically.
                println!(
                    "      {}  {}",
                    display_path(a),
                    style(l.drive_root_flag_hint(display_path(a))).dim()
                );
            } else {
                println!("      {}", display_path(a));
            }
        }
    }

    let dirs_todo = if cli.keep_dir_flags { 0 } else { scan.dirs.len() };
    if dirs_todo == 0 && scan.files.is_empty() {
        println!("\n{} {}", style("✔").green().bold(), l.nothing_found(notes.any_hint()));
        return Ok(ExitCode::SUCCESS);
    }

    if !cli.fix {
        println!(
            "\n{} {}",
            style("ℹ").blue().bold(),
            l.analysis_only_fix(style("--fix").yellow().bold())
        );
        return Ok(ExitCode::from(EXIT_FOUND));
    }

    print!("\n  {}", l.checking_free_space());
    io::stdout().flush()?;
    check_free_space(&roots, &scan.files)?;
    println!(" ok");

    let prompt = format!(
        "\n{}\n{} ",
        style("─".repeat(60)).yellow(),
        style(l.confirm_decompress(scan.files.len(), dirs_todo)).yellow().bold()
    );
    if !cli.yes && !confirm(&prompt)? {
        println!("{}", l.aborted());
        return Ok(ExitCode::SUCCESS);
    }

    // --- Phase 3: cleanup ------------------------------------------------
    println!("\n{} {}", style("[3/3]").bold().cyan(), l.cleaning_up());
    let mut failed: Vec<(PathBuf, String)> = Vec::new();
    let mut fixed_dirs = 0usize;

    // Folders first: from now on new files no longer inherit anything.
    if dirs_todo > 0 {
        let pb = ProgressBar::new(dirs_todo as u64);
        pb.set_style(ProgressStyle::with_template(l.bar_dirs_template()).unwrap());
        for dir in &scan.dirs {
            match remove_ntfs_compression(dir, true) {
                Ok(()) => fixed_dirs += 1,
                Err(e) => failed.push((dir.clone(), l.describe_error_at(&e, dir))),
            }
            pb.inc(1);
        }
        pb.finish();
    }

    // Files intentionally sequential: NTFS rewrites each file synchronously.
    let mut fixed_files = 0usize;
    let mut freed_fragments = 0u64;
    if !scan.files.is_empty() {
        let total: u64 = scan.files.iter().map(|f| f.logical).sum();
        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::with_template(l.bar_files_template())
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
                Err(e) => failed.push((f.path.clone(), l.describe_error_at(&e, &f.path))),
            }
            pb.inc(f.logical);
        }
        pb.finish_and_clear();
    }

    // --- Summary --------------------------------------------------------------
    println!("\n{}", style(l.result_header()).bold());
    if dirs_todo > 0 {
        println!("  {} {:<23}{}/{}", style("✔").green(), l.result_dir_flags(), fixed_dirs, dirs_todo);
    }
    println!(
        "  {} {:<23}{}/{}",
        style("✔").green(),
        l.result_files(),
        fixed_files,
        scan.files.len()
    );
    if freed_fragments > 0 {
        println!("  {} {:<23}{}", style("✔").green(), l.result_fragments(), freed_fragments);
    }

    if failed.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    println!("\n  {} {}", style("⚠").yellow().bold(), l.items_failed(failed.len()));
    let shown = if cli.verbose { failed.len() } else { 10 };
    for (p, why) in failed.iter().take(shown) {
        println!("    - {}: {}", display_path(p), style(why).red());
    }
    if failed.len() > shown {
        println!("    {}", l.more_items(failed.len() - shown));
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
    // exFAT/FAT/ReFS have no wof.sys – no per-file FSCTL queries there.
    let skip_wof = cli.no_wof || !info.wof_possible();

    // filter_entry also prevents descending into excluded folders.
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
        // On Windows the metadata comes from the FindNextFile data → no extra syscall.
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
        // Do not touch junctions, symlinks, dedup files etc.
        // (WOF files do not show this attribute – wof.sys hides it.)
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
        // DirectStorage DLLs are small – hence before the size filter. No syscall:
        // only the name. Evaluated after the walk (the order is arbitrary).
        if let (Some(name), Some(parent)) = (path.file_name(), path.parent()) {
            if DS_DLLS.iter().any(|d| comp_eq(name, d))
                && scan.ds_dll_dirs.last().is_none_or(|(_, p)| p != parent)
            {
                scan.ds_dll_dirs.push((root_idx, parent.to_path_buf()));
            }
        }
        let logical = meta.len();
        let small = logical < min_bytes;
        // Below --min-size only LZNT1 counts (attribute, free): otherwise every
        // small file (node_modules, .git …) would have to be opened for the WOF query.
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

        // One handle for the WOF query, hardlink identity and fragments.
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

        // Record hardlinks (e.g. mod manager staging ↔ game folder) only once –
        // otherwise counted twice, needed twice in space and decompressed twice.
        if let Some(id) = handle.as_ref().and_then(|h| file_identity_of(h).ok()) {
            if id.links > 1 && !scan.seen_links.insert(id.key()) {
                scan.hardlink_dupes += 1;
                continue;
            }
        }

        let physical = physical_size(path).unwrap_or(logical);
        let r = ratio(physical, logical);
        let known_ext = has_ext(path, HIGH_ENTROPY_EXTS);

        // WOF often makes sense for read-heavy data (games) – there only the
        // actual ratio counts. With LZNT1 every write costs, so the extension
        // is enough as well.
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
                // With WOF the data lives in the ::WofCompressedData stream – the
                // extents of the (sparse) main stream would be meaningless.
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
                // WOF below --min-size is intentionally left out: otherwise every
                // small file would have to be opened for FSCTL_GET_EXTERNAL_BACKING.
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
    let l = tr();
    match &info.vol {
        Some(v) if !v.fs_name.eq_ignore_ascii_case("NTFS") => println!(
            "      {} {}",
            style("ℹ").blue(),
            l.fs_without_wof(&v.fs_name, v.supports_compression)
        ),
        Some(v) if !v.supports_compression => {
            println!("      {} {}", style("ℹ").blue(), l.ntfs_large_clusters());
        }
        Some(_) => {}
        None => println!("      {} {}", style("⚠").yellow(), l.volume_info_unreadable()),
    }
    if let Some(d) = &info.dev {
        let kind = match d.seek_penalty {
            Some(true) => "HDD",
            Some(false) => "SSD",
            None => l.generic_drive(),
        };
        let bus = d.bus.map(|b| format!("{}-", l.bus(b))).unwrap_or_default();
        let product = d.product.as_deref().map(|p| format!(" ({p})")).unwrap_or_default();
        println!("      {}", style(l.drive_line(format!("{bus}{kind}{product}"))).dim());
    }
}

/// ⚠/ℹ blocks of the storage media rules (after the summary).
fn print_storage_notes(notes: &StorageNotes) {
    let l = tr();
    for (g, n, bytes) in &notes.ds_kept {
        println!(
            "\n  {} {}",
            style("⚠").yellow().bold(),
            l.ds_detected(style(display_path(g)).bold())
        );
        println!("{}", l.ds_kept_body(*n, format_size(*bytes, BINARY)));
        println!(
            "      {}",
            l.ds_decompress_hint(style("--recommended").yellow(), display_path(g))
        );
    }
    for NvmeHeavy { vol, total, dirs } in &notes.nvme_heavy {
        println!(
            "\n  {} {}",
            style("ℹ").blue().bold(),
            l.nvme_heavy(display_path(vol), format_size(*total, BINARY))
        );
        println!("{}", l.nvme_heavy_body());
        for (d, b) in dirs {
            println!("        {:>10}  {}", format_size(*b, BINARY), display_path(d));
        }
    }
}

/// One summary row: `  • <label padded> <value>`.
fn row(label: &str, value: impl std::fmt::Display) {
    println!("  • {label:<34}{value}");
}

fn print_report(cli: &Cli, scan: &Scan, notes: &StorageNotes, took: Duration) {
    let l = tr();
    let logical: u64 = scan.files.iter().map(|f| f.logical).sum();
    let physical: u64 = scan.files.iter().map(|f| f.physical).sum();

    println!(
        "\n{} {}",
        style("[2/3]").bold().cyan(),
        l.analysis_header(scan.entries, took.as_secs_f64())
    );
    row(
        l.lbl_compressed_dirs(),
        format!(
            "{}{}",
            style(scan.dirs.len()).yellow().bold(),
            if cli.keep_dir_flags { l.keep_dir_flags_note() } else { "" }
        ),
    );
    row(l.lbl_throttled_files(), style(scan.files.len()).yellow().bold());
    if !scan.files.is_empty() {
        row(
            l.lbl_data_volume(),
            l.data_volume(format_size(logical, BINARY), format_size(physical, BINARY)),
        );
        row(
            l.lbl_extra_space(),
            style(format_size(logical.saturating_sub(physical), BINARY)).bold(),
        );
    }
    if scan.kept_files > 0 {
        row(l.lbl_kept(), l.kept_files(scan.kept_files, format_size(scan.kept_bytes_saved, BINARY)));
    }
    // Intentionally outside of `kept_files > 0`: if --recommended moved all WOF
    // files, kept_files is 0 – the row should still appear.
    for (g, n) in &notes.ds_moved {
        row(l.lbl_ds_detected(), l.ds_moved(display_path(g), *n));
    }
    if scan.small_compressed > 0 {
        row(&l.lbl_small(cli.min_size), l.small_ignored(scan.small_compressed));
        if !cli.recommended && !cli.all {
            println!("    {}", style(l.tip_recommended()).dim());
        }
    }
    if scan.hardlink_dupes > 0 {
        row(l.lbl_hardlink_dupes(), scan.hardlink_dupes);
    }
    if scan.cloud_skipped > 0 {
        row(l.lbl_cloud_skipped(), scan.cloud_skipped);
    }
    if !scan.excluded.is_empty() {
        let names: Vec<String> = scan
            .excluded
            .iter()
            .take(if cli.verbose { usize::MAX } else { 6 })
            .map(|p| display_path(p))
            .collect();
        let more = scan.excluded.len().saturating_sub(names.len());
        row(
            l.lbl_excluded(),
            format!(
                "{}{}",
                names.join(", "),
                if more > 0 { format!(" … (+{more})") } else { String::new() }
            ),
        );
    }
    if scan.errors > 0 {
        row(l.lbl_unreadable(), style(scan.errors).dim());
    }
    print_storage_notes(notes);

    if !scan.files.is_empty() {
        let shown = if cli.verbose { scan.files.len() } else { 10 };
        let [size, phys, kind, frags, reason, path] = l.table_columns();
        println!("\n  {size:>10}  {phys:>6}  {kind:<15} {frags:>9}  {reason:<14} {path}");
        for f in scan.files.iter().take(shown) {
            println!(
                "  {:>10}  {:>5.1}%  {:<15} {:>9}  {:<14} {}",
                format_size(f.logical, BINARY),
                f.ratio(),
                f.kind.to_string(),
                f.fragments.map_or_else(|| "–".into(), |n| n.to_string()),
                l.reason(f.reason),
                display_path(&f.path)
            );
        }
        if scan.files.len() > shown {
            println!("  {}", l.more_items(scan.files.len() - shown));
        }
    }

    if cli.verbose && !scan.dirs.is_empty() {
        println!("\n  {}", l.compressed_dirs_list());
        for d in &scan.dirs {
            println!("    {}", display_path(d));
        }
    }
}

/// Checks per volume whether enough space is free for decompression (+ 256 MiB or 1 % buffer).
/// The volume is determined once per scan path (junctions/mount points are not
/// followed during the scan, so all files of a path live on it).
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
                tr().not_enough_space(
                    display_path(&root),
                    format_size(info.free_bytes, BINARY),
                    format_size(bytes + margin, BINARY),
                ),
            ));
        }
    }
    Ok(())
}

/// Asks a yes/no question; the accepted answers depend on the active language.
fn confirm(prompt: &str) -> io::Result<bool> {
    if !io::stdin().is_terminal() {
        return Err(io::Error::other(tr().no_interactive_console()));
    }
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(tr().is_yes(&input))
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
            game(r"E:\SteamLibrary\steamapps\common\Game\Engine\Binaries\ThirdParty\Win64", None),
            Some(p(r"E:\SteamLibrary\steamapps\common\Game"))
        );
        // Case-insensitive
        assert_eq!(
            game(r"E:\SteamApps\Common\Game\bin", None),
            Some(p(r"E:\SteamApps\Common\Game"))
        );
    }

    #[test]
    fn game_root_other_launchers() {
        assert_eq!(game(r"D:\EA Games\Game\Data\Win64", None), Some(p(r"D:\EA Games\Game")));
        assert_eq!(
            game(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Game\bin", None),
            Some(p(r"C:\Program Files (x86)\Ubisoft\Ubisoft Game Launcher\games\Game"))
        );
        assert_eq!(game(r"D:\GOG Galaxy\Games\Game", None), Some(p(r"D:\GOG Galaxy\Games\Game")));
        assert_eq!(game(r"D:\XboxGames\Game\Content", None), Some(p(r"D:\XboxGames\Game")));
    }

    #[test]
    fn game_root_unreal() {
        assert_eq!(game(r"E:\Games\Game\Game\Binaries\Win64", None), Some(p(r"E:\Games\Game")));
        assert_eq!(
            game(r"E:\Games\Game\Engine\Binaries\ThirdParty\DirectStorage\Win64", None),
            Some(p(r"E:\Games\Game"))
        );
        // Without an engine folder no UE double-folder jump
        assert_eq!(game(r"E:\Games\Game\Game", None), Some(p(r"E:\Games\Game\Game")));
    }

    #[test]
    fn game_root_content_dir() {
        // MS Store/XboxGames-like without marker
        assert_eq!(game(r"E:\Games\Game\Content", None), Some(p(r"E:\Games\Game")));
        assert_eq!(game(r"E:\Games\Game\Content\bin", None), Some(p(r"E:\Games\Game")));
    }

    /// Temporary folder that is deleted on drop.
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
        // Real project: package.json next to dist
        t.file(r"proj\package.json");
        let js = t.file(r"proj\dist\a.js");
        assert!(build(&js, &t.0));
        // Game folder without marker: dist/build do not count
        let pak = t.file(r"Games\Title\dist\a.pak");
        assert!(!build(&pak, &t.0));
        let bin = t.file(r"Games\Title\build\data\x.bin");
        assert!(!build(&bin, &t.0));
        // .sln marker (extension, case-insensitive)
        t.file(r"vs\Solution.SLN");
        assert!(build(&t.file(r"vs\build\out.dll"), &t.0));
        // target only with Cargo.toml, not with package.json
        t.file(r"rs\Cargo.toml");
        assert!(build(&t.file(r"rs\target\debug\x.rlib"), &t.0));
        t.file(r"web\package.json");
        assert!(!build(&t.file(r"web\target\x"), &t.0));
        // Specific names without marker
        assert!(build(&t.file(r"Games\Title\node_modules\m\i.js"), &t.0));
    }

    #[test]
    fn build_dir_ignores_folders_above_scan_root() {
        let t = TempDir::new("above");
        let f = t.file(r"node_modules\Games\Title\a.pak");
        // Scan root lies BELOW node_modules → do not treat as build folder
        assert!(!build(&f, &t.0.join(r"node_modules\Games")));
        // Scan root is the build folder itself → counts
        assert!(build(&f, &t.0.join("node_modules")));
    }

    #[test]
    fn game_root_unity() {
        assert_eq!(
            game(r"E:\Games\Game\Game_Data\Plugins\x86_64", None),
            Some(p(r"E:\Games\Game"))
        );
        // _Data only directly above Plugins
        assert_eq!(game(r"E:\Games\Game\Foo_Data\bin", None), Some(p(r"E:\Games\Game\Foo_Data")));
    }

    #[test]
    fn game_root_volume_guards() {
        // DLL directly in the root → mark nothing
        assert_eq!(game(r"E:\", None), None);
        // Climbing up to the root → DLL folder itself
        assert_eq!(game(r"E:\Binaries", None), Some(p(r"E:\Binaries")));
        // Mount point without drive letter
        assert_eq!(game(r"C:\Games\Binaries", Some(r"C:\Games\")), Some(p(r"C:\Games\Binaries")));
        assert_eq!(game(r"C:\Games", Some(r"C:\Games")), None);
        // Verbatim prefix vs. volume root without prefix
        assert_eq!(
            game(r"\\?\C:\Games\Binaries", Some(r"C:\Games\")),
            Some(p(r"\\?\C:\Games\Binaries"))
        );
        assert_eq!(
            game(r"\\?\E:\Games\Game\Binaries\Win64", Some(r"E:\")),
            Some(p(r"\\?\E:\Games\Game"))
        );
    }

    #[test]
    fn game_root_marker_edge_cases() {
        // DLL directly in the marker folder → rule 2, folder itself
        assert_eq!(game(r"E:\steamapps\common", None), Some(p(r"E:\steamapps\common")));
        // No substring match
        assert_eq!(
            game(r"E:\backup_steamapps_common_old\Game\bin", None),
            Some(p(r"E:\backup_steamapps_common_old\Game"))
        );
        assert_eq!(
            game(r"E:\My SteamApps Backup\common\Game\bin", None),
            Some(p(r"E:\My SteamApps Backup\common\Game"))
        );
    }

    #[test]
    fn under_is_component_wise_and_case_insensitive() {
        assert!(under(Path::new(r"E:\Games\GameA\x.bin"), Path::new(r"e:\games\gamea")));
        // Unicode case folding (non-ASCII folder name)
        assert!(under(Path::new(r"E:\Games\Übung\a"), Path::new(r"e:\games\übung")));
        assert!(under(Path::new(r"\\?\E:\Games\GameA"), Path::new(r"E:\Games")));
        assert!(!under(Path::new(r"E:\Games\GameAB\x"), Path::new(r"E:\Games\GameA")));
        assert!(!under(Path::new(r"E:\Games"), Path::new(r"E:\Games\GameA")));
        assert!(!under(Path::new(r"F:\Games\GameA"), Path::new(r"E:\Games")));
    }

    #[test]
    fn dedup_roots_drops_contained_paths() {
        let (kept, dropped) = dedup_roots(vec![p(r"E:\Games\GameA"), p(r"E:\Games")]);
        assert_eq!(kept, vec![p(r"E:\Games")]);
        assert_eq!(dropped, vec![(p(r"E:\Games\GameA"), p(r"E:\Games"))]);

        let (kept, _) = dedup_roots(vec![p(r"E:\Games"), p(r"E:\Games")]);
        assert_eq!(kept, vec![p(r"E:\Games")]);

        let (kept, _) = dedup_roots(vec![p(r"E:\games"), p(r"E:\Games\x")]);
        assert_eq!(kept, vec![p(r"E:\games")]);

        let (kept, _) = dedup_roots(vec![p(r"E:\Games\GameA"), p(r"E:\Games\GameAB")]);
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn group_dir_uses_full_path() {
        assert_eq!(
            group_dir(Path::new(r"E:\Games"), Path::new(r"E:\Games\GameB\data\a.bin")),
            p(r"E:\Games\GameB")
        );
        // File directly in the scan root → scan root itself
        assert_eq!(
            group_dir(Path::new(r"E:\Games\GameB"), Path::new(r"E:\Games\GameB\a.bin")),
            p(r"E:\Games\GameB")
        );
        // Scan root is the file itself
        assert_eq!(group_dir(Path::new(r"E:\a.bin"), Path::new(r"E:\a.bin")), p(r"E:\a.bin"));
        // Two scan roots with a same-named subfolder stay separate
        assert_ne!(
            group_dir(Path::new(r"E:\Games"), Path::new(r"E:\Games\Shared\a")),
            group_dir(Path::new(r"E:\Backup"), Path::new(r"E:\Backup\Shared\a"))
        );
    }
}
