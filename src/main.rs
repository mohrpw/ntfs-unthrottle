#[cfg(not(windows))]
compile_error!(
    "the ntfs-unthrottle CLI only supports Windows – use the library with default-features = false"
);

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::{self, IsTerminal, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Component, Path, PathBuf, Prefix};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod compact;
mod i18n;
mod optimize;
mod probe;

use clap::Parser;
use console::style;
use humansize::{format_size, BINARY};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressState, ProgressStyle};
use serde_json::{json, Map, Value};
use walkdir::WalkDir;

use i18n::{tr, LangChoice};
use ntfs_unthrottle::{
    compressed_ancestors, display_path, file_identity_of, fragment_count,
    fragment_count_of, is_system_drive_root, open_for_query, physical_size, remove_compression,
    remove_ntfs_compression, volume_info, wof_algorithm_of, CompressionKind, VolumeInfo,
    WofAlgorithm,
};
use ntfs_unthrottle::tune::{device_info, DeviceInfo};
use windows_sys::Win32::Foundation::BOOL;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_OFFLINE,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS, FILE_ATTRIBUTE_RECALL_ON_OPEN,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_ATTRIBUTE_SYSTEM,
};
use windows_sys::Win32::System::Console::{
    SetConsoleCtrlHandler, CTRL_BREAK_EVENT, CTRL_C_EVENT,
};

/// Placeholders of OneDrive & co. – opening them with write access would download them.
pub(crate) const CLOUD_ATTRS: u32 =
    FILE_ATTRIBUTE_OFFLINE | FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS | FILE_ATTRIBUTE_RECALL_ON_OPEN;

/// Known high-entropy formats (already compressed or encrypted).
pub(crate) const HIGH_ENTROPY_EXTS: &[&str] = &[
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
pub(crate) const WRITE_HEAVY_EXTS: &[&str] = &[
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

pub(crate) fn has_ext(path: &Path, list: &[&str]) -> bool {
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

/// Is `start_dir` itself (or an ancestor up to `root`) a build/tooling folder?
fn dir_in_build_tree(start_dir: &Path, root: &Path, cache: &mut HashMap<PathBuf, bool>) -> bool {
    let mut cur = Some(start_dir);
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

/// Is `path` located below a build/tooling folder? Only the scan root `root`
/// and folders below it are checked – not what lies above
/// (`E:\target\Games` as scan path does not turn everything into a build folder).
/// `cache` remembers the marker result per generic folder.
pub(crate) fn in_build_dir(path: &Path, root: &Path, cache: &mut HashMap<PathBuf, bool>) -> bool {
    path.parent().is_some_and(|d| dir_in_build_tree(d, root, cache))
}

pub(crate) const EXIT_FOUND: u8 = 2;
pub(crate) const EXIT_PARTIAL: u8 = 3;
pub(crate) const EXIT_INTERRUPTED: u8 = 130;

/// Minimum decompressed size of a WOF file before post-fix fragmentation is checked.
const WOF_POST_FRAG_MIN_BYTES: u64 = 64 * 1024 * 1024;

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
enum OnlyReason {
    #[value(alias = "ext")]
    Extension,
    #[value(alias = "ratio")]
    LowSavings,
    #[value(alias = "write")]
    WriteHeavy,
    #[value(alias = "build-dir")]
    Build,
    #[value(name = "ds", alias = "direct-storage")]
    DirectStorage,
    #[value(alias = "forced")]
    All,
}

#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Compress eligible static files using transparent WOF (Windows Overlay Filter)
    Compact(compact::CompactArgs),
}

#[derive(Parser, Debug)]
#[command(
    name = "ntfs-unthrottle",
    version,
    about = "Removes invisible I/O bottlenecks caused by transparent NTFS/WOF compression.",
    after_help = "Exit codes: 0 = nothing to do/all fixed, 1 = error, \
                  2 = dry-run found candidates, 3 = some items failed, 130 = interrupted (Ctrl+C).",
    args_conflicts_with_subcommands = true
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,

    /// Folders or files to check
    #[arg(value_parser = parse_scan_path)]
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

    /// Restrict selection to specific candidate reasons (auto-enables detection for write-heavy,
    /// build, ds and all). Without --clear-dirs, folder flags are scoped to matching folders.
    #[arg(long, value_enum, value_name = "REASON", value_delimiter = ',')]
    only: Vec<OnlyReason>,

    /// Do NOT clear the compression flag of folders
    #[arg(long)]
    keep_dir_flags: bool,

    /// Clear all discovered compressed folder flags even when --only filters file candidates
    #[arg(long, conflicts_with = "keep_dir_flags")]
    clear_dirs: bool,

    /// Skip WOF/CompactOS detection (saves one open per large file)
    #[arg(long)]
    no_wof: bool,

    /// Do not determine the fragment count
    #[arg(long)]
    no_fragments: bool,

    /// List all candidates and folders instead of only the largest
    #[arg(short, long, global = true)]
    verbose: bool,

    /// Emit machine-readable JSON on stdout (progress/warnings go to stderr or are suppressed;
    /// combining with --fix requires --yes)
    #[arg(long, global = true)]
    json: bool,

    /// Optimizer: check storage device, MFT, 8.3 names, last access and TRIM of the volumes
    /// (with --fix, apply safe fixes via fsutil). Does not scan files.
    #[arg(long)]
    optimize: bool,

    /// Exclude: name (e.g. node_modules – matches at any depth) or path (e.g. E:\Backup).
    /// Repeatable. System folders are always protected.
    #[arg(short = 'x', long = "exclude", value_name = "NAME|PATH", global = true)]
    exclude: Vec<String>,

    /// Output language of runtime messages (auto = LC_ALL/LC_MESSAGES/LANG,
    /// then the Windows UI language). --help is always English.
    #[arg(long, value_enum, value_name = "LANG", default_value_t = LangChoice::Auto, global = true)]
    lang: LangChoice,
}

impl Cli {
    fn only_matches(&self, r: Reason) -> bool {
        self.only.is_empty()
            || self.only.iter().any(|o| {
                matches!(
                    (o, r),
                    (OnlyReason::Extension, Reason::Extension)
                        | (OnlyReason::LowSavings, Reason::LowSavings)
                        | (OnlyReason::WriteHeavy, Reason::WriteHeavy)
                        | (OnlyReason::Build, Reason::BuildDir)
                        | (OnlyReason::DirectStorage, Reason::DirectStorage)
                        | (OnlyReason::All, Reason::Forced)
                )
            })
    }

    fn detect_write_heavy(&self) -> bool {
        self.only.contains(&OnlyReason::WriteHeavy) || (self.recommended && self.only.is_empty())
    }

    fn detect_build(&self) -> bool {
        self.only.contains(&OnlyReason::Build) || (self.recommended && self.only.is_empty())
    }

    fn detect_ds(&self) -> bool {
        self.only.contains(&OnlyReason::DirectStorage) || (self.recommended && self.only.is_empty())
    }

    fn effective_all(&self) -> bool {
        self.all || self.only.contains(&OnlyReason::All)
    }
}

pub(crate) fn put_path(obj: &mut Map<String, Value>, key: &str, path: &Path) {
    obj.insert(key.into(), Value::String(display_path(path)));
    if path.to_str().is_none() {
        obj.insert(format!("{key}_lossy"), Value::Bool(true));
    }
}

pub(crate) fn path_obj(path: &Path) -> Value {
    let mut m = Map::new();
    put_path(&mut m, "path", path);
    Value::Object(m)
}

fn raw_args_want_json_iter<'a>(args: impl IntoIterator<Item = &'a std::ffi::OsStr>) -> bool {
    args.into_iter().skip(1).take_while(|a| *a != "--").any(|a| a == "--json")
}

fn raw_args_want_json() -> bool {
    let args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    raw_args_want_json_iter(args.iter().map(|s| s.as_os_str()))
}

fn emit_json_error(msg: &str) {
    println!("{}", json!({ "error": msg }));
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

pub(crate) struct Excludes {
    names: Vec<String>,
    paths: Vec<String>,
}

impl Excludes {
    fn new(cli: &Cli) -> io::Result<Self> {
        Self::from_list(&cli.exclude, cli.json)
    }

    pub(crate) fn from_list(exclude: &[String], json: bool) -> io::Result<Self> {
        let mut names = Vec::new();
        let mut paths = Vec::new();
        for x in exclude {
            if x.contains(['\\', '/', ':']) {
                let c = match std::fs::canonicalize(x) {
                    Ok(c) => c,
                    // What does not exist cannot be scanned either – no reason to abort.
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        if !json {
                            eprintln!("{} {}", style("ℹ").blue().bold(), tr().exclude_missing(x));
                        }
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

    pub(crate) fn matches(&self, path: &Path, attrs: Option<u32>) -> bool {
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

fn parse_scan_path(s: &str) -> Result<PathBuf, String> {
    if s.eq_ignore_ascii_case("compact") {
        return Err(
            "cannot combine top-level flags/paths with the 'compact' subcommand \
             (pass '.\\compact' if targeting a directory named 'compact')"
                .into(),
        );
    }
    Ok(PathBuf::from(s))
}

pub(crate) fn parse_percent(s: &str) -> Result<f64, String> {
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

fn reason_slug(r: Reason) -> &'static str {
    match r {
        Reason::Extension => "extension",
        Reason::LowSavings => "low_savings",
        Reason::WriteHeavy => "write_heavy",
        Reason::BuildDir => "build_dir",
        Reason::DirectStorage => "direct_storage",
        Reason::Forced => "all",
    }
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
    dirs_filtered_from: Option<usize>,
    flagged_vol_roots: Vec<PathBuf>,
    files: Vec<Candidate>,
    entries: u64,
    errors: u64,
    cloud_skipped: u64,
    sparse_skipped: u64,
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
pub(crate) struct RootInfo {
    pub(crate) vol: Option<VolumeInfo>,
    pub(crate) dev: Option<DeviceInfo>,
}

impl RootInfo {
    pub(crate) fn new(root: &Path) -> Self {
        // device_info needs the volume root or mount point –
        // on a subfolder (E:\Games) it would silently fail.
        let vol = volume_info(root).ok();
        let dev = vol.as_ref().and_then(|v| device_info(&v.root).ok());
        Self { vol, dev }
    }

    pub(crate) fn vol_root(&self) -> Option<&Path> {
        self.vol.as_ref().map(|v| v.root.as_path())
    }

    pub(crate) fn cluster_size(&self) -> u64 {
        self.vol.as_ref().map_or(4096, |v| u64::from(v.bytes_per_cluster.max(512)))
    }

    /// WOF (`wof.sys`) only exists on NTFS – independent of `supports_compression`
    /// (NTFS with clusters > 4 KiB cannot do LZNT1, but WOF works).
    /// Unknown volume → check to be safe.
    fn wof_possible(&self) -> bool {
        self.vol.as_ref().is_none_or(|v| v.fs_name.eq_ignore_ascii_case("NTFS"))
    }

    /// Only real NVMe – RAID, Storage Spaces, USB enclosures do not count (no BypassIO).
    pub(crate) fn is_nvme(&self) -> bool {
        self.dev.as_ref().is_some_and(|d| d.bus == Some("NVMe"))
    }
}

// --- Path comparisons (NTFS is case-insensitive) ----------------------------

/// Normalized component name (Unicode lowercase, so `Übung` = `übung` as well).
pub(crate) fn fold(s: &std::ffi::OsStr) -> String {
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
pub(crate) fn under(path: &Path, base: &Path) -> bool {
    let (p, b) = (norm(path), norm(base));
    p.len() >= b.len() && p[..b.len()] == b[..]
}

fn same_path(a: &Path, b: &Path) -> bool {
    norm(a) == norm(b)
}

/// Compares a component name with an already lowercased name.
pub(crate) fn comp_eq(a: &std::ffi::OsStr, lower: &str) -> bool {
    fold(a) == lower
}

/// Removes paths contained in another (or the same) path.
/// Returns the kept and the dropped paths (together with the containing path).
pub(crate) fn dedup_roots(mut roots: Vec<PathBuf>) -> (Vec<PathBuf>, Vec<(PathBuf, PathBuf)>) {
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
pub(crate) const DS_DLLS: &[&str] = &["dstorage.dll", "dstoragecore.dll"];

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

/// Routes a compressed directory either to `dirs` (normal folders, including a
/// non-root scan path at depth 0) or to `flagged_vol_roots` (volume roots,
/// which are never modified automatically).
fn record_compressed_dir(
    path: PathBuf,
    vol_root: Option<&Path>,
    sysdrive: &str,
    dirs: &mut Vec<PathBuf>,
    flagged_vol_roots: &mut Vec<PathBuf>,
) {
    if is_vol_root(&path, vol_root) {
        if !is_system_drive_root(&path, sysdrive) {
            flagged_vol_roots.push(path);
        }
    } else {
        dirs.push(path);
    }
}

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
pub(crate) fn ds_game_root(dll_dir: &Path, vol_root: Option<&Path>) -> Option<PathBuf> {
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
    /// Without DS selection: (game root, files, logical bytes) that stay compressed.
    ds_kept: Vec<(PathBuf, u64, u64)>,
    /// With DS selection: (game root, files) scheduled for decompression.
    ds_moved: Vec<(PathBuf, u64)>,
    /// All detected DirectStorage game roots (used for scoping `--only ds` folder flags).
    ds_games: Vec<PathBuf>,
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
            if cli.detect_ds() {
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
        notes.ds_games.push(g.clone());
        if cli.detect_ds() {
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

/// Filters `scan.files` and (unless `--clear-dirs` or `--keep-dir-flags`) scopes `scan.dirs`
/// to the selected `--only` reasons. Unmatched file candidates remain counted under `kept_*`.
fn apply_only_filters(cli: &Cli, scan: &mut Scan, roots: &[PathBuf], notes: &StorageNotes) {
    if cli.only.is_empty() {
        return;
    }
    let mut kept = Vec::with_capacity(scan.files.len());
    for f in scan.files.drain(..) {
        if cli.only_matches(f.reason) {
            kept.push(f);
        } else {
            scan.kept_files += 1;
            scan.kept_bytes_saved += f.logical.saturating_sub(f.physical);
        }
    }
    scan.files = kept;

    if !cli.keep_dir_flags && !cli.clear_dirs {
        let before = scan.dirs.len();
        let want_build = cli.only.contains(&OnlyReason::Build);
        let want_ds = cli.only.contains(&OnlyReason::DirectStorage);
        let parents: HashSet<PathBuf> =
            scan.files.iter().filter_map(|f| f.path.parent().map(Path::to_path_buf)).collect();
        let mut cache = std::mem::take(&mut scan.build_cache);
        scan.dirs.retain(|d| {
            if parents.contains(d) {
                return true;
            }
            if want_ds && notes.ds_games.iter().any(|g| under(d, g)) {
                return true;
            }
            if want_build {
                return roots
                    .iter()
                    .find(|r| under(d, r))
                    .is_some_and(|r| dir_in_build_tree(d, r, &mut cache));
            }
            false
        });
        scan.build_cache = cache;
        if scan.dirs.len() < before {
            scan.dirs_filtered_from = Some(before);
        }
    }
}

pub(crate) static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static CTRL_C_COUNT: AtomicU8 = AtomicU8::new(0);

unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> BOOL {
    match ctrl_type {
        CTRL_C_EVENT | CTRL_BREAK_EVENT => {
            INTERRUPTED.store(true, Ordering::SeqCst);
            let prev = CTRL_C_COUNT.fetch_add(1, Ordering::SeqCst);
            if prev == 0 {
                1 // Finish current file and print partial result.
            } else {
                0 // Second Ctrl+C / Ctrl+Break → immediate OS termination.
            }
        }
        // Never swallow CTRL_CLOSE_EVENT / CTRL_LOGOFF_EVENT / CTRL_SHUTDOWN_EVENT.
        _ => 0,
    }
}

pub(crate) struct CtrlHandlerGuard {
    installed: bool,
}

impl CtrlHandlerGuard {
    pub(crate) fn install() -> Self {
        INTERRUPTED.store(false, Ordering::SeqCst);
        CTRL_C_COUNT.store(0, Ordering::SeqCst);
        // Safety: `console_ctrl_handler` matches Win32 `PHANDLER_ROUTINE`.
        let ok = unsafe { SetConsoleCtrlHandler(Some(console_ctrl_handler), 1) };
        Self { installed: ok != 0 }
    }
}

impl Drop for CtrlHandlerGuard {
    fn drop(&mut self) {
        if self.installed {
            // Safety: removes the handler installed by `CtrlHandlerGuard::install`.
            unsafe {
                let _ = SetConsoleCtrlHandler(Some(console_ctrl_handler), 0);
            }
        }
    }
}

const SMALL_FILE_THRESHOLD: u64 = 1024 * 1024;
const EMA_TAU_SECS: f64 = 5.0;

pub(crate) struct EtaTracker {
    total_files: usize,
    done_files: usize,
    total_bytes: u64,
    done_bytes: u64,
    small_files: usize,
    done_small_files: usize,
    started: Instant,
    last_sample: Instant,
    win_bytes: u64,
    win_files: usize,
    win_small_files: usize,
    ema_bps: Option<f64>,
    ema_small_spf: Option<f64>,
}

impl EtaTracker {
    fn with_totals(total_files: usize, total_bytes: u64, small_files: usize, now: Instant) -> Self {
        Self {
            total_files,
            done_files: 0,
            total_bytes,
            done_bytes: 0,
            small_files,
            done_small_files: 0,
            started: now,
            last_sample: now,
            win_bytes: 0,
            win_files: 0,
            win_small_files: 0,
            ema_bps: None,
            ema_small_spf: None,
        }
    }

    pub(crate) fn from_sizes(sizes: impl Iterator<Item = u64>, now: Instant) -> Self {
        let mut count = 0usize;
        let mut total_bytes = 0u64;
        let mut small_files = 0usize;
        for sz in sizes {
            count += 1;
            total_bytes = total_bytes.saturating_add(sz);
            if sz < SMALL_FILE_THRESHOLD {
                small_files += 1;
            }
        }
        Self::with_totals(count, total_bytes, small_files, now)
    }

    fn from_candidates(files: &[Candidate], now: Instant) -> Self {
        Self::from_sizes(files.iter().map(|f| f.logical), now)
    }

    pub(crate) fn record(&mut self, bytes: u64, now: Instant) {
        self.done_files += 1;
        self.done_bytes = self.done_bytes.saturating_add(bytes);
        self.win_files += 1;
        self.win_bytes = self.win_bytes.saturating_add(bytes);
        if bytes < SMALL_FILE_THRESHOLD {
            self.done_small_files += 1;
            self.win_small_files += 1;
        }

        let dt = now.saturating_duration_since(self.last_sample).as_secs_f64();
        if dt >= 0.25 || bytes >= 4 * 1024 * 1024 || self.done_files >= self.total_files {
            let dt = dt.max(0.001);
            let alpha = 1.0 - (-dt / EMA_TAU_SECS).exp();
            if self.win_bytes > 0 {
                let inst_bps = self.win_bytes as f64 / dt;
                self.ema_bps = Some(match self.ema_bps {
                    Some(prev) => prev + alpha * (inst_bps - prev),
                    None => inst_bps,
                });
            }
            // Only learn per-file metadata overhead from windows of purely small files
            // so a multi-GiB payload does not skew the small-file open/close rate.
            if self.win_small_files > 0 && self.win_small_files == self.win_files {
                let inst_spf = dt / self.win_small_files as f64;
                self.ema_small_spf = Some(match self.ema_small_spf {
                    Some(prev) => prev + alpha * (inst_spf - prev),
                    None => inst_spf,
                });
            }
            self.last_sample = now;
            self.win_bytes = 0;
            self.win_files = 0;
            self.win_small_files = 0;
        }
    }

    fn rate_bps(&self, now: Instant) -> Option<f64> {
        self.ema_bps.or_else(|| {
            let e = now.saturating_duration_since(self.started).as_secs_f64();
            (self.done_bytes > 0 && e > 0.0).then(|| self.done_bytes as f64 / e)
        })
    }

    fn eta_secs(&self, now: Instant) -> Option<u64> {
        let rem_bytes = self.total_bytes.saturating_sub(self.done_bytes) as f64;
        if rem_bytes == 0.0 && self.done_files >= self.total_files {
            return Some(0);
        }
        let byte_eta = self.rate_bps(now).filter(|&r| r > 0.0).map(|r| rem_bytes / r);
        let rem_small = self.small_files.saturating_sub(self.done_small_files) as f64;
        let small_eta = self.ema_small_spf.map(|spf| rem_small * spf);
        let secs = match (byte_eta, small_eta) {
            (Some(b), Some(s)) => Some(b.max(s)),
            (Some(b), None) => Some(b),
            (None, s) => s,
        };
        secs.map(|s| s.round().max(0.0) as u64)
    }

    fn format_rate(&self, now: Instant) -> String {
        match self.rate_bps(now) {
            Some(bps) if bps.is_finite() && bps >= 0.0 => format!("{}/s", format_size(bps as u64, BINARY)),
            _ => "–".into(),
        }
    }

    fn format_eta(&self, now: Instant) -> String {
        match self.eta_secs(now) {
            Some(s) => format_duration_hms(s),
            None => "--:--".into(),
        }
    }
}

fn format_duration_hms(secs: u64) -> String {
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m:02}:{s:02}")
    }
}

fn ratio(physical: u64, logical: u64) -> f64 {
    if logical == 0 {
        100.0
    } else {
        physical as f64 / logical as f64 * 100.0
    }
}

fn main() -> ExitCode {
    let want_json = raw_args_want_json();
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            use clap::error::ErrorKind;
            if want_json && !matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let msg = e.to_string();
                emit_json_error(msg.trim());
                return ExitCode::from(u8::try_from(e.exit_code()).unwrap_or(2));
            }
            e.exit();
        }
    };
    i18n::init(i18n::detect(cli.lang));
    let needs_yes = match &cli.command {
        Some(Command::Compact(c)) => c.fix && !c.yes,
        None => cli.fix && !cli.yes,
    };
    if cli.json && needs_yes {
        emit_json_error(tr().json_fix_requires_yes());
        return ExitCode::from(2);
    }
    match run(&cli) {
        Ok(code) => code,
        Err(e) => {
            if cli.json {
                emit_json_error(&e.to_string());
            } else {
                eprintln!("{} {}", style("✖").red().bold(), e);
            }
            ExitCode::FAILURE
        }
    }
}

pub(crate) fn resolve_scan_roots(paths: &[PathBuf], json: bool) -> io::Result<(Vec<PathBuf>, Vec<RootInfo>)> {
    let l = tr();
    // Canonical \\?\ paths: this way paths > 260 characters also work with
    // the raw Win32 calls.
    let mut roots = Vec::new();
    for p in paths {
        // Poka-yoke: reject directly given system paths (or paths inside them) –
        // first purely by name, because canonicalize already fails on locked
        // system paths (System Volume Information, pagefile.sys).
        let abs = std::path::absolute(p).unwrap_or_else(|_| p.clone());
        let canon = std::fs::canonicalize(p);
        let check = canon.as_deref().unwrap_or(&abs);
        if let Some((hit, why)) = protected_path(&abs).or_else(|| protected_path(check)) {
            if !json {
                eprintln!(
                    "{} {}",
                    style("⛔").red().bold(),
                    l.skipped_protected(display_path(&abs), l.protected(why), display_path(&hit))
                );
            }
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
    if !json {
        for (inner, outer) in &dropped {
            println!(
                "{} {}",
                style("ℹ").blue().bold(),
                l.root_contained(display_path(inner), display_path(outer))
            );
        }
    }
    let infos: Vec<RootInfo> = roots.iter().map(|r| RootInfo::new(r)).collect();
    Ok((roots, infos))
}

pub(crate) fn make_spinner(json: bool) -> ProgressBar {
    if json {
        ProgressBar::hidden()
    } else {
        let sp = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
        sp.set_style(ProgressStyle::with_template(tr().spinner_template()).unwrap());
        sp.enable_steady_tick(Duration::from_millis(100));
        sp
    }
}

pub(crate) fn make_file_bar(
    json: bool,
    total: u64,
    tracker: &Arc<Mutex<EtaTracker>>,
) -> ProgressBar {
    if json {
        ProgressBar::hidden()
    } else {
        let b = ProgressBar::with_draw_target(Some(total), ProgressDrawTarget::stderr());
        let style = ProgressStyle::with_template(tr().bar_files_template())
            .unwrap()
            .progress_chars("=> ")
            .with_key("files_pos", {
                let t = Arc::clone(tracker);
                move |_: &ProgressState, w: &mut dyn std::fmt::Write| {
                    let g = t.lock().unwrap();
                    let _ = write!(w, "{}", g.done_files);
                }
            })
            .with_key("files_len", {
                let t = Arc::clone(tracker);
                move |_: &ProgressState, w: &mut dyn std::fmt::Write| {
                    let g = t.lock().unwrap();
                    let _ = write!(w, "{}", g.total_files);
                }
            })
            .with_key("smoothed_rate", {
                let t = Arc::clone(tracker);
                move |_: &ProgressState, w: &mut dyn std::fmt::Write| {
                    let g = t.lock().unwrap();
                    let _ = w.write_str(&g.format_rate(Instant::now()));
                }
            })
            .with_key("smoothed_eta", {
                let t = Arc::clone(tracker);
                move |_: &ProgressState, w: &mut dyn std::fmt::Write| {
                    let g = t.lock().unwrap();
                    let _ = w.write_str(&g.format_eta(Instant::now()));
                }
            });
        b.set_style(style);
        b.enable_steady_tick(Duration::from_millis(200));
        b
    }
}

fn run(cli: &Cli) -> io::Result<ExitCode> {
    if let Some(Command::Compact(args)) = &cli.command {
        let global = compact::GlobalCliOpts {
            verbose: cli.verbose,
            json: cli.json,
            exclude: &cli.exclude,
        };
        return compact::run(args, &global);
    }
    let raw_paths: Vec<PathBuf> =
        if cli.paths.is_empty() { vec![PathBuf::from(".")] } else { cli.paths.clone() };
    if cli.optimize {
        return optimize::run(&raw_paths, cli.fix, cli.yes, cli.json);
    }
    let l = tr();
    let (roots, infos) = resolve_scan_roots(&raw_paths, cli.json)?;

    // --- Phase 1: scan ----------------------------------------------------
    if !cli.json {
        println!("{} {}", style("[1/3]").bold().cyan(), l.scanning_paths(roots.len()));
        for (root, info) in roots.iter().zip(&infos) {
            println!("      {}", style(display_path(root)).underlined());
            report_volume(info);
        }
    }

    let started = Instant::now();
    let spinner = make_spinner(cli.json);

    let excludes = Excludes::new(cli)?;
    let mut scan = Scan::default();
    for (i, (root, info)) in roots.iter().zip(&infos).enumerate() {
        scan_tree(cli, i, root, info, &excludes, &mut scan, &spinner);
    }
    spinner.finish_and_clear();
    scan.files.sort_by_key(|f| std::cmp::Reverse(f.logical));

    // --- Phase 2: evaluation ----------------------------------------------
    let notes = apply_storage_rules(cli, &mut scan, &roots, &infos);
    apply_only_filters(cli, &mut scan, &roots, &notes);
    if !cli.json {
        print_report(cli, &scan, &notes, started.elapsed());
    }

    let ancestors: Vec<PathBuf> = {
        let mut v: Vec<PathBuf> = roots
            .iter()
            .flat_map(|r| compressed_ancestors(r))
            .chain(scan.flagged_vol_roots.iter().cloned())
            .collect();
        v.sort();
        v.dedup();
        v
    };
    if !cli.json && !ancestors.is_empty() {
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
        if cli.json {
            let empty_fix = cli.fix.then(FixSummary::default);
            emit_scan_json(ScanJson {
                cli,
                roots: &roots,
                infos: &infos,
                scan: &scan,
                notes: &notes,
                took: started.elapsed(),
                ancestors: &ancestors,
                fix: empty_fix.as_ref(),
            })?;
        } else {
            println!("\n{} {}", style("✔").green().bold(), l.nothing_found(notes.any_hint()));
        }
        return Ok(ExitCode::SUCCESS);
    }

    if !cli.fix {
        if cli.json {
            emit_scan_json(ScanJson {
                cli,
                roots: &roots,
                infos: &infos,
                scan: &scan,
                notes: &notes,
                took: started.elapsed(),
                ancestors: &ancestors,
                fix: None,
            })?;
        } else {
            println!(
                "\n{} {}",
                style("ℹ").blue().bold(),
                l.analysis_only_fix(style("--fix").yellow().bold())
            );
        }
        return Ok(ExitCode::from(EXIT_FOUND));
    }

    if !cli.json {
        print!("\n  {}", l.checking_free_space());
        io::stdout().flush()?;
    }
    check_free_space(&roots, &scan.files)?;
    if !cli.json {
        println!(" ok");
    }

    if !cli.yes {
        let prompt = format!(
            "\n{}\n{} ",
            style("─".repeat(60)).yellow(),
            style(l.confirm_decompress(scan.files.len(), dirs_todo)).yellow().bold()
        );
        if !confirm(&prompt)? {
            println!("{}", l.aborted());
            return Ok(ExitCode::SUCCESS);
        }
    }

    // --- Phase 3: cleanup ------------------------------------------------
    if !cli.json {
        println!("\n{} {}", style("[3/3]").bold().cyan(), l.cleaning_up());
    }
    let _ctrl_guard = CtrlHandlerGuard::install();
    let mut fix = FixSummary { dirs_todo, files_todo: scan.files.len(), ..Default::default() };

    // Folders first: from now on new files no longer inherit anything.
    if dirs_todo > 0 {
        let pb = if cli.json {
            ProgressBar::hidden()
        } else {
            let b = ProgressBar::with_draw_target(Some(dirs_todo as u64), ProgressDrawTarget::stderr());
            b.set_style(ProgressStyle::with_template(l.bar_dirs_template()).unwrap());
            b
        };
        for dir in &scan.dirs {
            if INTERRUPTED.load(Ordering::SeqCst) {
                fix.interrupted = true;
                break;
            }
            match remove_ntfs_compression(dir, true) {
                Ok(()) => fix.fixed_dirs += 1,
                Err(e) => fix.failed.push((dir.clone(), l.describe_error_at(&e, dir))),
            }
            pb.inc(1);
        }
        pb.finish();
    }

    if !fix.interrupted && INTERRUPTED.load(Ordering::SeqCst) && !scan.files.is_empty() {
        fix.interrupted = true;
    }

    // Files intentionally sequential: NTFS rewrites each file synchronously.
    if !fix.interrupted && !scan.files.is_empty() {
        let total: u64 = scan.files.iter().map(|f| f.logical).sum();
        let tracker = Arc::new(Mutex::new(EtaTracker::from_candidates(&scan.files, Instant::now())));
        let pb = make_file_bar(cli.json, total, &tracker);
        for f in &scan.files {
            if INTERRUPTED.load(Ordering::SeqCst) {
                fix.interrupted = true;
                break;
            }
            pb.set_message(file_name(&f.path));
            match remove_compression(&f.path, f.kind) {
                Ok(()) => {
                    fix.fixed_files += 1;
                    let check_frags = !cli.no_fragments
                        && (f.kind == CompressionKind::Lznt1 || f.logical >= WOF_POST_FRAG_MIN_BYTES);
                    if check_frags {
                        if let Ok(after) = fragment_count(&f.path) {
                            if let Some(before) = f.fragments {
                                fix.freed_fragments += before.saturating_sub(after);
                            }
                            let is_hdd =
                                infos[f.root].dev.as_ref().and_then(|d| d.seek_penalty) == Some(true);
                            let warn_at = if is_hdd { 250 } else { 1000 };
                            if after >= warn_at {
                                fix.heavily_fragmented.push((f.root, f.path.clone(), after));
                            }
                        }
                    }
                }
                Err(e) => fix.failed.push((f.path.clone(), l.describe_error_at(&e, &f.path))),
            }
            {
                tracker.lock().unwrap().record(f.logical, Instant::now());
            }
            pb.inc(f.logical);
        }
        pb.finish_and_clear();
    }
    drop(_ctrl_guard);

    fix.heavily_fragmented.sort_by_key(|(_, _, frags)| std::cmp::Reverse(*frags));

    // --- Summary --------------------------------------------------------------
    if cli.json {
        emit_scan_json(ScanJson {
            cli,
            roots: &roots,
            infos: &infos,
            scan: &scan,
            notes: &notes,
            took: started.elapsed(),
            ancestors: &ancestors,
            fix: Some(&fix),
        })?;
    } else {
        if fix.interrupted {
            eprintln!("\n  {} {}", style("⚠").yellow().bold(), l.interrupted_partial());
        }
        println!("\n{}", style(l.result_header()).bold());
        if dirs_todo > 0 {
            println!("  {} {:<23}{}/{}", style("✔").green(), l.result_dir_flags(), fix.fixed_dirs, dirs_todo);
        }
        println!(
            "  {} {:<23}{}/{}",
            style("✔").green(),
            l.result_files(),
            fix.fixed_files,
            scan.files.len()
        );
        if fix.freed_fragments > 0 {
            println!("  {} {:<23}{}", style("✔").green(), l.result_fragments(), fix.freed_fragments);
        }

        if !fix.heavily_fragmented.is_empty() {
            println!(
                "\n  {} {}",
                style("ℹ").blue().bold(),
                l.heavily_fragmented_header(fix.heavily_fragmented.len())
            );
            let shown = if cli.verbose { fix.heavily_fragmented.len() } else { 5 };
            for (_, p, frags) in fix.heavily_fragmented.iter().take(shown) {
                println!("    {:>6}  {}", frags, l.heavily_fragmented_hint_contig(display_path(p)));
            }
            if fix.heavily_fragmented.len() > shown {
                println!("    {}", l.more_items(fix.heavily_fragmented.len() - shown));
            }
            let mut seen_vols = Vec::new();
            for (r_idx, _, _) in &fix.heavily_fragmented {
                if let Some(vol) = infos[*r_idx].vol_root() {
                    let v = display_path(vol).trim_end_matches('\\').to_string();
                    if !seen_vols.contains(&v) {
                        seen_vols.push(v);
                    }
                }
            }
            for v in seen_vols {
                println!("    {}", style(l.heavily_fragmented_hint_defrag(&v)).dim());
            }
        }

        if !fix.failed.is_empty() {
            println!("\n  {} {}", style("⚠").yellow().bold(), l.items_failed(fix.failed.len()));
            let shown = if cli.verbose { fix.failed.len() } else { 10 };
            for (p, why) in fix.failed.iter().take(shown) {
                println!("    - {}: {}", display_path(p), style(why).red());
            }
            if fix.failed.len() > shown {
                println!("    {}", l.more_items(fix.failed.len() - shown));
            }
        }
    }

    if fix.interrupted {
        return Ok(ExitCode::from(EXIT_INTERRUPTED));
    }
    if !fix.failed.is_empty() {
        return Ok(ExitCode::from(EXIT_PARTIAL));
    }
    Ok(ExitCode::SUCCESS)
}

#[derive(Default)]
struct FixSummary {
    interrupted: bool,
    fixed_dirs: usize,
    dirs_todo: usize,
    fixed_files: usize,
    files_todo: usize,
    freed_fragments: u64,
    heavily_fragmented: Vec<(usize, PathBuf, u64)>,
    failed: Vec<(PathBuf, String)>,
}

struct ScanJson<'a> {
    cli: &'a Cli,
    roots: &'a [PathBuf],
    infos: &'a [RootInfo],
    scan: &'a Scan,
    notes: &'a StorageNotes,
    took: Duration,
    ancestors: &'a [PathBuf],
    fix: Option<&'a FixSummary>,
}

fn emit_scan_json(data: ScanJson<'_>) -> io::Result<()> {
    let ScanJson { cli, roots, infos, scan, notes, took, ancestors, fix } = data;
    let logical: u64 = scan.files.iter().map(|f| f.logical).sum();
    let physical: u64 = scan.files.iter().map(|f| f.physical).sum();
    let dirs_todo = if cli.keep_dir_flags { 0 } else { scan.dirs.len() };

    let roots_json: Vec<Value> = roots
        .iter()
        .zip(infos)
        .map(|(root, info)| {
            let mut m = Map::new();
            put_path(&mut m, "root", root);
            m.insert(
                "volume".into(),
                match &info.vol {
                    Some(v) => {
                        let mut vm = Map::new();
                        put_path(&mut vm, "root", &v.root);
                        vm.insert("fs_name".into(), json!(v.fs_name));
                        vm.insert("supports_compression".into(), json!(v.supports_compression));
                        vm.insert("free_bytes".into(), json!(v.free_bytes));
                        Value::Object(vm)
                    }
                    None => Value::Null,
                },
            );
            m.insert(
                "device".into(),
                match &info.dev {
                    Some(d) => json!({
                        "product": d.product,
                        "bus": d.bus,
                        "seek_penalty": d.seek_penalty,
                        "trim_supported": d.trim_supported,
                    }),
                    None => Value::Null,
                },
            );
            Value::Object(m)
        })
        .collect();

    let files_json: Vec<Value> = scan
        .files
        .iter()
        .map(|f| {
            let mut m = Map::new();
            put_path(&mut m, "path", &f.path);
            m.insert("logical_bytes".into(), json!(f.logical));
            m.insert("physical_bytes".into(), json!(f.physical));
            m.insert("ratio_pct".into(), json!(f.ratio()));
            m.insert("compression".into(), json!(f.kind.to_string()));
            m.insert("fragments".into(), json!(f.fragments));
            m.insert("reason".into(), json!(reason_slug(f.reason)));
            Value::Object(m)
        })
        .collect();

    let ancestors_json: Vec<Value> = ancestors
        .iter()
        .map(|a| {
            let mut m = Map::new();
            put_path(&mut m, "path", a);
            m.insert("is_drive_root".into(), json!(a.parent().is_none()));
            Value::Object(m)
        })
        .collect();

    let dirs_json: Vec<Value> = scan.dirs.iter().map(|d| path_obj(d)).collect();
    let excluded_json: Vec<Value> = scan.excluded.iter().map(|e| path_obj(e)).collect();

    let ds_kept_json: Vec<Value> = notes
        .ds_kept
        .iter()
        .map(|(g, n, bytes)| {
            let mut m = Map::new();
            put_path(&mut m, "game_root", g);
            m.insert("files".into(), json!(n));
            m.insert("logical_bytes".into(), json!(bytes));
            Value::Object(m)
        })
        .collect();
    let ds_moved_json: Vec<Value> = notes
        .ds_moved
        .iter()
        .map(|(g, n)| {
            let mut m = Map::new();
            put_path(&mut m, "game_root", g);
            m.insert("files".into(), json!(n));
            Value::Object(m)
        })
        .collect();
    let nvme_heavy_json: Vec<Value> = notes
        .nvme_heavy
        .iter()
        .map(|nh| {
            let mut m = Map::new();
            put_path(&mut m, "volume", &nh.vol);
            m.insert("total_bytes".into(), json!(nh.total));
            let dirs: Vec<Value> = nh
                .dirs
                .iter()
                .map(|(d, b)| {
                    let mut dm = Map::new();
                    put_path(&mut dm, "path", d);
                    dm.insert("bytes".into(), json!(b));
                    Value::Object(dm)
                })
                .collect();
            m.insert("dirs".into(), Value::Array(dirs));
            Value::Object(m)
        })
        .collect();

    let fix_json = match fix {
        Some(f) => {
            let frag_json: Vec<Value> = f
                .heavily_fragmented
                .iter()
                .map(|(_, p, frags)| {
                    let mut m = Map::new();
                    put_path(&mut m, "path", p);
                    m.insert("fragments".into(), json!(frags));
                    Value::Object(m)
                })
                .collect();
            let failed_json: Vec<Value> = f
                .failed
                .iter()
                .map(|(p, why)| {
                    let mut m = Map::new();
                    put_path(&mut m, "path", p);
                    m.insert("error".into(), json!(why));
                    Value::Object(m)
                })
                .collect();
            json!({
                "interrupted": f.interrupted,
                "fixed_dirs": f.fixed_dirs,
                "dirs_todo": f.dirs_todo,
                "fixed_files": f.fixed_files,
                "files_todo": f.files_todo,
                "freed_fragments": f.freed_fragments,
                "heavily_fragmented": frag_json,
                "failed": failed_json,
            })
        }
        None => Value::Null,
    };

    let payload = json!({
        "mode": "scan",
        "roots": roots_json,
        "summary": {
            "entries": scan.entries,
            "duration_secs": took.as_secs_f64(),
            "compressed_dirs_total": scan.dirs_filtered_from.unwrap_or(scan.dirs.len()),
            "compressed_dirs_selected": dirs_todo,
            "throttled_files": scan.files.len(),
            "logical_bytes": logical,
            "physical_bytes": physical,
            "extra_space_bytes": logical.saturating_sub(physical),
            "kept_files": scan.kept_files,
            "kept_bytes_saved": scan.kept_bytes_saved,
            "small_compressed": scan.small_compressed,
            "hardlink_dupes": scan.hardlink_dupes,
            "cloud_skipped": scan.cloud_skipped,
            "sparse_skipped": scan.sparse_skipped,
            "errors": scan.errors,
        },
        "compressed_ancestors": ancestors_json,
        "dirs": dirs_json,
        "files": files_json,
        "excluded": excluded_json,
        "notes": {
            "ds_kept": ds_kept_json,
            "ds_moved": ds_moved_json,
            "nvme_heavy": nvme_heavy_json,
        },
        "fix": fix_json,
    });
    println!("{}", serde_json::to_string(&payload).map_err(io::Error::other)?);
    Ok(())
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
    let sysdrive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());

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
        // Sparse files must not be uncompressed blindly: FSCTL_SET_COMPRESSION(NONE)
        // can fail with ERROR_INVALID_PARAMETER or materialize sparse zero ranges on disk.
        if attrs & FILE_ATTRIBUTE_SPARSE_FILE != 0 {
            scan.sparse_skipped += 1;
            continue;
        }
        let ntfs_compressed = attrs & FILE_ATTRIBUTE_COMPRESSED != 0;

        if meta.is_dir() {
            if ntfs_compressed {
                record_compressed_dir(
                    entry.into_path(),
                    info.vol_root(),
                    &sysdrive,
                    &mut scan.dirs,
                    &mut scan.flagged_vol_roots,
                );
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
        let write_heavy = cli.detect_write_heavy() && has_ext(path, WRITE_HEAVY_EXTS);
        let build_dir =
            cli.detect_build() && !write_heavy && in_build_dir(path, root, &mut scan.build_cache);
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
        } else if cli.effective_all() {
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

pub(crate) fn report_volume(info: &RootInfo) {
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
            "{}{}{}",
            style(scan.dirs_filtered_from.unwrap_or(scan.dirs.len())).yellow().bold(),
            if cli.keep_dir_flags { l.keep_dir_flags_note() } else { "" },
            scan.dirs_filtered_from
                .map(|_| l.only_dirs_filtered_note(scan.dirs.len()))
                .unwrap_or_default()
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
        if !cli.recommended && !cli.effective_all() && cli.only.is_empty() {
            println!("    {}", style(l.tip_recommended()).dim());
        }
    }
    if scan.hardlink_dupes > 0 {
        row(l.lbl_hardlink_dupes(), scan.hardlink_dupes);
    }
    if scan.cloud_skipped > 0 {
        row(l.lbl_cloud_skipped(), scan.cloud_skipped);
    }
    if scan.sparse_skipped > 0 {
        row(l.lbl_sparse_skipped(), scan.sparse_skipped);
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
pub(crate) fn confirm(prompt: &str) -> io::Result<bool> {
    if !io::stdin().is_terminal() {
        return Err(io::Error::other(tr().no_interactive_console()));
    }
    print!("{prompt}");
    io::stdout().flush()?;
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(tr().is_yes(&input))
}

pub(crate) fn file_name(p: &Path) -> String {
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

    #[test]
    fn compressed_dir_skips_drive_root_but_keeps_subfolders() {
        let mut dirs = Vec::new();
        let mut roots = Vec::new();
        // Drive root E:\ must not be added to auto-modified dirs.
        record_compressed_dir(p(r"\\?\E:\"), Some(Path::new(r"E:\")), "C:", &mut dirs, &mut roots);
        assert!(dirs.is_empty());
        assert_eq!(roots, vec![p(r"\\?\E:\")]);

        // System drive root C:\ is excluded from both.
        record_compressed_dir(p(r"\\?\C:\"), Some(Path::new(r"C:\")), "C:", &mut dirs, &mut roots);
        assert!(dirs.is_empty());
        assert_eq!(roots, vec![p(r"\\?\E:\")]);

        // Normal subfolder (even as scan root at depth 0) IS queued in dirs.
        record_compressed_dir(
            p(r"\\?\E:\Games"),
            Some(Path::new(r"E:\")),
            "C:",
            &mut dirs,
            &mut roots,
        );
        assert_eq!(dirs, vec![p(r"\\?\E:\Games")]);
    }

    #[test]
    fn only_auto_enables_detectors_and_scopes_dirs() {
        let cli = Cli::try_parse_from(["ntfs-unthrottle", ".", "--only", "build"]).unwrap();
        assert!(cli.detect_build());
        assert!(!cli.detect_ds());
        assert!(!cli.detect_write_heavy());
        assert!(cli.only_matches(Reason::BuildDir));
        assert!(!cli.only_matches(Reason::Extension));

        let root = p(r"E:\Repo");
        let mut scan = Scan {
            dirs: vec![p(r"E:\Repo"), p(r"E:\Repo\docs"), p(r"E:\Repo\target"), p(r"E:\Repo\assets")],
            files: vec![
                Candidate {
                    root: 0,
                    path: p(r"E:\Repo\target\app.pdb"),
                    logical: 30_000_000,
                    physical: 10_000_000,
                    kind: CompressionKind::Lznt1,
                    reason: Reason::BuildDir,
                    fragments: None,
                },
                Candidate {
                    root: 0,
                    path: p(r"E:\Repo\assets\pack.zip"),
                    logical: 50_000_000,
                    physical: 49_000_000,
                    kind: CompressionKind::Lznt1,
                    reason: Reason::Extension,
                    fragments: None,
                },
            ],
            ..Default::default()
        };
        apply_only_filters(&cli, &mut scan, &[root], &StorageNotes::default());
        assert_eq!(scan.files.len(), 1);
        assert_eq!(scan.files[0].reason, Reason::BuildDir);
        assert_eq!(scan.kept_files, 1);
        assert_eq!(scan.kept_bytes_saved, 1_000_000);
        // Only the build dir is retained; non-matching dirs are filtered out.
        assert_eq!(scan.dirs, vec![p(r"E:\Repo\target")]);
        assert_eq!(scan.dirs_filtered_from, Some(4));

        // --only ds scopes dirs to DirectStorage game roots.
        let cli_ds = Cli::try_parse_from(["ntfs-unthrottle", ".", "--only", "ds"]).unwrap();
        assert!(cli_ds.detect_ds());
        let mut scan_ds = Scan {
            dirs: vec![p(r"E:\Games"), p(r"E:\Games\MyGame"), p(r"E:\Games\MyGame\sub"), p(r"E:\Games\Other")],
            ..Default::default()
        };
        let notes = StorageNotes { ds_games: vec![p(r"E:\Games\MyGame")], ..Default::default() };
        apply_only_filters(&cli_ds, &mut scan_ds, &[p(r"E:\Games")], &notes);
        assert_eq!(scan_ds.dirs, vec![p(r"E:\Games\MyGame"), p(r"E:\Games\MyGame\sub")]);

        // --clear-dirs overrides selective dir scoping.
        let cli_clear = Cli::try_parse_from(["ntfs-unthrottle", ".", "--only", "build", "--clear-dirs"]).unwrap();
        let mut scan_clear = Scan {
            dirs: vec![p(r"E:\Repo\docs"), p(r"E:\Repo\target")],
            ..Default::default()
        };
        apply_only_filters(&cli_clear, &mut scan_clear, &[p(r"E:\Repo")], &StorageNotes::default());
        assert_eq!(scan_clear.dirs.len(), 2);
        assert_eq!(scan_clear.dirs_filtered_from, None);
    }

    #[test]
    fn eta_tracker_smooths_and_formats() {
        let t0 = Instant::now();
        // 1 GiB big file + 1000 small 10 KiB files
        let small_bytes = 10_000 * 1024;
        let total_bytes = (1u64 << 30) + small_bytes;
        let mut trk = EtaTracker::with_totals(1001, total_bytes, 1000, t0);
        assert_eq!(trk.format_rate(t0), "–");
        assert_eq!(trk.format_eta(t0), "--:--");

        // Fast 1 GiB file in 1 s → 1 GiB/s
        trk.record(1 << 30, t0 + Duration::from_secs(1));
        assert!(trk.rate_bps(t0 + Duration::from_secs(1)).is_some());

        // Slowly record small files (e.g., 10 files across 1 s → 100 ms each)
        for i in 1..=10u64 {
            trk.record(10240, t0 + Duration::from_millis(1000 + i * 100));
        }
        let now = t0 + Duration::from_secs(2);
        // Should predict > 10s (not 0s from 1 GiB/s byte rate) thanks to small-file overhead EMA.
        let eta = trk.eta_secs(now).unwrap();
        assert!(eta >= 10, "expected smoothed small-file ETA >= 10s, got {eta}");
        assert_eq!(format_duration_hms(65), "01:05");
        assert_eq!(format_duration_hms(3665), "1:01:05");
    }

    #[test]
    fn json_path_helpers_and_arg_detection() {
        use std::ffi::{OsStr, OsString};
        use std::os::windows::ffi::OsStringExt;

        let mut obj = Map::new();
        put_path(&mut obj, "path", Path::new(r"C:\Temp\ok.bin"));
        assert_eq!(obj.get("path"), Some(&Value::String(r"C:\Temp\ok.bin".into())));
        assert!(!obj.contains_key("path_lossy"));

        // Unpaired high surrogate (0xD800) must serialize safely with `*_lossy: true`.
        let bad = OsString::from_wide(&[b'b' as u16, 0xD800, b'.' as u16, b'b' as u16]);
        let mut obj2 = Map::new();
        put_path(&mut obj2, "root", Path::new(&bad));
        assert_eq!(obj2.get("root_lossy"), Some(&Value::Bool(true)));
        assert!(obj2.get("root").is_some_and(Value::is_string));

        let a1 = [OsStr::new("ntfs-unthrottle"), OsStr::new("."), OsStr::new("--json")];
        assert!(raw_args_want_json_iter(a1));
        let a2 = [OsStr::new("ntfs-unthrottle"), OsStr::new("--"), OsStr::new("--json")];
        assert!(!raw_args_want_json_iter(a2));

        let cli = Cli::try_parse_from(["ntfs-unthrottle", "--fix", "--json"]).unwrap();
        assert!(cli.fix && cli.json && !cli.yes && cli.command.is_none());

        let cli_def = Cli::try_parse_from(["ntfs-unthrottle"]).unwrap();
        assert!(cli_def.command.is_none() && cli_def.paths.is_empty());

        let cli_rec = Cli::try_parse_from([
            "ntfs-unthrottle",
            r"E:\",
            "--recommended",
            "--fix",
        ])
        .unwrap();
        assert!(cli_rec.command.is_none() && cli_rec.recommended && cli_rec.fix);
        assert_eq!(cli_rec.paths, vec![PathBuf::from(r"E:\")]);

        let cli_opt = Cli::try_parse_from(["ntfs-unthrottle", r"E:\", "--optimize"]).unwrap();
        assert!(cli_opt.command.is_none() && cli_opt.optimize);

        let cli_compact = Cli::try_parse_from(["ntfs-unthrottle", "compact"]).unwrap();
        assert!(matches!(cli_compact.command, Some(Command::Compact(_))));

        let cli_compact_full = Cli::try_parse_from([
            "ntfs-unthrottle",
            "compact",
            r"D:\Games",
            "--profile",
            "space",
            "--min-size",
            "8",
            "--min-savings",
            "15",
            "--fix",
            "--yes",
            "--json",
            "-x",
            "temp",
        ])
        .unwrap();
        assert!(cli_compact_full.json);
        assert_eq!(cli_compact_full.exclude, vec!["temp".to_string()]);
        let Some(Command::Compact(ca)) = cli_compact_full.command else {
            panic!("expected compact subcommand");
        };
        assert_eq!(ca.paths, vec![PathBuf::from(r"D:\Games")]);
        assert_eq!(ca.profile, compact::CompactProfile::Space);
        assert_eq!(ca.min_size, 8);
        assert!((ca.min_savings - 15.0).abs() < 1e-9);
        assert!(ca.fix && ca.yes);

        assert!(raw_args_want_json_iter([
            OsStr::new("ntfs-unthrottle"),
            OsStr::new("compact"),
            OsStr::new("."),
            OsStr::new("--json"),
        ]));

        // Top-level flags / paths must not silently mix with the compact subcommand,
        // while explicit relative paths like `.\compact` and global flags still work.
        assert!(Cli::try_parse_from(["ntfs-unthrottle", "--optimize", "compact"]).is_err());
        assert!(Cli::try_parse_from(["ntfs-unthrottle", "--optimize", "compact", r"E:\"]).is_err());
        assert!(Cli::try_parse_from(["ntfs-unthrottle", "compact", "--optimize"]).is_err());
        assert!(Cli::try_parse_from(["ntfs-unthrottle", r"E:\", "compact"]).is_err());
        assert!(Cli::try_parse_from(["ntfs-unthrottle", "--optimize", r".\compact"]).is_ok());
        assert!(Cli::try_parse_from(["ntfs-unthrottle", "compact", "--json", "-v", "--lang", "de"]).is_ok());
    }
}
