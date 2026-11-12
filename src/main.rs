use std::collections::BTreeMap;
use std::io::{self, IsTerminal, Write};
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

mod optimize;

use clap::Parser;
use console::style;
use humansize::{format_size, BINARY};
use indicatif::{ProgressBar, ProgressStyle};
use walkdir::WalkDir;

use ntfs_unthrottle::{
    compressed_ancestors, describe_error, display_path, fragment_count, physical_size,
    remove_compression, remove_ntfs_compression, volume_info, wof_algorithm, CompressionKind,
    VolumeInfo,
};
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
const BUILD_DIRS: &[&str] = &[
    "node_modules", ".git", "target", "obj", ".vs", ".idea", "__pycache__", ".venv", "venv",
    ".tox", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".gradle", ".next", ".nuxt",
    ".turbo", ".parcel-cache", ".angular", ".svelte-kit", "build", "dist", ".cargo",
    ".rustup", ".nuget", ".m2", "go-build", "ccache", ".ccache",
];

fn has_ext(path: &Path, list: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| list.contains(&e.to_ascii_lowercase().as_str()))
}

/// Liegt `path` (irgendwo) unterhalb eines Build-/Tooling-Ordners?
fn in_build_dir(path: &Path) -> bool {
    path.ancestors().skip(1).any(|p| {
        p.file_name()
            .is_some_and(|n| BUILD_DIRS.contains(&n.to_string_lossy().to_lowercase().as_str()))
    })
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
    /// unfertige Downloads sowie alles in Build-Ordnern (node_modules, target, .git, …)
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
                let c = std::fs::canonicalize(x)
                    .map_err(|e| io::Error::new(e.kind(), format!("--exclude {x}: {e}")))?;
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
    Forced,
}

impl Reason {
    fn label(self) -> &'static str {
        match self {
            Reason::Extension => "Endung",
            Reason::LowSavings => "kaum Ersparnis",
            Reason::WriteHeavy => "Schreiblast",
            Reason::BuildDir => "Build-Ordner",
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

    // --- Phase 1: Scan ----------------------------------------------------
    println!("{} Scanne {} Pfad(e)", style("[1/3]").bold().cyan(), roots.len());
    for root in &roots {
        println!("      {}", style(display_path(root)).underlined());
        report_volume(root);
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
    for (i, root) in roots.iter().enumerate() {
        scan_tree(cli, i, root, &excludes, &mut scan, &spinner);
    }
    spinner.finish_and_clear();
    scan.files.sort_by_key(|f| std::cmp::Reverse(f.logical));

    // --- Phase 2: Auswertung ----------------------------------------------
    print_report(cli, &scan, started.elapsed());

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
            println!("      {}", display_path(a));
        }
    }

    let dirs_todo = if cli.keep_dir_flags { 0 } else { scan.dirs.len() };
    if dirs_todo == 0 && scan.files.is_empty() {
        println!(
            "\n{} Keine kontraproduktive Komprimierung gefunden.",
            style("✔").green().bold()
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
                Err(e) => failed.push((dir.clone(), describe_error(&e))),
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
                Err(e) => failed.push((f.path.clone(), describe_error(&e))),
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

fn scan_tree(cli: &Cli, root_idx: usize, root: &Path, excludes: &Excludes, scan: &mut Scan, spinner: &ProgressBar) {
    let min_bytes = cli.min_size.saturating_mul(1024 * 1024);

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
        let write_heavy = cli.recommended && has_ext(path, WRITE_HEAVY_EXTS);
        let build_dir = cli.recommended && !write_heavy && in_build_dir(path);

        let logical = meta.len();
        if logical < min_bytes && !write_heavy && !build_dir {
            if ntfs_compressed {
                scan.small_compressed += 1;
            }
            continue;
        }

        let kind = if ntfs_compressed {
            CompressionKind::Lznt1
        } else if cli.no_wof {
            continue;
        } else {
            match wof_algorithm(path) {
                Ok(Some(alg)) => CompressionKind::Wof(alg),
                Ok(None) => continue,
                Err(_) => {
                    scan.errors += 1;
                    continue;
                }
            }
        };

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
                    fragment_count(path).ok()
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
            }
        }
    }
    scan.excluded.extend(excluded.into_inner());
}

fn report_volume(root: &Path) {
    match volume_info(root) {
        Ok(v) if !v.supports_compression => println!(
            "      {} Dateisystem {} unterstützt keine Datei-Komprimierung – vermutlich nichts zu tun.",
            style("ℹ").blue(),
            v.fs_name
        ),
        Ok(_) => {}
        Err(e) => println!("      {} Volume-Info nicht lesbar: {e}", style("⚠").yellow()),
    }
}

fn print_report(cli: &Cli, scan: &Scan, took: Duration) {
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
    if scan.small_compressed > 0 {
        println!(
            "  • Komprimiert, aber < {} MiB:        {} (ignoriert)",
            cli.min_size, scan.small_compressed
        );
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
