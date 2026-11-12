//! Lightweight runtime localization (English + German) without extra crates.
//!
//! Every user-visible runtime message is a method on [`Lang`] built around an
//! exhaustive `match`. When a new [`Lang`] variant is added, the compiler reports
//! every message that still lacks a translation – nothing can be forgotten.
//!
//! `--help` stays English on purpose; only runtime output is localized.
//!
//! Language detection priority (see [`detect`]):
//! 1. `--lang <auto|en|de>`
//! 2. `LC_ALL`, `LC_MESSAGES`, `LANG` (ignored when empty or `C`/`POSIX`)
//! 3. Windows UI language (`GetUserDefaultUILanguage`)

use std::fmt::Display;
use std::io;
use std::path::Path;
use std::sync::OnceLock;

use ntfs_unthrottle::{error_hint, is_virtual_disk, ErrorHint};

use crate::optimize::OptLabel;
use crate::{Protected, Reason};

/// Supported output languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lang {
    En,
    De,
}

/// Value of the `--lang` CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, clap::ValueEnum)]
pub enum LangChoice {
    /// Detect from LC_ALL / LC_MESSAGES / LANG, then the Windows UI language
    #[default]
    Auto,
    /// English
    En,
    /// German (Deutsch)
    De,
}

/// Why a Windows driver blocks BypassIO (classified in `optimize.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverHint {
    Wof,
    BitLocker,
    VolSnap,
    StorageDriver,
    Other,
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

static CURRENT: OnceLock<Lang> = OnceLock::new();

/// Sets the process-wide language (only the first call wins).
pub fn init(lang: Lang) {
    let _ = CURRENT.set(lang);
}

/// The active language (English until [`init`] is called, e.g. in unit tests).
pub fn tr() -> Lang {
    CURRENT.get().copied().unwrap_or(Lang::En)
}

/// Resolves `--lang` to a concrete language.
pub fn detect(choice: LangChoice) -> Lang {
    match choice {
        LangChoice::En => Lang::En,
        LangChoice::De => Lang::De,
        LangChoice::Auto => from_env(|k| std::env::var(k).ok()).unwrap_or_else(system_ui_lang),
    }
}

/// POSIX locale variables in priority order.
const LOCALE_VARS: [&str; 3] = ["LC_ALL", "LC_MESSAGES", "LANG"];

/// Language from the POSIX locale variables (pure; `get` reads a variable).
/// The first variable that is set, non-empty and not `C`/`POSIX` decides;
/// an unsupported locale (e.g. `fr_FR`) falls back to English.
pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Option<Lang> {
    LOCALE_VARS.iter().find_map(|k| {
        let value = get(k)?;
        let value = value.trim();
        let base = value.split(['.', '@']).next().unwrap_or("");
        if base.is_empty() || base.eq_ignore_ascii_case("C") || base.eq_ignore_ascii_case("POSIX") {
            None
        } else {
            Some(parse_lang_tag(value).unwrap_or(Lang::En))
        }
    })
}

/// Maps a language tag (`de`, `de_DE.UTF-8`, `en-US`, `German_Germany.1252`)
/// to a supported language. `None` for anything else.
pub fn parse_lang_tag(tag: &str) -> Option<Lang> {
    let primary = tag.trim().split(['_', '-', '.', '@']).next()?.to_ascii_lowercase();
    match primary.as_str() {
        "en" | "english" => Some(Lang::En),
        "de" | "german" | "deutsch" => Some(Lang::De),
        _ => None,
    }
}

/// Maps a Windows LANGID via its primary language ID (`lang_id & 0x3FF`).
pub fn from_win32_lang_id(lang_id: u16) -> Lang {
    match lang_id & 0x3FF {
        0x07 => Lang::De, // LANG_GERMAN (de-DE, de-AT, de-CH, …)
        _ => Lang::En,
    }
}

fn system_ui_lang() -> Lang {
    // SAFETY: takes no arguments and only returns a LANGID.
    from_win32_lang_id(unsafe { windows_sys::Win32::Globalization::GetUserDefaultUILanguage() })
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

impl Lang {
    // --- General ----------------------------------------------------------

    /// Prompt suffix for a yes/no question (default: no).
    pub fn yes_no(self) -> &'static str {
        match self {
            Lang::En => "[y/N]",
            Lang::De => "[j/N]",
        }
    }

    /// Does `input` confirm a yes/no prompt?
    pub fn is_yes(self, input: &str) -> bool {
        let a = input.trim().to_lowercase();
        match self {
            Lang::En => matches!(a.as_str(), "y" | "yes"),
            Lang::De => matches!(a.as_str(), "j" | "ja" | "y" | "yes"),
        }
    }

    pub fn aborted(self) -> &'static str {
        match self {
            Lang::En => "Aborted.",
            Lang::De => "Abgebrochen.",
        }
    }

    pub fn no_interactive_console(self) -> &'static str {
        match self {
            Lang::En => "No interactive console – pass --yes to confirm.",
            Lang::De => "Keine interaktive Konsole – zum Bestätigen --yes angeben.",
        }
    }

    pub fn more_items(self, n: usize) -> String {
        match self {
            Lang::En => format!("… and {n} more (-v shows all)"),
            Lang::De => format!("… und {n} weitere (-v zeigt alle)"),
        }
    }

    pub fn word_off(self) -> &'static str {
        match self {
            Lang::En => "off",
            Lang::De => "aus",
        }
    }

    pub fn word_active(self) -> &'static str {
        match self {
            Lang::En => "active",
            Lang::De => "aktiv",
        }
    }

    pub fn not_queryable(self) -> &'static str {
        match self {
            Lang::En => "not queryable",
            Lang::De => "nicht abfragbar",
        }
    }

    pub fn not_queryable_err(self, err: impl Display) -> String {
        match self {
            Lang::En => format!("not queryable ({err})"),
            Lang::De => format!("nicht abfragbar ({err})"),
        }
    }

    /// Localized form of the bus names reported by `tune::device_info`.
    pub fn bus(self, bus: &'static str) -> &'static str {
        match (self, bus) {
            (Lang::De, "SD card") => "SD-Karte",
            (Lang::De, "Storage Spaces") => "Speicherplätze",
            (Lang::De, "virtual") => "virtuell",
            (Lang::De, "unknown") => "unbekannt",
            (Lang::En | Lang::De, other) => other,
        }
    }

    /// Localized, user-friendly description of an I/O error for `path`.
    pub fn describe_error_at(self, err: &io::Error, path: &Path) -> String {
        match self {
            Lang::En => ntfs_unthrottle::describe_error_at(err, path),
            Lang::De => {
                let Some(hint) = error_hint(err) else { return err.to_string() };
                let base = match hint {
                    ErrorHint::Locked => "Datei ist von einem anderen Prozess geöffnet/gesperrt",
                    ErrorHint::AccessDenied => {
                        "Zugriff verweigert (ACL/Systemdatei – ggf. Terminal als Administrator starten)"
                    }
                    ErrorHint::DiskFull => "Datenträger voll",
                    ErrorHint::FileSystemLimitation => {
                        "NTFS-Grenze erreicht: Datei zu stark fragmentiert (vorher defragmentieren)"
                    }
                    ErrorHint::InvalidParameter => {
                        "NTFS lehnt die Änderung ab (ungültiger Parameter – z. B. Cluster > 4 KiB \
                         oder Sparse-Konflikt)"
                    }
                };
                match (is_virtual_disk(path), hint) {
                    (true, ErrorHint::Locked) => format!(
                        "{base} – bei .vhdx ggf. VM beenden, `wsl --shutdown` ausführen bzw. Docker schließen"
                    ),
                    (true, ErrorHint::FileSystemLimitation) => {
                        format!("{base} – bei .vhdx alternativ `Optimize-VHD` oder die Datei umkopieren")
                    }
                    _ => base.to_string(),
                }
            }
        }
    }

    // --- Scan: setup --------------------------------------------------------

    pub fn exclude_missing(self, x: impl Display) -> String {
        match self {
            Lang::En => format!("--exclude {x}: does not exist – ignored."),
            Lang::De => format!("--exclude {x}: existiert nicht – ignoriert."),
        }
    }

    pub fn protected(self, why: Protected) -> &'static str {
        match (self, why) {
            (Lang::En, Protected::SystemFolder) => "system folder",
            (Lang::De, Protected::SystemFolder) => "Systemordner",
            (Lang::En, Protected::RootSystemItem) => "system file/folder at the volume root",
            (Lang::De, Protected::RootSystemItem) => "Systemdatei/-ordner in der Laufwerkswurzel",
            (Lang::En, Protected::RootHiddenSystem) => "hidden + system at the volume root",
            (Lang::De, Protected::RootHiddenSystem) => "versteckt + System in der Laufwerkswurzel",
        }
    }

    pub fn skipped_protected(self, path: impl Display, why: impl Display, hit: impl Display) -> String {
        match self {
            Lang::En => format!("Skipped: {path} – protected ({why}: {hit})."),
            Lang::De => format!("Übersprungen: {path} – geschützt ({why}: {hit})."),
        }
    }

    pub fn no_paths_left(self) -> &'static str {
        match self {
            Lang::En => "No processable paths left.",
            Lang::De => "Keine bearbeitbaren Pfade übrig.",
        }
    }

    pub fn root_contained(self, inner: impl Display, outer: impl Display) -> String {
        match self {
            Lang::En => format!("{inner} is contained in {outer} – not scanned twice."),
            Lang::De => format!("{inner} ist in {outer} enthalten – wird nicht doppelt gescannt."),
        }
    }

    pub fn scanning_paths(self, n: usize) -> String {
        match self {
            Lang::En => format!("Scanning {n} path(s)"),
            Lang::De => format!("Scanne {n} Pfad(e)"),
        }
    }

    /// `indicatif` template for the scan spinner.
    pub fn spinner_template(self) -> &'static str {
        match self {
            Lang::En => "{spinner:.cyan} {pos} entries checked  {wide_msg:.dim}",
            Lang::De => "{spinner:.cyan} {pos} Einträge geprüft  {wide_msg:.dim}",
        }
    }

    // --- Scan: volume / device lines -------------------------------------

    pub fn fs_without_wof(self, fs: impl Display, compression_supported: bool) -> String {
        match self {
            Lang::En => format!(
                "File system {fs}: WOF/CompactOS only exists on NTFS – WOF check skipped{}.",
                if compression_supported { "" } else { ", file compression not supported either" }
            ),
            Lang::De => format!(
                "Dateisystem {fs}: WOF/CompactOS gibt es nur auf NTFS – WOF-Prüfung entfällt{}.",
                if compression_supported { "" } else { ", Datei-Komprimierung ebenfalls nicht unterstützt" }
            ),
        }
    }

    pub fn ntfs_large_clusters(self) -> &'static str {
        match self {
            Lang::En => {
                "NTFS with clusters > 4 KiB: classic NTFS compression is not possible there, \
                 WOF/CompactOS is still checked."
            }
            Lang::De => {
                "NTFS mit Clustern > 4 KiB: klassische NTFS-Komprimierung ist dort nicht möglich, \
                 WOF/CompactOS wird trotzdem geprüft."
            }
        }
    }

    pub fn volume_info_unreadable(self) -> &'static str {
        match self {
            Lang::En => "Volume info not readable",
            Lang::De => "Volume-Info nicht lesbar",
        }
    }

    /// Device kind when the seek penalty is unknown (scan header).
    pub fn generic_drive(self) -> &'static str {
        match self {
            Lang::En => "drive",
            Lang::De => "Datenträger",
        }
    }

    pub fn drive_line(self, desc: impl Display) -> String {
        match self {
            Lang::En => format!("Drive: {desc}"),
            Lang::De => format!("Datenträger: {desc}"),
        }
    }

    // --- Scan: ancestors / result summary --------------------------------

    pub fn ancestors_flagged(self) -> &'static str {
        match self {
            Lang::En => "Parent folders carry the flag as well (new subfolders there inherit it):",
            Lang::De => "Übergeordnete Ordner tragen ebenfalls das Flag (neue Unterordner dort erben es):",
        }
    }

    pub fn drive_root_flag_hint(self, root: impl Display) -> String {
        match self {
            Lang::En => format!("(drive root – only remove the flag: compact /u {root})"),
            Lang::De => format!("(Laufwerkswurzel – nur das Flag entfernen: compact /u {root})"),
        }
    }

    pub fn nothing_found(self, see_hints: bool) -> String {
        match self {
            Lang::En => format!(
                "No counterproductive compression found{}.",
                if see_hints { " (see the notes above)" } else { "" }
            ),
            Lang::De => format!(
                "Keine kontraproduktive Komprimierung gefunden{}.",
                if see_hints { " (Hinweise oben beachten)" } else { "" }
            ),
        }
    }

    pub fn analysis_only_fix(self, flag: impl Display) -> String {
        match self {
            Lang::En => format!("Analysis only. Use {flag} to remove the compression."),
            Lang::De => format!("Nur Analyse. Mit {flag} wird die Komprimierung entfernt."),
        }
    }

    pub fn checking_free_space(self) -> &'static str {
        match self {
            Lang::En => "Checking free space …",
            Lang::De => "Prüfe freien Platz …",
        }
    }

    pub fn not_enough_space(self, root: impl Display, free: impl Display, need: impl Display) -> String {
        match self {
            Lang::En => format!("Not enough space on {root}: {free} free, {need} required incl. buffer"),
            Lang::De => format!("Nicht genug Platz auf {root}: frei {free}, benötigt inkl. Puffer {need}"),
        }
    }

    pub fn confirm_decompress(self, files: usize, dirs: usize) -> String {
        let yn = self.yes_no();
        match self {
            Lang::En => format!("▶ Decompress {files} file(s) and {dirs} folder(s) now? {yn}:"),
            Lang::De => format!("▶ {files} Datei(en) und {dirs} Ordner jetzt entpacken? {yn}:"),
        }
    }

    pub fn cleaning_up(self) -> &'static str {
        match self {
            Lang::En => "Cleaning up …",
            Lang::De => "Bereinige …",
        }
    }

    pub fn bar_dirs_template(self) -> &'static str {
        match self {
            Lang::En => "  Folders [{bar:30.cyan/blue}] {pos}/{len}",
            Lang::De => "  Ordner  [{bar:30.cyan/blue}] {pos}/{len}",
        }
    }

    pub fn bar_files_template(self) -> &'static str {
        match self {
            Lang::En => {
                "  Files   [{bar:30.green/white}] {files_pos}/{files_len} {bytes}/{total_bytes} {smoothed_rate} ETA {smoothed_eta}  {wide_msg:.dim}"
            }
            Lang::De => {
                "  Dateien [{bar:30.green/white}] {files_pos}/{files_len} {bytes}/{total_bytes} {smoothed_rate} ETA {smoothed_eta}  {wide_msg:.dim}"
            }
        }
    }

    pub fn json_fix_requires_yes(self) -> &'static str {
        match self {
            Lang::En => "--json with --fix requires --yes (no interactive prompt in JSON mode).",
            Lang::De => "--json zusammen mit --fix erfordert --yes (keine interaktive Abfrage im JSON-Modus).",
        }
    }

    pub fn interrupted_partial(self) -> &'static str {
        match self {
            Lang::En => "Interrupted by user (Ctrl+C) – partial result after current item:",
            Lang::De => "Vom Benutzer abgebrochen (Strg+C) – Teilergebnis nach aktuellem Element:",
        }
    }

    pub fn heavily_fragmented_header(self, n: usize) -> String {
        match self {
            Lang::En => format!("{n} file(s) still have many fragments (NTFS kept existing extents):"),
            Lang::De => format!("{n} Datei(en) haben weiterhin viele Fragmente (Extents blieben verteilt):"),
        }
    }

    pub fn heavily_fragmented_hint_contig(self, path: impl Display) -> String {
        match self {
            Lang::En => format!("contig.exe \"{path}\""),
            Lang::De => format!("contig.exe \"{path}\""),
        }
    }

    pub fn heavily_fragmented_hint_defrag(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!("Whole volume (especially on HDD): defrag {vol} /U /V"),
            Lang::De => format!("Ganzes Volume (besonders auf HDD): defrag {vol} /U /V"),
        }
    }

    pub fn result_header(self) -> &'static str {
        match self {
            Lang::En => "=== Result ===",
            Lang::De => "=== Ergebnis ===",
        }
    }

    pub fn result_dir_flags(self) -> &'static str {
        match self {
            Lang::En => "Folder flags removed:",
            Lang::De => "Ordner-Flags entfernt:",
        }
    }

    pub fn result_files(self) -> &'static str {
        match self {
            Lang::En => "Files decompressed:",
            Lang::De => "Dateien entpackt:",
        }
    }

    pub fn result_fragments(self) -> &'static str {
        match self {
            Lang::En => "Fragments eliminated:",
            Lang::De => "Fragmente abgebaut:",
        }
    }

    pub fn items_failed(self, n: usize) -> String {
        match self {
            Lang::En => format!("{n} item(s) could not be changed:"),
            Lang::De => format!("{n} Element(e) konnten nicht geändert werden:"),
        }
    }

    // --- Scan: report -------------------------------------------------------

    pub fn analysis_header(self, entries: u64, secs: f64) -> String {
        match self {
            Lang::En => format!("Analysis ({entries} entries in {secs:.1} s)"),
            Lang::De => format!("Analyse ({entries} Einträge in {secs:.1} s)"),
        }
    }

    pub fn lbl_compressed_dirs(self) -> &'static str {
        match self {
            Lang::En => "Compressed folders (inheritance):",
            Lang::De => "Komprimierte Ordner (Vererbung):",
        }
    }

    pub fn keep_dir_flags_note(self) -> &'static str {
        match self {
            Lang::En => "  (--keep-dir-flags: kept)",
            Lang::De => "  (--keep-dir-flags: bleiben)",
        }
    }

    pub fn only_dirs_filtered_note(self, kept: usize) -> String {
        match self {
            Lang::En => format!("  (--only: {kept} selected; --clear-dirs clears all)"),
            Lang::De => format!("  (--only: {kept} ausgewählt; --clear-dirs entfernt alle)"),
        }
    }

    pub fn lbl_throttled_files(self) -> &'static str {
        match self {
            Lang::En => "Throttled files:",
            Lang::De => "Ausgebremste Dateien:",
        }
    }

    pub fn lbl_data_volume(self) -> &'static str {
        match self {
            Lang::En => "Data volume:",
            Lang::De => "Datenvolumen:",
        }
    }

    pub fn data_volume(self, logical: impl Display, physical: impl Display) -> String {
        match self {
            Lang::En => format!("{logical} logical / {physical} physical"),
            Lang::De => format!("{logical} logisch / {physical} physisch"),
        }
    }

    pub fn lbl_extra_space(self) -> &'static str {
        match self {
            Lang::En => "Additional space needed:",
            Lang::De => "Zusätzlicher Platzbedarf:",
        }
    }

    pub fn lbl_kept(self) -> &'static str {
        match self {
            Lang::En => "Usefully compressed (kept):",
            Lang::De => "Sinnvoll komprimiert (bleibt):",
        }
    }

    pub fn kept_files(self, n: u64, saved: impl Display) -> String {
        match self {
            Lang::En => format!("{n} files, saving {saved}"),
            Lang::De => format!("{n} Dateien, sparen {saved}"),
        }
    }

    pub fn lbl_ds_detected(self) -> &'static str {
        match self {
            Lang::En => "DirectStorage detected:",
            Lang::De => "DirectStorage erkannt:",
        }
    }

    pub fn ds_moved(self, game: impl Display, n: u64) -> String {
        match self {
            Lang::En => format!("{game} – {n} WOF file(s) will be decompressed"),
            Lang::De => format!("{game} – {n} WOF-Datei(en) werden entpackt"),
        }
    }

    pub fn lbl_small(self, min_mib: u64) -> String {
        match self {
            Lang::En => format!("Compressed, but < {min_mib} MiB:"),
            Lang::De => format!("Komprimiert, aber < {min_mib} MiB:"),
        }
    }

    pub fn small_ignored(self, n: u64) -> String {
        match self {
            Lang::En => format!("{n} (ignored)"),
            Lang::De => format!("{n} (ignoriert)"),
        }
    }

    pub fn tip_recommended(self) -> &'static str {
        match self {
            Lang::En => "Tip: --recommended also covers build folders, VM images & databases below that size.",
            Lang::De => "Tipp: --recommended erfasst Build-Ordner, VM-Images & Datenbanken auch darunter.",
        }
    }

    pub fn lbl_hardlink_dupes(self) -> &'static str {
        match self {
            Lang::En => "Hardlink duplicates skipped:",
            Lang::De => "Hardlink-Duplikate übersprungen:",
        }
    }

    pub fn lbl_cloud_skipped(self) -> &'static str {
        match self {
            Lang::En => "Cloud placeholders skipped:",
            Lang::De => "Cloud-Platzhalter übersprungen:",
        }
    }

    pub fn lbl_sparse_skipped(self) -> &'static str {
        match self {
            Lang::En => "Sparse files skipped:",
            Lang::De => "Sparse-Dateien übersprungen:",
        }
    }

    pub fn lbl_excluded(self) -> &'static str {
        match self {
            Lang::En => "Excluded:",
            Lang::De => "Ausgeschlossen:",
        }
    }

    pub fn lbl_unreadable(self) -> &'static str {
        match self {
            Lang::En => "Unreadable paths:",
            Lang::De => "Nicht lesbare Pfade:",
        }
    }

    /// Column headers: size, physical ratio, kind, fragments, reason, path.
    pub fn table_columns(self) -> [&'static str; 6] {
        match self {
            Lang::En => ["Size", "phys.", "Type", "Frags", "Reason", "Path"],
            Lang::De => ["Größe", "phys.", "Art", "Fragm.", "Grund", "Pfad"],
        }
    }

    pub fn reason(self, r: Reason) -> &'static str {
        match (self, r) {
            (Lang::En, Reason::Extension) => "extension",
            (Lang::De, Reason::Extension) => "Endung",
            (Lang::En, Reason::LowSavings) => "low savings",
            (Lang::De, Reason::LowSavings) => "kaum Ersparnis",
            (Lang::En, Reason::WriteHeavy) => "write-heavy",
            (Lang::De, Reason::WriteHeavy) => "Schreiblast",
            (Lang::En, Reason::BuildDir) => "build folder",
            (Lang::De, Reason::BuildDir) => "Build-Ordner",
            (Lang::En | Lang::De, Reason::DirectStorage) => "DirectStorage",
            (Lang::En | Lang::De, Reason::Forced) => "--all",
        }
    }

    pub fn compressed_dirs_list(self) -> &'static str {
        match self {
            Lang::En => "Compressed folders:",
            Lang::De => "Komprimierte Ordner:",
        }
    }

    // --- Scan: storage notes (DirectStorage / NVMe) ------------------------

    pub fn ds_detected(self, game: impl Display) -> String {
        match self {
            Lang::En => format!("DirectStorage detected: {game}"),
            Lang::De => format!("DirectStorage erkannt: {game}"),
        }
    }

    /// Two indented lines explaining why WOF hurts DirectStorage on NVMe.
    pub fn ds_kept_body(self, n: u64, size: impl Display) -> String {
        match self {
            Lang::En => format!(
                "      {n} WOF file(s) ({size}) stay compressed. On NVMe, WOF disables the\n      \
                 BypassIO path (Windows 11) and slows down decompression."
            ),
            Lang::De => format!(
                "      {n} WOF-Datei(en) ({size}) bleiben komprimiert. Auf NVMe verhindert WOF den\n      \
                 BypassIO-Pfad (Windows 11) und bremst die Dekompression."
            ),
        }
    }

    pub fn ds_decompress_hint(self, flag: impl Display, game: impl Display) -> String {
        match self {
            Lang::En => format!("Decompress: {flag}  (entire game: ntfs-unthrottle \"{game}\" --all --fix)"),
            Lang::De => format!("Entpacken: {flag}  (alles im Spiel: ntfs-unthrottle \"{game}\" --all --fix)"),
        }
    }

    pub fn nvme_heavy(self, vol: impl Display, size: impl Display) -> String {
        match self {
            Lang::En => format!("NVMe {vol}: {size} in LZX/XPRESS16K files stay compressed. On fast"),
            Lang::De => format!("NVMe {vol}: {size} in LZX/XPRESS16K-Dateien bleiben komprimiert. Auf schnellen"),
        }
    }

    /// Two indented lines following [`Lang::nvme_heavy`].
    pub fn nvme_heavy_body(self) -> &'static str {
        match self {
            Lang::En => {
                "      NVMe SSDs, decompression can be slower than the raw read rate.\n      \
                 If load times matter more than space: ntfs-unthrottle \"<folder>\" --all --fix"
            }
            Lang::De => {
                "      NVMe-SSDs kann die Dekompression langsamer sein als die Rohleserate.\n      \
                 Wem Ladezeit wichtiger ist als Platz: ntfs-unthrottle \"<Ordner>\" --all --fix"
            }
        }
    }

    // --- Optimizer ------------------------------------------------------------

    pub fn opt_tag(self) -> &'static str {
        match self {
            Lang::En => "[Optimizer]",
            Lang::De => "[Optimierer]",
        }
    }

    pub fn opt_checking_volumes(self, n: usize) -> String {
        match self {
            Lang::En => format!("Checking {n} volume(s)"),
            Lang::De => format!("Prüfe {n} Volume(s)"),
        }
    }

    pub fn system_drive_suffix(self) -> &'static str {
        match self {
            Lang::En => "  (system drive)",
            Lang::De => "  (Systemlaufwerk)",
        }
    }

    /// Row labels of the optimizer (max. 12 characters for alignment).
    pub fn opt_label(self, l: OptLabel) -> &'static str {
        match (self, l) {
            (Lang::En, OptLabel::Drive) => "Drive:",
            (Lang::De, OptLabel::Drive) => "Datenträger:",
            (Lang::En, OptLabel::FileSystem) => "File system:",
            (Lang::De, OptLabel::FileSystem) => "Dateisystem:",
            (Lang::En | Lang::De, OptLabel::DevDrive) => "Dev Drive:",
            (Lang::En, OptLabel::Space) => "Space:",
            (Lang::De, OptLabel::Space) => "Platz:",
            (Lang::En | Lang::De, OptLabel::Cluster) => "Cluster:",
            (Lang::En | Lang::De, OptLabel::Mft) => "MFT:",
            (Lang::En, OptLabel::ShortNames) => "8.3 names:",
            (Lang::De, OptLabel::ShortNames) => "8.3-Namen:",
            (Lang::En | Lang::De, OptLabel::BypassIo) => "BypassIO:",
            (Lang::En | Lang::De, OptLabel::Indexer) => "Indexer:",
            (Lang::En, OptLabel::LastAccess) => "Last access:",
            (Lang::De, OptLabel::LastAccess) => "Last-Access:",
            (Lang::En | Lang::De, OptLabel::TrimNtfs) => "TRIM (NTFS):",
            (Lang::En | Lang::De, OptLabel::TrimRefs) => "TRIM (ReFS):",
            (Lang::En, OptLabel::MftZone) => "MFT zone:",
            (Lang::De, OptLabel::MftZone) => "MFT-Zone:",
        }
    }

    pub fn type_unknown(self) -> &'static str {
        match self {
            Lang::En => "type unknown",
            Lang::De => "Typ unbekannt",
        }
    }

    pub fn trim_suffix(self, supported: Option<bool>) -> &'static str {
        match (self, supported) {
            (Lang::En | Lang::De, Some(true)) => ", TRIM ✔",
            (Lang::En, Some(false)) => ", no TRIM",
            (Lang::De, Some(false)) => ", kein TRIM",
            (Lang::En | Lang::De, None) => "",
        }
    }

    pub fn hint_qlc(self, vol: impl Display, product: impl Display) -> String {
        match self {
            Lang::En => format!(
                "{vol} is a QLC SSD ({product}). After a few GiB in a row its SLC cache is full and the \
                 write rate drops to HDD level – that is hardware, not a settings problem. Run large \
                 extract/copy jobs on a TLC/NVMe SSD and move the result afterwards; more free space \
                 enlarges the cache."
            ),
            Lang::De => format!(
                "{vol} ist eine QLC-SSD ({product}). Nach einigen GiB am Stück ist ihr SLC-Cache voll, \
                 dann fällt die Schreibrate auf HDD-Niveau – das ist Hardware, kein Einstellungsproblem. \
                 Große Entpack-/Kopierjobs besser auf einer TLC/NVMe-SSD ausführen und erst danach \
                 verschieben; mehr freier Platz vergrößert den Cache."
            ),
        }
    }

    pub fn hint_hdd(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!(
                "{vol} is an HDD: many small files are inherently slow there. \
                 Defragment regularly: `defrag {vol} /U /V`"
            ),
            Lang::De => format!(
                "{vol} ist eine HDD: Viele kleine Dateien sind dort grundsätzlich langsam. \
                 Regelmäßig defragmentieren: `defrag {vol} /U /V`"
            ),
        }
    }

    pub fn hint_usb(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!(
                "{vol} is attached via USB – throughput and latency are limited by the cable/enclosure, \
                 not by NTFS."
            ),
            Lang::De => format!(
                "{vol} hängt an USB – Durchsatz und Latenz sind durch Kabel/Gehäuse begrenzt, \
                 nicht durch NTFS."
            ),
        }
    }

    pub fn refs_info(self) -> &'static str {
        match self {
            Lang::En => "ReFS – MFT/8.3 do not apply, TRIM see [Global]",
            Lang::De => "ReFS – MFT/8.3 entfallen, TRIM siehe [Global]",
        }
    }

    pub fn dev_drive_trusted(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!("trusted (Defender async mode; verify filters: `fsutil devdrv query {vol}`)"),
            Lang::De => format!("vertrauenswürdig (Defender-Async-Modus; prüfen: `fsutil devdrv query {vol}`)"),
        }
    }

    pub fn dev_drive_untrusted(self) -> &'static str {
        match self {
            Lang::En => "untrusted – Defender runs synchronous blocking scans",
            Lang::De => "nicht vertrauenswürdig – Defender scannt synchron und bremst",
        }
    }

    pub fn hint_dev_drive_untrusted(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!(
                "{vol} is an untrusted Dev Drive: enable Defender async performance mode with \
                 `fsutil devdrv trust {vol}` and inspect filters via `fsutil devdrv query {vol}`."
            ),
            Lang::De => format!(
                "{vol} ist ein nicht vertrauenswürdiges Dev Drive: Defender-Performance-Modus aktivieren mit \
                 `fsutil devdrv trust {vol}` und Filter prüfen via `fsutil devdrv query {vol}`."
            ),
        }
    }

    pub fn dev_drive_no(self) -> &'static str {
        match self {
            Lang::En => "no (standard ReFS)",
            Lang::De => "nein (Standard-ReFS)",
        }
    }

    pub fn indexer_off(self) -> &'static str {
        match self {
            Lang::En => "disabled on volume or WSearch service off",
            Lang::De => "auf Volume oder über WSearch-Dienst aus",
        }
    }

    pub fn indexer_active_soft(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!(
                "content indexing permitted on {vol} root (check Indexing Options / Drive Properties if build folders are crawled)"
            ),
            Lang::De => format!(
                "Inhaltsindizierung auf {vol}-Root erlaubt (bei Build-Ordnern Indizierungsoptionen / Laufwerkseigenschaften prüfen)"
            ),
        }
    }

    pub fn indexer_system(self) -> &'static str {
        match self {
            Lang::En => "active on system drive (normal for Windows Search)",
            Lang::De => "auf Systemlaufwerk aktiv (normal für Windows-Suche)",
        }
    }

    pub fn space_line(self, free: impl Display, total: impl Display, pct: f64) -> String {
        match self {
            Lang::En => format!("{free} free of {total} ({pct:.0} %)"),
            Lang::De => format!("{free} frei von {total} ({pct:.0} %)"),
        }
    }

    pub fn hint_full(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!(
                "{vol} is more than 90 % full – NTFS barely finds contiguous regions anymore, \
                 new files get fragmented."
            ),
            Lang::De => format!(
                "{vol} ist zu über 90 % voll – NTFS findet kaum noch zusammenhängende \
                 Bereiche, neue Dateien zerstückeln."
            ),
        }
    }

    pub fn mft_line(self, size: impl Display, million_records: f64, zone: impl Display) -> String {
        match self {
            Lang::En => format!("{size} (≈ {million_records:.1} M records), zone {zone}"),
            Lang::De => format!("{size} (≈ {million_records:.1} Mio. Datensätze), Zone {zone}"),
        }
    }

    pub fn mft_fragments(self, n: u64) -> String {
        match self {
            Lang::En => format!(", {n} fragment(s)"),
            Lang::De => format!(", {n} Fragment(e)"),
        }
    }

    pub fn hint_mft_fragmented(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!(
                "The MFT on {vol} is fragmented. Windows cannot defragment it while running; \
                 only offline/third-party tools or reformatting help."
            ),
            Lang::De => format!(
                "Die MFT auf {vol} ist zerstückelt. Windows kann sie im laufenden Betrieb \
                 nicht defragmentieren; nur offline/Drittanbieter oder Neuformatierung."
            ),
        }
    }

    pub fn admin_only(self) -> &'static str {
        match self {
            Lang::En => "only queryable as administrator",
            Lang::De => "nur als Administrator abfragbar",
        }
    }

    pub fn short_names_system(self) -> &'static str {
        match self {
            Lang::En => "active (system drive – intentionally left unchanged)",
            Lang::De => "aktiv (Systemlaufwerk – bewusst nicht geändert)",
        }
    }

    pub fn short_names_active(self) -> &'static str {
        match self {
            Lang::En => "active – costs a collision check for every new file name",
            Lang::De => "aktiv – kostet bei jedem neuen Dateinamen eine Kollisionsprüfung",
        }
    }

    pub fn fix_8dot3_global(self) -> &'static str {
        match self {
            Lang::En => "Make 8.3 names configurable per volume (global)",
            Lang::De => "8.3-Namen pro Volume steuerbar machen (global)",
        }
    }

    pub fn note_8dot3_global(self) -> &'static str {
        match self {
            Lang::En => "Does not change C: as long as the volume flag stays active there.",
            Lang::De => "Ändert nichts an C:, solange dort das Volume-Flag aktiv bleibt.",
        }
    }

    pub fn fix_8dot3_volume(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!("Disable 8.3 names on {vol}"),
            Lang::De => format!("8.3-Namen auf {vol} abschalten"),
        }
    }

    pub fn note_8dot3_volume(self) -> &'static str {
        match self {
            Lang::En => "Existing short names remain – `8dot3name strip` is intentionally not run.",
            Lang::De => "Bestehende Kurznamen bleiben – `8dot3name strip` wird bewusst nicht ausgeführt.",
        }
    }

    pub fn dirty_bit_set(self) -> &'static str {
        match self {
            Lang::En => "dirty bit set",
            Lang::De => "Dirty-Bit gesetzt",
        }
    }

    pub fn hint_dirty(self, vol: impl Display) -> String {
        match self {
            Lang::En => format!("{vol} is marked as faulty. Check with `chkdsk {vol} /scan` (online)."),
            Lang::De => format!("{vol} ist als fehlerhaft markiert. Prüfen mit `chkdsk {vol} /scan` (online)."),
        }
    }

    pub fn fs_clean(self) -> &'static str {
        match self {
            Lang::En => "clean",
            Lang::De => "sauber",
        }
    }

    pub fn bypass_diag(self, root: impl Display) -> String {
        match self {
            Lang::En => format!("Diagnose: `fsutil bypassIo state /v {root}` and `fltmc filters` (as administrator)."),
            Lang::De => format!("Diagnose: `fsutil bypassIo state /v {root}` und `fltmc filters` (als Administrator)."),
        }
    }

    pub fn bypass_no_storage(self) -> &'static str {
        match self {
            Lang::En => "no veto, but the storage driver does not report BypassIO support",
            Lang::De => "kein Veto, Speichertreiber meldet aber keine BypassIO-Fähigkeit",
        }
    }

    pub fn bypass_partial(self, driver: impl Display, hint: impl Display) -> String {
        match self {
            Lang::En => format!("partial (volume/storage stack: {driver} – {hint})"),
            Lang::De => format!("partiell (Volume-/Speicher-Stack: {driver} – {hint})"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn hint_bypass_partial(
        self,
        vol: impl Display,
        driver: impl Display,
        reason: impl Display,
        status: u32,
        hint: impl Display,
        diag: impl Display,
    ) -> String {
        match self {
            Lang::En => format!(
                "BypassIO on {vol} only partial: {driver} ({reason}, status 0x{status:08X}). {hint} {diag}"
            ),
            Lang::De => format!(
                "BypassIO auf {vol} nur partiell: {driver} ({reason}, Status 0x{status:08X}). {hint} {diag}"
            ),
        }
    }

    pub fn bypass_blocked_by(self, driver: impl Display) -> String {
        match self {
            Lang::En => format!("blocked by {driver}"),
            Lang::De => format!("blockiert durch {driver}"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn hint_bypass_blocked(
        self,
        vol: impl Display,
        driver: impl Display,
        reason: impl Display,
        status: u32,
        hint: impl Display,
        diag: impl Display,
    ) -> String {
        match self {
            Lang::En => format!(
                "BypassIO on {vol} blocked by {driver} ({reason}, status 0x{status:08X}): {hint}. \
                 {diag} Please do NOT unload minifilters via `fltmc unload` – that can disable \
                 protection or sync features."
            ),
            Lang::De => format!(
                "BypassIO auf {vol} blockiert durch {driver} ({reason}, Status 0x{status:08X}): {hint}. \
                 {diag} Minifilter bitte NICHT per `fltmc unload` entladen – das kann Schutz- \
                 oder Sync-Funktionen abschalten."
            ),
        }
    }

    pub fn bypass_unavailable(self) -> &'static str {
        match self {
            Lang::En => "not available (Windows 11 or later)",
            Lang::De => "nicht verfügbar (erst ab Windows 11)",
        }
    }

    pub fn driver_hint(self, h: DriverHint) -> &'static str {
        match (self, h) {
            (Lang::En, DriverHint::Wof) => {
                "WOF compression (CompactOS/compact /exe) – decompress affected files with \
                 `ntfs-unthrottle <folder> --recommended --fix`"
            }
            (Lang::De, DriverHint::Wof) => {
                "WOF-Komprimierung (CompactOS/compact /exe) – betroffene Dateien mit \
                 `ntfs-unthrottle <Ordner> --recommended --fix` entpacken"
            }
            (Lang::En, DriverHint::BitLocker) => "BitLocker encryption of the volume",
            (Lang::De, DriverHint::BitLocker) => "BitLocker-Verschlüsselung des Volumes",
            (Lang::En, DriverHint::VolSnap) => "volume shadow copy/restore point active",
            (Lang::De, DriverHint::VolSnap) => "Volumeschattenkopie/Wiederherstellungspunkt aktiv",
            (Lang::En, DriverHint::StorageDriver) => {
                "storage driver without BypassIO (SATA/AHCI or Intel RST/VMD) – only the \
                 Microsoft NVMe driver (stornvme.sys) supports BypassIO"
            }
            (Lang::De, DriverHint::StorageDriver) => {
                "Speichertreiber ohne BypassIO (SATA/AHCI bzw. Intel RST/VMD) – nur der \
                 Microsoft-NVMe-Treiber (stornvme.sys) unterstützt BypassIO"
            }
            (Lang::En, DriverHint::Other) => {
                "filter driver (e.g. antivirus, backup, sync, encryption) – check for a vendor update"
            }
            (Lang::De, DriverHint::Other) => {
                "Filtertreiber (z. B. Virenscanner, Backup, Sync, Verschlüsselung) – \
                 Hersteller-Update prüfen"
            }
        }
    }

    pub fn last_access_active(self) -> &'static str {
        match self {
            Lang::En => "active – every read writes a timestamp",
            Lang::De => "aktiv – jeder Lesezugriff schreibt einen Zeitstempel",
        }
    }

    pub fn fix_last_access(self) -> &'static str {
        match self {
            Lang::En => "Disable last-access timestamps",
            Lang::De => "Last-Access-Zeitstempel abschalten",
        }
    }

    pub fn trim_ntfs_disabled(self) -> &'static str {
        match self {
            Lang::En => "disabled – the SSD gets slower over time",
            Lang::De => "deaktiviert – die SSD wird mit der Zeit langsamer",
        }
    }

    pub fn fix_trim_ntfs(self) -> &'static str {
        match self {
            Lang::En => "Enable TRIM for NTFS",
            Lang::De => "TRIM für NTFS aktivieren",
        }
    }

    pub fn trim_refs_disabled(self) -> &'static str {
        match self {
            Lang::En => "disabled – Dev Drive/ReFS SSD gets slower over time",
            Lang::De => "deaktiviert – Dev Drive/ReFS-SSD wird mit der Zeit langsamer",
        }
    }

    pub fn fix_trim_refs(self) -> &'static str {
        match self {
            Lang::En => "Enable TRIM for ReFS",
            Lang::De => "TRIM für ReFS aktivieren",
        }
    }

    pub fn trim_refs_unset(self) -> &'static str {
        match self {
            Lang::En => "not set (default: active)",
            Lang::De => "nicht gesetzt (Standard: aktiv)",
        }
    }

    pub fn mft_zone_small(self, zone: u64) -> String {
        match self {
            Lang::En => format!("level {zone} – too small for volumes with millions of files"),
            Lang::De => format!("Stufe {zone} – zu klein für Volumes mit Millionen Dateien"),
        }
    }

    pub fn fix_mft_zone(self) -> &'static str {
        match self {
            Lang::En => "Reserve a larger MFT zone (level 2)",
            Lang::De => "Größere MFT-Zone reservieren (Stufe 2)",
        }
    }

    pub fn note_mft_zone(self) -> &'static str {
        match self {
            Lang::En => "Takes effect after a reboot and only for future MFT growth.",
            Lang::De => "Wirkt erst nach einem Neustart und nur für künftiges MFT-Wachstum.",
        }
    }

    pub fn mft_zone_level(self, zone: u64) -> String {
        match self {
            Lang::En => format!("level {zone}"),
            Lang::De => format!("Stufe {zone}"),
        }
    }

    pub fn hints_header(self) -> &'static str {
        match self {
            Lang::En => "Notes (not automated):",
            Lang::De => "Hinweise (nicht automatisch):",
        }
    }

    pub fn admin_needed(self) -> &'static str {
        match self {
            Lang::En => "Some values (MFT, dirty bit) require a terminal running as administrator.",
            Lang::De => "Einige Werte (MFT, Dirty-Bit) brauchen ein Terminal als Administrator.",
        }
    }

    pub fn no_fixes_needed(self) -> &'static str {
        match self {
            Lang::En => "No fixes needed.",
            Lang::De => "Keine Korrekturen nötig.",
        }
    }

    pub fn fixes_header(self) -> &'static str {
        match self {
            Lang::En => "Fixes:",
            Lang::De => "Korrekturen:",
        }
    }

    pub fn analysis_only_optimize(self, flag: impl Display) -> String {
        match self {
            Lang::En => format!("Analysis only. Use {flag} to apply the fixes (as administrator)."),
            Lang::De => format!("Nur Analyse. Mit {flag} werden die Korrekturen angewendet (als Administrator)."),
        }
    }

    pub fn confirm_fixes(self, n: usize) -> String {
        let yn = self.yes_no();
        match self {
            Lang::En => format!("▶ Apply {n} fix(es) now? {yn}:"),
            Lang::De => format!("▶ {n} Korrektur(en) jetzt anwenden? {yn}:"),
        }
    }

    pub fn fixes_failed(self, n: usize) -> String {
        match self {
            Lang::En => format!("{n} fix(es) failed – usually administrator rights are missing."),
            Lang::De => format!("{n} Korrektur(en) fehlgeschlagen – meist fehlen Administratorrechte."),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lang_tag_parsing() {
        assert_eq!(parse_lang_tag("de"), Some(Lang::De));
        assert_eq!(parse_lang_tag("de_DE.UTF-8"), Some(Lang::De));
        assert_eq!(parse_lang_tag("de-AT"), Some(Lang::De));
        assert_eq!(parse_lang_tag("German_Germany.1252"), Some(Lang::De));
        assert_eq!(parse_lang_tag("en_US.UTF-8"), Some(Lang::En));
        assert_eq!(parse_lang_tag("EN"), Some(Lang::En));
        assert_eq!(parse_lang_tag("fr_FR"), None);
        assert_eq!(parse_lang_tag(""), None);
        // "deu"/"dev" must not be mistaken for "de"
        assert_eq!(parse_lang_tag("dev"), None);
    }

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn env_priority_and_ignored_values() {
        assert_eq!(from_env(env(&[])), None);
        assert_eq!(from_env(env(&[("LANG", "de_DE.UTF-8")])), Some(Lang::De));
        // LC_ALL beats LC_MESSAGES beats LANG
        assert_eq!(
            from_env(env(&[("LC_ALL", "en_US"), ("LC_MESSAGES", "de_DE"), ("LANG", "de_DE")])),
            Some(Lang::En)
        );
        assert_eq!(from_env(env(&[("LC_MESSAGES", "de_DE"), ("LANG", "en_US")])), Some(Lang::De));
        // Empty, C and POSIX are skipped
        assert_eq!(from_env(env(&[("LC_ALL", ""), ("LANG", "de")])), Some(Lang::De));
        assert_eq!(from_env(env(&[("LC_ALL", "C"), ("LANG", "de")])), Some(Lang::De));
        assert_eq!(from_env(env(&[("LC_ALL", "C.UTF-8"), ("LANG", "de")])), Some(Lang::De));
        assert_eq!(from_env(env(&[("LC_ALL", "POSIX")])), None);
        // Unsupported locale → English
        assert_eq!(from_env(env(&[("LANG", "fr_FR.UTF-8")])), Some(Lang::En));
    }

    #[test]
    fn win32_lang_id_mapping() {
        assert_eq!(from_win32_lang_id(0x0407), Lang::De); // de-DE
        assert_eq!(from_win32_lang_id(0x0C07), Lang::De); // de-AT
        assert_eq!(from_win32_lang_id(0x0807), Lang::De); // de-CH
        assert_eq!(from_win32_lang_id(0x0409), Lang::En); // en-US
        assert_eq!(from_win32_lang_id(0x040C), Lang::En); // fr-FR → fallback
        assert_eq!(from_win32_lang_id(0), Lang::En);
    }

    #[test]
    fn explicit_choice_wins() {
        assert_eq!(detect(LangChoice::En), Lang::En);
        assert_eq!(detect(LangChoice::De), Lang::De);
    }

    #[test]
    fn yes_no_confirmation() {
        assert_eq!(Lang::En.yes_no(), "[y/N]");
        assert_eq!(Lang::De.yes_no(), "[j/N]");
        for yes in ["y", "Y", "yes", " YES \r\n"] {
            assert!(Lang::En.is_yes(yes), "{yes:?}");
            assert!(Lang::De.is_yes(yes), "{yes:?}");
        }
        for ja in ["j", "J", "ja", "Ja\n"] {
            assert!(Lang::De.is_yes(ja), "{ja:?}");
            assert!(!Lang::En.is_yes(ja), "{ja:?}");
        }
        for no in ["", "n", "no", "nein", "jein", "yess"] {
            assert!(!Lang::En.is_yes(no), "{no:?}");
            assert!(!Lang::De.is_yes(no), "{no:?}");
        }
        assert!(Lang::En.confirm_decompress(2, 1).ends_with("[y/N]:"));
        assert!(Lang::De.confirm_fixes(3).ends_with("[j/N]:"));
    }

    #[test]
    fn localized_errors() {
        let share = io::Error::from_raw_os_error(32); // ERROR_SHARING_VIOLATION
        let vhdx = Path::new(r"E:\VMs\disk.vhdx");
        let bin = Path::new(r"E:\data.bin");
        assert!(Lang::De.describe_error_at(&share, vhdx).contains("wsl --shutdown"));
        assert!(Lang::De.describe_error_at(&share, bin).contains("gesperrt"));
        assert!(Lang::En.describe_error_at(&share, vhdx).contains("wsl --shutdown"));
        assert!(Lang::En.describe_error_at(&share, bin).contains("locked"));
    }

    #[test]
    fn bus_names_localized() {
        assert_eq!(Lang::De.bus("SD card"), "SD-Karte");
        assert_eq!(Lang::En.bus("SD card"), "SD card");
        assert_eq!(Lang::De.bus("NVMe"), "NVMe");
    }

    #[test]
    fn labels_fit_their_columns() {
        for l in [Lang::En, Lang::De] {
            for r in [
                Reason::Extension,
                Reason::LowSavings,
                Reason::WriteHeavy,
                Reason::BuildDir,
                Reason::DirectStorage,
                Reason::Forced,
            ] {
                assert!(l.reason(r).chars().count() <= 14, "{}", l.reason(r));
            }
            for o in [
                OptLabel::Drive,
                OptLabel::FileSystem,
                OptLabel::DevDrive,
                OptLabel::Space,
                OptLabel::Cluster,
                OptLabel::Mft,
                OptLabel::ShortNames,
                OptLabel::BypassIo,
                OptLabel::Indexer,
                OptLabel::LastAccess,
                OptLabel::TrimNtfs,
                OptLabel::TrimRefs,
                OptLabel::MftZone,
            ] {
                assert!(l.opt_label(o).chars().count() <= 12, "{}", l.opt_label(o));
            }
        }
    }
}
