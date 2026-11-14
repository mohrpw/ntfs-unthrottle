//! `ntfs-unthrottle compact`: selective per-file WOF compression using PE header
//! inspection, in-memory `XPRESS_HUFF` probing, and drive/profile-aware policies.

use std::collections::{HashMap, HashSet};
use std::io;
use std::os::windows::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use console::style;
use humansize::{format_size, BINARY};
use serde_json::{json, Map, Value};
use walkdir::WalkDir;

use ntfs_unthrottle::tune::DeviceInfo;
use ntfs_unthrottle::{
    compress_wof, display_path, file_identity_of, open_for_query, physical_size,
    remove_ntfs_compression, remove_wof_compression, volume_free_and_total, wof_algorithm_of,
    CompressionKind, VolumeInfo, WofAlgorithm, WofCompressOutcome,
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SPARSE_FILE,
};

use crate::exts::{has_ext, COMPACT_SKIP_EXTS, HIGH_ENTROPY_EXTS, WRITE_HEAVY_EXTS};
use crate::i18n::tr;
use crate::optimize::QLC_MODELS;
use crate::probe::{
    estimate_wof_footprint, passes_savings_check, FootprintEstimate, PeProfile, ProbeOutcome,
    XpressHuffProbe,
};
use crate::{
    comp_eq, confirm, dedup_roots, ds_game_root, file_name, fold, in_build_dir, make_file_bar,
    make_spinner, parse_percent, path_obj, put_path, resolve_scan_roots, under, CtrlHandlerGuard,
    EtaTracker, Excludes, RootInfo, CLOUD_ATTRS, DS_DLLS, EXIT_FOUND, EXIT_INTERRUPTED,
    EXIT_PARTIAL, INTERRUPTED,
};

/// Gaming and GPU/shader cache directory names excluded from WOF compression.
const CACHE_DIRS: &[&str] = &[
    "shadercache",
    "downloading",
    "temp",
    ".egstore",
    "dxcache",
    "glcache",
    "nv_cache",
];

#[derive(clap::ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum CompactProfile {
    #[default]
    Auto,
    Speed,
    Balanced,
    Space,
}

impl CompactProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::Speed => "speed",
            Self::Balanced => "balanced",
            Self::Space => "space",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectiveProfile {
    Speed,
    Balanced,
    Space,
}

impl EffectiveProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Speed => "speed",
            Self::Balanced => "balanced",
            Self::Space => "space",
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct CompactArgs {
    /// Folders or files to check for selective WOF compression
    #[arg(default_value = ".")]
    pub paths: Vec<PathBuf>,

    /// Actually compress candidates (without: dry-run analysis only)
    #[arg(short, long)]
    pub fix: bool,

    /// Skip the confirmation prompt (for scripts)
    #[arg(short, long, requires = "fix")]
    pub yes: bool,

    /// Compression aggressiveness profile
    #[arg(long, value_enum, value_name = "PROFILE", default_value_t = CompactProfile::Auto)]
    pub profile: CompactProfile,

    /// Minimum estimated space savings in %
    #[arg(long, value_name = "PERCENT", default_value_t = 15.0, value_parser = parse_percent)]
    pub min_savings: f64,

    /// Minimum file size in KiB
    #[arg(long, value_name = "KiB", default_value_t = 32)]
    pub min_size: u64,

    /// Re-evaluate already WOF-compressed files for a better algorithm
    #[arg(long)]
    pub recompress: bool,

    /// Include hardlinked files (links > 1) outside protected paths
    #[arg(long)]
    pub include_hardlinks: bool,
}

pub struct GlobalCliOpts<'a> {
    pub verbose: bool,
    pub json: bool,
    pub exclude: &'a [String],
}

#[derive(Debug, Clone, Copy)]
pub struct PolicyContext {
    pub profile: EffectiveProfile,
    pub is_nvme: bool,
    pub min_savings: f64,
    pub cluster_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactPlanItem {
    pub target_alg: WofAlgorithm,
    pub footprint: FootprintEstimate,
    pub est_saved_bytes: u64,
    pub est_saved_clusters: u64,
}

fn in_cache_dir(path: &Path, root: &Path) -> bool {
    let mut cur = path.parent();
    while let Some(dir) = cur {
        if !dir.starts_with(root) {
            break;
        }
        if let Some(name) = dir.file_name() {
            if CACHE_DIRS.contains(&fold(name).as_str()) {
                return true;
            }
        }
        if dir == root {
            break;
        }
        cur = dir.parent();
    }
    false
}

pub fn is_qlc_model(dev: Option<&DeviceInfo>) -> bool {
    let Some(product) = dev.and_then(|d| d.product.as_deref()) else {
        return false;
    };
    let upper = product.to_ascii_uppercase();
    QLC_MODELS.iter().any(|m| upper.contains(m))
}

/// Resolves `--profile auto` per volume using device model (QLC) and free disk space.
pub fn resolve_effective_profile(
    requested: CompactProfile,
    dev: Option<&DeviceInfo>,
    vol: Option<&VolumeInfo>,
) -> (EffectiveProfile, bool) {
    match requested {
        CompactProfile::Speed => (EffectiveProfile::Speed, false),
        CompactProfile::Balanced => (EffectiveProfile::Balanced, false),
        CompactProfile::Space => (EffectiveProfile::Space, false),
        CompactProfile::Auto => {
            let qlc_low_space = is_qlc_model(dev)
                && vol.is_some_and(|v| {
                    v.total_bytes > 0 && v.free_bytes.saturating_mul(5) < v.total_bytes
                });
            if qlc_low_space {
                (EffectiveProfile::Balanced, true)
            } else {
                (EffectiveProfile::Speed, false)
            }
        }
    }
}

/// Pure algorithm selection matrix (without WOF header / cluster evaluation).
pub fn select_target_algorithm(
    profile: EffectiveProfile,
    is_nvme: bool,
    pe: PeProfile,
    est_ratio: f64,
    logical: u64,
    min_savings_pct: f64,
) -> Option<WofAlgorithm> {
    if !est_ratio.is_finite() || est_ratio > (100.0 - min_savings_pct) / 100.0 {
        return None;
    }
    match pe {
        PeProfile::PackedStub => None,
        PeProfile::ExecutableCode { .. } => {
            if is_nvme {
                match profile {
                    EffectiveProfile::Speed | EffectiveProfile::Balanced => None,
                    EffectiveProfile::Space => Some(WofAlgorithm::Xpress4K),
                }
            } else if logical <= 8 * 1024 * 1024 {
                Some(WofAlgorithm::Xpress4K)
            } else {
                Some(WofAlgorithm::Xpress8K)
            }
        }
        PeProfile::NotPe | PeProfile::LargeOverlay { .. } => {
            if est_ratio < 0.50 {
                if logical < 256 * 1024 {
                    Some(WofAlgorithm::Xpress8K)
                } else if is_nvme && profile == EffectiveProfile::Speed {
                    // LZX (~120-180 MiB/s) would throttle NVMe in `speed` profile; cap at Xpress16K.
                    Some(WofAlgorithm::Xpress16K)
                } else {
                    Some(WofAlgorithm::Lzx)
                }
            } else if is_nvme {
                match profile {
                    EffectiveProfile::Speed => None,
                    EffectiveProfile::Balanced | EffectiveProfile::Space => {
                        Some(WofAlgorithm::Xpress8K)
                    }
                }
            } else if logical < 1024 * 1024 {
                Some(WofAlgorithm::Xpress4K)
            } else if logical <= 32 * 1024 * 1024 {
                Some(WofAlgorithm::Xpress8K)
            } else {
                Some(WofAlgorithm::Xpress16K)
            }
        }
    }
}

/// Full pure per-file decision combining [`select_target_algorithm`], WOF chunk-table
/// footprint estimation, and cluster / MFT / LZNT1 / recompress regression checks.
pub fn evaluate_compact_candidate(
    ctx: &PolicyContext,
    pe: PeProfile,
    est_payload_bytes: u64,
    est_ratio: f64,
    logical: u64,
    existing_kind: Option<CompressionKind>,
    current_physical: Option<u64>,
) -> Option<CompactPlanItem> {
    let target_alg = select_target_algorithm(
        ctx.profile,
        ctx.is_nvme,
        pe,
        est_ratio,
        logical,
        ctx.min_savings,
    )?;
    if existing_kind == Some(CompressionKind::Wof(target_alg)) {
        return None;
    }
    let footprint =
        estimate_wof_footprint(logical, est_payload_bytes, target_alg, ctx.cluster_size)?;
    if !passes_savings_check(
        logical,
        footprint,
        ctx.min_savings,
        ctx.cluster_size,
        existing_kind,
        current_physical,
    ) {
        return None;
    }
    let baseline = current_physical.unwrap_or(logical);
    let cluster = ctx.cluster_size.max(512);
    let est_saved_bytes = baseline.saturating_sub(footprint.est_physical_bytes);
    let est_saved_clusters = baseline
        .div_ceil(cluster)
        .saturating_sub(footprint.est_clusters);
    Some(CompactPlanItem {
        target_alg,
        footprint,
        est_saved_bytes,
        est_saved_clusters,
    })
}

struct PrelimCandidate {
    root: usize,
    path: PathBuf,
    logical: u64,
    existing_kind: Option<CompressionKind>,
}

struct CompactCandidate {
    root: usize,
    path: PathBuf,
    logical: u64,
    existing_kind: Option<CompressionKind>,
    current_physical: Option<u64>,
    plan: CompactPlanItem,
}

#[derive(Default)]
struct CompactScan {
    prelim: Vec<PrelimCandidate>,
    candidates: Vec<CompactCandidate>,
    entries: u64,
    errors: u64,
    cloud_skipped: u64,
    sparse_skipped: u64,
    encrypted_skipped: u64,
    hardlinks_skipped: u64,
    small_skipped: u64,
    excluded_type_skipped: u64,
    already_wof: u64,
    ds_skipped: u64,
    packed_skipped: u64,
    unbeneficial_skipped: u64,
    excluded: Vec<PathBuf>,
    seen_links: HashSet<(u32, u64)>,
    build_cache: HashMap<PathBuf, bool>,
    ds_dll_dirs: Vec<(usize, PathBuf)>,
}

#[derive(Default)]
struct CompactFixSummary {
    interrupted: bool,
    compressed_files: usize,
    files_todo: usize,
    not_beneficial: usize,
    insufficient_space_skipped: usize,
    bytes_before: u64,
    bytes_after: u64,
    failed: Vec<(PathBuf, String)>,
}

impl CompactFixSummary {
    fn actual_saved(&self) -> u64 {
        self.bytes_before.saturating_sub(self.bytes_after)
    }
}

pub fn run(args: &CompactArgs, global: &GlobalCliOpts<'_>) -> io::Result<ExitCode> {
    let l = tr();
    let (roots, infos) = resolve_scan_roots(&args.paths, global.json)?;
    let profiles: Vec<(EffectiveProfile, bool)> = infos
        .iter()
        .map(|i| resolve_effective_profile(args.profile, i.dev.as_ref(), i.vol.as_ref()))
        .collect();

    if !global.json {
        println!(
            "{} {}",
            style("[1/3]").bold().cyan(),
            l.scanning_paths(roots.len())
        );
        for ((root, info), (eff, qlc_auto)) in roots.iter().zip(&infos).zip(&profiles) {
            println!("      {}", style(display_path(root)).underlined());
            crate::report_volume(info);
            if let Some(v) = &info.vol {
                if !info.wof_possible() {
                    println!(
                        "      {} {}",
                        style("ℹ").blue(),
                        l.compact_non_ntfs_skipped(&v.fs_name)
                    );
                    continue;
                }
            }
            println!(
                "      {}",
                style(l.compact_profile_line(args.profile.as_str(), eff.as_str(), *qlc_auto)).dim()
            );
        }
    }

    let started = Instant::now();
    let spinner = make_spinner(global.json);
    let excludes = Excludes::from_list(global.exclude, global.json)?;
    let mut scan = CompactScan::default();

    // Stage 1a: metadata walk (0 probe reads)
    for (i, (root, info)) in roots.iter().zip(&infos).enumerate() {
        if !info.wof_possible() {
            continue;
        }
        walk_compact_root(args, i, root, info, &excludes, &mut scan, &spinner);
    }

    // DirectStorage-on-NVMe veto BEFORE Stage 1b reads any bytes.
    let ds_games_raw: Vec<PathBuf> = scan
        .ds_dll_dirs
        .iter()
        .filter_map(|(i, dir)| ds_game_root(dir, infos[*i].vol_root()))
        .collect();
    let (ds_games, _) = dedup_roots(ds_games_raw);
    if !ds_games.is_empty() {
        let mut kept = Vec::with_capacity(scan.prelim.len());
        for c in scan.prelim.drain(..) {
            if infos[c.root].is_nvme() && ds_games.iter().any(|g| under(&c.path, g)) {
                scan.ds_skipped += 1;
            } else {
                kept.push(c);
            }
        }
        scan.prelim = kept;
    }

    // Stage 1b: PE inspection & XPRESS_HUFF probe
    if !scan.prelim.is_empty() {
        let mut probe = XpressHuffProbe::new()?;
        let contexts: Vec<PolicyContext> = infos
            .iter()
            .zip(&profiles)
            .map(|(info, (eff, _))| PolicyContext {
                profile: *eff,
                is_nvme: info.is_nvme(),
                min_savings: args.min_savings,
                cluster_size: info.cluster_size(),
            })
            .collect();

        for c in scan.prelim.drain(..) {
            spinner.set_message(display_path(&c.path));
            let current_physical = if c.existing_kind.is_some() {
                physical_size(&c.path).ok()
            } else {
                None
            };
            match probe.probe_file(&c.path, c.logical, CLOUD_ATTRS) {
                Ok(ProbeOutcome::SkipUnsafe) => {
                    scan.errors += 1;
                }
                Ok(ProbeOutcome::PackedStub) => {
                    scan.packed_skipped += 1;
                }
                Ok(ProbeOutcome::Measured {
                    pe,
                    est_payload_bytes,
                    est_ratio,
                }) => {
                    if let Some(plan) = evaluate_compact_candidate(
                        &contexts[c.root],
                        pe,
                        est_payload_bytes,
                        est_ratio,
                        c.logical,
                        c.existing_kind,
                        current_physical,
                    ) {
                        scan.candidates.push(CompactCandidate {
                            root: c.root,
                            path: c.path,
                            logical: c.logical,
                            existing_kind: c.existing_kind,
                            current_physical,
                            plan,
                        });
                    } else if matches!(c.existing_kind, Some(CompressionKind::Wof(_))) {
                        scan.already_wof += 1;
                    } else {
                        scan.unbeneficial_skipped += 1;
                    }
                }
                Err(_) => {
                    scan.errors += 1;
                }
            }
        }
    }
    spinner.finish_and_clear();

    // Sort descending by estimated saved bytes for dry-run reporting & JSON.
    scan.candidates
        .sort_by_key(|c| std::cmp::Reverse(c.plan.est_saved_bytes));

    if !global.json {
        print_compact_report(args, global, &scan, started.elapsed());
    }

    if scan.candidates.is_empty() {
        if global.json {
            emit_compact_json(
                args,
                &roots,
                &infos,
                &profiles,
                &scan,
                started.elapsed(),
                None,
            )?;
        } else {
            println!(
                "\n{} {}",
                style("✔").green().bold(),
                l.compact_nothing_found()
            );
        }
        return Ok(ExitCode::SUCCESS);
    }

    if !args.fix {
        if global.json {
            emit_compact_json(
                args,
                &roots,
                &infos,
                &profiles,
                &scan,
                started.elapsed(),
                None,
            )?;
        } else {
            println!(
                "\n{} {}",
                style("ℹ").blue().bold(),
                l.compact_analysis_only(style("--fix").yellow().bold())
            );
        }
        return Ok(ExitCode::from(EXIT_FOUND));
    }

    let total_est_saved: u64 = scan.candidates.iter().map(|c| c.plan.est_saved_bytes).sum();
    if !args.yes {
        let prompt = format!(
            "\n{}\n{} ",
            style("─".repeat(60)).yellow(),
            style(l.compact_confirm(scan.candidates.len(), format_size(total_est_saved, BINARY)))
                .yellow()
                .bold()
        );
        if !confirm(&prompt)? {
            println!("{}", l.aborted());
            return Ok(ExitCode::SUCCESS);
        }
    }

    // Sort ascending by logical size so smaller files free up disk space for large files.
    scan.candidates.sort_by_key(|c| c.logical);

    if !global.json {
        println!(
            "\n{} {}",
            style("[3/3]").bold().cyan(),
            l.compact_compressing()
        );
    }
    let _ctrl_guard = CtrlHandlerGuard::install();
    let mut fix = CompactFixSummary {
        files_todo: scan.candidates.len(),
        ..Default::default()
    };

    let total_bytes: u64 = scan.candidates.iter().map(|c| c.logical).sum();
    let tracker = Arc::new(Mutex::new(EtaTracker::from_sizes(
        scan.candidates.iter().map(|c| c.logical),
        Instant::now(),
    )));
    let pb = make_file_bar(global.json, total_bytes, &tracker);

    for c in &scan.candidates {
        if INTERRUPTED.load(Ordering::SeqCst) {
            fix.interrupted = true;
            break;
        }
        pb.set_message(file_name(&c.path));

        let vol_root = infos[c.root].vol_root().unwrap_or(&roots[c.root]);
        if let Ok((free, total)) = volume_free_and_total(vol_root) {
            let margin = (256 * 1024 * 1024).max(total / 100);
            if free < c.logical.saturating_add(margin) {
                fix.insufficient_space_skipped += 1;
                if let Ok(mut g) = tracker.lock() {
                    g.record(c.logical, Instant::now());
                }
                pb.inc(c.logical);
                continue;
            }
        }

        let prep_res = match c.existing_kind {
            Some(CompressionKind::Lznt1) => remove_ntfs_compression(&c.path, false),
            Some(CompressionKind::Wof(_)) => remove_wof_compression(&c.path),
            None => Ok(()),
        };
        match prep_res.and_then(|()| compress_wof(&c.path, c.plan.target_alg)) {
            Ok(WofCompressOutcome::Compressed) => {
                fix.compressed_files += 1;
                let prev = c.current_physical.unwrap_or(c.logical);
                let after = physical_size(&c.path).unwrap_or(c.plan.footprint.est_physical_bytes);
                fix.bytes_before = fix.bytes_before.saturating_add(prev);
                fix.bytes_after = fix.bytes_after.saturating_add(after);
            }
            Ok(WofCompressOutcome::NotBeneficial) => {
                fix.not_beneficial += 1;
            }
            Err(e) => {
                fix.failed
                    .push((c.path.clone(), l.describe_error_at(&e, &c.path)));
            }
        }

        if let Ok(mut g) = tracker.lock() {
            g.record(c.logical, Instant::now());
        }
        pb.inc(c.logical);
    }
    pb.finish_and_clear();
    drop(_ctrl_guard);

    if global.json {
        emit_compact_json(
            args,
            &roots,
            &infos,
            &profiles,
            &scan,
            started.elapsed(),
            Some(&fix),
        )?;
    } else {
        if fix.interrupted {
            eprintln!(
                "\n  {} {}",
                style("⚠").yellow().bold(),
                l.interrupted_partial()
            );
        }
        println!("\n{}", style(l.result_header()).bold());
        println!(
            "  {} {:<34}{}/{}",
            style("✔").green(),
            l.compact_result_compressed(),
            fix.compressed_files,
            fix.files_todo
        );
        if fix.bytes_before > 0 {
            println!(
                "  {} {:<34}{}",
                style("✔").green(),
                l.compact_result_actual_saved(),
                l.compact_saved_val(
                    format_size(fix.bytes_before, BINARY),
                    format_size(fix.bytes_after, BINARY),
                    format_size(fix.actual_saved(), BINARY),
                )
            );
        }
        if fix.not_beneficial > 0 {
            println!(
                "  {} {:<34}{}",
                style("ℹ").blue(),
                l.compact_result_not_beneficial(),
                fix.not_beneficial
            );
        }
        if fix.insufficient_space_skipped > 0 {
            println!(
                "  {} {:<34}{}",
                style("⚠").yellow(),
                l.compact_result_space_skipped(),
                fix.insufficient_space_skipped
            );
        }
        if !fix.failed.is_empty() {
            println!(
                "\n  {} {}",
                style("⚠").yellow().bold(),
                l.items_failed(fix.failed.len())
            );
            let shown = if global.verbose { fix.failed.len() } else { 10 };
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

fn walk_compact_root(
    args: &CompactArgs,
    root_idx: usize,
    root: &Path,
    info: &RootInfo,
    excludes: &Excludes,
    scan: &mut CompactScan,
    spinner: &indicatif::ProgressBar,
) {
    let min_bytes = args
        .min_size
        .saturating_mul(1024)
        .max(info.cluster_size().max(4096));

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
        let Ok(entry) = entry else {
            scan.errors += 1;
            continue;
        };
        let Ok(meta) = entry.metadata() else {
            scan.errors += 1;
            continue;
        };
        let attrs = meta.file_attributes();
        if attrs & CLOUD_ATTRS != 0 {
            scan.cloud_skipped += 1;
            continue;
        }
        if attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            continue;
        }
        if attrs & FILE_ATTRIBUTE_SPARSE_FILE != 0 {
            scan.sparse_skipped += 1;
            continue;
        }
        if attrs & FILE_ATTRIBUTE_ENCRYPTED != 0 {
            scan.encrypted_skipped += 1;
            continue;
        }
        if meta.is_dir() {
            continue;
        }

        let path = entry.path();
        if let (Some(name), Some(parent)) = (path.file_name(), path.parent()) {
            if DS_DLLS.iter().any(|d| comp_eq(name, d))
                && scan.ds_dll_dirs.last().is_none_or(|(_, p)| p != parent)
            {
                scan.ds_dll_dirs.push((root_idx, parent.to_path_buf()));
            }
        }

        let logical = meta.len();
        if logical < min_bytes {
            scan.small_skipped += 1;
            continue;
        }

        if has_ext(path, COMPACT_SKIP_EXTS)
            || has_ext(path, HIGH_ENTROPY_EXTS)
            || has_ext(path, WRITE_HEAVY_EXTS)
            || in_build_dir(path, root, &mut scan.build_cache)
            || in_cache_dir(path, root)
        {
            scan.excluded_type_skipped += 1;
            continue;
        }

        let Ok(handle) = open_for_query(path) else {
            scan.errors += 1;
            continue;
        };

        if let Ok(id) = file_identity_of(&handle) {
            if id.links > 1 && (!args.include_hardlinks || !scan.seen_links.insert(id.key())) {
                scan.hardlinks_skipped += 1;
                continue;
            }
        }

        let ntfs_compressed = attrs & FILE_ATTRIBUTE_COMPRESSED != 0;
        let existing_kind = if ntfs_compressed {
            Some(CompressionKind::Lznt1)
        } else {
            match wof_algorithm_of(&handle) {
                Ok(Some(alg)) => {
                    if !args.recompress {
                        scan.already_wof += 1;
                        continue;
                    }
                    Some(CompressionKind::Wof(alg))
                }
                Ok(None) => None,
                Err(_) => {
                    scan.errors += 1;
                    continue;
                }
            }
        };

        scan.prelim.push(PrelimCandidate {
            root: root_idx,
            path: path.to_path_buf(),
            logical,
            existing_kind,
        });
    }
    scan.excluded.extend(excluded.into_inner());
}

fn row(label: &str, value: impl std::fmt::Display) {
    println!("  • {label:<34}{value}");
}

const ALG_ORDER: [WofAlgorithm; 4] = [
    WofAlgorithm::Xpress4K,
    WofAlgorithm::Xpress8K,
    WofAlgorithm::Xpress16K,
    WofAlgorithm::Lzx,
];

fn print_compact_report(
    args: &CompactArgs,
    global: &GlobalCliOpts<'_>,
    scan: &CompactScan,
    took: std::time::Duration,
) {
    let l = tr();
    let total_baseline: u64 = scan
        .candidates
        .iter()
        .map(|c| c.current_physical.unwrap_or(c.logical))
        .sum();
    let total_est_saved: u64 = scan.candidates.iter().map(|c| c.plan.est_saved_bytes).sum();
    let total_est_clusters: u64 = scan
        .candidates
        .iter()
        .map(|c| c.plan.est_saved_clusters)
        .sum();
    let pct = if total_baseline == 0 {
        0.0
    } else {
        total_est_saved as f64 / total_baseline as f64 * 100.0
    };

    println!(
        "\n{} {}",
        style("[2/3]").bold().cyan(),
        l.analysis_header(scan.entries, took.as_secs_f64())
    );
    row(
        l.compact_lbl_candidates(),
        style(scan.candidates.len()).yellow().bold(),
    );
    if !scan.candidates.is_empty() {
        row(
            l.compact_lbl_est_savings(),
            style(l.compact_est_savings_val(
                format_size(total_est_saved, BINARY),
                pct,
                total_est_clusters,
            ))
            .bold(),
        );
    }
    if scan.already_wof > 0 {
        row(l.compact_lbl_already_wof(), scan.already_wof);
    }
    if scan.ds_skipped > 0 {
        row(l.compact_lbl_ds_skipped(), scan.ds_skipped);
    }
    if scan.packed_skipped > 0 {
        row(l.compact_lbl_packed_skipped(), scan.packed_skipped);
    }
    if scan.encrypted_skipped > 0 {
        row(l.compact_lbl_encrypted_skipped(), scan.encrypted_skipped);
    }
    if scan.hardlinks_skipped > 0 {
        row(l.compact_lbl_hardlinks_skipped(), scan.hardlinks_skipped);
    }
    if scan.unbeneficial_skipped > 0 {
        row(l.compact_lbl_unbeneficial(), scan.unbeneficial_skipped);
    }
    if scan.excluded_type_skipped > 0 {
        row(l.compact_lbl_excluded_type(), scan.excluded_type_skipped);
    }
    if scan.small_skipped > 0 {
        row(
            &l.compact_lbl_small_skipped(args.min_size),
            scan.small_skipped,
        );
    }
    if scan.cloud_skipped > 0 {
        row(l.lbl_cloud_skipped(), scan.cloud_skipped);
    }
    if scan.sparse_skipped > 0 {
        row(l.lbl_sparse_skipped(), scan.sparse_skipped);
    }
    if scan.errors > 0 {
        row(l.lbl_unreadable(), style(scan.errors).dim());
    }

    if !scan.candidates.is_empty() {
        println!("\n  {}", style(l.compact_alg_group_header()).bold());
        for alg in ALG_ORDER {
            let group: Vec<&CompactCandidate> = scan
                .candidates
                .iter()
                .filter(|c| c.plan.target_alg == alg)
                .collect();
            if group.is_empty() {
                continue;
            }
            let g_logical: u64 = group.iter().map(|c| c.logical).sum();
            let g_est_phys: u64 = group
                .iter()
                .map(|c| c.plan.footprint.est_physical_bytes)
                .sum();
            let g_saved: u64 = group.iter().map(|c| c.plan.est_saved_bytes).sum();
            let g_clusters: u64 = group.iter().map(|c| c.plan.est_saved_clusters).sum();
            println!(
                "    {:<10} {}",
                style(alg.to_string()).cyan().bold(),
                l.compact_alg_group_line(
                    group.len(),
                    format_size(g_logical, BINARY),
                    format_size(g_est_phys, BINARY),
                    format_size(g_saved, BINARY),
                    g_clusters,
                )
            );
        }

        let shown = if global.verbose {
            scan.candidates.len()
        } else {
            10
        };
        let [size, est, alg_col, saves, path] = l.compact_table_columns();
        println!("\n  {size:>10}  {est:>6}  {alg_col:<10} {saves:>10}  {path}");
        for c in scan.candidates.iter().take(shown) {
            let est_pct = if c.logical == 0 {
                100.0
            } else {
                c.plan.footprint.est_physical_bytes as f64 / c.logical as f64 * 100.0
            };
            println!(
                "  {:>10}  {:>5.1}%  {:<10} {:>10}  {}",
                format_size(c.logical, BINARY),
                est_pct,
                c.plan.target_alg.to_string(),
                format_size(c.plan.est_saved_bytes, BINARY),
                display_path(&c.path)
            );
        }
        if scan.candidates.len() > shown {
            println!("  {}", l.more_items(scan.candidates.len() - shown));
        }
    }
}

fn emit_compact_json(
    args: &CompactArgs,
    roots: &[PathBuf],
    infos: &[RootInfo],
    profiles: &[(EffectiveProfile, bool)],
    scan: &CompactScan,
    took: std::time::Duration,
    fix: Option<&CompactFixSummary>,
) -> io::Result<()> {
    let total_logical: u64 = scan.candidates.iter().map(|c| c.logical).sum();
    let total_est_phys: u64 = scan
        .candidates
        .iter()
        .map(|c| c.plan.footprint.est_physical_bytes)
        .sum();
    let total_est_saved: u64 = scan.candidates.iter().map(|c| c.plan.est_saved_bytes).sum();
    let total_est_clusters: u64 = scan
        .candidates
        .iter()
        .map(|c| c.plan.est_saved_clusters)
        .sum();

    let roots_json: Vec<Value> = roots
        .iter()
        .zip(infos)
        .zip(profiles)
        .map(|((root, info), (eff, qlc_auto))| {
            let mut m = Map::new();
            put_path(&mut m, "root", root);
            m.insert("effective_profile".into(), json!(eff.as_str()));
            m.insert("qlc_auto_balanced".into(), json!(qlc_auto));
            m.insert(
                "volume".into(),
                match &info.vol {
                    Some(v) => {
                        let mut vm = Map::new();
                        put_path(&mut vm, "root", &v.root);
                        vm.insert("fs_name".into(), json!(v.fs_name));
                        vm.insert("free_bytes".into(), json!(v.free_bytes));
                        vm.insert("total_bytes".into(), json!(v.total_bytes));
                        vm.insert("bytes_per_cluster".into(), json!(v.bytes_per_cluster));
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

    let mut by_algorithm = Map::new();
    for alg in ALG_ORDER {
        let group: Vec<&CompactCandidate> = scan
            .candidates
            .iter()
            .filter(|c| c.plan.target_alg == alg)
            .collect();
        if !group.is_empty() {
            by_algorithm.insert(
                alg.to_string(),
                json!({
                    "files": group.len(),
                    "logical_bytes": group.iter().map(|c| c.logical).sum::<u64>(),
                    "est_physical_bytes": group.iter().map(|c| c.plan.footprint.est_physical_bytes).sum::<u64>(),
                    "est_saved_bytes": group.iter().map(|c| c.plan.est_saved_bytes).sum::<u64>(),
                    "est_saved_clusters": group.iter().map(|c| c.plan.est_saved_clusters).sum::<u64>(),
                }),
            );
        }
    }

    let files_json: Vec<Value> = scan
        .candidates
        .iter()
        .map(|c| {
            let mut m = Map::new();
            put_path(&mut m, "path", &c.path);
            m.insert("logical_bytes".into(), json!(c.logical));
            m.insert(
                "est_physical_bytes".into(),
                json!(c.plan.footprint.est_physical_bytes),
            );
            m.insert("est_saved_bytes".into(), json!(c.plan.est_saved_bytes));
            m.insert(
                "est_saved_clusters".into(),
                json!(c.plan.est_saved_clusters),
            );
            m.insert(
                "target_algorithm".into(),
                json!(c.plan.target_alg.to_string()),
            );
            m.insert(
                "existing_compression".into(),
                json!(c.existing_kind.map(|k| k.to_string())),
            );
            Value::Object(m)
        })
        .collect();

    let excluded_json: Vec<Value> = scan.excluded.iter().map(|p| path_obj(p)).collect();

    let fix_json = match fix {
        Some(f) => {
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
                "compressed_files": f.compressed_files,
                "files_todo": f.files_todo,
                "not_beneficial": f.not_beneficial,
                "insufficient_space_skipped": f.insufficient_space_skipped,
                "bytes_before": f.bytes_before,
                "bytes_after": f.bytes_after,
                "actual_saved_bytes": f.actual_saved(),
                "failed": failed_json,
            })
        }
        None => Value::Null,
    };

    let payload = json!({
        "mode": "compact",
        "profile": args.profile.as_str(),
        "roots": roots_json,
        "summary": {
            "entries": scan.entries,
            "duration_secs": took.as_secs_f64(),
            "candidates": scan.candidates.len(),
            "logical_bytes": total_logical,
            "est_physical_bytes": total_est_phys,
            "est_saved_bytes": total_est_saved,
            "est_saved_clusters": total_est_clusters,
            "already_wof": scan.already_wof,
            "ds_skipped": scan.ds_skipped,
            "packed_skipped": scan.packed_skipped,
            "encrypted_skipped": scan.encrypted_skipped,
            "hardlinks_skipped": scan.hardlinks_skipped,
            "unbeneficial_skipped": scan.unbeneficial_skipped,
            "excluded_type_skipped": scan.excluded_type_skipped,
            "small_skipped": scan.small_skipped,
            "cloud_skipped": scan.cloud_skipped,
            "sparse_skipped": scan.sparse_skipped,
            "errors": scan.errors,
        },
        "by_algorithm": Value::Object(by_algorithm),
        "files": files_json,
        "excluded": excluded_json,
        "fix": fix_json,
    });
    println!(
        "{}",
        serde_json::to_string(&payload).map_err(io::Error::other)?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(profile: EffectiveProfile, is_nvme: bool) -> PolicyContext {
        PolicyContext {
            profile,
            is_nvme,
            min_savings: 15.0,
            cluster_size: 4096,
        }
    }

    #[test]
    fn policy_matrix_nvme_and_sata_rules() {
        let pe_exe = PeProfile::ExecutableCode { is_dotnet: false };
        let pe_dotnet = PeProfile::ExecutableCode { is_dotnet: true };
        // Executable on NVMe: skip in Speed & Balanced, Xpress4K in Space
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                true,
                pe_exe,
                0.4,
                2 * 1024 * 1024,
                15.0
            ),
            None
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Balanced,
                true,
                pe_dotnet,
                0.4,
                2 * 1024 * 1024,
                15.0
            ),
            None
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Space,
                true,
                pe_exe,
                0.4,
                2 * 1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress4K)
        );
        // Executable on SATA: Xpress4K <= 8 MiB, Xpress8K > 8 MiB
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                false,
                pe_exe,
                0.5,
                4 * 1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress4K)
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                false,
                pe_exe,
                0.5,
                16 * 1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress8K)
        );

        // Cold data with high redundancy (est_ratio < 0.50): NVMe Speed caps at Xpress16K; Balanced uses Lzx
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                true,
                PeProfile::NotPe,
                0.25,
                1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress16K)
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Balanced,
                true,
                PeProfile::NotPe,
                0.25,
                1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Lzx)
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                false,
                PeProfile::NotPe,
                0.25,
                1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Lzx)
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                true,
                PeProfile::NotPe,
                0.25,
                64 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress8K)
        );

        // Moderate redundancy (0.65)
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                true,
                PeProfile::NotPe,
                0.65,
                4 * 1024 * 1024,
                15.0
            ),
            None
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Balanced,
                true,
                PeProfile::NotPe,
                0.65,
                4 * 1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress8K)
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                false,
                PeProfile::NotPe,
                0.65,
                512 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress4K)
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                false,
                PeProfile::NotPe,
                0.65,
                8 * 1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress8K)
        );
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Speed,
                false,
                PeProfile::NotPe,
                0.65,
                64 * 1024 * 1024,
                15.0
            ),
            Some(WofAlgorithm::Xpress16K)
        );

        // PackedStub always skipped
        assert_eq!(
            select_target_algorithm(
                EffectiveProfile::Space,
                false,
                PeProfile::PackedStub,
                0.1,
                10 * 1024 * 1024,
                15.0
            ),
            None
        );
    }

    #[test]
    fn auto_profile_switches_to_balanced_on_qlc_low_free_space() {
        let qlc = DeviceInfo {
            product: Some("Samsung SSD 870 QVO 1TB".into()),
            bus: Some("SATA"),
            seek_penalty: Some(false),
            trim_supported: Some(true),
        };
        let low_vol = VolumeInfo {
            root: PathBuf::from(r"E:\"),
            fs_name: "NTFS".into(),
            supports_compression: true,
            free_bytes: 150,
            total_bytes: 1000,
            bytes_per_cluster: 4096,
        };
        assert_eq!(
            resolve_effective_profile(CompactProfile::Auto, Some(&qlc), Some(&low_vol)),
            (EffectiveProfile::Balanced, true)
        );

        let plenty_vol = VolumeInfo {
            free_bytes: 500,
            ..low_vol
        };
        assert_eq!(
            resolve_effective_profile(CompactProfile::Auto, Some(&qlc), Some(&plenty_vol)),
            (EffectiveProfile::Speed, false)
        );
    }

    #[test]
    fn recompress_rejects_minimal_gains_and_allows_worthwhile_upgrades() {
        let c = ctx(EffectiveProfile::Balanced, false);
        let logical = 100 * 1024 * 1024u64;
        let est_payload = 30 * 1024 * 1024u64; // LZX target ~30 MiB
                                               // Already Xpress8K at 31 MiB -> saving ~1 MiB (~3%) -> MUST reject (< 10% / 15%)
        assert!(evaluate_compact_candidate(
            &c,
            PeProfile::NotPe,
            est_payload,
            0.30,
            logical,
            Some(CompressionKind::Wof(WofAlgorithm::Xpress8K)),
            Some(31 * 1024 * 1024),
        )
        .is_none());

        // Same algorithm -> MUST reject
        assert!(evaluate_compact_candidate(
            &c,
            PeProfile::NotPe,
            est_payload,
            0.30,
            logical,
            Some(CompressionKind::Wof(WofAlgorithm::Lzx)),
            Some(50 * 1024 * 1024),
        )
        .is_none());

        // Currently Xpress4K at 60 MiB -> LZX ~30 MiB (50% savings) -> Allow
        let ok = evaluate_compact_candidate(
            &c,
            PeProfile::NotPe,
            est_payload,
            0.30,
            logical,
            Some(CompressionKind::Wof(WofAlgorithm::Xpress4K)),
            Some(60 * 1024 * 1024),
        );
        assert_eq!(ok.unwrap().target_alg, WofAlgorithm::Lzx);
    }

    #[test]
    fn skip_exts_and_cache_dirs_detected() {
        assert!(has_ext(Path::new(r"C:\Drivers\foo.SYS"), COMPACT_SKIP_EXTS));
        assert!(has_ext(
            Path::new(r"E:\Boot\bootx64.efi"),
            COMPACT_SKIP_EXTS
        ));
        assert!(!has_ext(Path::new(r"E:\Games\data.bin"), COMPACT_SKIP_EXTS));

        let root = Path::new(r"E:\Games");
        assert!(in_cache_dir(
            Path::new(r"E:\Games\MyGame\ShaderCache\a.bin"),
            root
        ));
        assert!(in_cache_dir(
            Path::new(r"E:\Games\Steam\downloading\123\x.dat"),
            root
        ));
        assert!(!in_cache_dir(
            Path::new(r"E:\Games\MyGame\Data\x.dat"),
            root
        ));
    }
}
