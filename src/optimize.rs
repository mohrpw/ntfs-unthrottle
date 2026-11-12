//! `--optimize`: checks volume and NTFS settings that slow down file I/O,
//! and applies the safe fixes via `fsutil` when `--fix` is given.
//!
//! Intentionally NOT automated: `8dot3name strip` (can break registry paths
//! that point to short names), Defender exclusions (security), defragmentation
//! and chkdsk – these are only mentioned as hints with the matching command.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use console::style;
use humansize::{format_size, BINARY};

use ntfs_unthrottle::tune::{
    bypass_io_status, decode_oem, device_info, filesystem_reg_value, ntfs_data, refs_trim_disabled,
    short_names_disabled_on_volume, volume_dirty, BypassIoStatus,
};
use ntfs_unthrottle::{display_path, fragment_count, volume_info};

use crate::i18n::{tr, DriverHint};

/// Known QLC SSD families: once the SLC cache is full, the write rate collapses.
const QLC_MODELS: &[&str] = &["QVO", "660P", "670P", "CT500P1", "CT1000P1", "CT2000P1", "P2 ", "NV2"];

/// From this many MFT records on, a larger MFT zone pays off.
const LARGE_MFT_RECORDS: u64 = 2_000_000;
/// From this many fragments on, the MFT counts as fragmented.
const MFT_FRAGMENT_WARN: u64 = 64;

/// Row labels of the optimizer output (localized in `i18n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptLabel {
    Drive,
    FileSystem,
    Space,
    Cluster,
    Mft,
    ShortNames,
    BypassIo,
    LastAccess,
    TrimNtfs,
    TrimRefs,
    MftZone,
}

struct Fix {
    title: String,
    args: Vec<String>,
    note: Option<&'static str>,
}

#[derive(Default)]
struct Plan {
    fixes: Vec<Fix>,
    hints: Vec<String>,
}

impl Plan {
    fn fix(&mut self, title: impl Into<String>, args: &[&str], note: Option<&'static str>) {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        if !self.fixes.iter().any(|f| f.args == args) {
            self.fixes.push(Fix { title: title.into(), args, note });
        }
    }
}

fn ok(label: OptLabel, value: impl std::fmt::Display) {
    println!("  {} {:<13}{}", style("✔").green(), tr().opt_label(label), value);
}
fn warn(label: OptLabel, value: impl std::fmt::Display) {
    println!("  {} {:<13}{}", style("⚠").yellow().bold(), tr().opt_label(label), style(value).yellow());
}
fn info(label: OptLabel, value: impl std::fmt::Display) {
    println!("  {} {:<13}{}", style("ℹ").blue(), tr().opt_label(label), value);
}

/// Classifies known drivers that prevent BypassIO.
fn bypass_driver_kind(driver: &str) -> DriverHint {
    match driver.to_ascii_lowercase().as_str() {
        "wof.sys" => DriverHint::Wof,
        "fvevol.sys" => DriverHint::BitLocker,
        "volsnap.sys" => DriverHint::VolSnap,
        "storahci.sys" | "iastorvd.sys" | "iastorac.sys" | "iastora.sys" | "rsttcs.sys" => {
            DriverHint::StorageDriver
        }
        _ => DriverHint::Other,
    }
}

/// Explanation for a driver that prevents BypassIO (localized).
fn bypass_driver_hint(driver: &str) -> &'static str {
    tr().driver_hint(bypass_driver_kind(driver))
}

/// `E:\` → `E:` (the form fsutil expects for drive letters); mount points stay as-is.
fn fsutil_volume(root: &Path) -> String {
    let s = display_path(root);
    let t = s.trim_end_matches('\\');
    if t.len() == 2 && t.ends_with(':') {
        t.to_string()
    } else {
        s
    }
}

pub fn run(paths: &[PathBuf], apply: bool, yes: bool) -> io::Result<ExitCode> {
    let l = tr();
    // Volumes of the given paths, without duplicates.
    let mut volumes: BTreeMap<String, PathBuf> = BTreeMap::new();
    for p in paths {
        let v = volume_info(p).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?;
        volumes.entry(display_path(&v.root).to_lowercase()).or_insert(v.root);
    }

    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).to_lowercase();
    let reg_8dot3 = filesystem_reg_value("NtfsDisable8dot3NameCreation");
    let mut plan = Plan::default();
    // TRIM switches are global, but separate per file system.
    let mut any_ntfs_ssd = false;
    let mut any_refs_ssd = false;
    let mut any_large_mft = false;
    let mut admin_hint = false;

    println!("{} {}\n", style(l.opt_tag()).bold().cyan(), l.opt_checking_volumes(volumes.len()));

    for root in volumes.values() {
        let vol = fsutil_volume(root);
        let is_system = vol.to_lowercase() == system_drive;
        let vi = volume_info(root)?;
        let is_ntfs = vi.fs_name.eq_ignore_ascii_case("NTFS");
        let is_refs = vi.fs_name.eq_ignore_ascii_case("ReFS");
        let mut is_nvme = false;
        println!(
            "{} {}{}",
            style(format!("[{}]", display_path(root))).bold(),
            vi.fs_name,
            if is_system { l.system_drive_suffix() } else { "" }
        );

        // --- Storage device ---------------------------------------------------
        match device_info(root) {
            Ok(d) => {
                let kind = match d.seek_penalty {
                    Some(true) => "HDD",
                    Some(false) => "SSD",
                    None => l.type_unknown(),
                };
                let trim = l.trim_suffix(d.trim_supported);
                let line = format!(
                    "{} ({}, {kind}{trim})",
                    d.product.as_deref().unwrap_or("?"),
                    d.bus.map_or("?", |b| l.bus(b))
                );
                is_nvme = d.bus == Some("NVMe");
                if d.seek_penalty == Some(false) {
                    any_ntfs_ssd |= is_ntfs;
                    any_refs_ssd |= is_refs;
                }
                let product = d.product.as_deref().unwrap_or("").to_uppercase();
                if QLC_MODELS.iter().any(|m| product.contains(m)) {
                    plan.hints.push(l.hint_qlc(&vol, d.product.as_deref().unwrap_or("?")));
                }
                match (d.seek_penalty, d.bus) {
                    (Some(true), _) => {
                        warn(OptLabel::Drive, line);
                        plan.hints.push(l.hint_hdd(&vol));
                    }
                    (_, Some("USB")) => {
                        warn(OptLabel::Drive, line);
                        plan.hints.push(l.hint_usb(&vol));
                    }
                    _ => ok(OptLabel::Drive, line),
                }
            }
            Err(e) => info(OptLabel::Drive, l.not_queryable_err(e)),
        }

        if is_refs {
            info(OptLabel::FileSystem, l.refs_info());
        }

        // --- Space, clusters, MFT ---------------------------------------------
        if is_ntfs {
            match ntfs_data(root) {
                Ok(n) => {
                    let free_pct = n.free_bytes as f64 / n.total_bytes.max(1) as f64 * 100.0;
                    let line = l.space_line(
                        format_size(n.free_bytes, BINARY),
                        format_size(n.total_bytes, BINARY),
                        free_pct,
                    );
                    if free_pct < 10.0 {
                        warn(OptLabel::Space, line);
                        plan.hints.push(l.hint_full(&vol));
                    } else {
                        ok(OptLabel::Space, line);
                    }
                    info(OptLabel::Cluster, format_size(n.bytes_per_cluster, BINARY));

                    let records = n.mft_records();
                    let frags = fragment_count(&root.join("$MFT")).ok();
                    let mut line = l.mft_line(
                        format_size(n.mft_valid_length, BINARY),
                        records as f64 / 1e6,
                        format_size(n.mft_zone_bytes, BINARY),
                    );
                    if let Some(f) = frags {
                        line.push_str(&l.mft_fragments(f));
                    }
                    if records >= LARGE_MFT_RECORDS {
                        any_large_mft = true;
                    }
                    if frags.is_some_and(|f| f >= MFT_FRAGMENT_WARN) {
                        warn(OptLabel::Mft, line);
                        plan.hints.push(l.hint_mft_fragmented(&vol));
                    } else {
                        ok(OptLabel::Mft, line);
                    }
                }
                Err(_) => {
                    info(OptLabel::Mft, l.admin_only());
                    admin_hint = true;
                }
            }

            // --- 8.3 short names --------------------------------------------
            let vol_flag = short_names_disabled_on_volume(root).ok();
            let enabled = match reg_8dot3 {
                Some(1) => Some(false),
                Some(0) => Some(true),
                Some(3) => Some(is_system),
                // 2 (default) or missing: the volume flag decides.
                _ => vol_flag.map(|d| !d),
            };
            match enabled {
                Some(false) => ok(OptLabel::ShortNames, l.word_off()),
                Some(true) if is_system => info(OptLabel::ShortNames, l.short_names_system()),
                Some(true) => {
                    warn(OptLabel::ShortNames, l.short_names_active());
                    if reg_8dot3 == Some(0) {
                        plan.fix(l.fix_8dot3_global(), &["8dot3name", "set", "2"], Some(l.note_8dot3_global()));
                    }
                    plan.fix(
                        l.fix_8dot3_volume(&vol),
                        &["8dot3name", "set", &vol, "1"],
                        Some(l.note_8dot3_volume()),
                    );
                }
                None => info(OptLabel::ShortNames, l.not_queryable()),
            }

            // --- Dirty bit ----------------------------------------------------
            match volume_dirty(root) {
                Ok(true) => {
                    warn(OptLabel::FileSystem, l.dirty_bit_set());
                    plan.hints.push(l.hint_dirty(&vol));
                }
                Ok(false) => ok(OptLabel::FileSystem, l.fs_clean()),
                Err(_) => admin_hint = true,
            }

            // --- BypassIO (diagnosis only, never unload filters) ------------
            let diag = l.bypass_diag(display_path(root));
            match bypass_io_status(root) {
                Ok(BypassIoStatus::Active { storage_compatible: true }) => {
                    ok(OptLabel::BypassIo, l.word_active());
                }
                Ok(BypassIoStatus::Active { storage_compatible: false }) => {
                    info(OptLabel::BypassIo, l.bypass_no_storage());
                }
                Ok(BypassIoStatus::Partial { driver, status, reason }) => {
                    info(OptLabel::BypassIo, l.bypass_partial(&driver, bypass_driver_hint(&driver)));
                    if is_nvme {
                        plan.hints.push(l.hint_bypass_partial(
                            &vol,
                            &driver,
                            &reason,
                            status,
                            bypass_driver_hint(&driver),
                            &diag,
                        ));
                    }
                }
                Ok(BypassIoStatus::Blocked { driver, status, reason }) => {
                    let line = l.bypass_blocked_by(&driver);
                    if is_nvme {
                        warn(OptLabel::BypassIo, line);
                    } else {
                        info(OptLabel::BypassIo, line);
                    }
                    plan.hints.push(l.hint_bypass_blocked(
                        &vol,
                        &driver,
                        &reason,
                        status,
                        bypass_driver_hint(&driver),
                        &diag,
                    ));
                }
                Ok(BypassIoStatus::Unavailable) => info(OptLabel::BypassIo, l.bypass_unavailable()),
                Err(e) => info(OptLabel::BypassIo, l.not_queryable_err(e)),
            }
        }
        println!();
    }

    // --- Global switches ---------------------------------------------------
    println!("{}", style("[Global]").bold());
    match filesystem_reg_value("NtfsDisableLastAccessUpdate") {
        Some(v) if v & 1 == 1 => ok(OptLabel::LastAccess, l.word_off()),
        _ => {
            warn(OptLabel::LastAccess, l.last_access_active());
            plan.fix(l.fix_last_access(), &["behavior", "set", "disablelastaccess", "1"], None);
        }
    }
    if any_ntfs_ssd {
        match filesystem_reg_value("DisableDeleteNotification") {
            Some(1) => {
                warn(OptLabel::TrimNtfs, l.trim_ntfs_disabled());
                plan.fix(l.fix_trim_ntfs(), &["behavior", "set", "DisableDeleteNotify", "NTFS", "0"], None);
            }
            _ => ok(OptLabel::TrimNtfs, l.word_active()),
        }
    }
    // Only query (possibly launching fsutil) if there is a ReFS volume on an SSD at all.
    if any_refs_ssd {
        match refs_trim_disabled() {
            Some(true) => {
                warn(OptLabel::TrimRefs, l.trim_refs_disabled());
                plan.fix(l.fix_trim_refs(), &["behavior", "set", "DisableDeleteNotify", "ReFS", "0"], None);
            }
            Some(false) => ok(OptLabel::TrimRefs, l.word_active()),
            None => info(OptLabel::TrimRefs, l.trim_refs_unset()),
        }
    }
    // 0 or missing = default (level 1).
    let zone = filesystem_reg_value("NtfsMftZoneReservation").unwrap_or(0).max(1);
    if any_large_mft && zone < 2 {
        warn(OptLabel::MftZone, l.mft_zone_small(zone));
        plan.fix(l.fix_mft_zone(), &["behavior", "set", "mftzone", "2"], Some(l.note_mft_zone()));
    } else {
        ok(OptLabel::MftZone, l.mft_zone_level(zone));
    }

    // --- Output & apply ------------------------------------------------------
    if !plan.hints.is_empty() {
        println!("\n{}", style(l.hints_header()).bold());
        for h in &plan.hints {
            println!("  • {h}");
        }
    }
    if admin_hint {
        println!("\n  {} {}", style("ℹ").blue(), l.admin_needed());
    }

    if plan.fixes.is_empty() {
        println!("\n{} {}", style("✔").green().bold(), l.no_fixes_needed());
        return Ok(ExitCode::SUCCESS);
    }

    println!("\n{}", style(l.fixes_header()).bold());
    for f in &plan.fixes {
        println!("  • {}", f.title);
        println!("      {}", style(format!("fsutil {}", f.args.join(" "))).dim());
        if let Some(n) = f.note {
            println!("      {}", style(n).dim());
        }
    }

    if !apply {
        println!(
            "\n{} {}",
            style("ℹ").blue().bold(),
            l.analysis_only_optimize(style("--optimize --fix").yellow().bold())
        );
        return Ok(ExitCode::from(crate::EXIT_FOUND));
    }

    let prompt = format!(
        "\n{}\n{} ",
        style("─".repeat(60)).yellow(),
        style(l.confirm_fixes(plan.fixes.len())).yellow().bold()
    );
    if !yes && !crate::confirm(&prompt)? {
        println!("{}", l.aborted());
        return Ok(ExitCode::SUCCESS);
    }

    let mut failed = 0;
    for f in &plan.fixes {
        let out = Command::new("fsutil").args(&f.args).output();
        match out {
            Ok(o) if o.status.success() => println!("  {} {}", style("✔").green(), f.title),
            Ok(o) => {
                failed += 1;
                // fsutil writes in the OEM code page – otherwise non-ASCII characters become `�`.
                let msg = [decode_oem(&o.stdout), decode_oem(&o.stderr)]
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                println!("  {} {}: {}", style("✖").red(), f.title, style(msg).red());
            }
            Err(e) => {
                failed += 1;
                println!("  {} {}: {e}", style("✖").red(), f.title);
            }
        }
    }
    if failed > 0 {
        println!("\n  {} {}", style("⚠").yellow().bold(), l.fixes_failed(failed));
        return Ok(ExitCode::from(crate::EXIT_PARTIAL));
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bypass_driver_classification() {
        assert_eq!(bypass_driver_kind("WOF.SYS"), DriverHint::Wof);
        assert_eq!(bypass_driver_kind("fvevol.sys"), DriverHint::BitLocker);
        assert_eq!(bypass_driver_kind("iaStorVD.sys"), DriverHint::StorageDriver);
        assert_eq!(bypass_driver_kind("someav.sys"), DriverHint::Other);
    }

    #[test]
    fn fsutil_volume_form() {
        assert_eq!(fsutil_volume(Path::new(r"E:\")), "E:");
        assert_eq!(fsutil_volume(Path::new(r"\\?\E:\")), "E:");
        assert_eq!(fsutil_volume(Path::new(r"C:\Mount\Data\")), r"C:\Mount\Data\");
    }
}
