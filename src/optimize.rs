//! `--optimize`: checks volume and NTFS settings that slow down file I/O,
//! and applies the safe fixes via `fsutil` when `--fix` is given.
//!
//! Intentionally NOT automated: `8dot3name strip` (can break registry paths
//! that point to short names), Defender exclusions (security), defragmentation
//! and chkdsk – these are only mentioned as hints with the matching command.

use std::collections::BTreeMap;
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use console::style;
use humansize::{format_size, BINARY};
use serde_json::{json, Map, Value};

use ntfs_unthrottle::tune::{
    bypass_io_status, decode_oem, dev_drive_info, device_info, filesystem_reg_value,
    indexer_status, ntfs_data, refs_trim_disabled, short_names_disabled_on_volume, volume_dirty,
    BypassIoStatus,
};
use ntfs_unthrottle::{display_path, fragment_count, volume_info};

use crate::i18n::tr;
use crate::put_path;

/// Why a Windows driver blocks BypassIO (classified in `optimize.rs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DriverHint {
    Wof,
    BitLocker,
    VolSnap,
    StorageDriver,
    Other,
}

struct HexStatus(u32);

impl fmt::Display for HexStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:08X}", self.0)
    }
}

/// Known QLC SSD families: once the SLC cache is full, the write rate collapses.
pub(crate) const QLC_MODELS: &[&str] = &["QVO", "660P", "670P", "CT500P1", "CT1000P1", "CT2000P1", "P2 ", "NV2"];

/// From this many MFT records on, a larger MFT zone pays off.
const LARGE_MFT_RECORDS: u64 = 2_000_000;
/// From this many fragments on, the MFT counts as fragmented.
const MFT_FRAGMENT_WARN: u64 = 64;

/// Row labels of the optimizer output (localized in `i18n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptLabel {
    Drive,
    FileSystem,
    DevDrive,
    Space,
    Cluster,
    Mft,
    ShortNames,
    BypassIo,
    Indexer,
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

#[derive(Clone, Copy)]
struct OptOut {
    json: bool,
}

impl OptOut {
    fn ok(self, label: OptLabel, value: impl std::fmt::Display) {
        if !self.json {
            let l = tr();
            println!(
                "  {} {}{}",
                style("✔").green(),
                l.opt_label(label).pad(l.col_width_optimize_labels),
                value
            );
        }
    }
    fn warn(self, label: OptLabel, value: impl std::fmt::Display) {
        if !self.json {
            let l = tr();
            println!(
                "  {} {}{}",
                style("⚠").yellow().bold(),
                l.opt_label(label).pad(l.col_width_optimize_labels),
                style(value).yellow()
            );
        }
    }
    fn info(self, label: OptLabel, value: impl std::fmt::Display) {
        if !self.json {
            let l = tr();
            println!(
                "  {} {}{}",
                style("ℹ").blue(),
                l.opt_label(label).pad(l.col_width_optimize_labels),
                value
            );
        }
    }
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

fn bypass_to_json(res: &io::Result<BypassIoStatus>) -> Value {
    match res {
        Ok(BypassIoStatus::Active { storage_compatible }) => json!({
            "status": "active",
            "storage_compatible": storage_compatible,
        }),
        Ok(BypassIoStatus::Partial { driver, status, reason }) => json!({
            "status": "partial",
            "driver": driver,
            "driver_status": status,
            "reason": reason,
        }),
        Ok(BypassIoStatus::Blocked { driver, status, reason }) => json!({
            "status": "blocked",
            "driver": driver,
            "driver_status": status,
            "reason": reason,
        }),
        Ok(BypassIoStatus::Unavailable) => json!({ "status": "unavailable" }),
        Err(e) => json!({
            "error": e.to_string(),
            "permission_denied": e.kind() == io::ErrorKind::PermissionDenied,
        }),
    }
}

pub fn run(paths: &[PathBuf], apply: bool, yes: bool, json_mode: bool) -> io::Result<ExitCode> {
    let l = tr();
    let out = OptOut { json: json_mode };
    // Volumes of the given paths, without duplicates.
    let mut volumes: BTreeMap<String, PathBuf> = BTreeMap::new();
    for p in paths {
        let v = volume_info(p).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?;
        volumes.entry(display_path(&v.root).to_lowercase()).or_insert(v.root);
    }

    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).to_lowercase();
    let reg_8dot3 = filesystem_reg_value("NtfsDisable8dot3NameCreation");
    let mut plan = Plan::default();
    let mut volumes_json = Vec::with_capacity(volumes.len());
    // TRIM switches are global, but separate per file system.
    let mut any_ntfs_ssd = false;
    let mut any_refs_ssd = false;
    let mut any_large_mft = false;
    let mut admin_hint = false;

    if !json_mode {
        println!(
            "{} {}\n",
            style(l.opt_tag()).bold().cyan(),
            l.opt_checking_volumes(volumes.len() as u64)
        );
    }

    for root in volumes.values() {
        let vol = fsutil_volume(root);
        let is_system = vol.to_lowercase() == system_drive;
        let vi = volume_info(root)?;
        let is_ntfs = vi.fs_name.eq_ignore_ascii_case("NTFS");
        let is_refs = vi.fs_name.eq_ignore_ascii_case("ReFS");
        let mut is_nvme = false;

        let mut vj = Map::new();
        put_path(&mut vj, "root", root);
        vj.insert("fs_name".into(), Value::String(vi.fs_name.clone()));
        vj.insert("is_system".into(), Value::Bool(is_system));

        if !json_mode {
            println!(
                "{} {}{}",
                style(format!("[{}]", display_path(root))).bold(),
                vi.fs_name,
                if is_system { l.opt_system_drive_suffix() } else { "" }
            );
        }

        // --- Storage device ---------------------------------------------------
        let dev_json = match device_info(root) {
            Ok(d) => {
                let kind = match d.seek_penalty {
                    Some(true) => "HDD",
                    Some(false) => "SSD",
                    None => l.opt_type_unknown(),
                };
                let trim = match d.trim_supported {
                    Some(true) => l.opt_trim_yes(),
                    Some(false) => l.opt_trim_no(),
                    None => "",
                };
                let line = format!(
                    "{} ({}, {kind}{trim})",
                    d.product.as_deref().unwrap_or("?"),
                    d.bus.map_or("?", |b| l.bus_name(b))
                );
                is_nvme = d.bus == Some("NVMe");
                if d.seek_penalty == Some(false) {
                    any_ntfs_ssd |= is_ntfs;
                    any_refs_ssd |= is_refs;
                }
                let product = d.product.as_deref().unwrap_or("").to_uppercase();
                if QLC_MODELS.iter().any(|m| product.contains(m)) {
                    let prod = d.product.as_deref().unwrap_or("?");
                    plan.hints.push(l.opt_hint_qlc(&vol, &prod).to_string());
                }
                match (d.seek_penalty, d.bus) {
                    (Some(true), _) => {
                        out.warn(OptLabel::Drive, line);
                        plan.hints.push(l.opt_hint_hdd(&vol).to_string());
                    }
                    (_, Some("USB")) => {
                        out.warn(OptLabel::Drive, line);
                        plan.hints.push(l.opt_hint_usb(&vol).to_string());
                    }
                    _ => out.ok(OptLabel::Drive, line),
                }
                json!({
                    "product": d.product,
                    "bus": d.bus,
                    "seek_penalty": d.seek_penalty,
                    "trim_supported": d.trim_supported,
                })
            }
            Err(e) => {
                let msg = l.general_not_queryable_err(&e);
                out.info(OptLabel::Drive, msg);
                json!({ "error": e.to_string() })
            }
        };
        vj.insert("device".into(), dev_json);

        let dev_drive_json = if is_refs {
            out.info(OptLabel::FileSystem, l.opt_refs_info());
            match dev_drive_info(root) {
                Ok(dd) => {
                    if dd.is_dev_drive && dd.is_trusted {
                        out.ok(OptLabel::DevDrive, l.opt_dev_drive_trusted(&vol));
                    } else if dd.is_dev_drive {
                        out.warn(OptLabel::DevDrive, l.opt_dev_drive_untrusted());
                        plan.hints.push(l.opt_hint_dev_drive_untrusted(&vol).to_string());
                    } else {
                        out.info(OptLabel::DevDrive, l.opt_dev_drive_no());
                    }
                    json!({
                        "is_dev_drive": dd.is_dev_drive,
                        "is_trusted": dd.is_trusted,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                    out.info(OptLabel::DevDrive, l.opt_admin_only());
                    admin_hint = true;
                    json!({ "error": "permission_denied", "permission_denied": true })
                }
                Err(e) => {
                    let msg = l.general_not_queryable_err(&e);
                    out.info(OptLabel::DevDrive, msg);
                    json!({ "error": e.to_string(), "permission_denied": false })
                }
            }
        } else {
            Value::Null
        };
        vj.insert("dev_drive".into(), dev_drive_json);

        // --- Space, clusters, MFT ---------------------------------------------
        if is_ntfs {
            let ntfs_json = match ntfs_data(root) {
                Ok(n) => {
                    let free_pct = n.free_bytes as f64 / n.total_bytes.max(1) as f64 * 100.0;
                    let free_s = format_size(n.free_bytes, BINARY);
                    let total_s = format_size(n.total_bytes, BINARY);
                    let pct_d = l.decimal(free_pct, 0);
                    let line = l.opt_space_line(&free_s, &total_s, &pct_d);
                    if free_pct < 10.0 {
                        out.warn(OptLabel::Space, line);
                        plan.hints.push(l.opt_hint_full(&vol).to_string());
                    } else {
                        out.ok(OptLabel::Space, line);
                    }
                    out.info(OptLabel::Cluster, format_size(n.bytes_per_cluster, BINARY));

                    let records = n.mft_records();
                    let frags = fragment_count(&root.join("$MFT")).ok();
                    let size_s = format_size(n.mft_valid_length, BINARY);
                    let mrec_d = l.decimal(records as f64 / 1e6, 1);
                    let zone_s = format_size(n.mft_zone_bytes, BINARY);
                    if records >= LARGE_MFT_RECORDS {
                        any_large_mft = true;
                    }
                    if let Some(f) = frags {
                        let line = l.opt_mft_line_frags(f, &size_s, &mrec_d, &zone_s);
                        if f >= MFT_FRAGMENT_WARN {
                            out.warn(OptLabel::Mft, line);
                            plan.hints.push(l.opt_hint_mft_fragmented(&vol).to_string());
                        } else {
                            out.ok(OptLabel::Mft, line);
                        }
                    } else {
                        out.ok(OptLabel::Mft, l.opt_mft_line(&size_s, &mrec_d, &zone_s));
                    }
                    json!({
                        "free_bytes": n.free_bytes,
                        "total_bytes": n.total_bytes,
                        "bytes_per_cluster": n.bytes_per_cluster,
                        "mft_valid_length": n.mft_valid_length,
                        "mft_records": records,
                        "mft_zone_bytes": n.mft_zone_bytes,
                        "mft_fragments": frags,
                    })
                }
                Err(_) => {
                    out.info(OptLabel::Mft, l.opt_admin_only());
                    admin_hint = true;
                    json!({ "error": "permission_denied", "permission_denied": true })
                }
            };
            vj.insert("ntfs".into(), ntfs_json);

            // --- 8.3 short names --------------------------------------------
            let vol_flag = short_names_disabled_on_volume(root).ok();
            let enabled = match reg_8dot3 {
                Some(1) => Some(false),
                Some(0) => Some(true),
                Some(3) => Some(is_system),
                // 2 (default) or missing: the volume flag decides.
                _ => vol_flag.map(|d| !d),
            };
            vj.insert("short_names_enabled".into(), json!(enabled));
            match enabled {
                Some(false) => out.ok(OptLabel::ShortNames, l.general_word_off()),
                Some(true) if is_system => out.info(OptLabel::ShortNames, l.opt_short_names_system()),
                Some(true) => {
                    out.warn(OptLabel::ShortNames, l.opt_short_names_active());
                    if reg_8dot3 == Some(0) {
                        plan.fix(
                            l.opt_fix_8dot3_global(),
                            &["8dot3name", "set", "2"],
                            Some(l.opt_note_8dot3_global()),
                        );
                    }
                    plan.fix(
                        l.opt_fix_8dot3_volume(&vol).to_string(),
                        &["8dot3name", "set", &vol, "1"],
                        Some(l.opt_note_8dot3_volume()),
                    );
                }
                None => out.info(OptLabel::ShortNames, l.general_not_queryable()),
            }

            // --- Dirty bit ----------------------------------------------------
            let dirty_res = volume_dirty(root);
            vj.insert("dirty".into(), json!(dirty_res.as_ref().ok().copied()));
            match dirty_res {
                Ok(true) => {
                    out.warn(OptLabel::FileSystem, l.opt_dirty_bit_set());
                    plan.hints.push(l.opt_hint_dirty(&vol).to_string());
                }
                Ok(false) => out.ok(OptLabel::FileSystem, l.opt_fs_clean()),
                Err(_) => admin_hint = true,
            }

            // --- BypassIO (diagnosis only, never unload filters) ------------
            let root_disp = display_path(root);
            let diag = l.opt_bypass_diag(&root_disp);
            let bypass_res = bypass_io_status(root);
            vj.insert("bypass_io".into(), bypass_to_json(&bypass_res));
            match bypass_res {
                Ok(BypassIoStatus::Active { storage_compatible: true }) => {
                    out.ok(OptLabel::BypassIo, l.general_word_active());
                }
                Ok(BypassIoStatus::Active { storage_compatible: false }) => {
                    out.info(OptLabel::BypassIo, l.opt_bypass_no_storage());
                }
                Ok(BypassIoStatus::Partial { driver, status, reason }) => {
                    let hint = bypass_driver_hint(&driver);
                    out.info(OptLabel::BypassIo, l.opt_bypass_partial(&driver, &hint));
                    if is_nvme {
                        let status_hex = HexStatus(status);
                        plan.hints.push(
                            l.opt_hint_bypass_partial(&vol, &driver, &reason, &status_hex, &hint, &diag)
                                .to_string(),
                        );
                    }
                }
                Ok(BypassIoStatus::Blocked { driver, status, reason }) => {
                    let line = l.opt_bypass_blocked_by(&driver);
                    if is_nvme {
                        out.warn(OptLabel::BypassIo, line);
                    } else {
                        out.info(OptLabel::BypassIo, line);
                    }
                    let hint = bypass_driver_hint(&driver);
                    let status_hex = HexStatus(status);
                    plan.hints.push(
                        l.opt_hint_bypass_blocked(&vol, &driver, &reason, &status_hex, &hint, &diag)
                            .to_string(),
                    );
                }
                Ok(BypassIoStatus::Unavailable) => out.info(OptLabel::BypassIo, l.opt_bypass_unavailable()),
                Err(e) => out.info(OptLabel::BypassIo, l.general_not_queryable_err(&e)),
            }
        } else {
            vj.insert("ntfs".into(), Value::Null);
            vj.insert("short_names_enabled".into(), Value::Null);
            vj.insert("dirty".into(), Value::Null);
            vj.insert("bypass_io".into(), Value::Null);
        }

        // --- Windows Search Indexer (read-only, gentle info note) ------------
        if is_ntfs || is_refs {
            let idx = indexer_status(root);
            vj.insert(
                "indexer".into(),
                json!({
                    "service_disabled": idx.service_disabled,
                    "root_not_indexed": idx.root_not_indexed,
                }),
            );
            if idx.service_disabled == Some(true) || idx.root_not_indexed == Some(true) {
                out.ok(OptLabel::Indexer, l.opt_indexer_off());
            } else if is_system {
                out.info(OptLabel::Indexer, l.opt_indexer_system());
            } else if idx.root_not_indexed == Some(false) {
                out.info(OptLabel::Indexer, l.opt_indexer_active_soft(&vol));
            } else {
                out.info(OptLabel::Indexer, l.general_not_queryable());
            }
        } else {
            vj.insert("indexer".into(), Value::Null);
        }
        volumes_json.push(Value::Object(vj));
        if !json_mode {
            println!();
        }
    }

    // --- Global switches ---------------------------------------------------
    if !json_mode {
        println!("{}", style(l.general_global_header()).bold());
    }
    let last_access_reg = filesystem_reg_value("NtfsDisableLastAccessUpdate");
    match last_access_reg {
        Some(v) if v & 1 == 1 => out.ok(OptLabel::LastAccess, l.general_word_off()),
        _ => {
            out.warn(OptLabel::LastAccess, l.opt_last_access_active());
            plan.fix(l.opt_fix_last_access(), &["behavior", "set", "disablelastaccess", "1"], None);
        }
    }
    let trim_ntfs_reg = if any_ntfs_ssd {
        let v = filesystem_reg_value("DisableDeleteNotification");
        match v {
            Some(1) => {
                out.warn(OptLabel::TrimNtfs, l.opt_trim_ntfs_disabled());
                plan.fix(l.opt_fix_trim_ntfs(), &["behavior", "set", "DisableDeleteNotify", "NTFS", "0"], None);
            }
            _ => out.ok(OptLabel::TrimNtfs, l.general_word_active()),
        }
        Some(v)
    } else {
        None
    };
    // Only query (possibly launching fsutil) if there is a ReFS volume on an SSD at all.
    let trim_refs_disabled = if any_refs_ssd {
        let v = refs_trim_disabled();
        match v {
            Some(true) => {
                out.warn(OptLabel::TrimRefs, l.opt_trim_refs_disabled());
                plan.fix(l.opt_fix_trim_refs(), &["behavior", "set", "DisableDeleteNotify", "ReFS", "0"], None);
            }
            Some(false) => out.ok(OptLabel::TrimRefs, l.general_word_active()),
            None => out.info(OptLabel::TrimRefs, l.opt_trim_refs_unset()),
        }
        Some(v)
    } else {
        None
    };
    // 0 or missing = default (level 1).
    let zone = filesystem_reg_value("NtfsMftZoneReservation").unwrap_or(0).max(1);
    let zone_int = l.int(zone);
    if any_large_mft && zone < 2 {
        out.warn(OptLabel::MftZone, l.opt_mft_zone_small(&zone_int));
        plan.fix(l.opt_fix_mft_zone(), &["behavior", "set", "mftzone", "2"], Some(l.opt_note_mft_zone()));
    } else {
        out.ok(OptLabel::MftZone, l.opt_mft_zone_level(&zone_int));
    }

    let global_json = json!({
        "disable_last_access_update": last_access_reg,
        "last_access_disabled": matches!(last_access_reg, Some(v) if v & 1 == 1),
        "disable_delete_notification_ntfs": trim_ntfs_reg,
        "refs_trim_disabled": trim_refs_disabled.flatten(),
        "ntfs_mft_zone_reservation": zone,
    });

    let fixes_json: Vec<Value> = plan
        .fixes
        .iter()
        .map(|f| {
            json!({
                "title": f.title,
                "command": format!("fsutil {}", f.args.join(" ")),
                "args": f.args,
                "note": f.note,
            })
        })
        .collect();

    // --- Output & apply ------------------------------------------------------
    if !json_mode {
        if !plan.hints.is_empty() {
            println!("\n{}", style(l.opt_hints_header()).bold());
            for h in &plan.hints {
                println!("  • {h}");
            }
        }
        if admin_hint {
            println!("\n  {} {}", style("ℹ").blue(), l.opt_admin_needed());
        }
    }

    if plan.fixes.is_empty() {
        if json_mode {
            emit_optimize_json(&volumes_json, &global_json, &plan.hints, admin_hint, &fixes_json, None, 0)?;
        } else {
            println!("\n{} {}", style("✔").green().bold(), l.opt_no_fixes_needed());
        }
        return Ok(ExitCode::SUCCESS);
    }

    if !json_mode {
        println!("\n{}", style(l.opt_fixes_header()).bold());
        for f in &plan.fixes {
            println!("  • {}", f.title);
            println!("      {}", style(format!("fsutil {}", f.args.join(" "))).dim());
            if let Some(n) = f.note {
                println!("      {}", style(n).dim());
            }
        }
    }

    if !apply {
        if json_mode {
            emit_optimize_json(&volumes_json, &global_json, &plan.hints, admin_hint, &fixes_json, None, 0)?;
        } else {
            let flag = style("--optimize --fix").yellow().bold();
            println!(
                "\n{} {}",
                style("ℹ").blue().bold(),
                l.opt_analysis_only_optimize(&flag)
            );
        }
        return Ok(ExitCode::from(crate::EXIT_FOUND));
    }

    if !yes {
        if json_mode {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, l.scan_json_fix_requires_yes()));
        }
        let yn = l.yes_no();
        let prompt = format!(
            "\n{}\n{} ",
            style("─".repeat(60)).yellow(),
            style(l.opt_confirm_fixes(plan.fixes.len() as u64, &yn)).yellow().bold()
        );
        if !crate::confirm(&prompt)? {
            println!("{}", l.general_aborted());
            return Ok(ExitCode::SUCCESS);
        }
    }

    let mut failed = 0usize;
    let mut applied_json = Vec::with_capacity(plan.fixes.len());
    for f in &plan.fixes {
        let out = Command::new("fsutil").args(&f.args).output();
        match out {
            Ok(o) if o.status.success() => {
                if !json_mode {
                    println!("  {} {}", style("✔").green(), f.title);
                }
                applied_json.push(json!({
                    "title": f.title,
                    "args": f.args,
                    "ok": true,
                    "error": Value::Null,
                }));
            }
            Ok(o) => {
                failed += 1;
                // fsutil writes in the OEM code page – otherwise non-ASCII characters become `�`.
                let msg = [decode_oem(&o.stdout), decode_oem(&o.stderr)]
                    .iter()
                    .map(|s| s.trim())
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
                    .join(" ");
                if !json_mode {
                    println!("  {} {}: {}", style("✖").red(), f.title, style(&msg).red());
                }
                applied_json.push(json!({
                    "title": f.title,
                    "args": f.args,
                    "ok": false,
                    "error": msg,
                }));
            }
            Err(e) => {
                failed += 1;
                if !json_mode {
                    println!("  {} {}: {e}", style("✖").red(), f.title);
                }
                applied_json.push(json!({
                    "title": f.title,
                    "args": f.args,
                    "ok": false,
                    "error": e.to_string(),
                }));
            }
        }
    }
    if json_mode {
        emit_optimize_json(
            &volumes_json,
            &global_json,
            &plan.hints,
            admin_hint,
            &fixes_json,
            Some(&applied_json),
            failed,
        )?;
    }
    if failed > 0 {
        if !json_mode {
            println!("\n  {} {}", style("⚠").yellow().bold(), l.opt_fixes_failed(failed as u64));
        }
        return Ok(ExitCode::from(crate::EXIT_PARTIAL));
    }
    Ok(ExitCode::SUCCESS)
}

fn emit_optimize_json(
    volumes: &[Value],
    global: &Value,
    hints: &[String],
    admin_hint: bool,
    fixes: &[Value],
    applied: Option<&[Value]>,
    failed: usize,
) -> io::Result<()> {
    let payload = json!({
        "mode": "optimize",
        "volumes": volumes,
        "global": global,
        "hints": hints,
        "admin_hint": admin_hint,
        "fixes": fixes,
        "applied": applied,
        "failed": failed,
    });
    println!("{}", serde_json::to_string(&payload).map_err(io::Error::other)?);
    Ok(())
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
