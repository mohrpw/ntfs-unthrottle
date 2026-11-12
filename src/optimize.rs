//! `--optimize`: prüft Volume- und NTFS-Einstellungen, die Datei-I/O bremsen,
//! und wendet mit `--fix` die sicheren Korrekturen über `fsutil` an.
//!
//! Bewusst NICHT automatisch: `8dot3name strip` (kann Registry-Pfade auf
//! Kurznamen brechen), Defender-Ausnahmen (Sicherheit), Defragmentierung
//! und chkdsk – die werden nur als Hinweis mit dem passenden Befehl genannt.

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

use console::style;
use humansize::{format_size, BINARY};

use ntfs_unthrottle::tune::{
    device_info, filesystem_reg_value, ntfs_data, short_names_disabled_on_volume, volume_dirty,
};
use ntfs_unthrottle::{display_path, fragment_count, volume_info};

/// Bekannte QLC-SSD-Familien: Nach dem SLC-Cache bricht die Schreibrate ein.
const QLC_MODELS: &[&str] = &["QVO", "660P", "670P", "CT500P1", "CT1000P1", "CT2000P1", "P2 ", "NV2"];

/// Ab so vielen MFT-Datensätzen lohnt eine größere MFT-Zone.
const LARGE_MFT_RECORDS: u64 = 2_000_000;
/// Ab so vielen Fragmenten gilt die MFT als zerstückelt.
const MFT_FRAGMENT_WARN: u64 = 64;

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

fn ok(label: &str, value: impl std::fmt::Display) {
    println!("  {} {:<13}{}", style("✔").green(), label, value);
}
fn warn(label: &str, value: impl std::fmt::Display) {
    println!("  {} {:<13}{}", style("⚠").yellow().bold(), label, style(value).yellow());
}
fn info(label: &str, value: impl std::fmt::Display) {
    println!("  {} {:<13}{}", style("ℹ").blue(), label, value);
}

/// `E:\` → `E:` (so erwartet fsutil Laufwerksbuchstaben), Mount-Punkte bleiben.
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
    // Volumes der angegebenen Pfade, ohne Duplikate.
    let mut volumes: BTreeMap<String, PathBuf> = BTreeMap::new();
    for p in paths {
        let v = volume_info(p).map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", p.display())))?;
        volumes.entry(display_path(&v.root).to_lowercase()).or_insert(v.root);
    }

    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into()).to_lowercase();
    let reg_8dot3 = filesystem_reg_value("NtfsDisable8dot3NameCreation");
    let mut plan = Plan::default();
    let mut any_ssd = false;
    let mut any_large_mft = false;
    let mut admin_hint = false;

    println!("{} Prüfe {} Volume(s)\n", style("[Optimierer]").bold().cyan(), volumes.len());

    for root in volumes.values() {
        let vol = fsutil_volume(root);
        let is_system = vol.to_lowercase() == system_drive;
        let vi = volume_info(root)?;
        println!(
            "{} {}{}",
            style(format!("[{}]", display_path(root))).bold(),
            vi.fs_name,
            if is_system { "  (Systemlaufwerk)" } else { "" }
        );

        // --- Datenträger ---------------------------------------------------
        match device_info(root) {
            Ok(d) => {
                let kind = match d.seek_penalty {
                    Some(true) => "HDD",
                    Some(false) => "SSD",
                    None => "Typ unbekannt",
                };
                let trim = match d.trim_supported {
                    Some(true) => ", TRIM ✔",
                    Some(false) => ", kein TRIM",
                    None => "",
                };
                let line = format!(
                    "{} ({}, {kind}{trim})",
                    d.product.as_deref().unwrap_or("?"),
                    d.bus.unwrap_or("?")
                );
                if d.seek_penalty == Some(false) {
                    any_ssd = true;
                }
                let product = d.product.as_deref().unwrap_or("").to_uppercase();
                if QLC_MODELS.iter().any(|m| product.contains(m)) {
                    plan.hints.push(format!(
                        "{vol} ist eine QLC-SSD ({}). Nach einigen GiB am Stück ist ihr SLC-Cache voll, dann fällt die Schreibrate auf HDD-Niveau – das ist Hardware, kein Einstellungsproblem. Große Entpack-/Kopierjobs besser auf einer TLC/NVMe-SSD ausführen und erst danach verschieben; mehr freier Platz vergrößert den Cache.",
                        d.product.as_deref().unwrap_or("?")
                    ));
                }
                match (d.seek_penalty, d.bus) {
                    (Some(true), _) => {
                        warn("Datenträger:", line);
                        plan.hints.push(format!(
                            "{vol} ist eine HDD: Viele kleine Dateien sind dort grundsätzlich langsam. \
                             Regelmäßig defragmentieren: `defrag {vol} /U /V`"
                        ));
                    }
                    (_, Some("USB")) => {
                        warn("Datenträger:", line);
                        plan.hints.push(format!(
                            "{vol} hängt an USB – Durchsatz und Latenz sind durch Kabel/Gehäuse begrenzt, \
                             nicht durch NTFS."
                        ));
                    }
                    _ => ok("Datenträger:", line),
                }
            }
            Err(e) => info("Datenträger:", format!("nicht abfragbar ({e})")),
        }

        // --- Platz, Cluster, MFT ------------------------------------------
        if vi.fs_name.eq_ignore_ascii_case("NTFS") {
            match ntfs_data(root) {
                Ok(n) => {
                    let free_pct = n.free_bytes as f64 / n.total_bytes.max(1) as f64 * 100.0;
                    let line = format!(
                        "{} frei von {} ({free_pct:.0} %)",
                        format_size(n.free_bytes, BINARY),
                        format_size(n.total_bytes, BINARY)
                    );
                    if free_pct < 10.0 {
                        warn("Platz:", line);
                        plan.hints.push(format!(
                            "{vol} ist zu über 90 % voll – NTFS findet kaum noch zusammenhängende \
                             Bereiche, neue Dateien zerstückeln."
                        ));
                    } else {
                        ok("Platz:", line);
                    }
                    info("Cluster:", format_size(n.bytes_per_cluster, BINARY));

                    let records = n.mft_records();
                    let frags = fragment_count(&root.join("$MFT")).ok();
                    let mut line = format!(
                        "{} (≈ {:.1} Mio. Datensätze), Zone {}",
                        format_size(n.mft_valid_length, BINARY),
                        records as f64 / 1e6,
                        format_size(n.mft_zone_bytes, BINARY)
                    );
                    if let Some(f) = frags {
                        line.push_str(&format!(", {f} Fragment(e)"));
                    }
                    if records >= LARGE_MFT_RECORDS {
                        any_large_mft = true;
                    }
                    if frags.is_some_and(|f| f >= MFT_FRAGMENT_WARN) {
                        warn("MFT:", line);
                        plan.hints.push(format!(
                            "Die MFT auf {vol} ist zerstückelt. Windows kann sie im laufenden Betrieb \
                             nicht defragmentieren; nur offline/Drittanbieter oder Neuformatierung."
                        ));
                    } else {
                        ok("MFT:", line);
                    }
                }
                Err(_) => {
                    info("MFT:", "nur als Administrator abfragbar");
                    admin_hint = true;
                }
            }

            // --- 8.3-Kurznamen ----------------------------------------------
            let vol_flag = short_names_disabled_on_volume(root).ok();
            let enabled = match reg_8dot3 {
                Some(1) => Some(false),
                Some(0) => Some(true),
                Some(3) => Some(is_system),
                // 2 (Standard) bzw. fehlend: Volume-Flag entscheidet.
                _ => vol_flag.map(|d| !d),
            };
            match enabled {
                Some(false) => ok("8.3-Namen:", "aus"),
                Some(true) if is_system => {
                    info("8.3-Namen:", "aktiv (Systemlaufwerk – bewusst nicht geändert)");
                }
                Some(true) => {
                    warn("8.3-Namen:", "aktiv – kostet bei jedem neuen Dateinamen eine Kollisionsprüfung");
                    if reg_8dot3 == Some(0) {
                        plan.fix(
                            "8.3-Namen pro Volume steuerbar machen (global)",
                            &["8dot3name", "set", "2"],
                            Some("Ändert nichts an C:, solange dort das Volume-Flag aktiv bleibt."),
                        );
                    }
                    plan.fix(
                        format!("8.3-Namen auf {vol} abschalten"),
                        &["8dot3name", "set", &vol, "1"],
                        Some("Bestehende Kurznamen bleiben – `8dot3name strip` wird bewusst nicht ausgeführt."),
                    );
                }
                None => info("8.3-Namen:", "nicht abfragbar"),
            }

            // --- Dirty-Bit ------------------------------------------------
            match volume_dirty(root) {
                Ok(true) => {
                    warn("Dateisystem:", "Dirty-Bit gesetzt");
                    plan.hints.push(format!(
                        "{vol} ist als fehlerhaft markiert. Prüfen mit `chkdsk {vol} /scan` (online)."
                    ));
                }
                Ok(false) => ok("Dateisystem:", "sauber"),
                Err(_) => admin_hint = true,
            }
        }
        println!();
    }

    // --- Globale Schalter --------------------------------------------------
    println!("{}", style("[Global]").bold());
    match filesystem_reg_value("NtfsDisableLastAccessUpdate") {
        Some(v) if v & 1 == 1 => ok("Last-Access:", "aus"),
        _ => {
            warn("Last-Access:", "aktiv – jeder Lesezugriff schreibt einen Zeitstempel");
            plan.fix(
                "Last-Access-Zeitstempel abschalten",
                &["behavior", "set", "disablelastaccess", "1"],
                None,
            );
        }
    }
    if any_ssd {
        match filesystem_reg_value("DisableDeleteNotification") {
            Some(1) => {
                warn("TRIM:", "deaktiviert – die SSD wird mit der Zeit langsamer");
                plan.fix(
                    "TRIM für NTFS aktivieren",
                    &["behavior", "set", "DisableDeleteNotify", "NTFS", "0"],
                    None,
                );
            }
            _ => ok("TRIM:", "aktiv"),
        }
    }
    // 0 bzw. fehlend = Standard (Stufe 1).
    let zone = filesystem_reg_value("NtfsMftZoneReservation").unwrap_or(0).max(1);
    if any_large_mft && zone < 2 {
        warn("MFT-Zone:", format!("Stufe {zone} – zu klein für Volumes mit Millionen Dateien"));
        plan.fix(
            "Größere MFT-Zone reservieren (Stufe 2)",
            &["behavior", "set", "mftzone", "2"],
            Some("Wirkt erst nach einem Neustart und nur für künftiges MFT-Wachstum."),
        );
    } else {
        ok("MFT-Zone:", format!("Stufe {zone}"));
    }

    // --- Ausgabe & Anwenden ------------------------------------------------
    if !plan.hints.is_empty() {
        println!("\n{}", style("Hinweise (nicht automatisch):").bold());
        for h in &plan.hints {
            println!("  • {h}");
        }
    }
    if admin_hint {
        println!(
            "\n  {} Einige Werte (MFT, Dirty-Bit) brauchen ein Terminal als Administrator.",
            style("ℹ").blue()
        );
    }

    if plan.fixes.is_empty() {
        println!("\n{} Keine Korrekturen nötig.", style("✔").green().bold());
        return Ok(ExitCode::SUCCESS);
    }

    println!("\n{}", style("Korrekturen:").bold());
    for f in &plan.fixes {
        println!("  • {}", f.title);
        println!("      {}", style(format!("fsutil {}", f.args.join(" "))).dim());
        if let Some(n) = f.note {
            println!("      {}", style(n).dim());
        }
    }

    if !apply {
        println!(
            "\n{} Nur Analyse. Mit {} werden die Korrekturen angewendet (als Administrator).",
            style("ℹ").blue().bold(),
            style("--optimize --fix").yellow().bold()
        );
        return Ok(ExitCode::from(crate::EXIT_FOUND));
    }

    let prompt = format!(
        "\n{}\n{} ",
        style("─".repeat(60)).yellow(),
        style(format!("▶ {} Korrektur(en) jetzt anwenden? [j/N]:", plan.fixes.len())).yellow().bold()
    );
    if !yes && !crate::confirm(&prompt)? {
        println!("Abgebrochen.");
        return Ok(ExitCode::SUCCESS);
    }

    let mut failed = 0;
    for f in &plan.fixes {
        let out = Command::new("fsutil").args(&f.args).output();
        match out {
            Ok(o) if o.status.success() => println!("  {} {}", style("✔").green(), f.title),
            Ok(o) => {
                failed += 1;
                let msg = String::from_utf8_lossy(&o.stdout).trim().to_string()
                    + String::from_utf8_lossy(&o.stderr).trim();
                println!("  {} {}: {}", style("✖").red(), f.title, style(msg).red());
            }
            Err(e) => {
                failed += 1;
                println!("  {} {}: {e}", style("✖").red(), f.title);
            }
        }
    }
    if failed > 0 {
        println!(
            "\n  {} {failed} Korrektur(en) fehlgeschlagen – meist fehlen Administratorrechte.",
            style("⚠").yellow().bold()
        );
        return Ok(ExitCode::from(crate::EXIT_PARTIAL));
    }
    Ok(ExitCode::SUCCESS)
}
