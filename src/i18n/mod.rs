//! Compile-time checked, zero-allocation localization backed by `locales/*.toml`.
//!
//! Each supported language lives in a single file `locales/<lang>.toml`.
//! `build.rs` validates all keys, placeholders, plural forms and terminal column
//! widths at compile time and generates `LOCALES` / `EN_LOCALE`.
//!
//! `--help` stays English on purpose; only runtime output is localized.
//!
//! Language detection priority (see [`detect`]):
//! 1. `--lang <auto|code...>`
//! 2. `LC_ALL`, `LC_MESSAGES`, `LANG` (ignored when empty or `C`/`POSIX`)
//! 3. Windows preferred UI languages (`GetUserPreferredUILanguages`)

pub mod runtime;

include!(concat!(env!("OUT_DIR"), "/i18n_gen.rs"));

use std::io;
use std::path::Path;
use std::sync::OnceLock;

use ntfs_unthrottle::{error_hint, is_virtual_disk, ErrorHint};

use crate::optimize::{DriverHint, OptLabel};
use crate::{Protected, Reason};

static CURRENT: OnceLock<&'static Locale> = OnceLock::new();

/// Sets the process-wide locale (only the first call wins).
pub fn init(loc: &'static Locale) {
    let _ = CURRENT.set(loc);
}

/// Active locale (defaults to English until [`init`] is called, e.g. in unit tests).
#[inline]
pub fn tr() -> &'static Locale {
    CURRENT.get().copied().unwrap_or(EN_LOCALE)
}

/// Resolves `--lang` (`"auto"` or a locale code) to a compiled [`Locale`].
pub fn detect(choice: &str) -> &'static Locale {
    let trimmed = choice.trim();
    if trimmed.eq_ignore_ascii_case("auto") {
        from_env(|k| std::env::var(k).ok()).unwrap_or_else(system_ui_lang)
    } else {
        LOCALES
            .iter()
            .find(|l| l.code.eq_ignore_ascii_case(trimmed))
            .unwrap_or(EN_LOCALE)
    }
}

/// POSIX locale variables in priority order.
const LOCALE_VARS: [&str; 3] = ["LC_ALL", "LC_MESSAGES", "LANG"];

/// Resolves a locale from POSIX locale environment variables (pure; `get` reads a variable).
/// The first variable that is set, non-empty and not `C`/`POSIX` decides;
/// an unsupported locale (e.g. `fr_FR`) falls back to English.
pub fn from_env(get: impl Fn(&str) -> Option<String>) -> Option<&'static Locale> {
    LOCALE_VARS.iter().find_map(|k| {
        let value = get(k)?;
        let value = value.trim();
        let base = value.split(['.', '@']).next().unwrap_or("");
        if base.is_empty()
            || base.eq_ignore_ascii_case("C")
            || base.eq_ignore_ascii_case("POSIX")
        {
            None
        } else {
            Some(parse_lang_tag(value).unwrap_or(EN_LOCALE))
        }
    })
}

/// Matches a BCP-47 or POSIX language tag (`de`, `de_DE.UTF-8`, `en-US`,
/// `zh-Hans-CN`, `German_Germany.1252`) against compiled locales using
/// progressive subtag fallback (`zh-hans-cn` → `zh-hans` → `zh`).
pub fn parse_lang_tag(tag: &str) -> Option<&'static Locale> {
    let base = tag.trim().split(['.', '@']).next()?.trim();
    if base.is_empty() {
        return None;
    }
    let mut norm = base.replace('_', "-").to_ascii_lowercase();
    while !norm.is_empty() {
        if let Some(loc) = LOCALES.iter().find(|l| {
            l.code.eq_ignore_ascii_case(&norm) || l.tags.iter().any(|&t| t == norm)
        }) {
            return Some(loc);
        }
        match norm.rfind('-') {
            Some(pos) => norm.truncate(pos),
            None => break,
        }
    }
    None
}

/// Parses the double-NUL-terminated UTF-16 buffer returned by Windows'
/// `GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, ...)` in priority order.
pub fn parse_preferred_ui_languages(buf: &[u16]) -> &'static Locale {
    for slice in buf.split(|&u| u == 0) {
        if slice.is_empty() {
            break;
        }
        let tag = String::from_utf16_lossy(slice);
        if let Some(loc) = parse_lang_tag(&tag) {
            return loc;
        }
    }
    EN_LOCALE
}

fn system_ui_lang() -> &'static Locale {
    use windows_sys::Win32::Globalization::{GetUserPreferredUILanguages, MUI_LANGUAGE_NAME};
    let mut num_langs: u32 = 0;
    let mut buf_len: u32 = 0;
    // SAFETY: passing null buffer queries the required UTF-16 buffer length.
    let ok = unsafe {
        GetUserPreferredUILanguages(
            MUI_LANGUAGE_NAME,
            &mut num_langs,
            core::ptr::null_mut(),
            &mut buf_len,
        )
    };
    if ok == 0 || buf_len == 0 {
        return EN_LOCALE;
    }
    let mut buf = vec![0u16; buf_len as usize];
    // SAFETY: `buf` is allocated with the length `buf_len` reported above.
    let ok = unsafe {
        GetUserPreferredUILanguages(MUI_LANGUAGE_NAME, &mut num_langs, buf.as_mut_ptr(), &mut buf_len)
    };
    if ok == 0 {
        return EN_LOCALE;
    }
    parse_preferred_ui_languages(&buf)
}

impl Locale {
    /// Localized storage bus label for values returned by `ntfs_unthrottle::tune::device_info`.
    pub const fn bus_name(&self, bus: &'static str) -> &'static str {
        if matches_str(bus, "SD card") {
            self.bus_sd_card()
        } else if matches_str(bus, "Storage Spaces") {
            self.bus_storage_spaces()
        } else if matches_str(bus, "virtual") {
            self.bus_virtual()
        } else if matches_str(bus, "unknown") {
            self.bus_unknown()
        } else {
            bus
        }
    }

    /// Localized, user-friendly description of an I/O error for `path`.
    pub fn describe_error_at(&self, err: &io::Error, path: &Path) -> String {
        let Some(hint) = error_hint(err) else {
            return err.to_string();
        };
        let vhdx = is_virtual_disk(path);
        match (hint, vhdx) {
            (ErrorHint::Locked, true) => self.error_locked_vhdx().to_owned(),
            (ErrorHint::Locked, false) => self.error_locked().to_owned(),
            (ErrorHint::AccessDenied, _) => self.error_access_denied().to_owned(),
            (ErrorHint::DiskFull, _) => self.error_disk_full().to_owned(),
            (ErrorHint::FileSystemLimitation, true) => self.error_fs_limitation_vhdx().to_owned(),
            (ErrorHint::FileSystemLimitation, false) => self.error_fs_limitation().to_owned(),
            (ErrorHint::InvalidParameter, _) => self.error_invalid_parameter().to_owned(),
        }
    }

    pub const fn protected(&self, why: Protected) -> &'static str {
        match why {
            Protected::SystemFolder => self.protected_system_folder(),
            Protected::RootSystemItem => self.protected_root_system_item(),
            Protected::RootHiddenSystem => self.protected_root_hidden_system(),
        }
    }

    pub const fn reason_label(&self, r: Reason) -> runtime::Label {
        match r {
            Reason::Extension => self.reason_extension_label(),
            Reason::LowSavings => self.reason_low_savings_label(),
            Reason::WriteHeavy => self.reason_write_heavy_label(),
            Reason::BuildDir => self.reason_build_dir_label(),
            Reason::DirectStorage => self.reason_direct_storage_label(),
            Reason::Forced => self.reason_forced_label(),
        }
    }

    pub const fn opt_label(&self, l: OptLabel) -> runtime::Label {
        match l {
            OptLabel::Drive => self.opt_lbl_drive_label(),
            OptLabel::FileSystem => self.opt_lbl_file_system_label(),
            OptLabel::DevDrive => self.opt_lbl_dev_drive_label(),
            OptLabel::Space => self.opt_lbl_space_label(),
            OptLabel::Cluster => self.opt_lbl_cluster_label(),
            OptLabel::Mft => self.opt_lbl_mft_label(),
            OptLabel::ShortNames => self.opt_lbl_short_names_label(),
            OptLabel::BypassIo => self.opt_lbl_bypass_io_label(),
            OptLabel::Indexer => self.opt_lbl_indexer_label(),
            OptLabel::LastAccess => self.opt_lbl_last_access_label(),
            OptLabel::TrimNtfs => self.opt_lbl_trim_ntfs_label(),
            OptLabel::TrimRefs => self.opt_lbl_trim_refs_label(),
            OptLabel::MftZone => self.opt_lbl_mft_zone_label(),
        }
    }

    pub const fn driver_hint(&self, h: DriverHint) -> &'static str {
        match h {
            DriverHint::Wof => self.opt_driver_wof(),
            DriverHint::BitLocker => self.opt_driver_bitlocker(),
            DriverHint::VolSnap => self.opt_driver_volsnap(),
            DriverHint::StorageDriver => self.opt_driver_storage(),
            DriverHint::Other => self.opt_driver_other(),
        }
    }
}

const fn matches_str(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::i18n::runtime::{GroupedDecimal, GroupedInt, Label, PluralRule};

    fn de_locale() -> &'static Locale {
        detect("de")
    }

    #[test]
    fn lang_tag_parsing_and_subtag_fallback() {
        let de = de_locale();
        assert_eq!(parse_lang_tag("de").map(|l| l.code), Some("de"));
        assert_eq!(parse_lang_tag("de_DE.UTF-8").map(|l| l.code), Some("de"));
        assert_eq!(parse_lang_tag("de_DE.UTF-8@euro").map(|l| l.code), Some("de"));
        assert_eq!(parse_lang_tag("de-AT").map(|l| l.code), Some("de"));
        assert_eq!(parse_lang_tag("German_Germany.1252").map(|l| l.code), Some("de"));
        assert_eq!(parse_lang_tag("en_US.UTF-8").map(|l| l.code), Some("en"));
        assert_eq!(parse_lang_tag("EN").map(|l| l.code), Some("en"));
        // Progressive fallback: zh-Hans-CN → zh-hans → zh (not compiled → None)
        assert!(parse_lang_tag("zh-Hans-CN").is_none());
        assert!(parse_lang_tag("fr_FR").is_none());
        assert!(parse_lang_tag("").is_none());
        // "deu"/"dev" must not be mistaken for "de"
        assert!(parse_lang_tag("dev").is_none());
        assert_eq!(de.code, "de");
    }

    fn env<'a>(vars: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| vars.iter().find(|(n, _)| *n == k).map(|(_, v)| v.to_string())
    }

    #[test]
    fn env_priority_and_ignored_values() {
        assert!(from_env(env(&[])).is_none());
        assert_eq!(from_env(env(&[("LANG", "de_DE.UTF-8")])).map(|l| l.code), Some("de"));
        // LC_ALL beats LC_MESSAGES beats LANG
        assert_eq!(
            from_env(env(&[
                ("LC_ALL", "en_US"),
                ("LC_MESSAGES", "de_DE"),
                ("LANG", "de_DE"),
            ]))
            .map(|l| l.code),
            Some("en")
        );
        assert_eq!(
            from_env(env(&[("LC_MESSAGES", "de_DE"), ("LANG", "en_US")])).map(|l| l.code),
            Some("de")
        );
        // Empty, C and POSIX are skipped
        assert_eq!(
            from_env(env(&[("LC_ALL", ""), ("LANG", "de")])).map(|l| l.code),
            Some("de")
        );
        assert_eq!(
            from_env(env(&[("LC_ALL", "C"), ("LANG", "de")])).map(|l| l.code),
            Some("de")
        );
        assert_eq!(
            from_env(env(&[("LC_ALL", "C.UTF-8"), ("LANG", "de")])).map(|l| l.code),
            Some("de")
        );
        assert!(from_env(env(&[("LC_ALL", "POSIX")])).is_none());
        // Unsupported locale → English
        assert_eq!(
            from_env(env(&[("LANG", "fr_FR.UTF-8")])).map(|l| l.code),
            Some("en")
        );
    }

    #[test]
    fn win32_preferred_ui_languages_buffer() {
        fn encode_multi_sz(tags: &[&str]) -> Vec<u16> {
            let mut out = Vec::new();
            for t in tags {
                out.extend(t.encode_utf16());
                out.push(0);
            }
            out.push(0);
            out
        }

        assert_eq!(
            parse_preferred_ui_languages(&encode_multi_sz(&["de-AT", "en-US"])).code,
            "de"
        );
        // First unsupported tag is skipped, second supported wins.
        assert_eq!(
            parse_preferred_ui_languages(&encode_multi_sz(&["fr-FR", "de-DE", "en-US"])).code,
            "de"
        );
        assert_eq!(
            parse_preferred_ui_languages(&encode_multi_sz(&["zh-Hans-CN", "en-US"])).code,
            "en"
        );
        assert_eq!(parse_preferred_ui_languages(&[0]).code, "en");
        assert_eq!(parse_preferred_ui_languages(&[]).code, "en");
    }

    #[test]
    fn explicit_choice_wins() {
        assert_eq!(detect("en").code, "en");
        assert_eq!(detect("de").code, "de");
        assert_eq!(detect("unknown-code").code, "en");
        assert_eq!(EN_LOCALE.code, "en");
    }

    #[test]
    fn yes_no_confirmation() {
        let en = EN_LOCALE;
        let de = de_locale();
        assert_eq!(en.yes_no(), "[y/N]");
        assert_eq!(de.yes_no(), "[j/N]");
        for yes in ["y", "Y", "yes", " YES \r\n"] {
            assert!(en.is_yes(yes), "{yes:?}");
            assert!(de.is_yes(yes), "{yes:?}");
        }
        for ja in ["j", "J", "ja", "Ja\n"] {
            assert!(de.is_yes(ja), "{ja:?}");
            assert!(!en.is_yes(ja), "{ja:?}");
        }
        for no in ["", "n", "no", "nein", "jein", "yess"] {
            assert!(!en.is_yes(no), "{no:?}");
            assert!(!de.is_yes(no), "{no:?}");
        }
        let files = en.noun_file(2);
        let dirs = en.noun_folder(1);
        assert!(en
            .scan_confirm_decompress(&files, &dirs, &en.yes_no())
            .to_string()
            .ends_with("[y/N]:"));
        assert!(de.opt_confirm_fixes(3, &de.yes_no()).to_string().ends_with("[j/N]:"));
    }

    #[test]
    fn localized_errors() {
        let en = EN_LOCALE;
        let de = de_locale();
        let share = io::Error::from_raw_os_error(32); // ERROR_SHARING_VIOLATION
        let vhdx = Path::new(r"E:\VMs\disk.vhdx");
        let bin = Path::new(r"E:\data.bin");
        assert!(de.describe_error_at(&share, vhdx).contains("wsl --shutdown"));
        assert!(de.describe_error_at(&share, bin).contains("gesperrt"));
        assert!(en.describe_error_at(&share, vhdx).contains("wsl --shutdown"));
        assert!(en.describe_error_at(&share, bin).contains("locked"));
    }

    #[test]
    fn bus_names_localized() {
        let en = EN_LOCALE;
        let de = de_locale();
        assert_eq!(de.bus_name("SD card"), "SD-Karte");
        assert_eq!(en.bus_name("SD card"), "SD card");
        assert_eq!(de.bus_name("NVMe"), "NVMe");
    }

    #[test]
    fn zero_alloc_numbers_and_decimals() {
        let en = EN_LOCALE;
        let de = de_locale();

        assert_eq!(GroupedInt { value: 0, sep: "." }.to_string(), "0");
        assert_eq!(en.int(1_234_567).to_string(), "1,234,567");
        assert_eq!(de.int(1_234_567).to_string(), "1.234.567");

        assert_eq!(de.decimal(1234.56, 1).to_string(), "1.234,6");
        assert_eq!(en.decimal(1234.56, 1).to_string(), "1,234.6");
        assert_eq!(de.decimal(42.0, 0).to_string(), "42");
        // -0.04 rounded to 1 decimal place must not render "-0,0"
        assert_eq!(de.decimal(-0.04, 1).to_string(), "0,0");
        assert_eq!(en.decimal(-0.04, 1).to_string(), "0.0");
        assert_eq!(de.decimal(-0.05, 1).to_string(), "-0,1");
        assert_eq!(de.decimal(f64::NAN, 1).to_string(), "NaN");
        assert_eq!(de.decimal(f64::INFINITY, 1).to_string(), "inf");
        assert_eq!(de.decimal(f64::NEG_INFINITY, 1).to_string(), "-inf");
        let _ = GroupedDecimal {
            value: 1.5,
            decimals: 2,
            decimal_sep: ",",
            thousand_sep: ".",
        };
    }

    #[test]
    fn plural_rules_behave_per_cldr() {
        use crate::i18n::runtime::PluralCat;
        assert_eq!(PluralRule::Germanic.classify(0), PluralCat::Other);
        assert_eq!(PluralRule::Germanic.classify(1), PluralCat::One);
        assert_eq!(PluralRule::Germanic.classify(2), PluralCat::Other);

        assert_eq!(PluralRule::French.classify(0), PluralCat::One);
        assert_eq!(PluralRule::French.classify(1), PluralCat::One);
        assert_eq!(PluralRule::French.classify(2), PluralCat::Other);

        assert_eq!(PluralRule::Slavic.classify(1), PluralCat::One);
        assert_eq!(PluralRule::Slavic.classify(21), PluralCat::One);
        assert_eq!(PluralRule::Slavic.classify(2), PluralCat::Few);
        assert_eq!(PluralRule::Slavic.classify(11), PluralCat::Many);
        assert_eq!(PluralRule::Slavic.classify(14), PluralCat::Many);
        assert_eq!(PluralRule::Slavic.classify(5), PluralCat::Many);

        assert_eq!(PluralRule::Arabic.classify(0), PluralCat::Zero);
        assert_eq!(PluralRule::Arabic.classify(1), PluralCat::One);
        assert_eq!(PluralRule::Arabic.classify(2), PluralCat::Two);
        assert_eq!(PluralRule::Arabic.classify(5), PluralCat::Few);
        assert_eq!(PluralRule::Arabic.classify(15), PluralCat::Many);
        assert_eq!(PluralRule::Arabic.classify(100), PluralCat::Other);
    }

    #[test]
    fn padded_label_and_dynamic_column_widths() {
        // CJK character '圧縮' occupies 4 terminal cells (2 chars).
        let cjk = Label { text: "圧縮", width: 4 };
        assert_eq!(cjk.pad(6).to_string(), "圧縮  ");
        assert_eq!(cjk.pad_left(6).to_string(), "  圧縮");

        // Column widths must always fit the longest label in each locale (+2 buffer).
        for loc in LOCALES {
            let enc = loc.compact_lbl_encrypted_skipped_label();
            assert!(
                loc.col_width_compact_summary >= enc.width + 2,
                "{}: {} < {} + 2",
                loc.code,
                loc.col_width_compact_summary,
                enc.width
            );
            assert_eq!(enc.pad(loc.col_width_compact_summary).to_string().len(), enc.text.len() + (loc.col_width_compact_summary - enc.width));
        }
    }
}
