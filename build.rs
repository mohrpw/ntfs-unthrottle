use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use unicode_width::UnicodeWidthStr;

#[derive(Clone, Debug)]
enum RawTok {
    Lit(String),
    Arg(String),
}

#[derive(Clone, Debug)]
enum BoundSeg {
    Lit(String),
    Arg(u8),
}

struct MessageSpec {
    key: String,
    ident: String,
    params: Vec<String>,
}

struct PluralSpec {
    key: String,
    ident: String,
    /// Additional placeholders after `count` (index 0), in order of first appearance in `en.toml` `other`.
    extra_params: Vec<String>,
}

struct ColumnGroupSpec {
    name: &'static str,
    extra_pad: usize,
    min_width: usize,
    keys: &'static [&'static str],
}

const COLUMN_GROUPS: &[ColumnGroupSpec] = &[
    ColumnGroupSpec {
        name: "scan_summary",
        extra_pad: 2,
        min_width: 0,
        keys: &[
            "report.lbl_compressed_dirs",
            "report.lbl_throttled_files",
            "report.lbl_data_volume",
            "report.lbl_extra_space",
            "report.lbl_kept",
            "report.lbl_ds_detected",
            "report.lbl_hardlink_dupes",
            "report.lbl_cloud_skipped",
            "report.lbl_sparse_skipped",
            "report.lbl_excluded",
            "report.lbl_unreadable",
        ],
    },
    ColumnGroupSpec {
        name: "scan_result",
        extra_pad: 2,
        min_width: 0,
        keys: &[
            "scan.result_dir_flags",
            "scan.result_files",
            "scan.result_fragments",
        ],
    },
    ColumnGroupSpec {
        name: "compact_summary",
        extra_pad: 2,
        min_width: 0,
        keys: &[
            "compact.lbl_candidates",
            "compact.lbl_est_savings",
            "compact.lbl_already_wof",
            "compact.lbl_ds_skipped",
            "compact.lbl_packed_skipped",
            "compact.lbl_encrypted_skipped",
            "compact.lbl_hardlinks_skipped",
            "compact.lbl_unbeneficial",
            "compact.lbl_excluded_type",
            "report.lbl_cloud_skipped",
            "report.lbl_sparse_skipped",
            "report.lbl_unreadable",
        ],
    },
    ColumnGroupSpec {
        name: "compact_result",
        extra_pad: 2,
        min_width: 0,
        keys: &[
            "compact.result_compressed",
            "compact.result_actual_saved",
            "compact.result_not_beneficial",
            "compact.result_space_skipped",
        ],
    },
    ColumnGroupSpec {
        name: "optimize_labels",
        extra_pad: 2,
        min_width: 0,
        keys: &[
            "opt.lbl_drive",
            "opt.lbl_file_system",
            "opt.lbl_dev_drive",
            "opt.lbl_space",
            "opt.lbl_cluster",
            "opt.lbl_mft",
            "opt.lbl_short_names",
            "opt.lbl_bypass_io",
            "opt.lbl_indexer",
            "opt.lbl_last_access",
            "opt.lbl_trim_ntfs",
            "opt.lbl_trim_refs",
            "opt.lbl_mft_zone",
        ],
    },
    ColumnGroupSpec {
        name: "bar_labels",
        extra_pad: 0,
        min_width: 0,
        keys: &["scan.bar_dirs_label", "scan.bar_files_label"],
    },
    ColumnGroupSpec {
        name: "scan_table_reason",
        extra_pad: 2,
        min_width: 0,
        keys: &[
            "report.col_reason",
            "reason.extension",
            "reason.low_savings",
            "reason.write_heavy",
            "reason.build_dir",
            "reason.direct_storage",
            "reason.forced",
        ],
    },
    ColumnGroupSpec {
        name: "scan_table_type",
        extra_pad: 1,
        min_width: 15,
        keys: &["report.col_type"],
    },
    ColumnGroupSpec {
        name: "scan_table_size",
        extra_pad: 0,
        min_width: 10,
        keys: &["report.col_size"],
    },
    ColumnGroupSpec {
        name: "scan_table_phys",
        extra_pad: 0,
        min_width: 6,
        keys: &["report.col_phys"],
    },
    ColumnGroupSpec {
        name: "scan_table_frags",
        extra_pad: 0,
        min_width: 9,
        keys: &["report.col_frags"],
    },
    ColumnGroupSpec {
        name: "compact_table_size",
        extra_pad: 0,
        min_width: 10,
        keys: &["compact.col_size"],
    },
    ColumnGroupSpec {
        name: "compact_table_est",
        extra_pad: 0,
        min_width: 6,
        keys: &["compact.col_est"],
    },
    ColumnGroupSpec {
        name: "compact_table_alg",
        extra_pad: 2,
        min_width: 9,
        keys: &["compact.col_algorithm"],
    },
    ColumnGroupSpec {
        name: "compact_table_saves",
        extra_pad: 0,
        min_width: 10,
        keys: &["compact.col_saves"],
    },
];

struct ParsedLocale {
    code: String,
    name: String,
    tags: Vec<String>,
    plural_rule_expr: &'static str,
    decimal_sep: String,
    thousand_sep: String,
    yes_no: String,
    yes_tokens: Vec<String>,
    /// 0-arg messages: key -> raw sanitized string (for Label).
    static_messages: BTreeMap<String, String>,
    /// Parameterized messages: key -> (segments, lit_width).
    dyn_messages: BTreeMap<String, (Vec<BoundSeg>, usize)>,
    /// Plurals: key -> [zero, one, two, few, many, other].
    plurals: BTreeMap<String, [Option<Vec<BoundSeg>>; 6]>,
    col_widths: BTreeMap<&'static str, usize>,
}

const PLURAL_CATS: [&str; 6] = ["zero", "one", "two", "few", "many", "other"];

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let locales_dir = manifest_dir.join("locales");
    println!("cargo:rerun-if-changed=locales");

    let mut files: Vec<PathBuf> = Vec::new();
    let entries = fs::read_dir(&locales_dir)
        .unwrap_or_else(|e| panic!("Failed to read {}: {e}", locales_dir.display()));
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            println!("cargo:rerun-if-changed={}", path.display());
            files.push(path);
        }
    }
    files.sort();

    let en_idx = files
        .iter()
        .position(|p| p.file_name().and_then(|s| s.to_str()) == Some("en.toml"))
        .expect("locales/en.toml is required as the canonical reference locale");
    files.swap(0, en_idx);
    // Keep non-en files sorted deterministically by filename.
    files[1..].sort();

    let mut raw_tables: Vec<(PathBuf, toml::Table)> = Vec::with_capacity(files.len());
    for p in &files {
        let content = fs::read_to_string(p)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", p.display()));
        let table: toml::Table = content
            .parse()
            .unwrap_or_else(|e| panic!("Invalid TOML in {}: {e}", p.display()));
        raw_tables.push((p.clone(), table));
    }

    // Extract canonical schema from en.toml.
    let (en_path, en_table) = &raw_tables[0];
    let (msg_specs, plural_specs) = extract_en_schema(en_path, en_table);

    let mut seen_codes = BTreeSet::new();
    let mut seen_tags = BTreeSet::new();
    let mut parsed_locales = Vec::with_capacity(raw_tables.len());

    for (path, table) in &raw_tables {
        let loc = parse_and_validate_locale(
            path,
            table,
            &msg_specs,
            &plural_specs,
            &mut seen_codes,
            &mut seen_tags,
        );
        parsed_locales.push(loc);
    }

    assert_eq!(
        parsed_locales[0].code, "en",
        "locales[0] must be 'en' for EN_LOCALE"
    );

    let generated = generate_rust(&msg_specs, &plural_specs, &parsed_locales);
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    fs::write(out_dir.join("i18n_gen.rs"), generated).unwrap();
}

fn sanitize_text(ctx: &str, s: &str) {
    for ch in s.chars() {
        let forbidden_ctrl = (ch < '\x20' && ch != '\n')
            || ch == '\x7F'
            || ('\u{0080}'..='\u{009F}').contains(&ch);
        let bidi_ctrl = matches!(
            ch,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        );
        if forbidden_ctrl || bidi_ctrl {
            panic!(
                "Forbidden control or bidi character U+{:04X} in {ctx}",
                ch as u32
            );
        }
    }
}

fn key_to_ident(key: &str) -> String {
    let ident: String = key
        .chars()
        .map(|c| if c == '.' || c == '-' { '_' } else { c })
        .collect();
    let valid = !ident.is_empty()
        && ident.bytes().enumerate().all(|(i, b)| {
            if i == 0 {
                b.is_ascii_lowercase() || b == b'_'
            } else {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
            }
        });
    assert!(valid, "Invalid i18n key identifier: '{key}' -> '{ident}'");
    ident
}

fn is_valid_param_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(i, b)| {
            if i == 0 {
                b.is_ascii_lowercase() || b == b'_'
            } else {
                b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'
            }
        })
}

fn parse_template_raw(ctx: &str, input: &str) -> (Vec<RawTok>, Vec<String>) {
    sanitize_text(ctx, input);
    let mut toks: Vec<RawTok> = Vec::new();
    let mut placeholders: Vec<String> = Vec::new();
    let mut lit_buf = String::new();
    let mut chars = input.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        match ch {
            '{' => {
                if let Some(&(_, '{')) = chars.peek() {
                    chars.next();
                    lit_buf.push('{');
                    continue;
                }
                if !lit_buf.is_empty() {
                    toks.push(RawTok::Lit(std::mem::take(&mut lit_buf)));
                }
                let start = idx + 1;
                let mut end = None;
                for (j, c2) in chars.by_ref() {
                    if c2 == '}' {
                        end = Some(j);
                        break;
                    }
                    if c2 == '{' {
                        panic!("Unescaped '{{' inside placeholder in {ctx}");
                    }
                }
                let end = end.unwrap_or_else(|| panic!("Unclosed '{{' in {ctx}"));
                let name = &input[start..end];
                assert!(
                    is_valid_param_name(name),
                    "Invalid placeholder '{{{name}}}' in {ctx} (use [a-z_][a-z0-9_]*)"
                );
                if !placeholders.iter().any(|p| p == name) {
                    placeholders.push(name.to_string());
                }
                toks.push(RawTok::Arg(name.to_string()));
            }
            '}' => {
                if let Some(&(_, '}')) = chars.peek() {
                    chars.next();
                    lit_buf.push('}');
                } else {
                    panic!("Unmatched '}}' in {ctx}");
                }
            }
            _ => lit_buf.push(ch),
        }
    }
    if !lit_buf.is_empty() {
        toks.push(RawTok::Lit(lit_buf));
    }
    (toks, placeholders)
}

fn bind_segments(
    ctx: &str,
    toks: &[RawTok],
    found_params: &[String],
    canonical_params: &[String],
    allow_subset: bool,
) -> (Vec<BoundSeg>, usize) {
    let expected: BTreeSet<&str> = canonical_params.iter().map(String::as_str).collect();
    let found: BTreeSet<&str> = found_params.iter().map(String::as_str).collect();

    let unknown: Vec<&str> = found.difference(&expected).copied().collect();
    assert!(
        unknown.is_empty(),
        "Unknown placeholder(s) {unknown:?} in {ctx} (expected subset of {canonical_params:?})"
    );
    if !allow_subset {
        let missing: Vec<&str> = expected.difference(&found).copied().collect();
        assert!(
            missing.is_empty(),
            "Missing placeholder(s) {missing:?} in {ctx} (expected {canonical_params:?})"
        );
    }

    let mut segments = Vec::with_capacity(toks.len());
    let mut lit_width = 0usize;
    for tok in toks {
        match tok {
            RawTok::Lit(s) => {
                lit_width += UnicodeWidthStr::width(s.as_str());
                segments.push(BoundSeg::Lit(s.clone()));
            }
            RawTok::Arg(name) => {
                let idx = canonical_params
                    .iter()
                    .position(|p| p == name)
                    .expect("validated above");
                let idx_u8 = u8::try_from(idx)
                    .unwrap_or_else(|_| panic!("Too many placeholders (> 255) in {ctx}"));
                segments.push(BoundSeg::Arg(idx_u8));
            }
        }
    }
    (segments, lit_width)
}

fn require_table<'a>(ctx: &str, root: &'a toml::Table, key: &str) -> &'a toml::Table {
    root.get(key)
        .and_then(|v| v.as_table())
        .unwrap_or_else(|| panic!("Missing or invalid [{key}] table in {ctx}"))
}

fn require_str<'a>(ctx: &str, tbl: &'a toml::Table, key: &str) -> &'a str {
    let s = tbl
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("Missing or invalid string '{key}' in {ctx}"));
    sanitize_text(&format!("{ctx}.{key}"), s);
    s
}

fn require_str_array(ctx: &str, tbl: &toml::Table, key: &str) -> Vec<String> {
    let arr = tbl
        .get(key)
        .and_then(|v| v.as_array())
        .unwrap_or_else(|| panic!("Missing or invalid array '{key}' in {ctx}"));
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let s = item
            .as_str()
            .unwrap_or_else(|| panic!("Non-string element at {key}[{i}] in {ctx}"));
        sanitize_text(&format!("{ctx}.{key}[{i}]"), s);
        out.push(s.to_string());
    }
    out
}

fn extract_en_schema(
    en_path: &Path,
    en_table: &toml::Table,
) -> (Vec<MessageSpec>, Vec<PluralSpec>) {
    let ctx = en_path.display().to_string();
    let messages = require_table(&ctx, en_table, "messages");
    let plurals = require_table(&ctx, en_table, "plurals");

    let mut seen_idents = BTreeSet::new();
    let mut msg_specs = Vec::with_capacity(messages.len());
    for (key, val) in messages {
        let raw = val
            .as_str()
            .unwrap_or_else(|| panic!("Message '{key}' in {ctx} must be a string"));
        let ident = key_to_ident(key);
        assert!(
            seen_idents.insert(ident.clone()),
            "Duplicate Rust identifier '{ident}' generated from key '{key}'"
        );
        let (_, params) = parse_template_raw(&format!("{ctx}:[messages].{key}"), raw);
        msg_specs.push(MessageSpec {
            key: key.clone(),
            ident,
            params,
        });
    }

    let mut plural_specs = Vec::with_capacity(plurals.len());
    for (key, val) in plurals {
        let ptable = val
            .as_table()
            .unwrap_or_else(|| panic!("Plural '{key}' in {ctx} must be a table"));
        let ident = key_to_ident(key);
        assert!(
            seen_idents.insert(ident.clone()),
            "Duplicate Rust identifier '{ident}' generated from plural key '{key}'"
        );
        let other = ptable
            .get("other")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Plural '{key}' in {ctx} must define 'other'"));
        let (_, all_params) = parse_template_raw(&format!("{ctx}:[plurals.{key}].other"), other);
        assert!(
            all_params.iter().any(|p| p == "count"),
            "Plural '{key}' in {ctx} 'other' form must contain '{{count}}'"
        );
        // `count` is always index 0; remaining placeholders follow their first appearance in `en.toml` `other`.
        let extra_params: Vec<String> = all_params
            .into_iter()
            .filter(|p| p != "count")
            .collect();
        plural_specs.push(PluralSpec {
            key: key.clone(),
            ident,
            extra_params,
        });
    }

    (msg_specs, plural_specs)
}

fn parse_and_validate_locale(
    path: &Path,
    table: &toml::Table,
    msg_specs: &[MessageSpec],
    plural_specs: &[PluralSpec],
    seen_codes: &mut BTreeSet<String>,
    seen_tags: &mut BTreeSet<String>,
) -> ParsedLocale {
    let ctx = path.display().to_string();
    let meta = require_table(&ctx, table, "meta");
    let code = require_str(&ctx, meta, "code").to_string();
    assert!(
        !code.is_empty()
            && code != "auto"
            && code
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'),
        "Invalid [meta].code '{code}' in {ctx}"
    );
    assert!(
        seen_codes.insert(code.clone()),
        "Duplicate [meta].code '{code}' in {ctx}"
    );

    let name = require_str(&ctx, meta, "name").to_string();
    assert!(!name.is_empty(), "[meta].name must not be empty in {ctx}");

    let tags_raw = require_str_array(&ctx, meta, "tags");
    assert!(
        !tags_raw.is_empty(),
        "[meta].tags must not be empty in {ctx}"
    );
    let mut tags = Vec::with_capacity(tags_raw.len());
    for t in tags_raw {
        let norm = t.trim().to_ascii_lowercase().replace('_', "-");
        assert!(
            !norm.is_empty() && !norm.chars().any(char::is_whitespace),
            "Invalid tag '{t}' in {ctx}"
        );
        assert!(
            seen_tags.insert(norm.clone()),
            "Duplicate language tag '{norm}' across locales (in {ctx})"
        );
        tags.push(norm);
    }

    let plural_rule = require_str(&ctx, meta, "plural_rule");
    let plural_rule_expr = match plural_rule {
        "none" => "PluralRule::None",
        "germanic" => "PluralRule::Germanic",
        "french" => "PluralRule::French",
        "slavic" => "PluralRule::Slavic",
        "arabic" => "PluralRule::Arabic",
        other => panic!("Unsupported [meta].plural_rule '{other}' in {ctx}"),
    };

    let decimal_sep = require_str(&ctx, meta, "decimal_sep").to_string();
    assert!(
        !decimal_sep.is_empty(),
        "[meta].decimal_sep must not be empty in {ctx}"
    );
    let thousand_sep = require_str(&ctx, meta, "thousand_sep").to_string();

    let yes_no = require_str(&ctx, meta, "yes_no").to_string();
    assert!(
        !yes_no.is_empty(),
        "[meta].yes_no must not be empty in {ctx}"
    );

    let yes_tokens_raw = require_str_array(&ctx, meta, "yes_tokens");
    assert!(
        !yes_tokens_raw.is_empty(),
        "[meta].yes_tokens must not be empty in {ctx}"
    );
    let mut yes_tokens = Vec::with_capacity(yes_tokens_raw.len());
    for tok in yes_tokens_raw {
        let lower = tok.to_lowercase();
        assert!(
            !lower.is_empty() && !lower.chars().any(char::is_whitespace),
            "Invalid yes_token '{tok}' in {ctx}"
        );
        assert!(
            !matches!(lower.as_str(), "n" | "no" | "nein"),
            "yes_token '{tok}' in {ctx} collides with negative answer"
        );
        yes_tokens.push(lower);
    }

    // Validate [messages].
    let messages_tbl = require_table(&ctx, table, "messages");
    let expected_msg_keys: BTreeSet<&str> = msg_specs.iter().map(|s| s.key.as_str()).collect();
    for k in messages_tbl.keys() {
        assert!(
            expected_msg_keys.contains(k.as_str()),
            "Unknown message key '{k}' in {ctx} (not present in locales/en.toml)"
        );
    }

    let mut static_messages = BTreeMap::new();
    let mut dyn_messages = BTreeMap::new();
    for spec in msg_specs {
        let raw = messages_tbl
            .get(&spec.key)
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("Missing message '{}' in {ctx}", spec.key));
        let msg_ctx = format!("{ctx}:[messages].{}", spec.key);
        let (toks, found_params) = parse_template_raw(&msg_ctx, raw);
        if spec.params.is_empty() {
            let (segs, _) = bind_segments(&msg_ctx, &toks, &found_params, &[], false);
            let mut text = String::new();
            for s in segs {
                if let BoundSeg::Lit(part) = s {
                    text.push_str(&part);
                }
            }
            static_messages.insert(spec.key.clone(), text);
        } else {
            let bound = bind_segments(&msg_ctx, &toks, &found_params, &spec.params, false);
            dyn_messages.insert(spec.key.clone(), bound);
        }
    }

    // Validate [plurals].
    let plurals_tbl = require_table(&ctx, table, "plurals");
    let expected_plural_keys: BTreeSet<&str> = plural_specs.iter().map(|s| s.key.as_str()).collect();
    for k in plurals_tbl.keys() {
        assert!(
            expected_plural_keys.contains(k.as_str()),
            "Unknown plural key '{k}' in {ctx} (not present in locales/en.toml)"
        );
    }

    let mut plurals = BTreeMap::new();
    for spec in plural_specs {
        let ptbl = plurals_tbl
            .get(&spec.key)
            .and_then(|v| v.as_table())
            .unwrap_or_else(|| panic!("Missing plural table '{}' in {ctx}", spec.key));

        for cat_key in ptbl.keys() {
            assert!(
                PLURAL_CATS.contains(&cat_key.as_str()),
                "Invalid plural category '{cat_key}' in {ctx}:[plurals.{}]",
                spec.key
            );
        }

        let mut canonical_params = Vec::with_capacity(1 + spec.extra_params.len());
        canonical_params.push("count".to_string());
        canonical_params.extend(spec.extra_params.iter().cloned());

        let mut variants: [Option<Vec<BoundSeg>>; 6] = [None, None, None, None, None, None];
        for (cat_idx, cat_name) in PLURAL_CATS.iter().enumerate() {
            if let Some(val) = ptbl.get(*cat_name) {
                let raw = val.as_str().unwrap_or_else(|| {
                    panic!(
                        "Plural category '{cat_name}' in {ctx}:[plurals.{}] must be a string",
                        spec.key
                    )
                });
                let p_ctx = format!("{ctx}:[plurals.{}].{cat_name}", spec.key);
                let (toks, found_params) = parse_template_raw(&p_ctx, raw);
                let allow_subset = *cat_name != "other";
                let (segs, _) =
                    bind_segments(&p_ctx, &toks, &found_params, &canonical_params, allow_subset);
                variants[cat_idx] = Some(segs);
            }
        }
        assert!(
            variants[5].is_some(),
            "Plural '{}' in {ctx} must define 'other'",
            spec.key
        );
        plurals.insert(spec.key.clone(), variants);
    }

    // Validate and compute COLUMN_GROUPS widths.
    let mut col_widths = BTreeMap::new();
    for grp in COLUMN_GROUPS {
        let mut max_w = grp.min_width;
        for &k in grp.keys {
            if dyn_messages.contains_key(k) {
                panic!(
                    "Key '{k}' in COLUMN_GROUPS['{}'] darf keine Platzhalter enthalten",
                    grp.name
                );
            }
            let text = static_messages.get(k).unwrap_or_else(|| {
                panic!(
                    "Key '{k}' in COLUMN_GROUPS['{}'] not found in [messages] ({ctx})",
                    grp.name
                )
            });
            let w = UnicodeWidthStr::width(text.as_str());
            if w > max_w {
                max_w = w;
            }
        }
        col_widths.insert(grp.name, max_w + grp.extra_pad);
    }

    ParsedLocale {
        code,
        name,
        tags,
        plural_rule_expr,
        decimal_sep,
        thousand_sep,
        yes_no,
        yes_tokens,
        static_messages,
        dyn_messages,
        plurals,
        col_widths,
    }
}

fn push_segments_literal(out: &mut String, segs: &[BoundSeg]) {
    out.push_str("&[");
    for seg in segs {
        match seg {
            BoundSeg::Lit(s) => {
                out.push_str(&format!("Segment::Lit({s:?}), "));
            }
            BoundSeg::Arg(idx) => {
                out.push_str(&format!("Segment::Arg({idx}), "));
            }
        }
    }
    out.push(']');
}

fn generate_rust(
    msg_specs: &[MessageSpec],
    plural_specs: &[PluralSpec],
    locales: &[ParsedLocale],
) -> String {
    let mut out = String::with_capacity(64 * 1024);
    out.push_str("// @generated by build.rs from locales/*.toml – DO NOT EDIT.\n\n");
    out.push_str("use core::fmt;\n");
    out.push_str(
        "use crate::i18n::runtime::{GroupedDecimal, GroupedInt, Label, Msg, PluralMsg, PluralRule, PluralSet, Segment};\n\n",
    );

    // CLI_LANG_CHOICES: ["auto", "en", ...]
    out.push_str("pub static CLI_LANG_CHOICES: &[&str] = &[\"auto\"");
    for loc in locales {
        out.push_str(&format!(", {:?}", loc.code));
    }
    out.push_str("];\n\n");

    // Locale struct definition.
    out.push_str("#[allow(dead_code)]\n");
    out.push_str("pub struct Locale {\n");
    out.push_str("    pub code: &'static str,\n");
    out.push_str("    pub name: &'static str,\n");
    out.push_str("    pub tags: &'static [&'static str],\n");
    out.push_str("    pub plural_rule: PluralRule,\n");
    out.push_str("    pub decimal_sep: &'static str,\n");
    out.push_str("    pub thousand_sep: &'static str,\n");
    out.push_str("    pub yes_no_str: &'static str,\n");
    out.push_str("    pub yes_tokens: &'static [&'static str],\n");
    for grp in COLUMN_GROUPS {
        out.push_str(&format!("    pub col_width_{}: usize,\n", grp.name));
    }
    for spec in msg_specs {
        if spec.params.is_empty() {
            out.push_str(&format!("    pub m_{}: Label,\n", spec.ident));
        } else {
            out.push_str(&format!(
                "    m_{}: (&'static [Segment], usize),\n",
                spec.ident
            ));
        }
    }
    for spec in plural_specs {
        out.push_str(&format!("    p_{}: PluralSet,\n", spec.ident));
    }
    out.push_str("}\n\n");

    // LOCALES static slice + EN_LOCALE.
    out.push_str("pub static LOCALES: &[Locale] = &[\n");
    for loc in locales {
        out.push_str("    Locale {\n");
        out.push_str(&format!("        code: {:?},\n", loc.code));
        out.push_str(&format!("        name: {:?},\n", loc.name));
        out.push_str("        tags: &[");
        for t in &loc.tags {
            out.push_str(&format!("{t:?}, "));
        }
        out.push_str("],\n");
        out.push_str(&format!("        plural_rule: {},\n", loc.plural_rule_expr));
        out.push_str(&format!("        decimal_sep: {:?},\n", loc.decimal_sep));
        out.push_str(&format!("        thousand_sep: {:?},\n", loc.thousand_sep));
        out.push_str(&format!("        yes_no_str: {:?},\n", loc.yes_no));
        out.push_str("        yes_tokens: &[");
        for y in &loc.yes_tokens {
            out.push_str(&format!("{y:?}, "));
        }
        out.push_str("],\n");
        for grp in COLUMN_GROUPS {
            let w = loc.col_widths[grp.name];
            out.push_str(&format!("        col_width_{}: {w},\n", grp.name));
        }
        for spec in msg_specs {
            if spec.params.is_empty() {
                let text = &loc.static_messages[&spec.key];
                let width = UnicodeWidthStr::width(text.as_str());
                out.push_str(&format!(
                    "        m_{}: Label {{ text: {text:?}, width: {width} }},\n",
                    spec.ident
                ));
            } else {
                let (segs, lit_width) = &loc.dyn_messages[&spec.key];
                out.push_str(&format!("        m_{}: (", spec.ident));
                push_segments_literal(&mut out, segs);
                out.push_str(&format!(", {lit_width}),\n"));
            }
        }
        for spec in plural_specs {
            let vars = &loc.plurals[&spec.key];
            out.push_str(&format!("        p_{}: PluralSet {{\n", spec.ident));
            for (cat_idx, cat_name) in PLURAL_CATS.iter().enumerate() {
                if cat_idx < 5 {
                    match &vars[cat_idx] {
                        Some(segs) => {
                            out.push_str(&format!("            {cat_name}: Some("));
                            push_segments_literal(&mut out, segs);
                            out.push_str("),\n");
                        }
                        None => out.push_str(&format!("            {cat_name}: None,\n")),
                    }
                } else {
                    let segs = vars[5].as_ref().unwrap();
                    out.push_str("            other: ");
                    push_segments_literal(&mut out, segs);
                    out.push_str(",\n");
                }
            }
            out.push_str("        },\n");
        }
        out.push_str("    },\n");
    }
    out.push_str("];\n\n");
    out.push_str("pub static EN_LOCALE: &Locale = &LOCALES[0];\n\n");

    // Generated methods on Locale.
    out.push_str("#[allow(dead_code)]\n");
    out.push_str("impl Locale {\n");
    out.push_str(
        "    #[inline]\n    pub const fn int(&self, value: u64) -> GroupedInt {\n        GroupedInt { value, sep: self.thousand_sep }\n    }\n\n",
    );
    out.push_str(
        "    #[inline]\n    pub const fn decimal(&self, value: f64, decimals: u8) -> GroupedDecimal {\n        GroupedDecimal { value, decimals, decimal_sep: self.decimal_sep, thousand_sep: self.thousand_sep }\n    }\n\n",
    );
    out.push_str(
        "    #[inline]\n    pub const fn yes_no(&self) -> &'static str {\n        self.yes_no_str\n    }\n\n",
    );
    out.push_str(
        "    pub fn is_yes(&self, input: &str) -> bool {\n        let norm = input.trim().to_lowercase();\n        self.yes_tokens.iter().any(|&tok| tok == norm)\n    }\n\n",
    );

    for spec in msg_specs {
        if spec.params.is_empty() {
            out.push_str(&format!(
                "    #[inline]\n    pub const fn {ident}(&self) -> &'static str {{\n        self.m_{ident}.text\n    }}\n\n",
                ident = spec.ident
            ));
            out.push_str(&format!(
                "    #[inline]\n    pub const fn {ident}_label(&self) -> Label {{\n        self.m_{ident}\n    }}\n\n",
                ident = spec.ident
            ));
        } else {
            let n = spec.params.len();
            out.push_str(&format!("    #[inline]\n    pub fn {}<'a>(&self", spec.ident));
            for p in &spec.params {
                out.push_str(&format!(", p_{p}: &'a impl fmt::Display"));
            }
            out.push_str(&format!(") -> Msg<'a, {n}> {{\n        Msg {{ segments: self.m_{}.0, lit_width: self.m_{}.1, args: [", spec.ident, spec.ident));
            for (i, p) in spec.params.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("p_{p}"));
            }
            out.push_str("] }\n    }\n\n");
        }
    }

    for spec in plural_specs {
        let n = spec.extra_params.len();
        if n == 0 {
            out.push_str(&format!(
                "    #[inline]\n    pub fn {}(&self, count: u64) -> PluralMsg<'static, 0> {{\n        PluralMsg {{ segments: self.p_{}.pick(self.plural_rule, count), count: self.int(count), args: [] }}\n    }}\n\n",
                spec.ident, spec.ident
            ));
        } else {
            out.push_str(&format!(
                "    #[inline]\n    pub fn {}<'a>(&self, count: u64",
                spec.ident
            ));
            for p in &spec.extra_params {
                out.push_str(&format!(", p_{p}: &'a impl fmt::Display"));
            }
            out.push_str(&format!(
                ") -> PluralMsg<'a, {n}> {{\n        PluralMsg {{ segments: self.p_{}.pick(self.plural_rule, count), count: self.int(count), args: [",
                spec.ident
            ));
            for (i, p) in spec.extra_params.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("p_{p}"));
            }
            out.push_str("] }\n    }\n\n");
        }
    }

    out.push_str("}\n");
    out
}

