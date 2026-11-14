# Contributing to ntfs-unthrottle

Thanks for your interest in improving `ntfs-unthrottle`! This guide explains how the
project is organized, which rules must never be broken, and how to add a new language.

## Project Overview

`ntfs-unthrottle` is a Windows-only Rust crate (library + CLI). Code, comments, API docs
and `--help` are written in **English**; only runtime messages are localized.

| File | Purpose |
|---|---|
| `src/lib.rs` | Public library API: detect/remove LZNT1 and WOF compression via `DeviceIoControl`, volume info, fragment counts, hardlink identity, error classification (`ErrorHint`, `describe_error*`). |
| `src/tune.rs` | Read-only queries for `--optimize`: storage device (bus, SSD/HDD, TRIM), NTFS volume data, 8.3 names, dirty bit, BypassIO, registry switches, `fsutil` output decoding/parsing. |
| `src/main.rs` | CLI (`clap`), directory walk, candidate selection (`--recommended`, `--all`, …), poka-yoke protection, DirectStorage/NVMe rules, report and cleanup. |
| `src/optimize.rs` | `--optimize`: volume/hardware diagnostics and the safe `fsutil` fixes. |
| `locales/<lang>.toml` | Single-file-per-language translations (`en.toml` is the canonical schema, plus `[meta]`, `[messages]`, `[plurals]`). |
| `build.rs` & `src/i18n/` | Compile-time TOML validation, CJK-safe column-width computation, zero-allocation code generation (`runtime.rs`, `mod.rs`), and language detection (`--lang`, `LC_ALL`/`LC_MESSAGES`/`LANG`, `GetUserPreferredUILanguages`). |

Every user-visible runtime string lives in `locales/<lang>.toml`. `main.rs`, `compact.rs` and
`optimize.rs` only call the methods generated on `Locale` via `tr()` – please do not add
hard-coded user-facing text elsewhere.

## Development

Requirements: Windows, a recent stable Rust toolchain (MSRV `1.83`).

```powershell
cargo test                               # unit tests (incl. i18n)
cargo clippy --all-targets -- -D warnings
cargo build --release
cargo run -- --lang en --optimize        # quick smoke test (read-only without --fix)
cargo run -- --lang de --optimize
```

Without `--fix` the tool never modifies anything, so dry runs are always safe.

## Adding a New Language (i18n)

Adding or updating a language requires editing **only a single file** (`locales/<lang>.toml`) –
zero Rust code changes are needed, and the runtime binary keeps **0 bytes** of extra
dependencies. `build.rs` checks every key, placeholder, plural form and column width against
`locales/en.toml` at compile time.

1. **Copy the canonical file.** Duplicate `locales/en.toml` as `locales/<lang>.toml` (e.g.
   `locales/fr.toml`).
2. **Update `[meta]`.** Set:
   - `code = "fr"` and human-readable `name = "Français"`
   - `tags = ["fr", "french"]` (lowercase BCP-47/POSIX base tags; Windows/POSIX regions like
     `fr-CA` or `fr_FR.UTF-8` automatically fall back to `fr`, and `zh-Hans-CN` falls back
     through `zh-hans` → `zh`)
   - `plural_rule` (`"none"`, `"germanic"`, `"french"`, `"slavic"`, or `"arabic"`)
   - `decimal_sep`, `thousand_sep`, `yes_no` (e.g. `"[o/N]"`) and `yes_tokens` (e.g.
     `["o", "oui", "y", "yes"]`)
3. **Translate `[messages]` and `[plurals.*]`.** Keep `{placeholder}` names unchanged (you may
   freely reorder them to match natural grammar; in `one`/`zero`/`few`/`many` plural variants,
   omitting `{count}` is allowed). Never insert ASCII control characters (except `\n`) or Unicode
   Bidi overrides. Column widths for aligned summaries and tables are automatically measured by
   `build.rs` via `unicode-width`.
4. **Verify.** Run `cargo test`, `cargo clippy --all-targets -- -D warnings`, and try
   `cargo run -- --lang <lang> --optimize`. Optionally add a translated `README.<code>.md` and
   link it from the language line at the top of `README.md`.

## Ground Rules

### Poka-yoke protection is not negotiable

The protected-path lists in `src/main.rs` (`PROTECTED_ANYWHERE`, `PROTECTED_AT_ROOT`, the
`HIDDEN | SYSTEM` root safety net) and the skipping of cloud placeholders and reparse points
are intentionally **not** configurable. Do not add flags that bypass them, and keep
`C:\Windows`, `WindowsApps`, `System Volume Information` & co. out of reach. Changes that
widen what the tool may modify need a clear justification and tests.

Likewise, keep these stable unless there is a strong reason: the extension/folder lists
(`HIGH_ENTROPY_EXTS`, `WRITE_HEAVY_EXTS`, `BUILD_DIRS`, `PROJECT_MARKERS`), `QLC_MODELS`,
the IOCTLs used, and the exit codes (`0` nothing to do / all fixed, `1` error, `2` dry-run
found candidates, `3` some items failed) – scripts depend on them.

### Windows locale safety

The tool must behave identically on German, English and any other Windows display
language:

- **Never parse localized text** from `fsutil` or other system tools. Only rely on
  language-independent parts (e.g. the `ReFS DisableDeleteNotify = N` prefix in
  `tune::parse_refs_ddn`) and prefer the registry or IOCTLs where possible.
- Decode console output of system tools with `tune::decode_oem` (OEM code page), not as
  UTF-8.
- Registry value names, `fsutil` arguments and driver names are not localized – never
  translate them.
- Add a test with both German and English sample output when you touch parsing code.

### Library API

Keep the public API in `src/lib.rs` backwards compatible (no signature changes or removed
items without a major version bump). The library itself stays English; localization
happens in the binary via `src/i18n.rs`.

## Commit Messages

Use [Conventional Commits](https://www.conventionalcommits.org/):

- `feat:` – new functionality (e.g. `feat: detect XPRESS16K on ReFS`)
- `fix:` – bug fixes
- `i18n:` – translations and language detection (e.g. `i18n: add French`)
- `docs:` – README/CONTRIBUTING/doc comments only
- `refactor:`, `test:`, `chore:` – as usual

Before opening a pull request, make sure `cargo test`, `cargo clippy --all-targets -- -D
warnings` and `cargo build --release` all pass.

## License

By contributing you agree that your contributions are dual-licensed under
[MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), like the rest of the project.
