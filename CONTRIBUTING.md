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
| `src/i18n.rs` | Language detection (`--lang`, `LC_ALL`/`LC_MESSAGES`/`LANG`, Windows UI language) and **all** localized runtime messages. |

Every user-visible runtime string lives in `src/i18n.rs` as a method on `Lang` with an
exhaustive `match`. `main.rs` and `optimize.rs` only call these methods (`tr().aborted()`,
`l.scanning_paths(n)`, …) – please do not add hard-coded user-facing text elsewhere.

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

The i18n layer is deliberately dependency-free. The compiler guides you through every
missing translation.

1. **Add the variant.** In `src/i18n.rs`, add a variant to `enum Lang` (e.g. `Fr`) and a
   matching CLI value to `enum LangChoice` (e.g. `/// French (Français)` + `Fr`), and map
   it in `detect()`.
2. **Map detection.** Teach `parse_lang_tag()` the new tag (e.g. `"fr" | "french"`) and
   `from_win32_lang_id()` the Windows *primary* language ID (`lang_id & 0x3FF`, e.g.
   `0x0C` for French – see Microsoft's *Language Identifier Constants*).
3. **Translate.** Run `cargo build`. Every message method in `src/i18n.rs` now fails with a
   "non-exhaustive patterns" error – add a `Lang::Fr => …` arm (or extend a tuple pattern
   such as `(Lang::Fr, Reason::Extension)`) to each one until it compiles. Don't forget
   `yes_no()` / `is_yes()` for the confirmation prompt, and keep the column-width limits
   checked by the `labels_fit_their_columns` test (reasons ≤ 14, optimizer labels ≤ 12
   characters).
4. **Verify.** Extend the unit tests in `src/i18n.rs` (tag parsing, LANGID mapping,
   yes/no answers), then run `cargo test` and try `cargo run -- --lang fr --optimize`.
   Optionally add a translated `README.<code>.md` and link it from the language line at the
   top of `README.md`.

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
