# ntfs-unthrottle

**Language:** **English** | [Deutsch](README.de.md)

> Detects counterproductive NTFS and WOF compression, removes hidden Windows I/O
> bottlenecks, and audits volume/storage settings for gaming, extraction, and developer
> workloads — directly via Win32 `DeviceIoControl` IOCTLs, without spawning `compact.exe`.

## Table of Contents

1. [The Problem: Invisible Windows I/O Bottlenecks](#the-problem-invisible-windows-io-bottlenecks)
2. [Real-World Benchmarks (v0.2.0 Origin & v0.7.0 Audit)](#real-world-benchmarks-v020-origin--v070-audit)
3. [What It Does](#what-it-does)
4. [Installation & Building](#installation--building)
5. [Quick Start](#quick-start)
6. [Use-Case Recipes](#use-case-recipes)
   - [Gaming (DirectStorage & NVMe)](#1-gaming-directstorage--nvme)
   - [Archives, Disk Images & Large Containers](#2-archives-disk-images--large-containers)
   - [Developers (Rust, Node, Docker, WSL2)](#3-developers-rust-node-docker-wsl2)
   - [System Maintenance (CompactGUI & CompactOS)](#4-system-maintenance-compactgui--compactos)
7. [Selective WOF Compression (`compact`)](#selective-wof-compression-compact)
8. [Volume Diagnostics & Tuning](#volume-diagnostics--tuning)
9. [CLI Reference](#cli-reference)
10. [Safety Mechanisms (Poka-Yoke)](#safety-mechanisms-poka-yoke)
11. [Using as a Rust Library](#using-as-a-rust-library)
12. [Technical Background](#technical-background)

---

## The Problem: Invisible Windows I/O Bottlenecks

Many Windows drives suffer from silent transparent compression — often inherited from a
parent directory flag:

1. **Classic NTFS Compression (LZNT1, `FILE_ATTRIBUTE_COMPRESSED`):**  
   Often shown as two blue arrows in File Explorer. If a parent directory (e.g., `E:\Games`
   or `E:\Programs`) carries this flag, **every newly created file and subdirectory inherits
   it automatically** — even when the drive root `E:\` looks uncompressed in Explorer.  
   *Impact:* On large, already-compressed or encrypted files (archives, videos, disk
   images like `.iso`, asset containers like `.pak`), LZNT1 saves virtually **0 bytes**.
   Yet `NTFS.sys` synchronously attempts to compress every `64 KiB` unit on write, causing
   user-space multithreading to stall on kernel locks.
2. **Windows Overlay Filter (WOF / CompactOS / CompactGUI):**  
   Uses `XPRESS4K`, `XPRESS8K`, `XPRESS16K`, or `LZX`. WOF does **not** set a visible
   `COMPRESSED` attribute; compressed chunks live in the alternate stream `::WofCompressedData`.  
   *Impact:* On fast NVMe SSDs under Windows 11, `wof.sys` disables the **DirectStorage
   BypassIO** fast path and adds unnecessary overhead to write-heavy folders (such as build
   directories).

`ntfs-unthrottle` inspects both mechanisms using native Win32 APIs and selectively removes
only counterproductive compression.

---

## Real-World Benchmarks (v0.2.0 Origin & v0.7.0 Audit)

`ntfs-unthrottle` originated from a performance post-mortem while unpacking an encrypted
`6.27 GB` binary container (`3,848` files) on Windows 11 onto a SATA SSD (`Samsung 870 QVO`,
NTFS). Although `E:\` appeared uncompressed in Explorer, subdirectories carried an inherited
`FILE_ATTRIBUTE_COMPRESSED` (LZNT1) flag: space savings were negligible (`1.1:1` to `1.2:1`),
while `NTFS.sys` compressed every `64 KiB` unit synchronously on write — causing even
multi-threaded Rust (`rayon`, `seek_read`, AES-NI) to hit a wall.

| Measurement (`E:\`, inherited NTFS compression → uncompressed) | Before | After | Speedup |
|---|---:|---:|---:|
| Observed container unpack (end-to-end) | `~200 s` | `~30 s` | **~6.7×** |
| Controlled run step 1 (container extraction, `6.27 GB`) | `111.64 s` | `13.05 s` | **~8.6×** |
| Controlled run total (container + decrypting `3,848` files, free SLC cache) | `218.67 s` | `85.74 s` | **~2.6×** |

### Follow-Up Benchmark Suite (`v0.7.0`, NVMe & SATA-QLC)

Measured on Windows 11 x64 (`WDC WDS250G1B0C-00S6U0` NVMe `C:` and `Samsung 870 QVO 1TB`
SATA-QLC `E:`), with `sync_all()` flushes, 8 s cooldowns between runs, and
`FILE_FLAG_NO_BUFFERING` for uncached reads:

| Workload (Method) | Compressed / Unguarded | Uncompressed / `v0.7.0` Guard | Result |
|---|---:|---:|---|
| **Seq. Write** (`512 MiB` incompressible, `sync_all`, NVMe, 2-run avg) | `7.65 s` (`66.9 MiB/s`) | **`1.31 s` (`391.2 MiB/s`)** | **~5.8× faster** (`0` overhead on normal folders: `1.40 s` vs. `1.41 s`) |
| **Random 4K Write** (`64 MiB`, `1,500 × 4 KiB` + `sync_all`, NVMe) | `0.86 s` (`1,748 IOPS`, `1,081` frags) | **`0.07 s` (`21,430 IOPS`, `1` frag)** | **~12.3× higher IOPS** (`WOF/XPRESS4K` unpacks to `64 MiB` on write) |
| **Uncached Read** (`256 MiB`, `FILE_FLAG_NO_BUFFERING`, NVMe) | WOF `XPRESS4K`: `540.8 MiB/s` (`6,507` IOPS) | **`1,224.4 MiB/s` (`7,814` IOPS)** | **~2.3×** faster sequential uncached read vs. WOF (WOF saves 41% space) |
| **Container Extract** (`6.23 GiB` encrypted, `E:` QLC → `C:` NVMe) | `89.28 s` (`284` frags, `308 KiB` saved) | **`22.71 s` (`~281 MiB/s`)** | **~3.9× faster**; fixing a `16,306`-frag LZNT1 source (`39.50 s`) sped `E:` extract from `108.44 s` → `67.83 s` |
| **Small-File Archive** (`1.27 GiB`, `7,636` files, `1,063` dirs via `7z`, NVMe) | `10.54 s` (`1,064` dirs + `67` `.db`/`.ldb`/`.dll` + `626`-frag cache infected) | `11.72 s` clean; `--recommended --fix` in **`0.84 s`** | Small-file unpack itself is MFT/CPU-bound; CLI cleans fallout in `< 1 s` |

---

## What It Does

1. **Low-Syscall Directory Walk:** Reads attributes directly from `FindNextFile` metadata,
   deduplicates overlapping scan roots and hardlinks, and automatically skips WOF queries
   on exFAT/FAT/ReFS.
2. **Selective Evaluation:** Measures actual on-disk allocation (`GetCompressedFileSizeW`)
   and physical fragmentation (`FSCTL_GET_RETRIEVAL_POINTERS`). A file is only targeted if:
   - it occupies ≥ `--threshold` % (default `90`) of its logical size, **or**
   - it uses LZNT1 compression and has a high-entropy file extension, **or**
   - it matches `--recommended` rules, **or** `--all` is passed.
   Files that compress well (logs, source code, plain assets) remain untouched.
3. **DirectStorage & Storage Media Heuristics:** Detects drive bus/media type (`NVMe-SSD`,
   `SATA-SSD`, `HDD`, …) per scan root and automatically identifies DirectStorage titles
   via `dstorage.dll` / `dstoragecore.dll`.
4. **Safe Remediation:** Clears directory inheritance flags first, then decompresses files
   sequentially via kernel IOCTLs. Read-only attributes are temporarily cleared via an RAII
   guard (`Drop` restores them even on error), and timestamps are preserved.

It also warns if **ancestor directories** above the scan path carry the compression flag.

---

## Installation & Building

Requires a recent Rust toolchain (`rust-version = "1.83"`):

```powershell
git clone https://github.com/mohrpw/ntfs-unthrottle.git
cd ntfs-unthrottle

cargo build --release
# → target\release\ntfs-unthrottle.exe (~0.7 MB, LTO, stripped)
```

The release profile enables `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`,
`panic = "abort"`, and `strip = true`.

> **Tip:** If your project directory itself sits under a compressed parent folder, Cargo's
> `target\` folder inherits compression and slows down builds.
> `ntfs-unthrottle . --recommended --fix` fixes this immediately.

---

## Quick Start

By default, `ntfs-unthrottle` runs in **dry-run mode** (analysis only, modifies nothing):

```powershell
# 1. Inspect a folder or drive (safe dry-run)
ntfs-unthrottle "E:\Games"

# 2. Apply recommended cleanup with interactive confirmation
ntfs-unthrottle "E:\Games" --recommended --fix

# 3. Script / Scheduled Task mode: skip prompt
ntfs-unthrottle "E:\Workspace" "F:\ISOs" --fix --yes --min-size 50
```

---

## Use-Case Recipes

### 1. Gaming (DirectStorage & NVMe)

On Windows 11, DirectStorage uses the **BypassIO** path on **NVMe + NTFS**. If game files
are WOF-compressed, `wof.sys` must stay in the filter stack and blocks BypassIO.

- **HDD / SATA-SSD:** WOF (`XPRESS4K`/`8K`) can actually speed up loading → no warning.
- **NVMe-SSD:** Volumes with `> 1 GiB` of `LZX`/`XPRESS16K` print an `ℹ` summary of top
  folders without touching them. DirectStorage games trigger a `⚠` warning; `--recommended`
  selectively decompresses their WOF files (`≥ --min-size`).

```powershell
# Check whether DirectStorage titles are blocked by WOF:
ntfs-unthrottle "D:\SteamLibrary\steamapps\common"

# Decompress DirectStorage assets on NVMe:
ntfs-unthrottle "D:\SteamLibrary\steamapps\common\MyGame" --recommended --fix

# Separate mod staging folders or small WOF files (< 16 MiB):
ntfs-unthrottle "D:\ModManager\Staging" --all --min-size 0 --fix
```

> **Notes:**  
> - Games under `C:\Program Files\WindowsApps` are protected by design (use the Xbox app
>   to move them to a standard folder like `C:\XboxGames`).  
> - Hardlinks (e.g. mod-manager staging ↔ game folder) are tracked by file ID and skipped
>   as duplicates.

### 2. Archives, Disk Images & Large Containers

Prevents severe write stalls when extracting or copying high-entropy files (`.iso`, `.img`,
`.pak`, `.zip`, `.7z`, `.rar`, encrypted containers) on NTFS data volumes:

```powershell
# Clear inherited compression flags BEFORE extracting archives:
ntfs-unthrottle "E:\Archives" --fix

# Clean up already extracted, uselessly compressed containers/images:
ntfs-unthrottle "E:\ISOs" --fix

# Decompress every compressed file >= 16 MiB regardless of extension/ratio:
ntfs-unthrottle "E:\Archives" --all --fix
```

### 3. Developers (Rust, Node, Docker, WSL2)

With `--recommended`, the following are additionally decompressed **regardless of size or ratio**:

- **Write-heavy formats:** VM images (`.vhdx`, `.vmdk`, `.vdi`, `.qcow2`, …), databases
  (`.db`, `.sqlite`, `.mdf`, `.pst`, …), and active downloads (`.part`, `.crdownload`,
  `.!qb`, …).
- **Build & tooling directories:** Unambiguous directories (`node_modules`, `.git`, `.vs`,
  `__pycache__`, `.venv`/`venv`, `.gradle`, `.next`, `.cargo`, `.nuget`, `.m2`). Generic
  names (`build`, `dist`, `target`, `obj`) only match when adjacent to a project marker
  (`package.json`, `Cargo.toml`, `pyproject.toml`, `CMakeLists.txt`, `Makefile`, `.git`,
  `*.sln`, `pom.xml`, `*.csproj`/`*.vcxproj`) — keeping `D:\Games\Title\dist` untouched.
  Below `--min-size`, only classic LZNT1 compression is checked for speed.

```powershell
# Clean developer workspaces including build artifacts and databases:
ntfs-unthrottle "C:\Users\<User>\Code" --recommended --fix

# Shut down WSL/Docker first so .vhdx files aren't locked (ERROR_SHARING_VIOLATION):
wsl --shutdown
ntfs-unthrottle "$env:LOCALAPPDATA\Docker\wsl\data" --recommended --fix
```

### 4. System Maintenance (CompactGUI & CompactOS)

```powershell
# Inspect WOF/CompactGUI footprint in an app folder:
ntfs-unthrottle "C:\Program Files\MyApp"

# Fully decompress a CompactGUI-compressed app folder (run as Administrator):
ntfs-unthrottle "C:\Program Files\MyApp" --all --min-size 0 --fix
```

> **CompactOS note:** `C:\Windows` is always protected. Manage system-wide CompactOS via
> built-in Windows tooling: `compact.exe /CompactOS:query` or `compact.exe /CompactOS:never`.

---

## Selective WOF Compression (`compact`)

While the default scan *removes* counterproductive compression, `ntfs-unthrottle compact` goes the
other direction on static, well-compressible files (game assets, toolchains, documentation,
archives of uncompressed text/blobs) via `FSCTL_SET_EXTERNAL_BACKING` (`WOF`):

- **Zero-Write Pre-Flight Analysis:** Reads up to `16 KiB` for PE header classification (PE32 /
  PE32+ / `.NET` / packer sections / large self-extracting or asset overlays) and samples `8 × 16 KiB`
  blocks through Windows' native `cabinet.dll` (`COMPRESS_ALGORITHM_XPRESS_HUFF`) in memory before
  touching a single byte on disk.
- **Anti-Trap Chunk & Header Math:** Accounts for the `::WofCompressedData` chunk offset table
  (`(total_chunks + 1) × 4/8 B`), cluster rounding, MFT/small-file overhead, and `LZNT1 -> WOF`
  cluster non-regression. `ERROR_COMPRESSION_NOT_BENEFICIAL` (`344`) is handled gracefully without
  error.
- **Hardware- & Workload-Aware Profiles (`--profile`):**
  - `auto` *(default)*: uses `speed`; switches to `balanced` per volume when a known QLC SSD has `< 20%` free space.
  - `speed`: skips executables and moderate savings on NVMe; caps high-redundancy NVMe files at `Xpress16K` (preventing LZX's `~120–180 MiB/s` decode limit from throttling NVMe reads).
  - `balanced`: uses `Xpress8K`/`Lzx` for data on NVMe while still skipping executables; full compression on SATA/HDD/USB.
  - `space`: enables `Xpress4K` on executables and `Lzx` on compressible data across drives.
- **Strict Exclusions (Hardcoded):** Never compresses `.sys` / `.efi` drivers, encrypted (`EFS`) or
  sparse files, cloud placeholders, reparse points, protected OS paths, `WRITE_HEAVY_EXTS`, build
  directories, shader caches, or files inside **DirectStorage games on NVMe** (filtered before probe
  reads). Hardlinks are skipped by default (`--include-hardlinks` enables deduplicated compression).
- **Safe Application (`--fix`):** Defaults to a read-only dry-run (exit code `2` on candidates).
  With `--fix`, candidates are sorted ascending by size so smaller files free space first, each file
  passes a live volume free-space check (`free >= logical + max(256 MiB, 1%)`), existing `LZNT1` or
  `WOF` streams are cleanly cleared first, and timestamps plus `ReadOnly` attributes are preserved.

```powershell
# Dry-run: inspect compression candidates using hardware-aware auto profile:
ntfs-unthrottle compact "D:\Games"

# Apply balanced compression cleanly in scripts:
ntfs-unthrottle compact "D:\Archive" --profile balanced --fix --yes --json

# Re-evaluate already WOF-compressed files for tighter space savings:
ntfs-unthrottle compact "E:\Assets" --profile space --recompress --fix
```

---

## Volume Diagnostics & Tuning

`--optimize` skips file scanning and audits volume/storage settings that throttle I/O
independently of compression:

| Check | Automatic Fix (`--fix`, Administrator) |
|---|---|
| Storage bus & type: NVMe/SATA/USB, SSD/HDD, TRIM, QLC models | – (advisory) |
| Free space < 10% | – (advisory) |
| MFT size, record count, fragments, MFT zone | `fsutil behavior set mftzone 2` if ≥ 2M records |
| 8.3 short names per volume | `fsutil 8dot3name set E: 1` (never on system drive) |
| Last-Access timestamps | `fsutil behavior set disablelastaccess 1` |
| TRIM on NTFS SSDs | `fsutil behavior set DisableDeleteNotify NTFS 0` |
| TRIM on ReFS SSDs (Dev Drive) | `fsutil behavior set DisableDeleteNotify ReFS 0` |
| ReFS Dev Drive trust status | – (points to `fsutil devdrv trust` / `query` if untrusted) |
| BypassIO (Windows 11, NTFS): active / partial / blocked by `<driver.sys>` | – (points to `fsutil bypassIo state /v E:\` & `fltmc filters`) |
| Windows Search Indexer (`WSearch` / root attribute) | – (soft advisory on data drives) |
| Volume dirty bit | – (points to `chkdsk E: /scan`) |

The BypassIO check sends `FSCTL_MANAGE_BYPASS_IO` (`FS_BPIO_OP_QUERY`, no admin required)
and distinguishes filter-stack blocks (e.g., `wof.sys` or AV minifilters) from storage-stack
limitations (e.g., BitLocker `fvevol.sys`, SATA/RST/VMD drivers). ReFS TRIM state is read
from `RefsDisableDeleteNotification` or via `fsutil behavior query DisableDeleteNotify ReFS`
when a ReFS volume resides on an SSD.

Intentionally **never** automated: `8dot3name strip` (can break legacy registry paths),
Defender exclusions, defragmentation, `chkdsk`, or unloading minifilters. Every automated
change runs transparently via `fsutil` and can be reverted the same way.

```powershell
ntfs-unthrottle E:\ --optimize          # inspect (partial info without Admin)
ntfs-unthrottle E:\ --optimize --fix    # apply safe tweaks (elevated terminal)
```

---

## CLI Reference

| Option | Default | Description |
|---|---|---|
| `<PATHS>...` | `.` | Directories or files to scan (overlapping paths are deduplicated) |
| `-f, --fix` | *off* | Apply changes (without this flag: dry-run analysis only) |
| `-y, --yes` | *off* | Skip confirmation prompt (requires `--fix`) |
| `--recommended` | *off* | Recommended mode (alias `--recommend`); conflicts with `--all` |
| `--all` | *off* | Include every compressed file `>= --min-size` regardless of ratio/extension |
| `--only <REASON>` | *empty* | Restrict to `extension`, `low-savings`, `write-heavy`, `build`, `ds`, `all` (auto-enables their detectors; repeatable/comma-separated) |
| `--min-size <MiB>` | `16` | Minimum file size threshold in MiB |
| `--threshold <PERCENT>` | `90` | Physical/logical ratio (%) above which compression is considered useless |
| `--keep-dir-flags` | *off* | Do not clear compression attributes on directories |
| `--clear-dirs` | *off* | Clear all found directory compression flags even when `--only` is set (conflicts with `--keep-dir-flags`) |
| `--no-wof` | *off* | Skip WOF/CompactOS detection (avoids opening large uncompressed-flag files) |
| `--no-fragments` | *off* | Skip physical fragment count lookup |
| `--json` | *off* | Emit machine-readable JSON on stdout (`--fix --json` requires `--yes`) |
| `--optimize` | *off* | Run volume/hardware diagnostics instead of file scan |
| `-v, --verbose` | *off* | List all candidates, directories, and per-file errors |
| `-x, --exclude <NAME\|PATH>` | *empty* | Exclude directory/file name (any depth) or path prefix; repeatable |
| `--lang <auto\|en\|de>` | `auto` | Language of runtime output (`--help` is always English) |

**Exit codes:** `0` nothing to do / all fixed · `1` error · `2` dry-run found candidates ·
`3` some items failed · `130` interrupted (`Ctrl+C`).

### `ntfs-unthrottle compact` Subcommand

| Option | Default | Description |
|---|---|---|
| `<PATHS>...` | `.` | Directories or files to evaluate for WOF compression |
| `-f, --fix` | *off* | Apply WOF compression (without this flag: dry-run analysis only) |
| `-y, --yes` | *off* | Skip confirmation prompt (requires `--fix`; mandatory with `--fix --json`) |
| `--profile <auto\|speed\|balanced\|space>` | `auto` | Compression aggressiveness & NVMe/QLC protection policy |
| `--min-savings <PERCENT>` | `15` | Minimum estimated physical space savings required (`%`) |
| `--min-size <KiB>` | `32` | Minimum logical file size in KiB |
| `--recompress` | *off* | Re-evaluate already WOF-compressed files when changing algorithm brings `>= max(min-savings, 10)%` & `>= 2` clusters extra gain |
| `--include-hardlinks` | *off* | Compress hardlinked files once per `FileId` instead of skipping `links > 1` |

Shared global flags `-v, --verbose`, `--json`, `-x, --exclude`, and `--lang` work with `compact` as well
(e.g. `ntfs-unthrottle compact E:\ --json`). Do not mix top-level scan flags like `--optimize` or
`--recommended` with `compact`.

**Output language:** With `--lang auto`, the language is taken from `LC_ALL`, `LC_MESSAGES`
or `LANG` (ignored if empty or `C`/`POSIX`), otherwise from the Windows UI language.
German Windows → German output, everything else → English. The confirmation prompt accepts
`y`/`yes` (English) or `j`/`ja`/`y`/`yes` (German). Want to add a language? See
[CONTRIBUTING.md](CONTRIBUTING.md#adding-a-new-language-i18n).

---

## Safety Mechanisms (Poka-Yoke)

Critical system locations are **hardcoded and cannot be overridden**, even if passed
directly on the command line (skipped with `⛔`, remaining paths proceed normally):

- **Protected anywhere:** `$RECYCLE.BIN`, `System Volume Information`, `Config.Msi`,
  `WindowsApps`, `WpSystem`, `WUDownloadCache`, `$WinREAgent`, `$Windows.~BT`,
  `$Windows.~WS`, `$SysReset`, `$GetCurrent`, `MSOCache`
- **Protected at volume root:** `Windows`, `Recovery`, `Boot`, `EFI`, `bootmgr`,
  `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`, `DumpStack.log(.tmp)`, `bootTel.dat`
- **Safety net:** Any root-level entry with `HIDDEN | SYSTEM` attributes
- **Per-volume free-space check:** Verifies `logical − physical` delta plus a safety buffer
  (`max(256 MiB, 1%)`) before modifying files
- **Cloud, sparse & reparse protection:** Skips OneDrive/cloud placeholders
  (`OFFLINE` / `RECALL_*`), sparse files (`SPARSE_FILE`, to avoid materializing zero ranges),
  and reparse points (junctions, symlinks, dedup), plus checks reparse attributes on open directory handles

---

## Using as a Rust Library

If you write custom unpackers or converters in Rust, disable NTFS compression immediately
upon file creation (`< 1 ms` while 0 bytes). Turn off the default features so that only
`windows-sys` is pulled in instead of the CLI dependencies:

```toml
# Cargo.toml
[dependencies]
ntfs-unthrottle = { git = "https://github.com/mohrpw/ntfs-unthrottle.git", default-features = false }
```

| Feature | Default | Contents |
|---|---|---|
| `cli` | yes | The `ntfs-unthrottle` binary (`clap`, `console`, `humansize`, `indicatif`, `serde_json`, `walkdir`); enables `tune` |
| `tune` | via `cli` | `ntfs_unthrottle::tune` – volume/drive diagnostics (TRIM, BypassIO, Dev Drive, MFT, 8.3 names, Indexer) |

```rust
use std::fs::OpenOptions;
use std::io::Write;
use ntfs_unthrottle::UncompressedOpenOptions;

fn main() -> std::io::Result<()> {
    ntfs_unthrottle::create_dir_all_uncompressed("D:/out/romfs")?;
    let mut out = ntfs_unthrottle::create_uncompressed_with_size("D:/out/romfs/archive.bin", data.len() as u64)?;
    out.write_all(&data)?;

    // Or combine custom OpenOptions (e.g. create_new, FILE_FLAG_SEQUENTIAL_SCAN):
    let _f = OpenOptions::new().read(true).write(true).create_new(true).open_uncompressed("D:/out/romfs/new.bin")?;
    Ok(())
}
```

- `create_uncompressed(path)` / `create_uncompressed_with_size(path, size)` – creates/truncates a
  file, disables compression **only if** it inherited `FILE_ATTRIBUTE_COMPRESSED` (no extra IOCTL
  in normal folders), and in `_with_size` reserves contiguous space (`FileAllocationInfo`) so
  NTFS/ReFS avoids fragmentation. Both compression removal and pre-allocation in these wrappers
  are **best-effort**: if rejected (e.g. FAT32/exFAT/SMB quota or filter driver), the file is still
  returned; only open/create errors are reported.
- `UncompressedOpenOptions` (`open_uncompressed(path)` / `open_uncompressed_with_size(path, size)`) –
  extension trait on `std::fs::OpenOptions` for callers needing `create_new(true)` or custom Windows
  flags while keeping the same best-effort compression and allocation guards.
- `preallocate(&file, size)` – explicit/strict wrapper around `SetFileInformationByHandle(FileAllocationInfo)`
  (requires write access; returns errors, and treats `size == 0` or existing length `>= size` as a no-op).
- `create_dir_all_uncompressed(path)` – like `std::fs::create_dir_all`, but clears the
  compression flag on every newly created folder and on the target folder itself
  (existing folders above it and reparse points are left alone). Also best-effort.
- `clear_dir_compression(dir)` – clears a folder's compression flag if set.
- `compression_kind(path)` – `None`, `Some(Lznt1)` or `Some(Wof(..))`, e.g. for a pre-flight
  warning that an input file is stored compressed.
- For existing handles, `disable_compression(&file)` reports errors (requires both `read` and
  `write` access; `File::create` alone is insufficient for `FSCTL_SET_COMPRESSION`). It is a
  no-op on FAT/exFAT/ReFS.
- `compress_wof(path, algorithm)` / `WofCompressOutcome` – applies WOF compression
  (`Xpress4K`, `Lzx`, `Xpress8K`, `Xpress16K`) via `FSCTL_SET_EXTERNAL_BACKING`, preserving
  timestamps and `ReadOnly` attributes, rejecting unsafe attributes (`SPARSE`, `REPARSE`,
  `DIRECTORY`, `ENCRYPTED`, `COMPRESSED`), and returning `Ok(WofCompressOutcome::NotBeneficial)` on `ERROR_COMPRESSION_NOT_BENEFICIAL`.

On non-Windows platforms the functions above compile as cheap no-ops (`File::create`,
`std::fs::create_dir_all`, `Ok(None)` …), so callers need no `cfg` switches. The rest of the
API and the CLI are Windows-only.

---

## Technical Background

- **LZNT1 operates in 16-cluster Compression Units** (`64 KiB` on `4 KiB` clusters). If a
  CU cannot shrink by at least one cluster, NTFS stores it *uncompressed*. High-entropy
  files still occupy ~100% disk space — reads barely decompress, but **writes** pay
  synchronous kernel compression overhead on every CU.
- **Fragmentation** spikes on partially compressible files and random writes/appends.
  Severely fragmented compressed files can hit `ERROR_FILE_SYSTEM_LIMITATION` (`665`),
  commonly seen with `.vhdx` or database files.
- **Inheritance** only comes from the *immediate* parent folder at creation time; clearing
  the folder flag does not decompress existing files, so `ntfs-unthrottle` handles both.
- **WOF** stores compressed chunks in `::WofCompressedData` (preceded by a `(chunks + 1) × 4/8 B`
  offset table) without setting `COMPRESSED`. Writing to a WOF file triggers automatic decompression by
  Windows, making WOF harmful for build directories and DirectStorage titles on NVMe, while still useful
  for static, compressible data when chosen selectively. `FSCTL_SET_EXTERNAL_BACKING` performs in-kernel
  WOF compression without spawning `compact.exe` and leaves `LastAccessTime` updates suppressed during `compact`'s dry-run probes.
- `FSCTL_SET_COMPRESSION` (`COMPRESSION_FORMAT_NONE`) blocks until the file is rewritten
  uncompressed and only needs `logical − physical` extra free space. On SSDs, read throughput
  recovers immediately even though `FSCTL_SET_COMPRESSION` does not coalesce physical extents
  in-place (on mechanical HDDs, running `defrag` afterwards can still help severely
  fragmented files).

## Contributing

Contributions are welcome – see [CONTRIBUTING.md](CONTRIBUTING.md) for the project layout,
safety rules, the i18n workflow, and commit conventions.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
