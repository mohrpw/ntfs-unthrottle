# ntfs-unthrottle

**Sprache:** [English](README.md) | **Deutsch**

> Spürt kontraproduktive NTFS- und WOF-Komprimierung auf, entfernt E/A-Bremsen und
> prüft Windows-Volumes für Gaming-, Entpack- und Entwickler-Workloads – direkt über
> die Win32-API (`DeviceIoControl`), ohne `compact.exe`.

## Inhaltsverzeichnis

1. [Das Problem: Unsichtbare I/O-Bremsen unter Windows](#das-problem-unsichtbare-io-bremsen-unter-windows)
2. [Praxis-Benchmarks (v0.2.0 & Messreihe v0.7.0)](#praxis-benchmarks-v020--messreihe-v070)
3. [Was das Tool macht](#was-das-tool-macht)
4. [Installation und Bauen](#installation-und-bauen)
5. [Schnellstart](#schnellstart)
6. [Praxis-Rezepte nach Anwendungsfall](#praxis-rezepte-nach-anwendungsfall)
   - [Gamer (DirectStorage und NVMe)](#1-gamer-directstorage-und-nvme)
   - [Archive, Disk-Images und große Container](#2-archive-disk-images-und-große-container)
   - [Entwickler (Rust, Node, Docker, WSL2)](#3-entwickler-rust-node-docker-wsl2)
   - [System-Pflege mit CompactGUI und CompactOS](#4-system-pflege-mit-compactgui-und-compactos)
7. [Volume-Diagnose und Tuning](#volume-diagnose-und-tuning)
8. [Befehlsreferenz](#befehlsreferenz)
9. [Schutzmechanismen (Poka-Yoke)](#schutzmechanismen-poka-yoke)
10. [Als Rust-Bibliothek verwenden](#als-rust-bibliothek-verwenden)
11. [Technischer Hintergrund](#technischer-hintergrund)

---

## Das Problem: Unsichtbare I/O-Bremsen unter Windows

Auf vielen Windows-Laufwerken ist transparente Komprimierung aktiv – oft unbemerkt
durch Vererbung eines Ordner-Flags:

1. **Klassische NTFS-Komprimierung (LZNT1, `FILE_ATTRIBUTE_COMPRESSED`):**  
   Im Explorer oft an zwei blauen Pfeilen erkennbar. Trägt ein übergeordneter Ordner
   (z. B. `E:\Games` oder `E:\Programme`) dieses Flag, **erbt jede neu angelegte Datei
   und jeder Unterordner das Attribut automatisch** – selbst wenn das Laufwerks-Root
   `E:\` im Explorer unkomprimiert wirkt.  
   *Folge:* Bei großen, bereits gepackten oder verschlüsselten Dateien (Archive,
   Videos, Disk-Images wie `.iso`, Asset-Container wie `.pak`) spart LZNT1 praktisch
   **0 Byte** Platz. Der Windows-Kernel (`NTFS.sys`) versucht jedoch bei jedem
   Schreibzugriff synchron pro `64-KiB`-Block zu komprimieren – User-Space-Multithreading
   verpufft im Kernel-Lock.
2. **Windows Overlay Filter (WOF / CompactOS / CompactGUI):**  
   Nutzt Algorithmen wie `XPRESS4K`, `XPRESS8K`, `XPRESS16K` oder `LZX`. WOF setzt
   **kein** sichtbares Dateiattribut; die Daten liegen im Alternate Stream
   `::WofCompressedData`.  
   *Folge:* Auf NVMe-SSDs schaltet `wof.sys` den schnellen **DirectStorage-BypassIO-Pfad**
   unter Windows 11 ab, und bei vielen kleinen Schreibzugriffen (z. B. Build-Ordner)
   entsteht unnötiger Overhead.

`ntfs-unthrottle` analysiert beide Mechanismen direkt über native Win32-APIs und
entfernt nur wirklich kontraproduktive Komprimierung.

---

## Praxis-Benchmarks (v0.2.0 & Messreihe v0.7.0)

`ntfs-unthrottle` entstand aus einem realen Performance-Post-Mortem beim Entpacken
eines verschlüsselten `6,27-GB`-Binärcontainers (`3.848` Einzeldateien) unter
Windows 11 auf einer SATA-SSD (`Samsung 870 QVO`, NTFS). Obwohl das Laufwerks-Root
`E:\` im Explorer unkomprimiert wirkte, trugen die Ziel-Unterordner vererbtes
`FILE_ATTRIBUTE_COMPRESSED` (LZNT1): kaum Platzersparnis (`1,1 : 1` bis `1,2 : 1`),
aber `NTFS.sys` prüfte jede `64-KiB`-Compression-Unit synchron beim Schreiben –
selbst paralleler Rust-Code (`rayon`, `seek_read`, AES-NI) skalierte kaum.

| Messung (`E:\`, vererbte NTFS-Komprimierung → unkomprimiert) | Vorher | Nachher | Speedup |
|---|---:|---:|---:|
| Beobachteter Container-Unpack (End-to-End) | `~200 s` | `~30 s` | **~6,7×** |
| Kontrolllauf Schritt 1 (Container-Extraktion, `6,27 GB`) | `111,64 s` | `13,05 s` | **~8,6×** |
| Kontrolllauf gesamt (Container + Entschlüsselung von `3.848` Dateien, freier SLC-Cache) | `218,67 s` | `85,74 s` | **~2,6×** |

### Erweiterte Messreihe (`v0.7.0`, NVMe & SATA-QLC)

Gemessen unter Windows 11 x64 (`WDC WDS250G1B0C-00S6U0` NVMe `C:` und `Samsung 870 QVO 1TB`
SATA-QLC `E:`) mit explizitem `sync_all()`-Flush, `8 s` Abkühl-/TRIM-Pause zwischen allen
Einzelläufen sowie `FILE_FLAG_NO_BUFFERING` für ungepufferte Lese-Tests:

| Workload (Methodik) | Komprimiert / Ungeschützt | Unkomprimiert / `v0.7.0`-Guard | Ergebnis |
|---|---:|---:|---|
| **Seq. Schreiben** (`512 MiB` inkompressibel, `sync_all`, NVMe, Ø 2 Läufe) | `7,65 s` (`66,9 MiB/s`) | **`1,31 s` (`391,2 MiB/s`)** | **~5,8× schneller** (`0` Overhead auf Normalordnern: `1,40 s` vs. `1,41 s`) |
| **Random-4K-Schreiben** (`64 MiB`, `1.500 × 4 KiB` + `sync_all`, NVMe) | `0,86 s` (`1.748 IOPS`, `1.081` Fragm.) | **`0,07 s` (`21.430 IOPS`, `1` Fragm.)** | **~12,3× höhere IOPS** (`WOF/XPRESS4K` entpackt beim Write auf `64 MiB`) |
| **Kalt-Lesen** (`256 MiB`, `FILE_FLAG_NO_BUFFERING`, NVMe) | WOF `XPRESS4K`: `540,8 MiB/s` (`6.507` IOPS) | **`1.224,4 MiB/s` (`7.814` IOPS)** | **~2,3×** schnellerer seq. Read als WOF (WOF spart dabei 41 % Platz) |
| **Container-Extraktion** (`6,23 GiB` verschlüsselt, `E:` QLC → `C:` NVMe) | `89,28 s` (`284` Fragm., `308 KiB` gespart) | **`22,71 s` (`~281 MiB/s`)** | **~3,9× schneller**; `--fix` einer `16.306`-Fragm.-Quelle (`39,50 s`) beschleunigte `E:` von `108,44 s` → `67,83 s` |
| **Kleindatei-Archiv** (`1,27 GiB`, `7.636` Dateien, `1.063` Ordner via `7z`, NVMe) | `10,54 s` (`1.064` Ordner + `67` `.db`/`.ldb`/`.dll` + `626`-Fragm.-Cache infiziert) | `11,72 s` sauber; `--recommended --fix` in **`0,84 s`** | Entpacken selbst MFT-/CPU-gebunden; CLI bereinigt Folgeschäden in `< 1 s` |

---

## Was das Tool macht

1. **Scan ohne unnötige Syscalls:** Liest Attribute direkt aus `FindNextFile`-Metadaten,
   dedupliziert überlappende Scan-Pfade sowie Hardlinks (`Hardlink-Duplikate übersprungen`)
   und überspringt WOF-Abfragen auf exFAT/FAT/ReFS automatisch.
2. **Selektive Bewertung:** Misst reale physische Belegung (`GetCompressedFileSizeW`)
   und Fragmentierung (`FSCTL_GET_RETRIEVAL_POINTERS`). Eine Datei wird nur angefasst, wenn:
   - sie physisch ≥ `--threshold` % (Standard `90`) ihrer logischen Größe belegt, **oder**
   - sie LZNT1-komprimiert ist und eine Hoch-Entropie-Endung hat, **oder**
   - sie unter die `--recommended`-Regeln fällt, **oder** `--all` gesetzt ist.
   Sinnvoll komprimierte Daten (Logs, Quelltext, gut gepackte Archive) bleiben unangetastet.
3. **DirectStorage- & Medien-Heuristik:** Ermittelt pro Scan-Pfad den Datenträger
   (`NVMe-SSD`, `SATA-SSD`, `HDD`, …) und erkennt DirectStorage-Spiele automatisch über
   `dstorage.dll` / `dstoragecore.dll`.
4. **Sichere Bereinigung:** Entfernt zuerst Ordner-Flags (stoppt Vererbung sofort) und
   entpackt anschließend Dateien sequenziell über Kernel-IOCTLs. Schreibschutz wird per
   RAII-Guard temporär gelöst und garantiert wiederhergestellt; Zeitstempel bleiben erhalten.

Zusätzlich warnt das Tool, wenn **übergeordnete** Ordner des Scan-Pfads das Flag tragen.

---

## Installation und Bauen

Voraussetzung ist eine aktuelle Rust-Toolchain (`rust-version = "1.83"`):

```powershell
git clone https://github.com/mohrpw/ntfs-unthrottle.git
cd ntfs-unthrottle

cargo build --release
# → target\release\ntfs-unthrottle.exe (~0,7 MB, LTO, gestrippt)
```

Das Release-Profil nutzt `opt-level = 3`, `lto = "fat"`, `codegen-units = 1`,
`panic = "abort"` und `strip = true`.

> **Tipp:** Liegt der Projektordner selbst auf einem komprimierten Pfad, wird auch
> Cargos `target\`-Verzeichnis komprimiert – das bremst jeden Build.
> `ntfs-unthrottle . --recommended --fix` behebt das.

---

## Schnellstart

Standardmäßig läuft `ntfs-unthrottle` im **Dry-Run** (reine Analyse, verändert nichts):

```powershell
# 1. Analyse eines Ordners oder Laufwerks
ntfs-unthrottle "E:\Games"

# 2. Empfohlene Bereinigung mit Bestätigungsabfrage anwenden
ntfs-unthrottle "E:\Games" --recommended --fix

# 3. Für Skripte / Scheduled Tasks: ohne Rückfrage
ntfs-unthrottle "E:\Workspace" "F:\ISOs" --fix --yes --min-size 50
```

---

## Praxis-Rezepte nach Anwendungsfall

### 1. Gamer (DirectStorage und NVMe)

DirectStorage nutzt unter Windows 11 auf **NVMe + NTFS** den **BypassIO**-Pfad. Ist eine
Spieldatei WOF-komprimiert, muss `wof.sys` im Filter-Stack bleiben und blockiert BypassIO.

- **HDD / SATA-SSD:** WOF (`XPRESS4K`/`8K`) kann Ladezeiten verkürzen → keine Warnung.
- **NVMe-SSD:** Bei `> 1 GiB` `LZX`/`XPRESS16K` erscheint ein `ℹ`-Hinweis mit den größten
  Ordnern (ohne automatisches Entpacken). Bei DirectStorage-Spielen erscheint eine
  `⚠`-Warnung; `--recommended` entpackt deren WOF-Dateien (`≥ --min-size`) gezielt.

```powershell
# Prüfen, ob DirectStorage-Spiele durch WOF blockiert werden:
ntfs-unthrottle "D:\SteamLibrary\steamapps\common"

# DirectStorage-Dateien auf NVMe gezielt entpacken:
ntfs-unthrottle "D:\SteamLibrary\steamapps\common\MeinSpiel" --recommended --fix

# Bei separaten Mod-Ordnern oder vielen kleinen WOF-Dateien (< 16 MiB):
ntfs-unthrottle "D:\ModManager\Staging" --all --min-size 0 --fix
```

> **Hinweise:**  
> - Spiele unter `C:\Program Files\WindowsApps` sind durch das Poka-Yoke-Design geschützt
>   (in der Xbox-App ggf. in einen Ordner wie `C:\XboxGames` verschieben).  
> - Hardlinks (z. B. Mod-Manager-Staging ↔ Spielordner) werden nur einmal erfasst und
>   als `Hardlink-Duplikate übersprungen` gezählt.

### 2. Archive, Disk-Images und große Container

Verhindert massive I/O-Einbrüche beim Entpacken oder Kopieren hoch-entropischer Daten
(`.iso`, `.img`, `.pak`, `.zip`, `.7z`, `.rar`, verschlüsselte Container) auf Daten-Volumes:

```powershell
# Zielordner VOR dem Entpacken von geerbten Komprimierungs-Flags befreien:
ntfs-unthrottle "E:\Archive" --fix

# Bereits entpackte, nutzlos komprimierte Container und Images bereinigen:
ntfs-unthrottle "E:\ISOs" --fix

# Jede komprimierte Datei (unabhängig von Endung und Quote) ab 16 MiB entpacken:
ntfs-unthrottle "E:\Archive" --all --fix
```

### 3. Entwickler (Rust, Node, Docker, WSL2)

Mit `--recommended` werden zusätzlich **unabhängig von Größe und Quote** entpackt:

- **Schreiblastige Formate (`Schreiblast`):** VM-Images (`.vhdx`, `.vmdk`, `.vdi`,
  `.qcow2`, …), Datenbanken (`.db`, `.sqlite`, `.mdf`, `.pst`, …) und unfertige Downloads
  (`.part`, `.crdownload`, `.!qb`, …).
- **Build- und Tooling-Ordner (`Build-Ordner`):** Eindeutige Namen wie `node_modules`,
  `.git`, `.vs`, `__pycache__`, `.venv`/`venv`, `.gradle`, `.next`, `.cargo`, `.nuget`,
  `.m2`. Generische Namen (`build`, `dist`, `target`, `obj`) zählen **nur**, wenn neben
  ihnen ein passender Projekt-Marker liegt (`package.json`, `Cargo.toml`, `pyproject.toml`,
  `CMakeLists.txt`, `Makefile`, `.git`, `*.sln` bzw. `pom.xml`, `*.csproj`/`*.vcxproj`) –
  `D:\Games\Titel\dist` bleibt also unangetastet. Unter `--min-size` wird dort aus
  Performancegründen nur klassische NTFS-Komprimierung (LZNT1) erfasst.

```powershell
# Entwickler-Workspace inkl. Build-Ordnern und Datenbanken bereinigen:
ntfs-unthrottle "C:\Users\<User>\Code" --recommended --fix

# Vor dem Bereinigen von Docker-/WSL2-VHDX-Dateien WSL stoppen (verhindert Sharing-Locks):
wsl --shutdown
ntfs-unthrottle "$env:LOCALAPPDATA\Docker\wsl\data" --recommended --fix
```

### 4. System-Pflege mit CompactGUI und CompactOS

```powershell
# Prüfen, wie viel Speicherplatz durch WOF/CompactGUI belegt ist:
ntfs-unthrottle "C:\Program Files\MeinProgramm"

# Durch CompactGUI komprimierten Anwendungsordner vollständig entpacken (als Admin):
ntfs-unthrottle "C:\Program Files\MeinProgramm" --all --min-size 0 --fix
```

> **Hinweis zu CompactOS:** `C:\Windows` bleibt aus Sicherheitsgründen immer tabu.
> Den systemweiten CompactOS-Status steuerst du über Windows-Bordmittel:
> `compact.exe /CompactOS:query` bzw. `compact.exe /CompactOS:never`.

---

## Volume-Diagnose und Tuning

`--optimize` scannt keine Einzeldateien, sondern prüft für die Volumes der angegebenen
Pfade, was Datei-I/O unabhängig von der Komprimierung bremst:

| Prüfung | Automatische Korrektur (`--fix`, als Administrator) |
|---|---|
| Datenträger: NVMe/SATA/USB, SSD/HDD, TRIM, QLC-Modelle | – (Hinweis) |
| Freier Platz < 10 % | – (Hinweis) |
| MFT-Größe, Datensätze, Fragmente, MFT-Zone | `fsutil behavior set mftzone 2` bei ≥ 2 Mio. Datensätzen |
| 8.3-Kurznamen pro Volume | `fsutil 8dot3name set E: 1` (nie auf dem Systemlaufwerk) |
| Last-Access-Zeitstempel | `fsutil behavior set disablelastaccess 1` |
| TRIM bei NTFS-SSDs | `fsutil behavior set DisableDeleteNotify NTFS 0` |
| TRIM bei ReFS-SSDs (Dev Drive) | `fsutil behavior set DisableDeleteNotify ReFS 0` |
| ReFS Dev-Drive-Status (Vertrauenswürdigkeit) | – (Hinweis auf `fsutil devdrv trust` / `query`) |
| BypassIO (Windows 11, NTFS): aktiv / partiell / blockiert durch `<treiber.sys>` | – (Hinweis auf `fsutil bypassIo state /v E:\` und `fltmc filters`) |
| Windows Search Indexer (`WSearch` / Root-Attribut) | – (sanfter Hinweis auf Datenlaufwerken) |
| Dirty-Bit | – (Hinweis auf `chkdsk E: /scan`) |

Die BypassIO-Zeile nutzt `FSCTL_MANAGE_BYPASS_IO` (`FS_BPIO_OP_QUERY`, ohne
Administratorrechte) und unterscheidet zwischen Filter-Stack (Minifilter wie `wof.sys`
oder Virenscanner → `⚠ blockiert`) und Volume-/Speicher-Stack (z. B. `fvevol.sys` bei
BitLocker, SATA-/RST-/VMD-Treiber → `partiell`). Den ReFS-TRIM-Status liest das Tool aus
`RefsDisableDeleteNotification` in der Registry oder per Fallback aus
`fsutil behavior query DisableDeleteNotify ReFS` (nur bei ReFS auf einer SSD).

Bewusst **nicht** automatisch: `8dot3name strip` (kann Programme mit Registry-Kurznamen
brechen), Defender-Ausnahmen, Defragmentierung, `chkdsk` und das Entladen von
Minifiltern (`fltmc unload`). Alle Korrekturen laufen transparent über `fsutil`.

```powershell
ntfs-unthrottle E:\ --optimize          # prüfen (ohne Admin eingeschränkt)
ntfs-unthrottle E:\ --optimize --fix    # anwenden (Terminal als Administrator)
```

---

## Befehlsreferenz

| Option | Standard | Bedeutung |
|---|---|---|
| `<PFADE>...` | `.` | Zu prüfende Ordner oder Dateien (überlappende Pfade werden zusammengefasst) |
| `-f, --fix` | *aus* | Änderungen tatsächlich anwenden (ohne: reine Analyse / Dry-Run) |
| `-y, --yes` | *aus* | Keine Sicherheitsabfrage (nur zusammen mit `--fix`) |
| `--recommended` | *aus* | Empfohlene Auswahl (Alias `--recommend`); nicht mit `--all` kombinierbar |
| `--all` | *aus* | Jede komprimierte Datei ab `--min-size` erfassen (Endung/Quote egal) |
| `--only <GRUND>` | *leer* | Auswahl auf `extension`, `low-savings`, `write-heavy`, `build`, `ds`, `all` beschränken (aktiviert Erkennung automatisch; mehrfach/kommagetrennt) |
| `--min-size <MiB>` | `16` | Mindestgröße für Dateien in MiB |
| `--threshold <PROZENT>` | `90` | Ab dieser physischen Quote (`physisch / logisch`) gilt Komprimierung als nutzlos |
| `--keep-dir-flags` | *aus* | Komprimierungsflag von Ordnern nicht entfernen |
| `--clear-dirs` | *aus* | Auch unter `--only` alle gefundenen Ordner-Flags bereinigen (schließt `--keep-dir-flags` aus) |
| `--no-wof` | *aus* | WOF-/CompactOS-Erkennung überspringen (spart ein Öffnen pro großer Datei) |
| `--no-fragments` | *aus* | Fragmentanzahl nicht ermitteln |
| `--json` | *aus* | Maschinenlesbares JSON auf stdout (`--fix --json` erfordert `--yes`) |
| `--optimize` | *aus* | Volume- und Hardware-Diagnose statt Dateiscan |
| `-v, --verbose` | *aus* | Alle Kandidaten, Ordner und Fehler im Detail auflisten |
| `-x, --exclude <NAME\|PFAD>` | *leer* | Name (greift in jeder Tiefe) oder Pfad (Präfix) ausschließen; mehrfach angebbar |
| `--lang <auto\|en\|de>` | `auto` | Sprache der Laufzeitausgaben (`--help` ist immer Englisch) |

**Exit-Codes:** `0` nichts zu tun / alles behoben · `1` Fehler · `2` Dry-Run hat
Kandidaten gefunden · `3` einzelne Elemente schlugen fehl · `130` durch Benutzer abgebrochen (`Strg+C`).

**Ausgabesprache:** Mit `--lang auto` gilt zuerst `LC_ALL`, `LC_MESSAGES` bzw. `LANG`
(ignoriert, wenn leer oder `C`/`POSIX`), sonst die Windows-Anzeigesprache. Deutsches
Windows → deutsche Ausgabe, alles andere → Englisch. Die Sicherheitsabfrage akzeptiert auf
Deutsch `j`/`ja`/`y`/`yes`, auf Englisch `y`/`yes`. Eine weitere Sprache ergänzen? Siehe
[CONTRIBUTING.md](CONTRIBUTING.md#adding-a-new-language-i18n) (englisch).

Für Dateien unter `C:\Program Files` o. Ä. das Terminal als Administrator starten.
Gesperrte Dateien (geöffnet in anderen Programmen, vom Virenscanner gehalten) werden
gemeldet und übersprungen.

---

## Schutzmechanismen (Poka-Yoke)

Diese Pfade werden nie betreten oder verändert. Der Schutz ist **nicht abschaltbar**
und greift auch bei direkter Angabe (`ntfs-unthrottle E:\$RECYCLE.BIN`,
`ntfs-unthrottle E:\pagefile.sys`) oder Unterpfaden – der Pfad wird mit `⛔`
übersprungen, alle anderen Pfade laufen normal weiter:

- **Überall geschützt:** `$RECYCLE.BIN`, `System Volume Information`, `Config.Msi`,
  `WindowsApps`, `WpSystem`, `WUDownloadCache`, `$WinREAgent`, `$Windows.~BT`,
  `$Windows.~WS`, `$SysReset`, `$GetCurrent`, `MSOCache`
- **In der Laufwerkswurzel geschützt:** `Windows`, `Recovery`, `Boot`, `EFI`, `bootmgr`,
  `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`, `DumpStack.log(.tmp)`, `bootTel.dat`
- **Auffangnetz:** Jedes Element in der Laufwerkswurzel mit `HIDDEN | SYSTEM`
- **Freier-Platz-Check:** Prüft je Volume den Mehrbedarf (`logisch − physisch`) plus
  Sicherheitspuffer (`max(256 MiB, 1 %)`)
- **Cloud-, Sparse- & Link-Schutz:** Cloud-Platzhalter (OneDrive & Co.), Sparse-Dateien
  (`SPARSE_FILE`, damit Nullbereiche nicht unerwartet materialisiert werden) sowie Reparse-Points
  (Junctions, Symlinks, Dedup) werden übersprungen; offene Ordner-Handles werden zusätzlich geprüft

---

## Als Rust-Bibliothek verwenden

Wer eigene Entpacker oder Konverter in Rust schreibt, kann die NTFS-Komprimierung beim
Anlegen der Zieldatei direkt abschalten – solange sie 0 Byte groß ist, kostet das `< 1 ms`.
Mit abgeschalteten Default-Features wird statt der CLI-Abhängigkeiten nur `windows-sys`
eingebunden:

```toml
# Cargo.toml
[dependencies]
ntfs-unthrottle = { git = "https://github.com/mohrpw/ntfs-unthrottle.git", default-features = false }
```

| Feature | Standard | Inhalt |
|---|---|---|
| `cli` | ja | Das Programm `ntfs-unthrottle` (`clap`, `console`, `humansize`, `indicatif`, `serde_json`, `walkdir`); aktiviert `tune` |
| `tune` | über `cli` | `ntfs_unthrottle::tune` – Volume-/Laufwerksdiagnose (TRIM, BypassIO, Dev Drive, MFT, 8.3-Namen, Indexer) |

```rust
use std::fs::OpenOptions;
use std::io::Write;
use ntfs_unthrottle::UncompressedOpenOptions;

fn main() -> std::io::Result<()> {
    ntfs_unthrottle::create_dir_all_uncompressed("D:/out/romfs")?;
    let mut out = ntfs_unthrottle::create_uncompressed_with_size("D:/out/romfs/archive.bin", data.len() as u64)?;
    out.write_all(&data)?;

    // Oder mit eigenem OpenOptions-Setup (z. B. create_new, FILE_FLAG_SEQUENTIAL_SCAN):
    let _f = OpenOptions::new().read(true).write(true).create_new(true).open_uncompressed("D:/out/romfs/new.bin")?;
    Ok(())
}
```

- `create_uncompressed(path)` / `create_uncompressed_with_size(path, size)` – legt eine Datei an
  (bzw. kürzt sie), schaltet die Komprimierung **nur dann** ab, wenn sie `FILE_ATTRIBUTE_COMPRESSED`
  geerbt hat (in normalen Ordnern fällt kein IOCTL an) und reserviert bei `_with_size` die Zielgröße
  am Stück (`FileAllocationInfo`), um Fragmentierung unter NTFS/ReFS zu vermeiden. Beide Schutzmaßnahmen
  sind **best-effort**: lehnt ein Dateisystem oder Filtertreiber ab (z. B. FAT32/exFAT/SMB-Quota),
  wird die Datei trotzdem zurückgegeben; gemeldet werden nur Fehler beim Öffnen/Anlegen.
- `UncompressedOpenOptions` (`open_uncompressed(path)` / `open_uncompressed_with_size(path, size)`) –
  Extension-Trait für `std::fs::OpenOptions` (z. B. für `create_new(true)` oder eigene Windows-Flags)
  mit demselben Best-Effort-Schutz gegen Komprimierung und Fragmentierung.
- `preallocate(&file, size)` – explizite/strikte Vorallokation über `SetFileInformationByHandle`
  (`FileAllocationInfo`; meldet Fehler, benötigt Schreibzugriff und behandelt `size == 0` sowie
  Dateien, die bereits `>= size` groß sind, als No-op).
- `create_dir_all_uncompressed(path)` – wie `std::fs::create_dir_all`, löscht aber das
  Komprimierungs-Flag auf jedem neu angelegten Ordner und auf dem Zielordner selbst
  (bestehende Ordner darüber und Reparse-Points bleiben unverändert). Ebenfalls best-effort.
- `clear_dir_compression(dir)` – löscht das Komprimierungs-Flag eines Ordners, falls gesetzt.
- `compression_kind(path)` – `None`, `Some(Lznt1)` oder `Some(Wof(..))`, z. B. für einen
  Hinweis vorab, dass eine Eingabedatei komprimiert auf der Platte liegt.
- Für bereits offene Dateien meldet `disable_compression(&file)` Fehler – das Handle braucht
  dafür Lese- **und** Schreibzugriff (`File::create` allein reicht nicht). Auf FAT/exFAT/ReFS
  ist es ein No-op.

Auf anderen Plattformen als Windows kompilieren die obigen Funktionen als günstige No-ops
(`File::create`, `std::fs::create_dir_all`, `Ok(None)` …) – Aufrufer brauchen keine eigenen
`cfg`-Weichen. Die übrige API und das CLI gibt es nur unter Windows.

---

## Technischer Hintergrund

- **LZNT1 arbeitet in Compression Units** von 16 Clustern (`64 KiB` bei `4-KiB`-Clustern).
  Lässt sich eine CU nicht um mindestens einen Cluster verkleinern, speichert NTFS sie
  *unkomprimiert*. Hoch-Entropie-Daten belegen deshalb ~100 % – beim **Lesen** fällt
  kaum Dekompression an, beim **Schreiben** wird aber jede CU erst vergeblich
  komprimiert.
- **Fragmentierung** entsteht vor allem bei teilweise komprimierbaren Daten und beim
  Überschreiben/Anhängen. Extrem fragmentierte, große komprimierte Dateien können
  `ERROR_FILE_SYSTEM_LIMITATION` (665) auslösen (z. B. bei `.vhdx` oder Datenbanken).
  Frisch sequenziell geschriebene, unkomprimierbare Dateien bleiben dagegen oft in einem
  Stück (im Test: 1 Fragment bei `48 MiB` Zufallsdaten).
- **Vererbung** gilt nur vom *direkten* Elternordner zum Zeitpunkt des Anlegens.
  Bestehende Dateien ändern sich nicht, wenn man das Ordnerflag entfernt – daher
  bereinigt `ntfs-unthrottle` beides.
- **WOF** speichert Daten komprimiert im Stream `::WofCompressedData`, ohne das Attribut
  `COMPRESSED` zu setzen. Schreibt ein Programm in eine WOF-Datei, entpackt Windows sie
  automatisch. `compact /exe` überspringt unkomprimierbare Dateien selbst – WOF ist für
  Hoch-Entropie-Daten also selten das Problem, für Build-Ordner und DirectStorage-Spiele
  auf NVMe jedoch durchaus.
- `FSCTL_SET_COMPRESSION` mit `COMPRESSION_FORMAT_NONE` blockiert, bis die Datei
  vollständig unkomprimiert neu geschrieben ist. Es braucht dafür nur die Differenz
  `logisch − physisch` an freiem Platz. Auf SSDs steigt der Lesedurchsatz sofort wieder
  auf volle Geschwindigkeit, obwohl physische Extents dabei nicht in-place zusammengelegt
  werden (auf mechanischen HDDs kann bei extrem fragmentierten Dateien anschließend ein
  `defrag` sinnvoll sein).

## Mitwirken

Beiträge sind willkommen – Projektaufbau, Schutzregeln, i18n-Ablauf und Commit-Konventionen
stehen in [CONTRIBUTING.md](CONTRIBUTING.md) (englisch).

## Lizenz

Dual-lizenziert unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE).

