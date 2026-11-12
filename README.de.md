# ntfs-unthrottle

**Sprache:** [English](README.md) | **Deutsch**

> Spürt kontraproduktive NTFS- und WOF-Komprimierung auf, entfernt E/A-Bremsen und
> prüft Windows-Volumes für Gaming-, Entpack- und Entwickler-Workloads – direkt über
> die Win32-API (`DeviceIoControl`), ohne `compact.exe`.

## Inhaltsverzeichnis

1. [Das Problem: Unsichtbare I/O-Bremsen unter Windows](#das-problem-unsichtbare-io-bremsen-unter-windows)
2. [Praxis-Benchmark (Entstehungsmessung, Stand v0.2.0)](#praxis-benchmark-entstehungsmessung-stand-v020)
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

## Praxis-Benchmark (Entstehungsmessung, Stand v0.2.0)

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

*(Referenzwert auf unkomprimierter NVMe-SSD `C:`: `22,43–31,09 s`. Ein aktualisierter
Benchmark für `v0.6.0` inkl. WOF/DirectStorage/BypassIO folgt.)*

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
| BypassIO (Windows 11, NTFS): aktiv / partiell / blockiert durch `<treiber.sys>` | – (Hinweis auf `fsutil bypassIo state /v E:\` und `fltmc filters`) |
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
| `--min-size <MiB>` | `16` | Mindestgröße für Dateien in MiB |
| `--threshold <PROZENT>` | `90` | Ab dieser physischen Quote (`physisch / logisch`) gilt Komprimierung als nutzlos |
| `--keep-dir-flags` | *aus* | Komprimierungsflag von Ordnern nicht entfernen |
| `--no-wof` | *aus* | WOF-/CompactOS-Erkennung überspringen (spart ein Öffnen pro großer Datei) |
| `--no-fragments` | *aus* | Fragmentanzahl nicht ermitteln |
| `--optimize` | *aus* | Volume- und Hardware-Diagnose statt Dateiscan |
| `-v, --verbose` | *aus* | Alle Kandidaten, Ordner und Fehler im Detail auflisten |
| `-x, --exclude <NAME\|PFAD>` | *leer* | Name (greift in jeder Tiefe) oder Pfad (Präfix) ausschließen; mehrfach angebbar |
| `--lang <auto\|en\|de>` | `auto` | Sprache der Laufzeitausgaben (`--help` ist immer Englisch) |

**Exit-Codes:** `0` nichts zu tun / alles behoben · `1` Fehler · `2` Dry-Run hat
Kandidaten gefunden · `3` einzelne Elemente schlugen fehl.

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
- **Cloud- & Link-Schutz:** Cloud-Platzhalter (OneDrive & Co.) sowie Reparse-Points
  (Junctions, Symlinks, Dedup) werden übersprungen

---

## Als Rust-Bibliothek verwenden

Wer eigene Entpacker oder Konverter in Rust schreibt, kann die NTFS-Komprimierung beim
Anlegen der Zieldatei direkt abschalten – solange sie 0 Byte groß ist, kostet das `< 1 ms`:

```toml
# Cargo.toml
[dependencies]
ntfs-unthrottle = { git = "https://github.com/mohrpw/ntfs-unthrottle.git" }
```

```rust
use std::io::Write;

fn main() -> std::io::Result<()> {
    let mut out = ntfs_unthrottle::create_uncompressed("D:/out/archive.bin".as_ref())?;
    out.write_all(&data)?;
    Ok(())
}
```

Für bereits offene Dateien: `ntfs_unthrottle::disable_compression(&file)` – das Handle
braucht dafür Lese- **und** Schreibzugriff (`File::create` allein reicht nicht). Auf
FAT/exFAT/ReFS sind beide Funktionen ein No-op.

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
  `logisch − physisch` an freiem Platz.

## Mitwirken

Beiträge sind willkommen – Projektaufbau, Schutzregeln, i18n-Ablauf und Commit-Konventionen
stehen in [CONTRIBUTING.md](CONTRIBUTING.md) (englisch).

## Lizenz

Dual-lizenziert unter [MIT](LICENSE-MIT) oder [Apache-2.0](LICENSE-APACHE).

