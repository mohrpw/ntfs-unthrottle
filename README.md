# ntfs-unthrottle

Viele Windows-Laufwerke oder Ordner nutzen unbemerkt transparente Komprimierung –
entweder klassisch per NTFS (LZNT1, blaue Doppelpfeile im Explorer) oder per
**Windows Overlay Filter (WOF / CompactOS)**, der *gar kein* sichtbares Attribut setzt.
Bei großen, bereits gepackten oder verschlüsselten Dateien (`.xci`, `.nsp`, `.nca`,
Archive, Videos, Images) spart das praktisch keinen Platz, kostet aber CPU beim
Schreiben und bremst Entpack-/Kopiervorgänge aus – ohne Fehlermeldung.

`ntfs-unthrottle` spürt solche kontraproduktiven Komprimierungen auf und entfernt sie
direkt über die Win32-API (`DeviceIoControl`), ohne `compact.exe`.

## Was das Tool macht

1. **Scan** – durchläuft den Verzeichnisbaum (Metadaten aus `FindNextFile`, kein
   zusätzlicher Syscall pro Datei) und findet
   - Ordner mit Komprimierungsflag (neue Dateien darin erben es),
   - LZNT1-komprimierte Dateien,
   - WOF-komprimierte Dateien (`FSCTL_GET_EXTERNAL_BACKING`; XPRESS4K/8K/16K, LZX).
2. **Bewertung** – misst die echte Belegung (`GetCompressedFileSizeW`) und die
   physische Fragmentierung (`FSCTL_GET_RETRIEVAL_POINTERS`). Eine Datei wird nur
   angefasst, wenn
   - sie physisch ≥ `--threshold` % (Standard 90 %) ihrer logischen Größe belegt, **oder**
   - sie LZNT1-komprimiert ist und eine Hoch-Entropie-Endung hat, **oder**
   - `--all` gesetzt ist.

   Sinnvoll komprimierte Dateien (Logs, Quelltext, …) bleiben unangetastet.
   WOF-Dateien werden nur über die Quote ausgewählt, weil WOF für lese-lastige
   Daten (Spiele) oft gewollt und schnell ist.
3. **Sicherheitschecks** – freier Platz *je Volume* (+ 256 MiB bzw. 1 % Puffer),
   Rückfrage vor Änderungen, Cloud-Platzhalter (OneDrive) und Reparse-Points
   (Junctions, Dedup) werden übersprungen.
4. **Bereinigung** – zuerst die Ordner-Flags (stoppt die Vererbung sofort), dann die
   Dateien sequenziell. Schreibschutz wird temporär entfernt und per RAII-Guard
   garantiert wiederhergestellt; Zeitstempel bleiben erhalten.

Zusätzlich warnt das Tool, wenn **übergeordnete** Ordner des Scan-Pfads das Flag tragen.

## Verwendung

```powershell
# Analyse (Dry-Run, ändert nichts)
ntfs-unthrottle D:\Games\Switch

# Bereinigen mit Rückfrage
ntfs-unthrottle D:\Games\Switch --fix

# Skript/Scheduled Task: alles ab 50 MiB, ohne Rückfrage
ntfs-unthrottle E:\Workspace F:\ISOs --fix --yes --min-size 50

# Jede komprimierte Datei (auch kleine, auch gut komprimierte) entpacken
ntfs-unthrottle C:\code --all --min-size 0 --fix
```

| Option | Bedeutung |
|---|---|
| `-f, --fix` | Änderungen anwenden (sonst nur Analyse) |
| `-y, --yes` | Keine Rückfrage (nur mit `--fix`) |
| `--min-size <MiB>` | Mindestgröße für Dateien (Standard 16) |
| `--threshold <%>` | Ab dieser physischen Quote gilt Komprimierung als nutzlos (Standard 90) |
| `--all` | Jede komprimierte Datei ab Mindestgröße erfassen |
| `--optimize` | Optimierer: Volume-Einstellungen prüfen (mit `--fix` anwenden), scannt keine Dateien |
| `--recommended` | Empfohlene Auswahl (siehe unten), Alias `--recommend`; nicht mit `--all` kombinierbar |
| `--keep-dir-flags` | Ordner-Flags nicht entfernen |
| `--no-wof` | WOF-Erkennung überspringen (spart ein Öffnen pro großer Datei) |
| `--no-fragments` | Fragmentanzahl nicht ermitteln |
| `-v, --verbose` | Alle Kandidaten, Ordner und Fehler auflisten |
| `-x, --exclude <NAME\|PFAD>` | Zusätzlich ausschließen – Name greift in jeder Tiefe, Pfad als Präfix; mehrfach angebbar |

### `--recommended` – die empfohlene Auswahl

Wie der Standard (nutzlose Komprimierung wird entfernt, sinnvolle bleibt), zusätzlich
werden **unabhängig von Größe und Quote** immer entpackt:

- **Schreiblastige Formate** (Grund `Schreiblast`): VM-Images (`.vhdx`, `.vmdk`, `.vdi`,
  `.qcow2`, …), Datenbanken (`.db`, `.sqlite`, `.mdf`, `.ldf`, `.pst`, `.ost`, …) und
  unfertige Downloads (`.part`, `.crdownload`, `.!qb`, …). Komprimierung zerstückelt
  solche Dateien stark.
- **Alles in Build-/Tooling-Ordnern** (Grund `Build-Ordner`): `node_modules`, `.git`,
  `.vs`, `__pycache__`, `.venv`/`venv`, `.gradle`, `.next`, `.cargo`, `.nuget`, `.m2`, … –
  viele kleine, ständig neu geschriebene Dateien. Die generischen Namen `build`, `dist`,
  `target` und `obj` zählen nur, wenn der Ordner daneben ein Projekt-Marker liegt
  (`package.json`, `Cargo.toml`, `pyproject.toml`, `CMakeLists.txt`, `Makefile`, `.git`,
  `*.sln` bzw. für `target` `Cargo.toml`/`pom.xml`, für `obj` `*.csproj`/`*.vcxproj`) –
  `D:\Games\Titel\dist` bleibt also unangetastet. Ordner oberhalb des Scan-Pfads zählen
  nicht. Unter `--min-size` wird dort nur klassische NTFS-Komprimierung (LZNT1) erfasst.
- **WOF in DirectStorage-Spielen auf NVMe** (Grund `DirectStorage`): Liegt im Spielordner
  `dstorage.dll`/`dstoragecore.dll` und ist das Volume eine NVMe-SSD, werden die WOF-Dateien
  des Spiels entpackt – WOF verhindert dort den BypassIO-Pfad (Windows 11) und bremst die
  Dekompression. Ohne `--recommended` gibt es dafür nur einen Hinweis.

Archive, Videos, Backups und andere gut komprimierte, selten geschriebene Daten
behalten ihre Platzersparnis.

### Speichermedium und DirectStorage

Pro Scan-Pfad zeigt der Scan den Datenträger (`NVMe-SSD`, `SATA-SSD`, `HDD`, …).

- **HDD / SATA-SSD:** WOF (vor allem XPRESS4K/8K) kann Ladezeiten sogar verkürzen, weil
  weniger Daten gelesen werden. Keine Meldung.
- **NVMe-SSD:** Die Dekompression kann langsamer sein als die Rohleserate. Bleiben auf einem
  NVMe-Volume mehr als 1 GiB in `LZX`/`XPRESS16K`, nennt ein `ℹ`-Hinweis die größten Ordner –
  entpackt wird nichts.
- **DirectStorage:** Erkannt über die mitgelieferten DLLs. Der Spielordner wird aus dem
  DLL-Pfad abgeleitet (Steam/Xbox/Epic/GOG/EA/Ubisoft-Bibliotheken, Unreal- und
  Unity-Layouts), sodass bei `E:\Games` nur das betroffene Spiel zählt. Gilt nur auf NVMe;
  ohne `--recommended` erscheint eine `⚠`-Meldung, mit `--recommended` werden die Dateien
  entpackt.

Grenzen: WOF-Dateien unter `--min-size` bleiben außen vor (sonst müsste jede kleine Datei
geöffnet werden). Mit `--no-wof` oder wenn der DLL-Ordner per `-x` ausgeschlossen ist, greift
die Erkennung nicht. Überlappende Scan-Pfade (`E:\Games E:\Games\Spiel`) werden
zusammengefasst und nur einmal gescannt. Hardlinks (z. B. Mod-Manager-Staging ↔ Spielordner)
werden nur einmal erfasst und als `Hardlink-Duplikate übersprungen` gezählt. Auf exFAT/FAT/ReFS
entfällt die WOF-Prüfung (WOF gibt es nur auf NTFS).

```powershell
ntfs-unthrottle E:\ --recommended          # ansehen
ntfs-unthrottle E:\ --recommended --fix    # anwenden
```

### `--optimize` – Volume- und NTFS-Einstellungen

Prüft für die Volumes der angegebenen Pfade, was Datei-I/O unabhängig von der
Komprimierung bremst:

| Prüfung | Automatische Korrektur (`--fix`, als Administrator) |
|---|---|
| Datenträger: NVMe/SATA/USB, SSD/HDD, TRIM, QLC-Modelle | – (Hinweis) |
| Freier Platz < 10 % | – (Hinweis) |
| MFT-Größe, Datensätze, Fragmente, MFT-Zone | `fsutil behavior set mftzone 2` bei ≥ 2 Mio. Datensätzen |
| 8.3-Kurznamen pro Volume | `fsutil 8dot3name set E: 1` (nie auf dem Systemlaufwerk) |
| Last-Access-Zeitstempel | `fsutil behavior set disablelastaccess 1` |
| TRIM bei SSDs | `fsutil behavior set DisableDeleteNotify NTFS 0` |
| Dirty-Bit | – (Hinweis auf `chkdsk E: /scan`) |

Bewusst **nicht** automatisch: `8dot3name strip` (kann Programme brechen, die
Kurznamen in der Registry gespeichert haben), Defender-Ausnahmen, Defragmentierung
und chkdsk. Alle Korrekturen laufen sichtbar über `fsutil` und lassen sich damit auch
wieder zurücksetzen.

```powershell
ntfs-unthrottle E:\ --optimize          # prüfen (ohne Admin eingeschränkt)
ntfs-unthrottle E:\ --optimize --fix    # anwenden (Terminal als Administrator)
```

### Geschützte Systempfade (Poka-Yoke)

Diese Pfade werden nie betreten oder verändert. Der Schutz ist **nicht abschaltbar**
und greift auch, wenn man sie direkt angibt (`ntfs-unthrottle E:\$RECYCLE.BIN`,
`ntfs-unthrottle E:\pagefile.sys`) oder einen Pfad darunter – der Pfad wird dann mit
⛔ übersprungen, alle anderen angegebenen Pfade laufen normal weiter:

- **überall:** `$RECYCLE.BIN`, `System Volume Information`, `Config.Msi`, `WindowsApps`,
  `WpSystem`, `WUDownloadCache`, `$WinREAgent`, `$Windows.~BT`, `$Windows.~WS`,
  `$SysReset`, `$GetCurrent`, `MSOCache`
- **nur in der Laufwerkswurzel:** `Windows`, `Recovery`, `Boot`, `EFI`, `bootmgr`,
  `pagefile.sys`, `swapfile.sys`, `hiberfil.sys`, `DumpStack.log(.tmp)`, `bootTel.dat`
- **Auffangnetz:** alles in der Laufwerkswurzel, das gleichzeitig *versteckt* und
  *System* ist – deckt auch künftige/unbekannte Windows-Dateien ab

Reparse-Points (Junctions, Symlinks, Dedup) und Cloud-Platzhalter werden ohnehin
übersprungen. Ein ganzes Datenlaufwerk entpacken:

```powershell
ntfs-unthrottle E:\ --all --min-size 0              # erst ansehen
ntfs-unthrottle E:\ --all --min-size 0 --fix        # dann entpacken
```

**Exit-Codes:** `0` nichts zu tun / alles behoben · `1` Fehler · `2` Dry-Run hat
Kandidaten gefunden · `3` einzelne Elemente schlugen fehl.

Für Dateien unter `C:\Program Files` o. Ä. das Terminal als Administrator starten.
Gesperrte Dateien (geöffnet in anderen Programmen, vom Virenscanner gehalten) werden
gemeldet und übersprungen.

## Als Bibliothek in eigenen Tools

Wer selbst Entpacker/Konverter schreibt, kann die Komprimierung beim Anlegen der
Zieldatei abschalten – solange sie 0 Byte groß ist, kostet das < 1 ms:

```rust
use std::io::Write;

let mut out = ntfs_unthrottle::create_uncompressed("D:/out/game.xci".as_ref())?;
out.write_all(&data)?;
```

Für bereits offene Dateien: `ntfs_unthrottle::disable_compression(&file)` – das
Handle braucht dafür Lese- **und** Schreibzugriff (`File::create` allein reicht nicht).
Auf FAT/exFAT/ReFS sind beide Funktionen ein No-op.

## Bauen

```powershell
cargo build --release
# → target\release\ntfs-unthrottle.exe (~0,7 MB, LTO, gestrippt)
```

Das Release-Profil nutzt `lto = "fat"`, `codegen-units = 1`, `panic = "abort"` und
`strip = true`.

> **Tipp:** Liegt der Projektordner selbst auf einem komprimierten Pfad, wird auch
> Cargos `target\`-Verzeichnis komprimiert – das bremst jeden Build.
> `ntfs-unthrottle . --all --min-size 0 --fix` behebt das.

## Technischer Hintergrund – was stimmt, was ist übertrieben

- **LZNT1 arbeitet in Compression Units** von 16 Clustern (64 KiB bei 4-KiB-Clustern).
  Lässt sich eine CU nicht um mindestens einen Cluster verkleinern, speichert NTFS sie
  *unkomprimiert*. Hoch-Entropie-Daten belegen deshalb ~100 % – beim **Lesen** fällt
  dann kaum Dekompression an, beim **Schreiben** wird aber jede CU erst vergeblich
  komprimiert.
- **Fragmentierung** entsteht vor allem bei teilweise komprimierbaren Daten und beim
  Überschreiben/Anhängen. Extrem fragmentierte, große komprimierte Dateien können
  `ERROR_FILE_SYSTEM_LIMITATION` (665) auslösen – ein bekanntes Problem z. B. bei
  VHDX- oder Datenbankdateien. Frisch sequenziell geschriebene, unkomprimierbare
  Dateien bleiben dagegen oft in einem Stück (im Test: 1 Fragment bei 48 MiB Zufall).
- **Vererbung** gilt nur vom *direkten* Elternordner zum Zeitpunkt des Anlegens.
  Bestehende Dateien ändern sich nicht, wenn man das Ordnerflag entfernt – daher
  bereinigt das Tool beides.
- **WOF** ist ein anderer Mechanismus: Die Daten liegen komprimiert im Stream
  `::WofCompressedData`, das Attribut `COMPRESSED` fehlt. Schreibt ein Programm in
  eine WOF-Datei, entpackt Windows sie automatisch. `compact /exe` überspringt
  unkomprimierbare Dateien von selbst – WOF ist für Hoch-Entropie-Daten also selten
  das Problem, für Build-Ordner mit vielen Schreibzugriffen aber durchaus.
- `FSCTL_SET_COMPRESSION` mit `COMPRESSION_FORMAT_NONE` blockiert, bis die Datei
  vollständig unkomprimiert neu geschrieben ist. Es braucht dafür nur die Differenz
  `logisch − physisch` an freiem Platz.

## Lizenz

MIT OR Apache-2.0
