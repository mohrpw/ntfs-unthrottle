//! File extension lists used for decompression heuristics (`HIGH_ENTROPY_EXTS`,
//! `WRITE_HEAVY_EXTS`) and selective WOF compression exclusions (`COMPACT_SKIP_EXTS`).

use std::path::Path;

/// Known high-entropy formats (already compressed or encrypted).
pub(crate) const HIGH_ENTROPY_EXTS: &[&str] = &[
    // Compressed / encrypted binary containers
    "xci", "xcz", "nsp", "nsz", "nca", "ncz",
    // Archives & compressed streams
    "zip", "7z", "rar", "zst", "gz", "xz", "bz2", "lz4", "cab", "msi",
    "dl_", "xap", "lzx", "tgz", "lz", "txz", "br", "lzma", "tbz2", "tbz",
    "tlz", "tzst", "z", "ace", "arj", "lha", "lzh", "deb", "rpm", "esd", "msu",
    // App & language ZIP packages / e-books
    "jar", "war", "ear", "apk", "aab", "apks", "xapk", "ipa", "whl", "nupkg",
    "vsix", "crx", "xpi", "appx", "msix", "appxbundle", "msixbundle",
    "epub", "cbz", "cbr",
    // Office (OpenXML / OpenDocument = ZIP) & gzipped metafiles
    "docx", "docm", "dotx", "xlsx", "xlsm", "xltx", "pptx", "pptm", "potx",
    "vsdx", "vssx", "vstx", "onepkg", "odt", "ods", "odp", "odg", "odf",
    "wmz", "emz",
    // Video
    "mp4", "mkv", "webm", "mov", "avi", "wmv", "bik", "bk2", "flv", "mpg",
    "mpeg", "m2v", "m4v", "vob", "ogv", "m2ts", "mts", "3gp", "3g2", "rmvb",
    "rm", "asf", "f4v", "divx",
    // Audio
    "mp3", "flac", "ogg", "opus", "aac", "wma", "m4a", "m4b", "m4p", "oga",
    "spx", "wv", "ape", "alac", "ac3", "dts", "amr",
    // Images
    "jpg", "jpeg", "png", "webp", "heic", "gif", "avif", "jxl", "heif", "hif",
    "apng", "jp2", "j2k", "svgz",
    // Compressed web fonts
    "woff", "woff2",
    // Disk images & game asset containers
    "iso", "dmg", "chd", "rvz", "wbfs", "cso", "pak", "ucas", "utoc", "bundle", "vpk",
    // Encrypted containers
    "hc", "tc", "vc", "kdbx", "gpg", "pgp",
];

/// `--recommended`: formats with many (random) writes. Compression fragments
/// them heavily (up to `ERROR_FILE_SYSTEM_LIMITATION`) – always decompress.
pub(crate) const WRITE_HEAVY_EXTS: &[&str] = &[
    // VM images & snapshots
    "vhd", "vhdx", "avhdx", "vmdk", "vdi", "qcow2", "vmem", "vmsn", "vmss", "nvram",
    // Databases
    "db", "db-wal", "db-shm", "sqlite", "sqlite3", "mdf", "ldf", "ndf", "edb", "ibd",
    "mdb", "accdb", "ldb", "pst", "ost",
    // Incomplete downloads (written block by block in random order)
    "part", "partial", "crdownload", "!qb", "!ut", "aria2",
];

/// Boot/early-load driver extensions that must never be WOF-compressed, even outside `C:\Windows`.
pub(crate) const COMPACT_SKIP_EXTS: &[&str] = &["sys", "efi"];

/// Case-insensitive check whether `path`'s extension is in `list` (expects lowercase ASCII entries).
pub(crate) fn has_ext(path: &Path, list: &[&str]) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| list.iter().any(|x| e.eq_ignore_ascii_case(x)))
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::Path;

    use super::{has_ext, COMPACT_SKIP_EXTS, HIGH_ENTROPY_EXTS, WRITE_HEAVY_EXTS};

    #[test]
    fn ext_lists_are_normalized_disjoint_and_selective() {
        let mut seen = HashSet::new();
        for (group, list) in [
            ("HIGH_ENTROPY_EXTS", HIGH_ENTROPY_EXTS),
            ("WRITE_HEAVY_EXTS", WRITE_HEAVY_EXTS),
            ("COMPACT_SKIP_EXTS", COMPACT_SKIP_EXTS),
        ] {
            let mut local = HashSet::new();
            for ext in list {
                assert!(!ext.is_empty() && !ext.starts_with('.'), "invalid ext in {group}: {ext}");
                assert!(ext.is_ascii(), "ext must be ASCII in {group}: {ext}");
                assert_eq!(*ext, ext.to_ascii_lowercase(), "ext must be lowercase in {group}: {ext}");
                assert!(local.insert(*ext), "duplicate ext in {group}: {ext}");
                assert!(seen.insert(*ext), "overlapping ext across lists ({group}): {ext}");
            }
        }

        // Newly added pre-compressed formats
        assert!(has_ext(Path::new(r"E:\Games\intro.BK2"), HIGH_ENTROPY_EXTS));
        assert!(has_ext(Path::new(r"C:\Docs\report.docx"), HIGH_ENTROPY_EXTS));
        assert!(has_ext(Path::new(r"C:\Web\font.woff2"), HIGH_ENTROPY_EXTS));
        assert!(has_ext(Path::new(r"C:\Pics\photo.avif"), HIGH_ENTROPY_EXTS));
        assert!(has_ext(Path::new(r"C:\Apps\app.msix"), HIGH_ENTROPY_EXTS));

        // Uncompressed / ambiguous formats intentionally kept out
        assert!(!has_ext(Path::new(r"E:\Archive\src.tar"), HIGH_ENTROPY_EXTS));
        assert!(!has_ext(Path::new(r"E:\Clipart\vec.wmf"), HIGH_ENTROPY_EXTS));
        assert!(!has_ext(Path::new(r"E:\Audio\raw.wav"), HIGH_ENTROPY_EXTS));
        assert!(!has_ext(Path::new(r"E:\Images\raw.bmp"), HIGH_ENTROPY_EXTS));
        assert!(!has_ext(Path::new(r"E:\Code\index.ts"), HIGH_ENTROPY_EXTS));
    }
}

