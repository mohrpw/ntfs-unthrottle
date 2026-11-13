//! Panic-free PE header/overlay inspector, in-memory `XPRESS_HUFF` probe
//! (`cabinet.dll`), and WOF cluster/header footprint math.

use std::cell::Cell;
use std::ffi::c_void;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::marker::PhantomData;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;
use std::ptr::null;

use ntfs_unthrottle::{file_attributes_of, CompressionKind, SystemDll, WofAlgorithm};
use windows_sys::Win32::Foundation::{GetLastError, ERROR_ACCESS_DENIED, FILETIME};
use windows_sys::Win32::Storage::FileSystem::{
    SetFileTime, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_SPARSE_FILE, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_WRITE_ATTRIBUTES,
};

/// Maximum section headers parsed in [`inspect_pe`].
pub const MAX_SECTIONS: usize = 128;
/// Initial header read size (covers almost all PE headers in 1 read).
const INITIAL_HEADER_READ: usize = 4096;
/// Upper bound for extended PE section-table reads.
const MAX_HEADER_READ: usize = 16384;
/// Minimum overlay excess over `pe_end` to classify as `LargeOverlay`.
const LARGE_OVERLAY_MIN_BYTES: u64 = 1024 * 1024;
/// Sample block size (`16 KiB`).
pub const PROBE_BLOCK_SIZE: usize = 16 * 1024;
/// Maximum number of blocks sampled per file.
const PROBE_MAX_BLOCKS: u64 = 8;

/// Known packer/protector section names (case-insensitive, NUL-trimmed).
const PACKER_SECTIONS: &[&str] = &[
    "upx0", "upx1", "upx2", ".vmp0", ".vmp1", ".vmp2", ".themida", ".winlice", ".enigma1",
    ".enigma2", ".aspack", ".adata", ".mpress1", ".mpress2",
];

/// Classification of a file's PE structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeProfile {
    NotPe,
    PackedStub,
    ExecutableCode {
        is_dotnet: bool,
    },
    LargeOverlay {
        overlay_offset: u64,
        payload_end: u64,
    },
}

fn read_u16_le(buf: &[u8], off: usize) -> Option<u16> {
    let end = off.checked_add(2)?;
    let bytes: [u8; 2] = buf.get(off..end)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn read_u32_le(buf: &[u8], off: usize) -> Option<u32> {
    let end = off.checked_add(4)?;
    let bytes: [u8; 4] = buf.get(off..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

struct PeOffsets {
    num_sections: usize,
    size_of_opt: usize,
    opt_off: usize,
    sec_off: usize,
    rva_count_off: usize,
    data_dir_off: usize,
}

fn parse_pe_offsets(header: &[u8]) -> Option<PeOffsets> {
    if header.len() < 0x40 || read_u16_le(header, 0)? != 0x5A4D {
        return None;
    }
    let pe_off = usize::try_from(read_u32_le(header, 0x3C)?).ok()?;
    if read_u32_le(header, pe_off)? != 0x0000_4550 {
        return None;
    }
    let num_sections = usize::from(read_u16_le(header, pe_off.checked_add(6)?)?);
    let size_of_opt = usize::from(read_u16_le(header, pe_off.checked_add(20)?)?);
    let opt_off = pe_off.checked_add(24)?;
    let magic = read_u16_le(header, opt_off)?;
    let (rva_rel, dd_rel) = match magic {
        0x010B => (92usize, 96usize),   // PE32
        0x020B => (108usize, 112usize), // PE32+
        _ => return None,
    };
    let sec_off = opt_off.checked_add(size_of_opt)?;
    let rva_count_off = opt_off.checked_add(rva_rel)?;
    let data_dir_off = opt_off.checked_add(dd_rel)?;
    Some(PeOffsets {
        num_sections,
        size_of_opt,
        opt_off,
        sec_off,
        rva_count_off,
        data_dir_off,
    })
}

/// Returns the required byte length to read the full PE section table, if known.
pub fn pe_section_table_end(header: &[u8]) -> Option<usize> {
    let off = parse_pe_offsets(header)?;
    if off.num_sections > MAX_SECTIONS {
        return None;
    }
    off.num_sections.checked_mul(40)?.checked_add(off.sec_off)
}

/// Panic-free PE header & overlay inspector operating strictly on `header` bytes.
pub fn inspect_pe(header: &[u8], file_size: u64) -> PeProfile {
    let Some(off) = parse_pe_offsets(header) else {
        return PeProfile::NotPe;
    };

    let num_rva = {
        let need_rva = off
            .rva_count_off
            .checked_sub(off.opt_off)
            .and_then(|d| d.checked_add(4));
        if need_rva.is_some_and(|n| off.size_of_opt >= n) {
            read_u32_le(header, off.rva_count_off).unwrap_or(0) as usize
        } else {
            0
        }
    };

    let data_dir_entry = |idx: usize| -> Option<(u32, u32)> {
        if num_rva <= idx {
            return None;
        }
        let rel_end = off
            .data_dir_off
            .checked_sub(off.opt_off)?
            .checked_add(idx.checked_add(1)?.checked_mul(8)?)?;
        if off.size_of_opt < rel_end {
            return None;
        }
        let entry_off = off.data_dir_off.checked_add(idx.checked_mul(8)?)?;
        let va = read_u32_le(header, entry_off)?;
        let sz = read_u32_le(header, entry_off.checked_add(4)?)?;
        Some((va, sz))
    };

    let is_dotnet = data_dir_entry(14).is_some_and(|(va, sz)| va != 0 && sz != 0);
    let cert_entry = data_dir_entry(4)
        .and_then(|(va, sz)| (va > 0 && sz > 0).then_some((u64::from(va), u64::from(sz))));

    let sec_end = off
        .num_sections
        .checked_mul(40)
        .and_then(|b| off.sec_off.checked_add(b));
    let truncated = off.num_sections > MAX_SECTIONS || sec_end.is_none_or(|e| e > header.len());

    let avail_sections = header.len().saturating_sub(off.sec_off) / 40;
    let iter_sections = off.num_sections.min(MAX_SECTIONS).min(avail_sections);

    let mut pe_end = 0u64;
    for i in 0..iter_sections {
        let Some(entry_off) = i.checked_mul(40).and_then(|b| off.sec_off.checked_add(b)) else {
            break;
        };
        let Some(name_bytes) = entry_off
            .checked_add(8)
            .and_then(|e| header.get(entry_off..e))
        else {
            break;
        };
        let nul = name_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(name_bytes.len());
        if let Some(trimmed) = name_bytes
            .get(..nul)
            .and_then(|s| std::str::from_utf8(s).ok())
        {
            if PACKER_SECTIONS
                .iter()
                .any(|p| trimmed.eq_ignore_ascii_case(p))
            {
                return PeProfile::PackedStub;
            }
        }
        let raw_size = u64::from(
            entry_off
                .checked_add(16)
                .and_then(|o| read_u32_le(header, o))
                .unwrap_or(0),
        );
        let raw_ptr = u64::from(
            entry_off
                .checked_add(20)
                .and_then(|o| read_u32_le(header, o))
                .unwrap_or(0),
        );
        if raw_size > 0 && raw_ptr > 0 {
            if let Some(end) = raw_ptr.checked_add(raw_size) {
                pe_end = pe_end.max(end);
            }
        }
    }

    // Never classify as LargeOverlay if the section table was truncated or invalid.
    if truncated || pe_end == 0 {
        return PeProfile::ExecutableCode { is_dotnet };
    }

    let payload_end = match cert_entry {
        Some((coff, csize)) if coff >= pe_end && coff.checked_add(csize) == Some(file_size) => coff,
        _ => file_size,
    };

    let overlay_len = payload_end.saturating_sub(pe_end);
    if overlay_len > LARGE_OVERLAY_MIN_BYTES && overlay_len >= pe_end {
        PeProfile::LargeOverlay {
            overlay_offset: pe_end,
            payload_end,
        }
    } else {
        PeProfile::ExecutableCode { is_dotnet }
    }
}

/// Computes up to 8 non-overlapping `(offset, len)` sample blocks within `[start .. end]`.
pub fn sample_offsets(sample_start: u64, sample_end: u64) -> Vec<(u64, usize)> {
    let block = PROBE_BLOCK_SIZE as u64;
    let len = sample_end.saturating_sub(sample_start);
    if len == 0 {
        return Vec::new();
    }
    if len <= block {
        return vec![(sample_start, len as usize)];
    }
    if len <= PROBE_MAX_BLOCKS * block {
        let mut out = Vec::new();
        let mut pos = sample_start;
        while pos < sample_end && (out.len() as u64) < PROBE_MAX_BLOCKS {
            let take = (sample_end - pos).min(block) as usize;
            if take >= 4096 || out.is_empty() {
                out.push((pos, take));
            }
            pos = pos.saturating_add(block);
        }
        return out;
    }
    let span = len - block;
    let step = span / (PROBE_MAX_BLOCKS - 1);
    (0..PROBE_MAX_BLOCKS)
        .map(|i| (sample_start + i * step, PROBE_BLOCK_SIZE))
        .collect()
}

/// Computes the median of block compression ratios (anti-padding metric).
pub fn median_ratio(ratios: &mut [f64]) -> Option<f64> {
    if ratios.is_empty() {
        return None;
    }
    ratios.sort_by(f64::total_cmp);
    let mid = ratios.len() / 2;
    if ratios.len() % 2 == 1 {
        ratios.get(mid).copied()
    } else {
        let a = ratios.get(mid.checked_sub(1)?)?;
        let b = ratios.get(mid)?;
        Some((a + b) * 0.5)
    }
}

/// Estimated WOF footprint including `::WofCompressedData` chunk-offset table overhead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FootprintEstimate {
    pub est_physical_bytes: u64,
    pub est_clusters: u64,
    pub logical_clusters: u64,
    pub header_bytes: u64,
}

/// Estimates compressed on-disk size and clusters for `algorithm` including WOF chunk-table overhead.
pub fn estimate_wof_footprint(
    logical: u64,
    est_payload_bytes: u64,
    algorithm: WofAlgorithm,
    cluster_size: u64,
) -> Option<FootprintEstimate> {
    let chunk_size = u64::from(algorithm.chunk_size()?);
    let cluster = cluster_size.max(512);
    let total_chunks = logical.div_ceil(chunk_size);
    let entry_size = if logical >= (1u64 << 32) { 8 } else { 4 };
    let header_bytes = total_chunks.saturating_add(1).saturating_mul(entry_size);
    let est_physical_bytes = est_payload_bytes.saturating_add(header_bytes);
    let est_clusters = est_physical_bytes.div_ceil(cluster);
    let logical_clusters = logical.div_ceil(cluster);
    Some(FootprintEstimate {
        est_physical_bytes,
        est_clusters,
        logical_clusters,
        header_bytes,
    })
}

/// Validates minimum savings, cluster gain, MFT overhead (< 32 KiB), and LZNT1/WOF regression guards.
pub fn passes_savings_check(
    logical: u64,
    est: FootprintEstimate,
    min_savings_pct: f64,
    cluster_size: u64,
    existing_kind: Option<CompressionKind>,
    current_physical: Option<u64>,
) -> bool {
    if logical == 0 {
        return false;
    }
    let max_ratio = (100.0 - min_savings_pct) / 100.0;
    if (est.est_physical_bytes as f64 / logical as f64) > max_ratio {
        return false;
    }
    if est.est_clusters >= est.logical_clusters {
        return false;
    }
    // Compensate MFT overhead of `IO_REPARSE_TAG_WOF` + `::WofCompressedData` on small files.
    if logical < 32 * 1024 && est.logical_clusters.saturating_sub(est.est_clusters) < 2 {
        return false;
    }

    let cluster = cluster_size.max(512);
    match existing_kind {
        Some(CompressionKind::Lznt1) => {
            if let Some(cp) = current_physical {
                let cp_clusters = cp.div_ceil(cluster);
                if est.est_clusters > cp_clusters {
                    return false;
                }
            }
            true
        }
        Some(CompressionKind::Wof(_)) => {
            let Some(cp) = current_physical else {
                return false;
            };
            if cp == 0 || cp <= est.est_physical_bytes {
                return false;
            }
            let cp_clusters = cp.div_ceil(cluster);
            if cp_clusters.saturating_sub(est.est_clusters) < 2 {
                return false;
            }
            let min_recompress_frac = min_savings_pct.max(10.0) / 100.0;
            ((cp - est.est_physical_bytes) as f64 / cp as f64) >= min_recompress_frac
        }
        None => true,
    }
}

// ---------------------------------------------------------------------------
// Cabinet.dll XPRESS_HUFF compressor probe
// ---------------------------------------------------------------------------

type CompressorHandle = *mut c_void;
const COMPRESS_ALGORITHM_XPRESS_HUFF: u32 = 4;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

type CreateCompressorFn = unsafe extern "system" fn(u32, *mut c_void, *mut CompressorHandle) -> i32;
type CompressFn = unsafe extern "system" fn(
    CompressorHandle,
    *const c_void,
    usize,
    *mut c_void,
    usize,
    *mut usize,
) -> i32;
type CloseCompressorFn = unsafe extern "system" fn(CompressorHandle) -> i32;

/// Outcome of probing a single file.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProbeOutcome {
    /// File changed to unsafe state (reparse point, sparse, cloud, encrypted) before read.
    SkipUnsafe,
    /// Packed executable stub detected in PE headers (0 payload reads).
    PackedStub,
    /// Sampled compressibility estimate.
    Measured {
        pe: PeProfile,
        est_payload_bytes: u64,
        est_ratio: f64,
    },
}

/// Reusable, non-`Sync` `XPRESS_HUFF` compressor backed by `cabinet.dll`.
///
/// Field order matters: `handle` is declared before `_dll` and closed in `Drop`
/// so `CloseCompressor` always executes before `FreeLibrary`.
pub struct XpressHuffProbe {
    handle: CompressorHandle,
    _dll: SystemDll,
    compress_fn: CompressFn,
    close_fn: CloseCompressorFn,
    scratch: Vec<u8>,
    read_buf: Vec<u8>,
    _not_sync: PhantomData<Cell<()>>,
}

impl XpressHuffProbe {
    pub fn new() -> io::Result<Self> {
        let dll = SystemDll::load("cabinet.dll")
            .ok_or_else(|| io::Error::other("failed to load cabinet.dll from System32"))?;
        let create_ptr = dll
            .proc(c"CreateCompressor")
            .ok_or_else(|| io::Error::other("CreateCompressor missing in cabinet.dll"))?;
        let compress_ptr = dll
            .proc(c"Compress")
            .ok_or_else(|| io::Error::other("Compress missing in cabinet.dll"))?;
        let close_ptr = dll
            .proc(c"CloseCompressor")
            .ok_or_else(|| io::Error::other("CloseCompressor missing in cabinet.dll"))?;

        // SAFETY: function signatures match Win32 `compressapi.h`.
        let create_fn: CreateCompressorFn = unsafe { std::mem::transmute(create_ptr) };
        let compress_fn: CompressFn = unsafe { std::mem::transmute(compress_ptr) };
        let close_fn: CloseCompressorFn = unsafe { std::mem::transmute(close_ptr) };

        let mut handle: CompressorHandle = std::ptr::null_mut();
        // SAFETY: valid output pointer; `COMPRESS_ALGORITHM_XPRESS_HUFF = 4`.
        if unsafe {
            create_fn(
                COMPRESS_ALGORITHM_XPRESS_HUFF,
                std::ptr::null_mut(),
                &mut handle,
            )
        } == 0
            || handle.is_null()
        {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            handle,
            _dll: dll,
            compress_fn,
            close_fn,
            scratch: vec![0u8; PROBE_BLOCK_SIZE],
            read_buf: vec![0u8; PROBE_BLOCK_SIZE],
            _not_sync: PhantomData,
        })
    }

    /// Returns the compressed byte count for `chunk` (`<= chunk.len()`).
    #[cfg(test)]
    pub fn compress_block(&mut self, chunk: &[u8]) -> usize {
        compress_with_handle(self.handle, self.compress_fn, chunk, &mut self.scratch)
    }

    /// Computes median compression ratio over an in-memory buffer.
    #[cfg(test)]
    pub fn estimate_slice_ratio(&mut self, data: &[u8]) -> Option<f64> {
        let offsets = sample_offsets(0, data.len() as u64);
        if offsets.is_empty() {
            return None;
        }
        let mut ratios = Vec::with_capacity(offsets.len());
        for (off, len) in offsets {
            let start = usize::try_from(off).ok()?;
            let end = start.checked_add(len)?;
            let chunk = data.get(start..end)?;
            let comp = self.compress_block(chunk);
            ratios.push(comp as f64 / chunk.len() as f64);
        }
        median_ratio(&mut ratios)
    }

    /// Probes a file on disk without updating `LastAccessTime` or following reparse points.
    pub fn probe_file(
        &mut self,
        path: &Path,
        logical: u64,
        cloud_attrs: u32,
    ) -> io::Result<ProbeOutcome> {
        let mut file = open_for_probe(path)?;
        let unsafe_mask = cloud_attrs
            | FILE_ATTRIBUTE_REPARSE_POINT
            | FILE_ATTRIBUTE_SPARSE_FILE
            | FILE_ATTRIBUTE_ENCRYPTED
            | FILE_ATTRIBUTE_DIRECTORY;
        if file_attributes_of(&file)? & unsafe_mask != 0 {
            return Ok(ProbeOutcome::SkipUnsafe);
        }

        let mut hdr = vec![0u8; INITIAL_HEADER_READ];
        let mut hdr_len = read_up_to(&mut file, &mut hdr)?;
        if let Some(sec_end) = hdr.get(..hdr_len).and_then(pe_section_table_end) {
            if sec_end > hdr_len && sec_end <= MAX_HEADER_READ {
                hdr.resize(sec_end, 0);
                if let Some(tail) = hdr.get_mut(hdr_len..) {
                    hdr_len = hdr_len.saturating_add(read_up_to(&mut file, tail)?);
                }
            }
        }

        let pe = inspect_pe(hdr.get(..hdr_len).unwrap_or(&[]), logical);
        let (sample_start, sample_end, pe_prefix) = match pe {
            PeProfile::PackedStub => return Ok(ProbeOutcome::PackedStub),
            PeProfile::LargeOverlay {
                overlay_offset,
                payload_end,
            } => (overlay_offset, payload_end, Some(overlay_offset)),
            PeProfile::NotPe | PeProfile::ExecutableCode { .. } => (0, logical, None),
        };

        let offsets = sample_offsets(sample_start, sample_end);
        if offsets.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "empty probe range",
            ));
        }

        let mut ratios = Vec::with_capacity(offsets.len());
        for (off, len) in offsets {
            let chunk_len = len.min(self.read_buf.len());
            // Reuse already-read header bytes when reading from offset 0 within `hdr_len`.
            let n = if off == 0 && chunk_len <= hdr_len {
                if let (Some(dst), Some(src)) =
                    (self.read_buf.get_mut(..chunk_len), hdr.get(..chunk_len))
                {
                    dst.copy_from_slice(src);
                    chunk_len
                } else {
                    0
                }
            } else {
                file.seek(SeekFrom::Start(off))?;
                match self.read_buf.get_mut(..chunk_len) {
                    Some(dst) => read_up_to(&mut file, dst)?,
                    None => 0,
                }
            };
            if n == 0 {
                continue;
            }
            let Some(chunk) = self.read_buf.get(..n) else {
                continue;
            };
            // Avoid double borrow of `self` by passing via temporary slice copy or splitting borrow.
            let comp =
                compress_with_handle(self.handle, self.compress_fn, chunk, &mut self.scratch);
            ratios.push(comp as f64 / n as f64);
        }

        let Some(med) = median_ratio(&mut ratios) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "no sample bytes read",
            ));
        };

        let est_payload_bytes = match pe_prefix {
            Some(pe_end) => {
                let overlay_len = sample_end.saturating_sub(pe_end);
                pe_end.saturating_add(((overlay_len as f64) * med).ceil() as u64)
            }
            None => ((logical as f64) * med).ceil() as u64,
        };
        let est_ratio = if logical == 0 {
            1.0
        } else {
            est_payload_bytes as f64 / logical as f64
        };

        Ok(ProbeOutcome::Measured {
            pe,
            est_payload_bytes,
            est_ratio,
        })
    }
}

impl Drop for XpressHuffProbe {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: closes compressor before `_dll` drops and frees `cabinet.dll`.
            unsafe {
                let _ = (self.close_fn)(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

fn open_for_probe(path: &Path) -> io::Result<File> {
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let flags = FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN;
    match OpenOptions::new()
        .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
        .share_mode(share)
        .custom_flags(flags)
        .open(path)
    {
        Ok(file) => {
            // Suppress LastAccessTime updates for dry-run reads on this handle (`0xFFFFFFFF`).
            let disable_access = FILETIME {
                dwLowDateTime: u32::MAX,
                dwHighDateTime: u32::MAX,
            };
            // SAFETY: `file` is open with `FILE_WRITE_ATTRIBUTES`; pointer is valid for stack `FILETIME`.
            unsafe {
                let _ = SetFileTime(file.as_raw_handle() as _, null(), &disable_access, null());
            }
            Ok(file)
        }
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => OpenOptions::new()
            .access_mode(FILE_READ_DATA | FILE_READ_ATTRIBUTES)
            .share_mode(share)
            .custom_flags(flags)
            .open(path),
        Err(e) => Err(e),
    }
}

fn compress_with_handle(
    handle: CompressorHandle,
    compress_fn: CompressFn,
    chunk: &[u8],
    scratch: &mut Vec<u8>,
) -> usize {
    if chunk.is_empty() {
        return 0;
    }
    if scratch.len() < chunk.len() {
        scratch.resize(chunk.len(), 0);
    }
    let mut out_size = 0usize;
    // SAFETY: `handle` is valid; input and scratch buffers match their lengths.
    let ok = unsafe {
        compress_fn(
            handle,
            chunk.as_ptr().cast(),
            chunk.len(),
            scratch.as_mut_ptr().cast(),
            chunk.len(),
            &mut out_size,
        )
    };
    if ok != 0 {
        out_size.min(chunk.len())
    } else {
        // SAFETY: reads thread-local error code from `Compress`.
        let _ = unsafe { GetLastError() == ERROR_INSUFFICIENT_BUFFER };
        chunk.len()
    }
}

fn read_up_to(file: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0usize;
    while let Some(dst) = buf.get_mut(total..) {
        if dst.is_empty() {
            break;
        }
        match file.read(dst) {
            Ok(0) => break,
            Ok(n) => total = total.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }
    fn put_u32(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn build_pe(
        pe32_plus: bool,
        sections: &[(&[u8], u32, u32)],
        dotnet: bool,
        cert: Option<(u32, u32)>,
    ) -> Vec<u8> {
        let opt_size: usize = if pe32_plus { 240 } else { 224 };
        let pe_off: usize = 0x80;
        let opt_off = pe_off + 24;
        let sec_off = opt_off + opt_size;
        let total = sec_off + sections.len() * 40;
        let mut buf = vec![0u8; total.max(512)];
        put_u16(&mut buf, 0, 0x5A4D);
        put_u32(&mut buf, 0x3C, pe_off as u32);
        put_u32(&mut buf, pe_off, 0x0000_4550);
        put_u16(&mut buf, pe_off + 6, sections.len() as u16);
        put_u16(&mut buf, pe_off + 20, opt_size as u16);
        put_u16(&mut buf, opt_off, if pe32_plus { 0x020B } else { 0x010B });
        let (rva_off, dd_off) = if pe32_plus {
            (opt_off + 108, opt_off + 112)
        } else {
            (opt_off + 92, opt_off + 96)
        };
        put_u32(&mut buf, rva_off, 16);
        if dotnet {
            put_u32(&mut buf, dd_off + 14 * 8, 0x2000);
            put_u32(&mut buf, dd_off + 14 * 8 + 4, 0x48);
        }
        if let Some((va, sz)) = cert {
            put_u32(&mut buf, dd_off + 4 * 8, va);
            put_u32(&mut buf, dd_off + 4 * 8 + 4, sz);
        }
        for (i, (name, raw_ptr, raw_sz)) in sections.iter().enumerate() {
            let o = sec_off + i * 40;
            let n = name.len().min(8);
            buf[o..o + n].copy_from_slice(&name[..n]);
            put_u32(&mut buf, o + 16, *raw_sz);
            put_u32(&mut buf, o + 20, *raw_ptr);
        }
        buf
    }

    #[test]
    fn pe_parser_recognizes_pe32_pe32plus_dotnet_and_packers() {
        let pe32 = build_pe(false, &[(b".text", 0x400, 0x1000)], false, None);
        assert_eq!(
            inspect_pe(&pe32, 0x2000),
            PeProfile::ExecutableCode { is_dotnet: false }
        );

        let pe64_net = build_pe(true, &[(b".text", 0x400, 0x1000)], true, None);
        assert_eq!(
            inspect_pe(&pe64_net, 0x2000),
            PeProfile::ExecutableCode { is_dotnet: true }
        );

        let upx = build_pe(
            false,
            &[(b"UPX0", 0, 0), (b"UPX1", 0x400, 0x1000)],
            false,
            None,
        );
        assert_eq!(inspect_pe(&upx, 0x2000), PeProfile::PackedStub);

        let vmp = build_pe(
            true,
            &[(b".text", 0x400, 0x1000), (b".vmp0", 0x1400, 0x800)],
            false,
            None,
        );
        assert_eq!(inspect_pe(&vmp, 0x3000), PeProfile::PackedStub);
    }

    #[test]
    fn pe_parser_detects_large_overlay_with_and_without_authenticode() {
        let pe_end = 0x10_0000u32; // 1 MiB PE code
        let pe = build_pe(true, &[(b".text", 0x400, pe_end - 0x400)], false, None);
        // Overlay 4 MiB (>= pe_end and > 1 MiB) -> LargeOverlay
        assert_eq!(
            inspect_pe(&pe, 5 * 1024 * 1024),
            PeProfile::LargeOverlay {
                overlay_offset: u64::from(pe_end),
                payload_end: 5 * 1024 * 1024,
            }
        );

        // With Authenticode certificate at tail
        let cert_off = 5 * 1024 * 1024u32;
        let cert_sz = 8192u32;
        let pe_signed = build_pe(
            true,
            &[(b".text", 0x400, pe_end - 0x400)],
            false,
            Some((cert_off, cert_sz)),
        );
        assert_eq!(
            inspect_pe(&pe_signed, u64::from(cert_off + cert_sz)),
            PeProfile::LargeOverlay {
                overlay_offset: u64::from(pe_end),
                payload_end: u64::from(cert_off),
            }
        );

        // Huge PE code (10 MiB) + small overlay (2 MiB) -> stay ExecutableCode
        let big_pe_end = 10 * 1024 * 1024u32;
        let big_pe = build_pe(true, &[(b".text", 0x400, big_pe_end - 0x400)], false, None);
        assert_eq!(
            inspect_pe(&big_pe, u64::from(big_pe_end) + 2 * 1024 * 1024),
            PeProfile::ExecutableCode { is_dotnet: false }
        );
    }

    #[test]
    fn pe_parser_never_panics_and_handles_truncated_sections() {
        assert_eq!(inspect_pe(&[], 0), PeProfile::NotPe);
        assert_eq!(inspect_pe(&[0u8; 4096], 4096), PeProfile::NotPe);

        let mut bad_lfanew = vec![0u8; 256];
        put_u16(&mut bad_lfanew, 0, 0x5A4D);
        put_u32(&mut bad_lfanew, 0x3C, u32::MAX);
        assert_eq!(inspect_pe(&bad_lfanew, 10_000_000), PeProfile::NotPe);

        // Truncated section table must NEVER return LargeOverlay
        let mut trunc = build_pe(true, &[(b".text", 0x400, 0x1000)], false, None);
        put_u16(&mut trunc, 0x80 + 6, 50); // claims 50 sections, buffer only holds 1
        assert_eq!(
            inspect_pe(&trunc, 100 * 1024 * 1024),
            PeProfile::ExecutableCode { is_dotnet: false }
        );

        // > MAX_SECTIONS must NEVER return LargeOverlay even if buffer is large enough
        let many: Vec<(&[u8], u32, u32)> = vec![(b".text", 0x400, 0x1000); MAX_SECTIONS + 1];
        let big_hdr = build_pe(true, &many, false, None);
        assert_eq!(
            inspect_pe(&big_hdr, 100 * 1024 * 1024),
            PeProfile::ExecutableCode { is_dotnet: false }
        );
    }

    #[test]
    fn cluster_and_wof_header_math() {
        // 10 KiB shrinking to 9 KiB on 4 KiB clusters -> 3 clusters remain 3 -> Skip
        let est_10k =
            estimate_wof_footprint(10 * 1024, 9 * 1024, WofAlgorithm::Xpress4K, 4096).unwrap();
        assert_eq!(est_10k.logical_clusters, 3);
        assert_eq!(est_10k.est_clusters, 3);
        assert!(!passes_savings_check(
            10 * 1024,
            est_10k,
            5.0,
            4096,
            None,
            None
        ));

        // 20 KiB (< 32 KiB) saving only 1 cluster (5 -> 4) -> Skip due to MFT overhead guard
        let est_20k =
            estimate_wof_footprint(20 * 1024, 15 * 1024, WofAlgorithm::Xpress4K, 4096).unwrap();
        assert_eq!(est_20k.logical_clusters, 5);
        assert_eq!(est_20k.est_clusters, 4);
        assert!(!passes_savings_check(
            20 * 1024,
            est_20k,
            15.0,
            4096,
            None,
            None
        ));

        // 20 KiB saving 2 clusters (5 -> 3) -> Pass
        let est_20k_ok =
            estimate_wof_footprint(20 * 1024, 10 * 1024, WofAlgorithm::Xpress4K, 4096).unwrap();
        assert_eq!(est_20k_ok.est_clusters, 3);
        assert!(passes_savings_check(
            20 * 1024,
            est_20k_ok,
            15.0,
            4096,
            None,
            None
        ));

        // 100 MiB Xpress4K chunk table: (25600 + 1) * 4 = 102,404 bytes
        let mib100 = 100 * 1024 * 1024;
        let est_100m =
            estimate_wof_footprint(mib100, 50 * 1024 * 1024, WofAlgorithm::Xpress4K, 4096).unwrap();
        assert_eq!(est_100m.header_bytes, (25600 + 1) * 4);

        // >= 4 GiB uses 8-byte chunk table entries
        let gib4 = 4u64 * 1024 * 1024 * 1024;
        let est_4g = estimate_wof_footprint(gib4, gib4 / 2, WofAlgorithm::Xpress8K, 4096).unwrap();
        assert_eq!(est_4g.header_bytes, (gib4 / 8192 + 1) * 8);

        // LZNT1 -> WOF regression guard: reject if est_clusters > current_physical_clusters
        let est_lznt =
            estimate_wof_footprint(1024 * 1024, 300 * 1024, WofAlgorithm::Xpress4K, 4096).unwrap();
        assert!(!passes_savings_check(
            1024 * 1024,
            est_lznt,
            15.0,
            4096,
            Some(CompressionKind::Lznt1),
            Some(200 * 1024),
        ));
        assert!(passes_savings_check(
            1024 * 1024,
            est_lznt,
            15.0,
            4096,
            Some(CompressionKind::Lznt1),
            Some(400 * 1024),
        ));
    }

    #[test]
    fn cabinet_probe_rejects_padded_incompressible_container_and_preserves_last_access() {
        let mut probe = XpressHuffProbe::new().expect("cabinet.dll should load on Windows");

        // Block 1 = 16 KiB zeros (~0%), Blocks 2..=8 = pseudo-random (~100%)
        let mut data = vec![0u8; 8 * PROBE_BLOCK_SIZE];
        let mut state: u64 = 0xD1B5_4A32_D192_ED03;
        for chunk in data[PROBE_BLOCK_SIZE..].chunks_exact_mut(8) {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            chunk.copy_from_slice(&state.to_le_bytes());
        }
        let ratio = probe.estimate_slice_ratio(&data).unwrap();
        assert!(
            ratio > 0.90,
            "median must reject zero-padded start, got {ratio}"
        );

        // Verify probe_file does not mutate LastAccessTime in dry-run
        let dir =
            std::env::temp_dir().join(format!("ntfs-unthrottle-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("sample.log");
        let payload: Vec<u8> = b"repetitive-log-line\n"
            .iter()
            .copied()
            .cycle()
            .take(128 * 1024)
            .collect();
        std::fs::write(&path, &payload).unwrap();

        let old_ft = FILETIME {
            dwLowDateTime: 0x1111_2222,
            dwHighDateTime: 0x01D8_0000,
        };
        {
            let f = OpenOptions::new()
                .access_mode(FILE_WRITE_ATTRIBUTES)
                .open(&path)
                .unwrap();
            assert_ne!(
                unsafe { SetFileTime(f.as_raw_handle() as _, &old_ft, &old_ft, &old_ft) },
                0
            );
        }

        let out = probe.probe_file(&path, payload.len() as u64, 0).unwrap();
        assert!(matches!(out, ProbeOutcome::Measured { est_ratio, .. } if est_ratio < 0.25));

        let check_f = ntfs_unthrottle::open_for_query(&path).unwrap();
        let mut c = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut a = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        let mut w = FILETIME {
            dwLowDateTime: 0,
            dwHighDateTime: 0,
        };
        assert_ne!(
            unsafe {
                windows_sys::Win32::Storage::FileSystem::GetFileTime(
                    check_f.as_raw_handle() as _,
                    &mut c,
                    &mut a,
                    &mut w,
                )
            },
            0
        );
        assert_eq!(
            (a.dwLowDateTime, a.dwHighDateTime),
            (old_ft.dwLowDateTime, old_ft.dwHighDateTime)
        );
        drop(check_f);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
