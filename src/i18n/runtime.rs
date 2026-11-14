//! Zero-allocation formatting primitives used by the `build.rs`-generated i18n module.

use core::fmt;

/// Static chunk of spaces used to pad labels without heap allocations.
const SPACES: &str = "                                                                ";

#[inline]
fn write_spaces(f: &mut fmt::Formatter<'_>, mut count: usize) -> fmt::Result {
    while count > 0 {
        let chunk = count.min(SPACES.len());
        f.write_str(&SPACES[..chunk])?;
        count -= chunk;
    }
    Ok(())
}

/// Number of ASCII digits required to render `n` in base 10.
#[inline]
pub const fn decimal_digits(mut n: u64) -> usize {
    if n == 0 {
        return 1;
    }
    let mut digits = 0;
    while n > 0 {
        digits += 1;
        n /= 10;
    }
    digits
}

/// A pre-parsed template segment stored in `.rodata`.
#[derive(Copy, Clone, Debug)]
pub enum Segment {
    Lit(&'static str),
    Arg(u8),
}

/// Zero-allocation renderer for parameterized message templates.
#[derive(Copy, Clone)]
pub struct Msg<'a, const N: usize> {
    pub segments: &'static [Segment],
    pub lit_width: usize,
    pub args: [&'a dyn fmt::Display; N],
}

impl<'a, const N: usize> Msg<'a, N> {
    /// Pads the formatted message to `target_width` terminal cells assuming all
    /// formatted arguments contribute `args_width` cells (e.g., ASCII digits).
    #[inline]
    pub const fn pad_with(self, args_width: usize, target_width: usize) -> PaddedMsg<'a, N> {
        PaddedMsg {
            msg: self,
            total_width: self.lit_width + args_width,
            target_width,
        }
    }
}

impl<const N: usize> fmt::Display for Msg<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for seg in self.segments {
            match *seg {
                Segment::Lit(s) => f.write_str(s)?,
                Segment::Arg(idx) => self.args[idx as usize].fmt(f)?,
            }
        }
        Ok(())
    }
}

/// Zero-allocation right-padded renderer for parameterized numeric labels.
#[derive(Copy, Clone)]
pub struct PaddedMsg<'a, const N: usize> {
    msg: Msg<'a, N>,
    total_width: usize,
    target_width: usize,
}

impl<const N: usize> fmt::Display for PaddedMsg<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.msg.fmt(f)?;
        write_spaces(f, self.target_width.saturating_sub(self.total_width))
    }
}

/// Zero-allocation renderer for pluralized message templates.
///
/// `Segment::Arg(0)` renders `count` using the active locale's thousand separator;
/// `Segment::Arg(i)` (`i >= 1`) renders `args[i - 1]`.
#[derive(Copy, Clone)]
pub struct PluralMsg<'a, const N: usize> {
    pub segments: &'static [Segment],
    pub count: GroupedInt,
    pub args: [&'a dyn fmt::Display; N],
}

impl<const N: usize> fmt::Display for PluralMsg<'_, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for seg in self.segments {
            match *seg {
                Segment::Lit(s) => f.write_str(s)?,
                Segment::Arg(0) => self.count.fmt(f)?,
                Segment::Arg(idx) => self.args[(idx - 1) as usize].fmt(f)?,
            }
        }
        Ok(())
    }
}

/// Static label paired with its precomputed terminal cell width (CJK-safe).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub text: &'static str,
    pub width: usize,
}

impl Label {
    /// Left-aligns `text` and pads on the right to `target_width` terminal cells.
    #[inline]
    pub const fn pad(self, target_width: usize) -> PaddedLabel {
        PaddedLabel {
            label: self,
            target_width,
        }
    }

    /// Right-aligns `text` by padding spaces on the left to `target_width` terminal cells.
    #[inline]
    pub const fn pad_left(self, target_width: usize) -> LeftPaddedLabel {
        LeftPaddedLabel {
            label: self,
            target_width,
        }
    }
}

impl fmt::Display for Label {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.text)
    }
}

/// Zero-allocation right-padded static label.
#[derive(Copy, Clone, Debug)]
pub struct PaddedLabel {
    label: Label,
    target_width: usize,
}

impl fmt::Display for PaddedLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label.text)?;
        write_spaces(f, self.target_width.saturating_sub(self.label.width))
    }
}

/// Zero-allocation left-padded (right-aligned) static label.
#[derive(Copy, Clone, Debug)]
pub struct LeftPaddedLabel {
    label: Label,
    target_width: usize,
}

impl fmt::Display for LeftPaddedLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_spaces(f, self.target_width.saturating_sub(self.label.width))?;
        f.write_str(self.label.text)
    }
}

/// Zero-allocation thousand-separated integer formatter for `u64`.
#[derive(Copy, Clone, Debug)]
pub struct GroupedInt {
    pub value: u64,
    pub sep: &'static str,
}

impl fmt::Display for GroupedInt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.value == 0 {
            return f.write_str("0");
        }
        let mut buf = [0u8; 20]; // u64::MAX has 20 digits
        let mut n = self.value;
        let mut i = buf.len();
        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }
        let digits = &buf[i..];
        let first_group = if digits.len() % 3 == 0 { 3 } else { digits.len() % 3 };
        // SAFETY: `digits` contains exclusively ASCII `'0'..='9'`.
        f.write_str(unsafe { core::str::from_utf8_unchecked(&digits[..first_group]) })?;
        let mut pos = first_group;
        while pos < digits.len() {
            f.write_str(self.sep)?;
            // SAFETY: `digits` contains exclusively ASCII `'0'..='9'`.
            f.write_str(unsafe { core::str::from_utf8_unchecked(&digits[pos..pos + 3]) })?;
            pos += 3;
        }
        Ok(())
    }
}

/// Zero-allocation locale-aware decimal formatter for `f64`.
#[derive(Copy, Clone, Debug)]
pub struct GroupedDecimal {
    pub value: f64,
    pub decimals: u8,
    pub decimal_sep: &'static str,
    pub thousand_sep: &'static str,
}

impl GroupedDecimal {
    /// Right-aligns `<decimal><suffix>` within `target_width` ASCII/cell columns on stack.
    #[inline]
    pub const fn pad_left_suffix(self, suffix: &'static str, target_width: usize) -> LeftPaddedDecimal {
        LeftPaddedDecimal {
            decimal: self,
            suffix,
            target_width,
        }
    }
}

/// Zero-allocation right-aligned decimal with optional suffix (e.g. `"%"`).
#[derive(Copy, Clone, Debug)]
pub struct LeftPaddedDecimal {
    decimal: GroupedDecimal,
    suffix: &'static str,
    target_width: usize,
}

impl fmt::Display for LeftPaddedDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use core::fmt::Write;
        struct StackBuf {
            buf: [u8; 48],
            len: usize,
        }
        impl fmt::Write for StackBuf {
            fn write_str(&mut self, s: &str) -> fmt::Result {
                let bytes = s.as_bytes();
                let avail = self.buf.len().saturating_sub(self.len);
                if bytes.len() > avail {
                    return Err(fmt::Error);
                }
                self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
                self.len += bytes.len();
                Ok(())
            }
        }

        let mut sb = StackBuf {
            buf: [0u8; 48],
            len: 0,
        };
        if write!(sb, "{}{}", self.decimal, self.suffix).is_ok() {
            // SAFETY: StackBuf received only valid UTF-8 chunks via `write_str`.
            let rendered = unsafe { core::str::from_utf8_unchecked(&sb.buf[..sb.len]) };
            let chars = rendered.chars().count();
            write_spaces(f, self.target_width.saturating_sub(chars))?;
            f.write_str(rendered)
        } else {
            write!(f, "{}{}", self.decimal, self.suffix)
        }
    }
}

impl fmt::Display for GroupedDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.value.is_nan() {
            return f.write_str("NaN");
        }
        if self.value.is_infinite() {
            return f.write_str(if self.value.is_sign_negative() { "-inf" } else { "inf" });
        }
        let dec = self.decimals.min(9) as usize;
        let mut neg = self.value.is_sign_negative();
        let abs = self.value.abs();
        let scale_u64 = 10u64.pow(dec as u32);
        let scaled = (abs * scale_u64 as f64).round();
        if !scaled.is_finite() || scaled >= u64::MAX as f64 {
            return write!(f, "{:.*}", dec, self.value);
        }
        let rounded = scaled as u64;
        if rounded == 0 {
            neg = false;
        }
        let int_part = rounded / scale_u64;
        let mut frac_part = rounded % scale_u64;

        if neg {
            f.write_str("-")?;
        }
        GroupedInt {
            value: int_part,
            sep: self.thousand_sep,
        }
        .fmt(f)?;
        if dec > 0 {
            f.write_str(self.decimal_sep)?;
            let mut fbuf = [b'0'; 9];
            for idx in (0..dec).rev() {
                fbuf[idx] = b'0' + (frac_part % 10) as u8;
                frac_part /= 10;
            }
            // SAFETY: `fbuf[..dec]` contains exclusively ASCII `'0'..='9'`.
            f.write_str(unsafe { core::str::from_utf8_unchecked(&fbuf[..dec]) })?;
        }
        Ok(())
    }
}

/// CLDR integer plural categories.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PluralCat {
    Zero,
    One,
    Two,
    Few,
    Many,
    Other,
}

/// Supported CLDR integer plural rule families.
#[allow(dead_code)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PluralRule {
    None,
    Germanic,
    French,
    Slavic,
    Arabic,
}

impl PluralRule {
    #[inline]
    pub const fn classify(self, n: u64) -> PluralCat {
        match self {
            PluralRule::None => PluralCat::Other,
            PluralRule::Germanic => {
                if n == 1 {
                    PluralCat::One
                } else {
                    PluralCat::Other
                }
            }
            PluralRule::French => {
                if n <= 1 {
                    PluralCat::One
                } else {
                    PluralCat::Other
                }
            }
            PluralRule::Slavic => {
                let m10 = n % 10;
                let m100 = n % 100;
                if m10 == 1 && m100 != 11 {
                    PluralCat::One
                } else if m10 >= 2 && m10 <= 4 && !(m100 >= 12 && m100 <= 14) {
                    PluralCat::Few
                } else if m10 == 0 || m10 >= 5 || (m100 >= 11 && m100 <= 14) {
                    PluralCat::Many
                } else {
                    PluralCat::Other
                }
            }
            PluralRule::Arabic => {
                let m100 = n % 100;
                if n == 0 {
                    PluralCat::Zero
                } else if n == 1 {
                    PluralCat::One
                } else if n == 2 {
                    PluralCat::Two
                } else if m100 >= 3 && m100 <= 10 {
                    PluralCat::Few
                } else if m100 >= 11 && m100 <= 99 {
                    PluralCat::Many
                } else {
                    PluralCat::Other
                }
            }
        }
    }
}

/// Pre-compiled plural template variants stored per locale.
#[derive(Copy, Clone, Debug)]
pub struct PluralSet {
    pub zero: Option<&'static [Segment]>,
    pub one: Option<&'static [Segment]>,
    pub two: Option<&'static [Segment]>,
    pub few: Option<&'static [Segment]>,
    pub many: Option<&'static [Segment]>,
    pub other: &'static [Segment],
}

impl PluralSet {
    #[inline]
    pub const fn pick(&self, rule: PluralRule, n: u64) -> &'static [Segment] {
        let candidate = match rule.classify(n) {
            PluralCat::Zero => self.zero,
            PluralCat::One => self.one,
            PluralCat::Two => self.two,
            PluralCat::Few => self.few,
            PluralCat::Many => self.many,
            PluralCat::Other => None,
        };
        match candidate {
            Some(s) => s,
            None => self.other,
        }
    }
}
