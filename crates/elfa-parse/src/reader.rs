//! Bounds-checked, endian-aware reads over a byte slice.
//!
//! Every read returns `Option` and every offset is a `u64` converted through
//! `try_from`. An ELF file is a set of offsets that point at each other, all of them
//! attacker-controlled in the general case; a parser built on slice indexing is one
//! malformed `sh_offset` away from a panic, and this one runs in a browser tab.

#[derive(Clone, Copy, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    little_endian: bool,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub const fn new(bytes: &'a [u8], little_endian: bool) -> Self {
        Self {
            bytes,
            little_endian,
        }
    }

    #[must_use]
    pub const fn len(&self) -> u64 {
        self.bytes.len() as u64
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// `len` bytes at `off`, or `None` if that runs past the end.
    #[must_use]
    pub fn slice_at(&self, off: u64, len: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(off).ok()?;
        let len = usize::try_from(len).ok()?;
        let end = start.checked_add(len)?;
        self.bytes.get(start..end)
    }

    #[must_use]
    pub fn u8_at(&self, off: u64) -> Option<u8> {
        self.slice_at(off, 1)?.first().copied()
    }

    #[must_use]
    pub fn u16_at(&self, off: u64) -> Option<u16> {
        let b: [u8; 2] = self.slice_at(off, 2)?.try_into().ok()?;
        Some(if self.little_endian {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    }

    #[must_use]
    pub fn u32_at(&self, off: u64) -> Option<u32> {
        let b: [u8; 4] = self.slice_at(off, 4)?.try_into().ok()?;
        Some(if self.little_endian {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    }

    #[must_use]
    pub fn u64_at(&self, off: u64) -> Option<u64> {
        let b: [u8; 8] = self.slice_at(off, 8)?.try_into().ok()?;
        Some(if self.little_endian {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    }

    #[must_use]
    pub fn i64_at(&self, off: u64) -> Option<i64> {
        self.u64_at(off).map(|v| v as i64)
    }

    /// Bytes from `off` up to but excluding the next NUL, capped at `max`.
    ///
    /// Returns `None` only if `off` is out of bounds — an unterminated string at the end
    /// of a truncated table is a fact about the file, not a parse failure.
    #[must_use]
    pub fn cstr_at(&self, off: u64, max: u64) -> Option<&'a [u8]> {
        let start = usize::try_from(off).ok()?;
        let rest = self.bytes.get(start..)?;
        let max = usize::try_from(max).unwrap_or(usize::MAX);
        let window = rest.get(..max.min(rest.len()))?;
        let end = window.iter().position(|&b| b == 0).unwrap_or(window.len());
        window.get(..end)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn reads_respect_endianness() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(Reader::new(&data, true).u32_at(0), Some(0x0403_0201));
        assert_eq!(Reader::new(&data, false).u32_at(0), Some(0x0102_0304));
    }

    #[test]
    fn out_of_bounds_reads_are_none_not_panics() {
        let r = Reader::new(&[0u8; 4], true);
        assert_eq!(r.u64_at(0), None);
        assert_eq!(r.u32_at(1), None);
        assert_eq!(r.u8_at(u64::MAX), None);
        assert_eq!(r.slice_at(2, u64::MAX), None);
    }

    #[test]
    fn strings_stop_at_nul_and_at_the_cap() {
        let data = b"libc.so.6\0next\0";
        let r = Reader::new(data, true);
        assert_eq!(r.cstr_at(0, 64), Some(&b"libc.so.6"[..]));
        assert_eq!(r.cstr_at(10, 64), Some(&b"next"[..]));
        assert_eq!(r.cstr_at(0, 4), Some(&b"libc"[..]));
        assert_eq!(r.cstr_at(99, 64), None);
    }

    #[test]
    fn an_unterminated_string_yields_what_is_there() {
        let r = Reader::new(b"nonul", true);
        assert_eq!(r.cstr_at(0, 64), Some(&b"nonul"[..]));
    }
}
