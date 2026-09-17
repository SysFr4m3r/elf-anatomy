//! Byte spans — the coordinate system everything else is expressed in.

use core::fmt;

/// Identifies one file in a specimen's dependency closure.
///
/// The analysed binary is [`FileId::PRIMARY`]; its `DT_NEEDED` closure is numbered from 1
/// in the order the loader model resolves them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct FileId(pub u32);

impl FileId {
    /// The specimen itself.
    pub const PRIMARY: FileId = FileId(0);
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "f{}", self.0)
    }
}

/// A half-open byte range `[start, start + len)` within one file.
///
/// All arithmetic saturates. Spans are routinely constructed from untrusted header fields,
/// so a malformed `sh_size` of `u64::MAX` must produce a nonsensical span, not a panic.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Span {
    pub file: FileId,
    pub start: u64,
    pub len: u64,
}

impl Span {
    #[must_use]
    pub const fn new(file: FileId, start: u64, len: u64) -> Self {
        Self { file, start, len }
    }

    /// A zero-length marker at `start`. Legal, and excluded from the coverage partition.
    #[must_use]
    pub const fn empty_at(file: FileId, start: u64) -> Self {
        Self {
            file,
            start,
            len: 0,
        }
    }

    /// One past the last byte, saturating.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.start.saturating_add(self.len)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    #[must_use]
    pub const fn contains(self, file: FileId, off: u64) -> bool {
        self.file.0 == file.0 && off >= self.start && off < self.end()
    }

    /// True if `other` lies entirely within `self`. Empty spans are contained if their
    /// start point falls inside the closed range, so a zero-length section at the end of a
    /// parent still nests correctly.
    #[must_use]
    pub const fn contains_span(self, other: Span) -> bool {
        if self.file.0 != other.file.0 {
            return false;
        }
        other.start >= self.start && other.end() <= self.end()
    }

    /// True if the two spans share at least one byte. Empty spans never overlap.
    #[must_use]
    pub const fn overlaps(self, other: Span) -> bool {
        if self.file.0 != other.file.0 || self.is_empty() || other.is_empty() {
            return false;
        }
        self.start < other.end() && other.start < self.end()
    }

    #[must_use]
    pub fn intersection(self, other: Span) -> Option<Span> {
        if !self.overlaps(other) {
            return None;
        }
        let start = self.start.max(other.start);
        let end = self.end().min(other.end());
        Some(Span::new(self.file, start, end.saturating_sub(start)))
    }

    /// The hole between the end of `self` and the start of `next`, if there is one.
    #[must_use]
    pub fn gap_to(self, next: Span) -> Option<Span> {
        if self.file.0 != next.file.0 || next.start <= self.end() {
            return None;
        }
        Some(Span::new(
            self.file,
            self.end(),
            next.start.saturating_sub(self.end()),
        ))
    }
}

impl fmt::Debug for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{:#x}..{:#x} ({})",
            self.file,
            self.start,
            self.end(),
            self.len
        )
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const F: FileId = FileId::PRIMARY;

    #[test]
    fn end_saturates_instead_of_panicking() {
        let s = Span::new(F, u64::MAX - 4, 1024);
        assert_eq!(s.end(), u64::MAX);
    }

    #[test]
    fn overlap_is_half_open() {
        let a = Span::new(F, 0, 16);
        let b = Span::new(F, 16, 16);
        assert!(!a.overlaps(b));
        assert!(a.overlaps(Span::new(F, 15, 2)));
    }

    #[test]
    fn empty_spans_never_overlap_but_do_nest() {
        let parent = Span::new(F, 0, 64);
        let empty = Span::empty_at(F, 64);
        assert!(!parent.overlaps(empty));
        assert!(parent.contains_span(empty));
    }

    #[test]
    fn different_files_never_interact() {
        let a = Span::new(FileId(0), 0, 64);
        let b = Span::new(FileId(1), 0, 64);
        assert!(!a.overlaps(b));
        assert!(!a.contains_span(b));
        assert_eq!(a.intersection(b), None);
    }

    #[test]
    fn gap_between_headers_and_first_section() {
        let ehdr = Span::new(F, 0, 64);
        let sect = Span::new(F, 0x1000, 32);
        assert_eq!(ehdr.gap_to(sect), Some(Span::new(F, 64, 0x1000 - 64)));
        assert_eq!(sect.gap_to(ehdr), None);
    }
}
