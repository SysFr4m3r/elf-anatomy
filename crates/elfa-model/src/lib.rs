//! The memory image: what the file becomes once the kernel has mapped it.
//!
//! Phase 1b models only what `execve` does before any dynamic linker runs — the
//! `PT_LOAD` mappings and the zero-filled tail of each one. That is enough for the morph,
//! and it is the half of the story that is true even for a static binary.
//!
//! The dynamic linker's work — dependencies, relocations, RELRO, init order — is phase 3.
//! What this crate establishes now is the direction of translation: a file offset has at
//! most one virtual address, and **most file offsets have none at all**.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use elfa_parse::{FileId, Segment, Span};

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const PF_W: u32 = 2;
const PF_R: u32 = 4;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Prot {
    pub read: bool,
    pub write: bool,
    pub exec: bool,
}

impl Prot {
    #[must_use]
    pub const fn from_flags(f: u32) -> Self {
        Self {
            read: f & PF_R != 0,
            write: f & PF_W != 0,
            exec: f & PF_X != 0,
        }
    }

    /// `rwx`-style string, with `-` for absent bits.
    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match (self.read, self.write, self.exec) {
            (true, false, false) => "r--",
            (true, true, false) => "rw-",
            (true, false, true) => "r-x",
            (true, true, true) => "rwx",
            (false, true, false) => "-w-",
            (false, false, true) => "--x",
            (false, true, true) => "-wx",
            (false, false, false) => "---",
        }
    }
}

/// Where the bytes of a mapping come from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MapSource {
    /// Copied from this span of the file.
    FromFile(Span),
    /// `.bss`: `p_memsz` beyond `p_filesz`, zeroed by the kernel. No file behind it.
    ZeroFill,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Mapping {
    pub vaddr: u64,
    pub len: u64,
    pub prot: Prot,
    pub source: MapSource,
    /// Index of the `PT_LOAD` that produced this mapping.
    pub segment: u32,
}

impl Mapping {
    #[must_use]
    pub const fn end(&self) -> u64 {
        self.vaddr.saturating_add(self.len)
    }
}

/// The address space of one loaded object.
#[derive(Clone, Debug, Default)]
pub struct MemImage {
    mappings: Vec<Mapping>,
}

impl MemImage {
    /// Build from the program headers, as the kernel would.
    ///
    /// For `ET_DYN` the addresses are relative to a load base the kernel randomises; they
    /// are used here as given, which is what `readelf` shows and what makes two runs
    /// comparable.
    #[must_use]
    pub fn from_segments(segments: &[Segment]) -> Self {
        let mut mappings = Vec::new();
        for (i, seg) in segments.iter().enumerate() {
            if seg.p_type != PT_LOAD {
                continue;
            }
            let idx = u32::try_from(i).unwrap_or(u32::MAX);
            let prot = Prot::from_flags(seg.flags);

            if seg.filesz > 0 {
                mappings.push(Mapping {
                    vaddr: seg.vaddr,
                    len: seg.filesz,
                    prot,
                    source: MapSource::FromFile(Span::new(FileId::PRIMARY, seg.offset, seg.filesz)),
                    segment: idx,
                });
            }
            let zero = seg.zero_fill();
            if zero > 0 {
                mappings.push(Mapping {
                    vaddr: seg.vaddr.saturating_add(seg.filesz),
                    len: zero,
                    prot,
                    source: MapSource::ZeroFill,
                    segment: idx,
                });
            }
        }
        mappings.sort_unstable_by_key(|m| (m.vaddr, m.len));
        Self { mappings }
    }

    #[must_use]
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }

    /// The virtual address a file offset ends up at, if any.
    ///
    /// Returns `None` for the large fraction of a file that is never loaded: section
    /// headers, symbol tables, debug info, and the padding between segments.
    #[must_use]
    pub fn vaddr_of(&self, offset: u64) -> Option<u64> {
        for m in &self.mappings {
            if let MapSource::FromFile(span) = m.source
                && offset >= span.start
                && offset < span.end()
            {
                return Some(m.vaddr.saturating_add(offset.saturating_sub(span.start)));
            }
        }
        None
    }

    /// Lowest and highest virtual address in the image.
    #[must_use]
    pub fn extent(&self) -> Option<(u64, u64)> {
        let lo = self.mappings.first()?.vaddr;
        let hi = self.mappings.iter().map(Mapping::end).max()?;
        Some((lo, hi))
    }

    /// Bytes of the file that end up in memory.
    #[must_use]
    pub fn mapped_bytes(&self) -> u64 {
        self.mappings
            .iter()
            .filter_map(|m| match m.source {
                MapSource::FromFile(s) => Some(s.len),
                MapSource::ZeroFill => None,
            })
            .fold(0, u64::saturating_add)
    }

    /// Bytes of memory with no file behind them.
    #[must_use]
    pub fn zero_filled_bytes(&self) -> u64 {
        self.mappings
            .iter()
            .filter(|m| m.source == MapSource::ZeroFill)
            .map(|m| m.len)
            .fold(0, u64::saturating_add)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    fn load(offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Segment {
        Segment {
            p_type: PT_LOAD,
            flags: PF_R | PF_W,
            offset,
            vaddr,
            filesz,
            memsz,
            align: 0x1000,
        }
    }

    #[test]
    fn a_segment_with_memsz_past_filesz_produces_bss() {
        let img = MemImage::from_segments(&[load(0x2db0, 0x3db0, 0x268, 0x690)]);
        assert_eq!(img.mappings().len(), 2);
        assert_eq!(img.zero_filled_bytes(), 0x690 - 0x268);
        assert_eq!(img.mapped_bytes(), 0x268);
        // The zero-filled part begins where the file part ends.
        assert_eq!(img.mappings()[1].vaddr, 0x3db0 + 0x268);
        assert_eq!(img.mappings()[1].source, MapSource::ZeroFill);
    }

    #[test]
    fn file_offsets_outside_any_segment_have_no_address() {
        let img = MemImage::from_segments(&[load(0x1000, 0x1000, 0x175, 0x175)]);
        assert_eq!(img.vaddr_of(0x1000), Some(0x1000));
        assert_eq!(img.vaddr_of(0x1100), Some(0x1100));
        // Section headers, symtab, debug info, padding: all of this.
        assert_eq!(img.vaddr_of(0x2000), None);
        assert_eq!(img.vaddr_of(0), None);
    }

    #[test]
    fn non_load_segments_are_not_mapped_by_the_kernel() {
        let mut dynamic = load(0x2dc8, 0x3dc8, 0x1f0, 0x1f0);
        dynamic.p_type = 2; // PT_DYNAMIC — a view of bytes already inside a PT_LOAD
        let img = MemImage::from_segments(&[dynamic]);
        assert!(img.is_empty());
    }

    #[test]
    fn protection_comes_from_the_flag_bits() {
        assert_eq!(Prot::from_flags(PF_R | PF_X).as_str(), "r-x");
        assert_eq!(Prot::from_flags(PF_R | PF_W).as_str(), "rw-");
    }
}
