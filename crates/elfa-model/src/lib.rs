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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use elfa_parse::{FileId, RelocTableKind, Segment, Span};

/// `mmap` granularity. Everything the kernel does to an image is in these units, and
/// forgetting that is the difference between "never loaded" and "loaded by accident".
pub const PAGE_SIZE: u64 = 4096;

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
    /// Parse a `/proc/<pid>/maps` permission field such as `r-xp`.
    #[must_use]
    pub fn from_perms(s: &str) -> Self {
        let has = |c: char| s.contains(c);
        Self {
            read: has('r'),
            write: has('w'),
            exec: has('x'),
        }
    }

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

/// A page-rounded mapping — what `/proc/<pid>/maps` shows.
///
/// A `PT_LOAD` says `0xab30 .. 0xb0a0`; `mmap` produces `0xa000 .. 0xc000`. The rounding
/// is not cosmetic: it decides whether a byte is in the process at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Vma {
    pub start: u64,
    pub end: u64,
    pub prot: Prot,
    /// File offset the mapping starts at, or `None` when it is anonymous. `/proc` prints
    /// this, and it is what decides whether two neighbours are one mapping or two.
    pub offset: Option<u64>,
    pub segment: u32,
}

/// A range of *file* bytes that ends up visible in memory, and where.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Resident {
    /// Everything reachable through this segment, page rounding included.
    pub file: Span,
    /// The segment's own `p_offset .. p_offset + p_filesz`, without the rounding.
    pub exact: Span,
    /// Virtual address of `file.start`.
    pub vaddr: u64,
    pub segment: u32,
}

const fn page_down(v: u64) -> u64 {
    v & !(PAGE_SIZE - 1)
}

fn page_up(v: u64) -> u64 {
    v.saturating_add(PAGE_SIZE - 1) & !(PAGE_SIZE - 1)
}

/// The address space of one loaded object.
#[derive(Clone, Debug, Default)]
pub struct MemImage {
    /// Segment extents, exactly as the headers state them. What the morph draws.
    mappings: Vec<Mapping>,
    /// Page-rounded mappings. What the kernel actually created.
    vmas: Vec<Vma>,
    /// File ranges that end up visible in a process. What "never loaded" is measured
    /// against.
    resident: Vec<Resident>,
}

impl MemImage {
    /// Build from the program headers, as the kernel would.
    ///
    /// For `ET_DYN` the addresses are relative to a load base the kernel randomises; they
    /// are used here as given, which is what `readelf` shows and what makes two runs
    /// comparable.
    ///
    /// `file_len` bounds the resident ranges: page rounding must not claim bytes past the
    /// end of the file.
    #[must_use]
    pub fn from_segments(segments: &[Segment], file_len: u64) -> Self {
        let mut mappings = Vec::new();
        let mut vmas = Vec::new();
        let mut resident = Vec::new();
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
            vmas.push(Vma {
                start: page_down(seg.vaddr),
                end: page_up(seg.vaddr.saturating_add(seg.memsz)),
                prot,
                offset: Some(page_down(seg.offset)),
                segment: idx,
            });

            // Page rounding extends the mapping at both ends, and the two ends follow
            // different rules.
            //
            // Leading: `mmap` starts at the page containing `p_offset`, so file bytes
            // before the segment — the tail of whatever precedes it — are pulled in too.
            //
            // Trailing: the kernel maps whole pages from the file, so the bytes after
            // `p_filesz` in the last page are also present *unless* the segment has a
            // zero-fill tail, in which case `padzero()` wipes them. That is why the rule
            // below is conditional on `memsz > filesz`.
            let file_lo = page_down(seg.offset);
            let page_off = seg.offset.saturating_sub(file_lo);
            let file_hi_exact = seg.offset.saturating_add(seg.filesz);
            let file_hi = if seg.memsz > seg.filesz {
                file_hi_exact
            } else {
                page_up(file_hi_exact)
            }
            .min(file_len);

            if file_hi > file_lo {
                resident.push(Resident {
                    file: Span::new(FileId::PRIMARY, file_lo, file_hi.saturating_sub(file_lo)),
                    exact: Span::new(FileId::PRIMARY, seg.offset, seg.filesz),
                    vaddr: seg.vaddr.saturating_sub(page_off),
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
        vmas.sort_unstable_by_key(|v| (v.start, v.end));
        resident.sort_unstable_by_key(|r| (r.file.start, r.file.len));
        Self {
            mappings,
            vmas,
            resident,
        }
    }

    #[must_use]
    pub fn vmas(&self) -> &[Vma] {
        &self.vmas
    }

    #[must_use]
    pub fn resident(&self) -> &[Resident] {
        &self.resident
    }

    /// Distinct file bytes that end up in a process, counting doubly-mapped bytes once.
    #[must_use]
    pub fn resident_bytes(&self) -> u64 {
        let mut total = 0u64;
        let mut cursor = 0u64;
        for r in &self.resident {
            let start = r.file.start.max(cursor);
            if r.file.end() > start {
                total = total.saturating_add(r.file.end().saturating_sub(start));
                cursor = r.file.end();
            }
        }
        total
    }

    /// File bytes that appear at more than one virtual address.
    ///
    /// Not a curiosity: when two segments share a file page, that page is mapped twice at
    /// different addresses with different protections.
    #[must_use]
    pub fn double_mapped_bytes(&self) -> u64 {
        let sum: u64 = self
            .resident
            .iter()
            .map(|r| r.file.len)
            .fold(0, u64::saturating_add);
        sum.saturating_sub(self.resident_bytes())
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
    /// Page-aware: a byte in the padding after a segment's content but inside its last
    /// mapped page *is* in the process, and this says so. Returns `None` for what is
    /// genuinely never loaded — section headers, symbol tables, debug info, and any
    /// padding large enough to fall outside every mapped page.
    ///
    /// When a byte is mapped twice, the segment that *owns* it wins.
    ///
    /// Page rounding means a byte can be reachable through a segment it does not belong
    /// to — `.dynamic` lives in the read-write segment but also appears in the read-only
    /// segment's last page. Answering with the accidental address would put `.dynamic` at
    /// an address where nothing reads it, and (worse) make it look unmapped whenever the
    /// accidental mapping had not been created yet.
    #[must_use]
    pub fn vaddr_of(&self, offset: u64) -> Option<u64> {
        let translate = |r: &Resident| r.vaddr.saturating_add(offset.saturating_sub(r.file.start));
        self.resident
            .iter()
            .find(|r| offset >= r.exact.start && offset < r.exact.end())
            .or_else(|| {
                self.resident
                    .iter()
                    .find(|r| offset >= r.file.start && offset < r.file.end())
            })
            .map(translate)
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
        let img = MemImage::from_segments(&[load(0x2db0, 0x3db0, 0x268, 0x690)], 0x4000);
        assert_eq!(img.mappings().len(), 2);
        assert_eq!(img.zero_filled_bytes(), 0x690 - 0x268);
        assert_eq!(img.mapped_bytes(), 0x268);
        // The zero-filled part begins where the file part ends.
        assert_eq!(img.mappings()[1].vaddr, 0x3db0 + 0x268);
        assert_eq!(img.mappings()[1].source, MapSource::ZeroFill);
    }

    #[test]
    fn file_offsets_outside_any_mapped_page_have_no_address() {
        let img = MemImage::from_segments(&[load(0x1000, 0x1000, 0x175, 0x175)], 0x4000);
        assert_eq!(img.vaddr_of(0x1000), Some(0x1000));
        assert_eq!(img.vaddr_of(0x1100), Some(0x1100));
        // Past p_filesz but inside the last mapped page: loaded, because mmap works in
        // whole pages. This is the correction that page-awareness buys.
        assert_eq!(img.vaddr_of(0x1500), Some(0x1500));
        assert_eq!(img.vaddr_of(0x1fff), Some(0x1fff));
        // The next page belongs to nothing.
        assert_eq!(img.vaddr_of(0x2000), None);
        assert_eq!(img.vaddr_of(0), None);
    }

    #[test]
    fn a_zero_fill_tail_stops_the_trailing_page_from_counting() {
        // memsz > filesz, so padzero() wipes the rest of the last page. Those file bytes
        // are not visible in the process even though their page is mapped.
        let img = MemImage::from_segments(&[load(0x2db0, 0x3db0, 0x268, 0x690)], 0x4000);
        assert_eq!(img.vaddr_of(0x3017), Some(0x4017));
        assert_eq!(img.vaddr_of(0x3018), None);
        // And the leading partial page is pulled in whole.
        assert_eq!(img.vaddr_of(0x2000), Some(0x3000));
    }

    #[test]
    fn a_byte_is_reported_at_the_address_of_the_segment_that_owns_it() {
        let img = MemImage::from_segments(
            &[
                load(0x2000, 0x2000, 0x140, 0x140),
                load(0x2db0, 0x3db0, 0x268, 0x690),
            ],
            0x4000,
        );
        // File 0x2db0 is .dynamic: it belongs to the read-write segment at 0x3db0, and is
        // only reachable at 0x2db0 because the read-only segment's last page includes it.
        assert_eq!(img.vaddr_of(0x2db0), Some(0x3db0));
        // A byte that only the rounding reaches still gets the accidental answer, which
        // is the truthful one: that is the only place it exists.
        assert_eq!(img.vaddr_of(0x2500), Some(0x2500));
    }

    #[test]
    fn two_segments_sharing_a_file_page_map_it_twice() {
        let img = MemImage::from_segments(
            &[
                load(0x2000, 0x2000, 0x140, 0x140),
                load(0x2db0, 0x3db0, 0x268, 0x690),
            ],
            0x4000,
        );
        // File page 0x2000 is reachable at 0x2000 and again at 0x3000.
        assert_eq!(img.resident().len(), 2);
        assert!(img.double_mapped_bytes() > 0);
        // resident_bytes counts each file byte once.
        assert!(img.resident_bytes() < 0x1000 + 0x1018);
    }

    #[test]
    fn vmas_are_page_rounded() {
        let img = MemImage::from_segments(&[load(0xab30, 0xab30, 0x570, 0x758)], 0x10000);
        let v = img.vmas()[0];
        assert_eq!((v.start, v.end), (0xa000, 0xc000));
        assert_eq!(v.offset, Some(0xa000));
    }

    #[test]
    fn non_load_segments_are_not_mapped_by_the_kernel() {
        let mut dynamic = load(0x2dc8, 0x3dc8, 0x1f0, 0x1f0);
        dynamic.p_type = 2; // PT_DYNAMIC — a view of bytes already inside a PT_LOAD
        let img = MemImage::from_segments(&[dynamic], 0x4000);
        assert!(img.is_empty());
    }

    #[test]
    fn protection_comes_from_the_flag_bits() {
        assert_eq!(Prot::from_flags(PF_R | PF_X).as_str(), "r-x");
        assert_eq!(Prot::from_flags(PF_R | PF_W).as_str(), "rw-");
    }
}

// ---------------------------------------------------------------------------
// The timeline
// ---------------------------------------------------------------------------

use alloc::format;
use alloc::string::{String, ToString};
use elfa_parse::{Reloc, Summary};

const PT_GNU_RELRO: u32 = 0x6474_e552;

/// Which part of the load a step belongs to. Mirrors `PROJECT_PLAN.md` §5.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Phase {
    Kernel,
    Interp,
    Resolve,
    Relocate,
    Protect,
    Init,
    Entry,
}

impl Phase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Interp => "interp",
            Self::Resolve => "resolve",
            Self::Relocate => "relocate",
            Self::Protect => "protect",
            Self::Init => "init",
            Self::Entry => "entry",
        }
    }
}

/// Who is doing the work. The distinction matters: the kernel's half of a load happens
/// before any userspace code of the program's has run at all.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Actor {
    Kernel,
    Interp,
    Program,
}

impl Actor {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Kernel => "kernel",
            Self::Interp => "ld.so",
            Self::Program => "program",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PokeCause {
    /// A relocation wrote an address into memory.
    Relocation { r_type: u32 },
    /// A pointer to an initialiser was read and called.
    InitPointer,
}

/// A write into the image, attributed to the step that made it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Poke {
    pub addr: u64,
    pub len: u8,
    pub cause: PokeCause,
}

/// What a step does to the image.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Effect {
    Map(Mapping),
    Protect { start: u64, len: u64, to: Prot },
    Write(Poke),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step {
    pub n: u32,
    pub phase: Phase,
    pub actor: Actor,
    pub narration: String,
    /// File bytes this step consults. Drives the byte-river highlight.
    pub reads: Vec<Span>,
    pub effects: Vec<Effect>,
}

/// A step before it has been numbered.
type Pending = (Phase, Actor, String, Vec<Span>, Vec<Effect>);

/// The modelled load, as an ordered list of steps.
///
/// Scope, deliberately: this models the **main object**. Dependencies are named as they
/// are resolved but not themselves mapped or relocated — doing that means loading and
/// parsing libc, which is real work and belongs in its own pass. What is here is already
/// checkable against an observed trace, and being checkable is the point.
#[derive(Clone, Debug, Default)]
pub struct Timeline {
    steps: Vec<Step>,
}

/// Carve `[lo, hi)` out of a mapping, keeping its file source aligned.
fn slice(m: &Mapping, lo: u64, hi: u64, prot: Prot) -> Mapping {
    let source = match m.source {
        MapSource::FromFile(span) => MapSource::FromFile(Span::new(
            span.file,
            span.start.saturating_add(lo.saturating_sub(m.vaddr)),
            hi.saturating_sub(lo),
        )),
        MapSource::ZeroFill => MapSource::ZeroFill,
    };
    Mapping {
        vaddr: lo,
        len: hi.saturating_sub(lo),
        prot,
        source,
        segment: m.segment,
    }
}

/// The image as of some step.
#[derive(Clone, Debug, Default)]
pub struct State {
    pub mappings: Vec<Mapping>,
    /// Addresses written so far, in the order they were written.
    pub poked: Vec<Poke>,
}

impl State {
    /// The mappings as the kernel would report them: page-rounded, and merged wherever
    /// adjacent pages share a protection.
    ///
    /// The raw `mappings` list is segment-exact — `.bss` is its own entry, and an
    /// `mprotect` split stays split even if both halves end up identical. `/proc` shows
    /// neither. Any comparison against an observed trace has to be made on this view, or
    /// it compares two different things and calls the difference a divergence.
    ///
    /// Built page by page so that later mappings overwrite earlier ones at the same
    /// address, which is what `mmap` and `mprotect` actually do.
    #[must_use]
    pub fn vmas(&self) -> Vec<Vma> {
        struct Page {
            prot: Prot,
            offset: Option<u64>,
            segment: u32,
        }
        let mut pages: BTreeMap<u64, Page> = BTreeMap::new();

        for m in &self.mappings {
            let base = page_down(m.vaddr);
            let mut page = base;
            let end = page_up(m.end());
            while page < end {
                let offset = match m.source {
                    MapSource::FromFile(span) => {
                        Some(page_down(span.start).saturating_add(page.saturating_sub(base)))
                    }
                    // A zero-fill tail shares the last file-backed page; the kernel maps
                    // that page from the file and wipes part of it, so the offset already
                    // recorded for the page is the right one.
                    MapSource::ZeroFill => pages.get(&page).and_then(|p| p.offset),
                };
                pages.insert(
                    page,
                    Page {
                        prot: m.prot,
                        offset,
                        segment: m.segment,
                    },
                );
                page = page.saturating_add(PAGE_SIZE);
            }
        }

        let mut out: Vec<Vma> = Vec::new();
        for (page, p) in pages {
            // Two neighbours merge only when they came from the same segment, their
            // protections agree, *and* their file offsets continue.
            //
            // The offset condition is why hello-dyn keeps two read-only VMAs: its
            // read-only and read-write segments both start inside file page 0x2000, so
            // the second does not continue the first.
            //
            // The segment condition is why /bin/true does. Its third segment ends at page
            // 0x9000 and RELRO turns the first page of the fourth read-only, leaving two
            // adjacent read-only pages whose offsets *do* line up — and the kernel still
            // reports them separately, because a VMA merge needs identical vm_flags and
            // those two carry different lineage. Modelling that as "never merge across
            // segments" reproduces every mapping table observed so far.
            let continues = out.last().is_some_and(|last| {
                last.end == page
                    && last.prot == p.prot
                    && last.segment == p.segment
                    && match (last.offset, p.offset) {
                        (Some(a), Some(b)) => {
                            a.saturating_add(page.saturating_sub(last.start)) == b
                        }
                        (None, None) => true,
                        _ => false,
                    }
            });
            match out.last_mut() {
                Some(last) if continues => last.end = page.saturating_add(PAGE_SIZE),
                _ => out.push(Vma {
                    start: page,
                    end: page.saturating_add(PAGE_SIZE),
                    prot: p.prot,
                    offset: p.offset,
                    segment: p.segment,
                }),
            }
        }
        out
    }

    /// Protection in force at an address, if it is mapped at all.
    #[must_use]
    pub fn prot_at(&self, addr: u64) -> Option<Prot> {
        self.mappings
            .iter()
            .find(|m| addr >= m.vaddr && addr < m.end())
            .map(|m| m.prot)
    }
}

impl Timeline {
    #[must_use]
    pub fn steps(&self) -> &[Step] {
        &self.steps
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Replay effects `0..=n`.
    ///
    /// State is derived rather than stored, so scrubbing backwards costs the same as
    /// scrubbing forwards and there is no way for the two to disagree.
    #[must_use]
    pub fn state_at(&self, n: usize) -> State {
        let mut state = State::default();
        for step in self.steps.iter().take(n.saturating_add(1)) {
            for effect in &step.effects {
                match effect {
                    Effect::Map(m) => state.mappings.push(*m),
                    Effect::Write(p) => state.poked.push(*p),
                    Effect::Protect { start, len, to } => {
                        // `mprotect` splits a mapping rather than recolouring it. This is
                        // why a hardened binary has more VMAs than it has segments, and
                        // modelling it as a recolour makes the mapping counts disagree
                        // with /proc for reasons that look like a bug in the diff.
                        let end = start.saturating_add(*len);
                        let mut out = Vec::with_capacity(state.mappings.len());
                        for m in state.mappings.drain(..) {
                            if m.end() <= *start || m.vaddr >= end {
                                out.push(m);
                                continue;
                            }
                            if m.vaddr < *start {
                                out.push(slice(&m, m.vaddr, *start, m.prot));
                            }
                            let mid_lo = m.vaddr.max(*start);
                            let mid_hi = m.end().min(end);
                            out.push(slice(&m, mid_lo, mid_hi, *to));
                            if m.end() > end {
                                out.push(slice(&m, end, m.end(), m.prot));
                            }
                        }
                        out.sort_unstable_by_key(|m| (m.vaddr, m.len));
                        state.mappings = out;
                    }
                }
            }
        }
        state
    }

    /// Build the timeline for one object.
    #[must_use]
    pub fn plan(summary: &Summary, image: &MemImage) -> Self {
        let mut steps: Vec<Pending> = Vec::new();

        let mut push = |phase, actor, narration: String, reads: Vec<Span>, effects| {
            steps.push((phase, actor, narration, reads, effects));
        };

        // --- the kernel ---
        push(
            Phase::Kernel,
            Actor::Kernel,
            "read the first page and check e_ident: magic, class, byte order, machine".to_string(),
            alloc::vec![Span::new(FileId::PRIMARY, 0, 64)],
            Vec::new(),
        );

        if let Some(interp) = &summary.interp {
            push(
                Phase::Kernel,
                Actor::Kernel,
                format!("PT_INTERP names {interp} — this program needs a loader"),
                Vec::new(),
                Vec::new(),
            );
        }

        for m in image.mappings() {
            let narration = match m.source {
                MapSource::FromFile(span) => format!(
                    "map segment {}: file {:#x}..{:#x} → {:#x} {}",
                    m.segment,
                    span.start,
                    span.end(),
                    m.vaddr,
                    m.prot.as_str()
                ),
                MapSource::ZeroFill => format!(
                    "zero-fill {:#x}..{:#x} — p_memsz beyond p_filesz, this is .bss and it is in no file",
                    m.vaddr,
                    m.end()
                ),
            };
            let reads = match m.source {
                MapSource::FromFile(span) => alloc::vec![span],
                MapSource::ZeroFill => Vec::new(),
            };
            push(
                Phase::Kernel,
                Actor::Kernel,
                narration,
                reads,
                alloc::vec![Effect::Map(*m)],
            );
        }

        push(
            Phase::Kernel,
            Actor::Kernel,
            "build the stack: argv, envp, and the auxiliary vector (AT_PHDR, AT_BASE, AT_ENTRY, AT_RANDOM)"
                .to_string(),
            Vec::new(),
            Vec::new(),
        );

        if summary.interp.is_some() {
            push(
                Phase::Kernel,
                Actor::Kernel,
                "jump to the *interpreter's* entry — the program's own entry does not run first"
                    .to_string(),
                Vec::new(),
                Vec::new(),
            );
            push(
                Phase::Interp,
                Actor::Interp,
                "ld.so relocates itself before it can touch a global variable".to_string(),
                Vec::new(),
                Vec::new(),
            );
            push(
                Phase::Interp,
                Actor::Interp,
                "read PT_DYNAMIC: the table that drives everything after this point".to_string(),
                Vec::new(),
                Vec::new(),
            );
        }

        for needed in &summary.needed {
            push(
                Phase::Resolve,
                Actor::Interp,
                format!(
                    "DT_NEEDED {needed}: search DT_RPATH, LD_LIBRARY_PATH, DT_RUNPATH, ld.so.cache, then the default directories"
                ),
                Vec::new(),
                Vec::new(),
            );
        }

        if !summary.needed.is_empty() {
            push(
                Phase::Resolve,
                Actor::Interp,
                "build the global symbol scope — first definition wins, and LD_PRELOAD goes in ahead of the dependencies"
                    .to_string(),
                Vec::new(),
                Vec::new(),
            );
        }

        // --- relocation, in the order glibc applies the tables ---
        let mut deferred_plt = 0usize;
        for table in [
            RelocTableKind::Relr,
            RelocTableKind::Rela,
            RelocTableKind::Rel,
            RelocTableKind::JmpRel,
        ] {
            let group: Vec<&Reloc> = summary.relocs.iter().filter(|r| r.table == table).collect();
            if group.is_empty() {
                continue;
            }
            // Under lazy binding the PLT relocations are *not* applied here. Listing
            // them as writes in this pass would be the 2008 animation: it is the thing
            // §0.6 exists to avoid.
            let lazy = table == RelocTableKind::JmpRel && !summary.bind_now;
            push(
                Phase::Relocate,
                Actor::Interp,
                format!(
                    "{}: {}{}",
                    table_name(table),
                    plural(group.len(), "relocation"),
                    if lazy {
                        " — lazy, so nothing is written yet"
                    } else {
                        ""
                    }
                ),
                Vec::new(),
                Vec::new(),
            );
            if lazy {
                deferred_plt = group.len();
                continue;
            }
            for r in group {
                let what = elfa_parse::elf::r_x86_64_name(r.r_type)
                    .map_or_else(|| format!("type {}", r.r_type), ToString::to_string);
                let sym = r
                    .symbol
                    .as_deref()
                    .map_or_else(String::new, |s| format!(" → {s}"));
                push(
                    Phase::Relocate,
                    Actor::Interp,
                    format!("write {:#x}: {what}{sym}", r.offset),
                    alloc::vec![r.file_span],
                    alloc::vec![Effect::Write(Poke {
                        addr: r.offset,
                        len: 8,
                        cause: PokeCause::Relocation { r_type: r.r_type },
                    })],
                );
            }
        }

        // --- RELRO ---
        //
        // Both ends round *down*, which is what glibc's _dl_protect_relro does:
        //
        //     start = ALIGN_DOWN(l_addr + l_relro_addr, pagesize);
        //     end   = ALIGN_DOWN(l_addr + l_relro_addr + l_relro_size, pagesize);
        //
        // Rounding the end up would be the flattering answer rather than the true one: a
        // RELRO region that stops mid-page leaves that page writable, and a tool that
        // reports it as sealed is worse than one that says nothing.
        if let Some(relro) = summary.segments.iter().find(|s| s.p_type == PT_GNU_RELRO) {
            let start = page_down(relro.vaddr);
            let end = page_down(relro.vaddr.saturating_add(relro.memsz));
            let partial = relro.vaddr.saturating_add(relro.memsz) > end;
            if end > start {
                push(
                    Phase::Protect,
                    Actor::Interp,
                    format!(
                        "mprotect {:#x}..{:#x} read-only — PT_GNU_RELRO: the GOT is sealed now that relocation is done{}",
                        start,
                        end,
                        if partial {
                            ", and the partial page above it stays writable"
                        } else {
                            ""
                        }
                    ),
                    Vec::new(),
                    alloc::vec![Effect::Protect {
                        start,
                        len: end.saturating_sub(start),
                        to: Prot {
                            read: true,
                            write: false,
                            exec: false,
                        },
                    }],
                );
            }
        }

        // --- initialisers ---
        if let Some(init) = summary.init {
            push(
                Phase::Init,
                Actor::Interp,
                format!("call DT_INIT at {init:#x}"),
                Vec::new(),
                Vec::new(),
            );
        }
        if let Some((addr, size)) = summary.init_array
            && size > 0
        {
            let count = size / 8;
            push(
                Phase::Init,
                Actor::Interp,
                format!(
                    "run DT_INIT_ARRAY at {addr:#x}: {} — C++ static constructors and __attribute__((constructor)) live here",
                    plural(count as usize, "initialiser")
                ),
                Vec::new(),
                Vec::new(),
            );
        }

        push(
            Phase::Entry,
            Actor::Program,
            format!(
                "transfer control to {:#x}: _start → __libc_start_main → main",
                summary.entry
            ),
            Vec::new(),
            Vec::new(),
        );

        if deferred_plt > 0 {
            push(
                Phase::Entry,
                Actor::Program,
                format!(
                    "first call through each PLT stub traps into _dl_runtime_resolve, which patches the GOT: {} still unresolved as main begins",
                    plural(deferred_plt, "entry")
                ),
                Vec::new(),
                Vec::new(),
            );
        }

        Self {
            steps: steps
                .into_iter()
                .enumerate()
                .map(|(i, (phase, actor, narration, reads, effects))| Step {
                    n: u32::try_from(i).unwrap_or(u32::MAX),
                    phase,
                    actor,
                    narration,
                    reads,
                    effects,
                })
                .collect(),
        }
    }
}

/// English, so the narration does not say "1 relocations".
fn plural(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else if let Some(stem) = noun.strip_suffix('y') {
        format!("{n} {stem}ies")
    } else {
        format!("{n} {noun}s")
    }
}

const fn table_name(t: RelocTableKind) -> &'static str {
    match t {
        RelocTableKind::Rel => "DT_REL",
        RelocTableKind::Rela => "DT_RELA",
        RelocTableKind::Relr => "DT_RELR",
        RelocTableKind::JmpRel => "DT_JMPREL",
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used
)]
mod timeline_tests {
    use super::*;
    use elfa_parse::{RelocTableKind, Summary};

    fn seg(p_type: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64, flags: u32) -> Segment {
        Segment {
            p_type,
            flags,
            offset,
            vaddr,
            filesz,
            memsz,
            align: 0x1000,
        }
    }

    fn reloc(table: RelocTableKind, offset: u64, r_type: u32) -> elfa_parse::Reloc {
        elfa_parse::Reloc {
            table,
            offset,
            r_type,
            addend: 0,
            symbol: None,
            weak: false,
            file_span: Span::new(FileId::PRIMARY, 0, 24),
        }
    }

    fn summary(bind_now: bool) -> Summary {
        Summary {
            entry: 0x1050,
            interp: Some("/lib64/ld-linux-x86-64.so.2".into()),
            bind_now,
            has_dynamic: true,
            segments: alloc::vec![
                seg(PT_LOAD, 0, 0, 0x670, 0x670, PF_R),
                seg(PT_LOAD, 0x2db0, 0x3db0, 0x268, 0x690, PF_R | PF_W),
                seg(PT_GNU_RELRO, 0x2db0, 0x3db0, 0x250, 0x250, PF_R),
            ],
            relocs: alloc::vec![
                reloc(RelocTableKind::Relr, 0x3db0, 8),
                reloc(RelocTableKind::JmpRel, 0x4000, 7),
            ],
            ..Summary::default()
        }
    }

    fn plan(bind_now: bool) -> (Timeline, Summary) {
        let s = summary(bind_now);
        let image = MemImage::from_segments(&s.segments, 0x4000);
        (Timeline::plan(&s, &image), s)
    }

    #[test]
    fn lazy_binding_writes_nothing_during_relocation() {
        let (tl, _) = plan(false);
        let writes: Vec<u64> = tl
            .steps()
            .iter()
            .flat_map(|s| s.effects.iter())
            .filter_map(|e| match e {
                Effect::Write(p) => Some(p.addr),
                _ => None,
            })
            .collect();
        // The RELR relocation is applied; the PLT one is not.
        assert_eq!(writes, alloc::vec![0x3db0]);

        // And the timeline says where it went instead.
        assert!(
            tl.steps()
                .iter()
                .any(|s| s.narration.contains("_dl_runtime_resolve")),
            "lazy PLT must be accounted for after control transfers"
        );
    }

    #[test]
    fn bind_now_applies_the_plt_relocations_up_front() {
        let (tl, _) = plan(true);
        let writes: Vec<u64> = tl
            .steps()
            .iter()
            .flat_map(|s| s.effects.iter())
            .filter_map(|e| match e {
                Effect::Write(p) => Some(p.addr),
                _ => None,
            })
            .collect();
        assert_eq!(writes, alloc::vec![0x3db0, 0x4000]);
        assert!(
            !tl.steps()
                .iter()
                .any(|s| s.narration.contains("_dl_runtime_resolve"))
        );
    }

    #[test]
    fn a_relro_range_that_stops_mid_page_leaves_that_page_writable() {
        // glibc rounds the RELRO end *down*. The fixtures on this host both happen to end
        // on a page boundary, which hides the difference; this does not.
        let mut s = summary(true);
        s.segments = alloc::vec![
            seg(PT_LOAD, 0x2db0, 0x3db0, 0x268, 0x690, PF_R | PF_W),
            seg(PT_GNU_RELRO, 0x2db0, 0x3db0, 0x200, 0x200, PF_R),
        ];
        let image = MemImage::from_segments(&s.segments, 0x4000);
        let tl = Timeline::plan(&s, &image);

        // 0x3db0 + 0x200 = 0x3fb0, which rounds down to 0x3000 — equal to the start, so
        // glibc protects nothing at all and the model must not pretend otherwise.
        assert!(
            !tl.steps().iter().any(|s| s.phase == Phase::Protect),
            "an empty RELRO range must not produce a protect step"
        );
        let end = tl.state_at(tl.len().saturating_sub(1));
        assert!(
            end.prot_at(0x3db0).expect("mapped").write,
            "nothing was sealed, so the GOT is still writable"
        );
    }

    #[test]
    fn relro_seals_its_own_range_and_splits_the_mapping() {
        let (tl, _) = plan(true);
        let protect_at = tl
            .steps()
            .iter()
            .position(|s| s.phase == Phase::Protect)
            .expect("a protect step");

        let before = tl.state_at(protect_at - 1);
        let after = tl.state_at(protect_at);

        // The GOT and .init_array live here: writable during relocation, sealed after.
        assert!(before.prot_at(0x3db0).expect("mapped").write);
        assert!(!after.prot_at(0x3db0).expect("mapped").write);

        // .bss is past the RELRO range and must stay writable — a model that seals the
        // whole segment would break every program that has a global variable.
        assert!(after.prot_at(0x4100).expect("mapped").write);

        // mprotect splits, so there is one more mapping than before.
        assert!(
            after.mappings.len() > before.mappings.len(),
            "expected a split: {:?}",
            after.mappings
        );
    }

    #[test]
    fn the_loader_changes_protection_but_never_what_is_mapped() {
        let (tl, _) = plan(true);
        let kernel_end = tl
            .steps()
            .iter()
            .rposition(|s| s.phase == Phase::Kernel)
            .expect("kernel steps");
        let end = tl.len().saturating_sub(1);

        let bytes = |st: &State| -> u64 { st.mappings.iter().map(|m| m.len).sum() };
        // Everything the process will ever have is mapped by the time the kernel is
        // done. The loader splits and re-protects; it does not add address space.
        assert_eq!(bytes(&tl.state_at(kernel_end)), bytes(&tl.state_at(end)));
        // But it does change how many mappings that takes.
        assert!(tl.state_at(end).mappings.len() > tl.state_at(kernel_end).mappings.len());
    }

    #[test]
    fn vmas_are_page_rounded_and_merged() {
        let (tl, _) = plan(true);
        let end = tl.state_at(tl.len().saturating_sub(1));
        let vmas = end.vmas();

        // Page-aligned at both ends, contiguous where protections agree, and strictly
        // ordered — the shape /proc reports.
        for w in vmas.windows(2) {
            assert!(w[0].end <= w[1].start, "vmas overlap: {vmas:?}");
            // Adjacent, same protection *and* continuing file offset would have merged.
            let would_merge = w[0].end == w[1].start
                && w[0].prot == w[1].prot
                && match (w[0].offset, w[1].offset) {
                    (Some(a), Some(b)) => a + (w[1].start - w[0].start) == b,
                    (None, None) => true,
                    _ => false,
                };
            assert!(!would_merge, "vmas were not merged: {vmas:?}");
        }
        for v in &vmas {
            assert_eq!(v.start % PAGE_SIZE, 0);
            assert_eq!(v.end % PAGE_SIZE, 0);
        }
        // The raw list is more granular than the merged one: .bss is its own mapping but
        // shares a page and a protection with what precedes it.
        assert!(vmas.len() < end.mappings.len(), "{vmas:?}");
    }

    #[test]
    fn neighbours_from_different_segments_never_merge() {
        // Two read-only pages, adjacent, with offsets that line up perfectly — and the
        // kernel still reports them separately, because they came from different
        // segments. /bin/true does exactly this after RELRO.
        let state = State {
            mappings: alloc::vec![
                Mapping {
                    vaddr: 0x7000,
                    len: 0x2000,
                    prot: Prot::from_flags(PF_R),
                    source: MapSource::FromFile(Span::new(FileId::PRIMARY, 0x7000, 0x2000)),
                    segment: 3,
                },
                Mapping {
                    vaddr: 0x9000,
                    len: 0x1000,
                    prot: Prot::from_flags(PF_R),
                    source: MapSource::FromFile(Span::new(FileId::PRIMARY, 0x9000, 0x1000)),
                    segment: 4,
                },
            ],
            poked: Vec::new(),
        };
        let vmas = state.vmas();
        assert_eq!(vmas.len(), 2, "different segments must not merge: {vmas:?}");
        assert_eq!(vmas[0].end, vmas[1].start);
        assert_eq!(vmas[0].prot, vmas[1].prot);
    }

    #[test]
    fn narration_counts_in_english() {
        assert_eq!(plural(1, "relocation"), "1 relocation");
        assert_eq!(plural(2, "relocation"), "2 relocations");
        assert_eq!(plural(1, "entry"), "1 entry");
        assert_eq!(plural(3, "entry"), "3 entries");
    }
}
