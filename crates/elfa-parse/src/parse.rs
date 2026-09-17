//! The ELF64 parser.
//!
//! Produces a [`Coverage`] in which every byte of the file is accounted for. Structures
//! are claimed at three levels — table, entry, field — so the UI can zoom from "this is
//! the program header table" to "these eight bytes are `p_memsz`, and they are why there
//! is a region of memory with no file behind it".
//!
//! Phase 1a is ELF64 little-endian. Other classes and byte orders are rejected by name
//! rather than misparsed; they arrive in phase 5.

use alloc::borrow::ToOwned;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::claim::{Claim, ClaimId, ClaimKind, RelocTableKind, Value, VersionTableKind};
use crate::coverage::{Coverage, CoverageBuilder, CoverageError};
use crate::elf;
use crate::reader::Reader;
use crate::span::{FileId, Span};

const F: FileId = FileId::PRIMARY;

/// Why a file could not be parsed at all.
///
/// Note how few of these there are. Structural nonsense *inside* a file is not an error —
/// it becomes an `Unclaimed` region or a coverage failure that `elfa verify` reports. Only
/// "this is not an ELF64 LE file" stops the parse.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseError {
    TooSmall { len: u64 },
    BadMagic { found: [u8; 4] },
    UnsupportedClass { class: u8 },
    UnsupportedData { data: u8 },
    Truncated { what: &'static str, off: u64 },
    Coverage(CoverageError),
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall { len } => {
                write!(f, "file is {len} bytes; an ELF64 header needs 64")
            }
            Self::BadMagic { found } => write!(
                f,
                "not an ELF file: magic is {found:02x?}, expected [7f, 45, 4c, 46]"
            ),
            Self::UnsupportedClass { class } => match *class {
                elf::ELFCLASS32 => write!(f, "ELF32 is not supported yet (phase 5)"),
                other => write!(f, "unknown EI_CLASS {other}"),
            },
            Self::UnsupportedData { data } => match *data {
                elf::ELFDATA2MSB => write!(f, "big-endian ELF is not supported yet (phase 5)"),
                other => write!(f, "unknown EI_DATA {other}"),
            },
            Self::Truncated { what, off } => {
                write!(f, "file ends inside {what} at offset {off:#x}")
            }
            Self::Coverage(e) => write!(f, "coverage: {e}"),
        }
    }
}

impl core::error::Error for ParseError {}

impl From<CoverageError> for ParseError {
    fn from(e: CoverageError) -> Self {
        Self::Coverage(e)
    }
}

/// One program header, decoded.
///
/// The loader model needs these as values, not as claims: walking the claim tree to
/// recover `p_vaddr` would mean parsing the parse output.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Segment {
    pub p_type: u32,
    pub flags: u32,
    pub offset: u64,
    pub vaddr: u64,
    pub filesz: u64,
    pub memsz: u64,
    pub align: u64,
}

impl Segment {
    /// Bytes the kernel zero-fills because they are in `p_memsz` but not `p_filesz`.
    /// This is `.bss`, and it is the part of a process that exists in no file.
    #[must_use]
    pub const fn zero_fill(&self) -> u64 {
        self.memsz.saturating_sub(self.filesz)
    }
}

/// One relocation, decoded.
///
/// `DT_RELR` entries are expanded here: a bitmap word encodes up to 63 relative
/// relocations, and the loader applies them individually, so the model must see them
/// individually. `file_span` points at the entry (or the bitmap word) that produced this.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Reloc {
    pub table: RelocTableKind,
    /// `r_offset` — the address to be written.
    pub offset: u64,
    pub r_type: u32,
    pub addend: i64,
    pub symbol: Option<Box<str>>,
    /// The referenced symbol is weak-undefined. The loader does not fail on these and
    /// does not report binding them: they resolve to zero and nothing happens.
    pub weak: bool,
    pub file_span: Span,
}

/// Header-level facts, pulled out so callers do not have to walk the claim tree to print
/// a one-line description of a file.
#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub e_type: u16,
    pub machine: u16,
    pub entry: u64,
    pub phnum: u64,
    pub shnum: u64,
    pub interp: Option<Box<str>>,
    pub needed: Vec<Box<str>>,
    pub soname: Option<Box<str>>,
    pub bind_now: bool,
    pub has_relr: bool,
    pub has_dynamic: bool,
    pub segments: Vec<Segment>,
    pub relocs: Vec<Reloc>,
    /// `DT_INIT`, and `DT_INIT_ARRAY` with its size — the code that runs before `main`.
    pub init: Option<u64>,
    pub init_array: Option<(u64, u64)>,
}

#[derive(Clone, Debug)]
pub struct Parsed {
    pub coverage: Coverage,
    pub summary: Summary,
}

#[derive(Clone, Copy, Debug, Default)]
struct SectionInfo {
    name_off: u32,
    sh_type: u32,
    offset: u64,
    size: u64,
    link: u32,
    entsize: u64,
}

/// Parse an ELF64 little-endian file into a total coverage.
pub fn parse(bytes: &[u8]) -> Result<Parsed, ParseError> {
    let len = bytes.len() as u64;
    if len < elf::EHDR64_SIZE {
        return Err(ParseError::TooSmall { len });
    }

    let magic: [u8; 4] = bytes
        .get(0..4)
        .and_then(|s| s.try_into().ok())
        .ok_or(ParseError::TooSmall { len })?;
    if magic != elf::ELF_MAGIC {
        return Err(ParseError::BadMagic { found: magic });
    }

    let class = bytes.get(4).copied().unwrap_or(0);
    if class != elf::ELFCLASS64 {
        return Err(ParseError::UnsupportedClass { class });
    }
    let data = bytes.get(5).copied().unwrap_or(0);
    if data != elf::ELFDATA2LSB {
        return Err(ParseError::UnsupportedData { data });
    }

    let r = Reader::new(bytes, true);
    let mut b = CoverageBuilder::new();
    b.add_file(F, len);
    let mut summary = Summary::default();

    let ehdr = parse_ehdr(&r, &mut b, &mut summary)?;
    let phoff = r.u64_at(32).unwrap_or(0);
    let shoff = r.u64_at(40).unwrap_or(0);
    let phentsize = u64::from(r.u16_at(54).unwrap_or(0));
    let shentsize = u64::from(r.u16_at(58).unwrap_or(0));
    let mut phnum = u64::from(r.u16_at(56).unwrap_or(0));
    let mut shnum = u64::from(r.u16_at(60).unwrap_or(0));
    let shstrndx = u64::from(r.u16_at(62).unwrap_or(0));
    let _ = ehdr;

    // Both counts have an escape hatch for files with more than 0xffff of a thing; the
    // real value hides in section 0, which is otherwise all zeroes.
    if shoff != 0 && shentsize >= elf::SHDR64_SIZE {
        if shnum == 0 {
            shnum = r.u64_at(shoff.saturating_add(32)).unwrap_or(0);
        }
        if phnum == u64::from(elf::PN_XNUM) {
            phnum = u64::from(r.u32_at(shoff.saturating_add(44)).unwrap_or(0));
        }
    }
    summary.phnum = phnum;
    summary.shnum = shnum;

    let sections = parse_shdrs(&r, &mut b, shoff, shnum, shentsize, shstrndx)?;
    parse_phdrs(&r, &mut b, phoff, phnum, phentsize, &sections, &mut summary)?;
    parse_section_bodies(&r, &mut b, &sections, shstrndx, &mut summary)?;

    b.fill_unclaimed();
    let coverage = b.finish()?;
    Ok(Parsed { coverage, summary })
}

fn push(b: &mut CoverageBuilder, c: Claim) -> Result<ClaimId, ParseError> {
    b.push(c).map_err(ParseError::Coverage)
}

fn field(
    b: &mut CoverageBuilder,
    parent: ClaimId,
    kind: ClaimKind,
    off: u64,
    len: u64,
    value: Value,
    note: Option<String>,
) -> Result<(), ParseError> {
    let mut claim = Claim::new(Span::new(F, off, len), kind).child_of(parent);
    claim.value = value;
    if let Some(n) = note {
        claim.note = Some(n.into_boxed_str());
    }
    push(b, claim)?;
    Ok(())
}

fn named(value: u64, name: Option<&'static str>) -> Option<String> {
    name.map(ToOwned::to_owned)
        .or_else(|| Some(format!("unknown ({value:#x})")))
}

fn parse_ehdr(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    summary: &mut Summary,
) -> Result<ClaimId, ParseError> {
    let ehdr = push(
        b,
        Claim::new(Span::new(F, 0, elf::EHDR64_SIZE), ClaimKind::FileHeader).with_note(
            "the only structure at a fixed location; everything else is found through it",
        ),
    )?;

    let ident = push(
        b,
        Claim::new(
            Span::new(F, 0, 16),
            ClaimKind::FileHeaderField { name: "e_ident" },
        )
        .child_of(ehdr),
    )?;
    for (off, len, name, note) in [
        (0u64, 4u64, "ei_mag", Some("\\x7fELF")),
        (4, 1, "ei_class", Some("ELFCLASS64")),
        (5, 1, "ei_data", Some("ELFDATA2LSB")),
        (6, 1, "ei_version", None),
        (7, 1, "ei_osabi", None),
        (8, 1, "ei_abiversion", None),
        (9, 7, "ei_pad", Some("reserved, must be zero")),
    ] {
        field(
            b,
            ident,
            ClaimKind::FileHeaderField { name },
            off,
            len,
            if len == 1 {
                Value::Unsigned(u64::from(r.u8_at(off).unwrap_or(0)))
            } else {
                Value::Raw
            },
            note.map(ToOwned::to_owned),
        )?;
    }

    let e_type = r.u16_at(16).unwrap_or(0);
    let machine = r.u16_at(18).unwrap_or(0);
    let entry = r.u64_at(24).unwrap_or(0);
    summary.e_type = e_type;
    summary.machine = machine;
    summary.entry = entry;

    field(
        b,
        ehdr,
        ClaimKind::FileHeaderField { name: "e_type" },
        16,
        2,
        Value::Unsigned(u64::from(e_type)),
        named(u64::from(e_type), elf::et_name(e_type)),
    )?;
    field(
        b,
        ehdr,
        ClaimKind::FileHeaderField { name: "e_machine" },
        18,
        2,
        Value::Unsigned(u64::from(machine)),
        named(u64::from(machine), elf::em_name(machine)),
    )?;
    field(
        b,
        ehdr,
        ClaimKind::FileHeaderField { name: "e_version" },
        20,
        4,
        Value::Unsigned(u64::from(r.u32_at(20).unwrap_or(0))),
        None,
    )?;
    field(
        b,
        ehdr,
        ClaimKind::FileHeaderField { name: "e_entry" },
        24,
        8,
        Value::Address(entry),
        Some(if e_type == 3 {
            "first instruction, relative to the load base".to_owned()
        } else {
            "first instruction".to_owned()
        }),
    )?;

    for (off, len, name, value) in [
        (
            32u64,
            8u64,
            "e_phoff",
            Value::FileOffset(r.u64_at(32).unwrap_or(0)),
        ),
        (
            40,
            8,
            "e_shoff",
            Value::FileOffset(r.u64_at(40).unwrap_or(0)),
        ),
        (
            48,
            4,
            "e_flags",
            Value::Flags(u64::from(r.u32_at(48).unwrap_or(0))),
        ),
        (
            52,
            2,
            "e_ehsize",
            Value::Unsigned(u64::from(r.u16_at(52).unwrap_or(0))),
        ),
        (
            54,
            2,
            "e_phentsize",
            Value::Unsigned(u64::from(r.u16_at(54).unwrap_or(0))),
        ),
        (
            56,
            2,
            "e_phnum",
            Value::Unsigned(u64::from(r.u16_at(56).unwrap_or(0))),
        ),
        (
            58,
            2,
            "e_shentsize",
            Value::Unsigned(u64::from(r.u16_at(58).unwrap_or(0))),
        ),
        (
            60,
            2,
            "e_shnum",
            Value::Unsigned(u64::from(r.u16_at(60).unwrap_or(0))),
        ),
        (
            62,
            2,
            "e_shstrndx",
            Value::Unsigned(u64::from(r.u16_at(62).unwrap_or(0))),
        ),
    ] {
        field(
            b,
            ehdr,
            ClaimKind::FileHeaderField { name },
            off,
            len,
            value,
            None,
        )?;
    }

    Ok(ehdr)
}

fn parse_phdrs(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    phoff: u64,
    phnum: u64,
    phentsize: u64,
    sections: &[SectionInfo],
    summary: &mut Summary,
) -> Result<(), ParseError> {
    if phoff == 0 || phnum == 0 || phentsize == 0 {
        return Ok(());
    }
    let table_len = phnum.saturating_mul(phentsize);
    if r.slice_at(phoff, table_len).is_none() {
        return Err(ParseError::Truncated {
            what: "the program header table",
            off: phoff,
        });
    }

    let table = push(
        b,
        Claim::new(
            Span::new(F, phoff, table_len),
            ClaimKind::ProgramHeaderTable,
        )
        .with_note(
            "what the kernel reads; the section headers below are for tools, not for loading",
        ),
    )?;

    for i in 0..phnum {
        let base = phoff.saturating_add(i.saturating_mul(phentsize));
        let idx = u32::try_from(i).unwrap_or(u32::MAX);
        let p_type = r.u32_at(base).unwrap_or(0);
        let p_offset = r.u64_at(base.saturating_add(8)).unwrap_or(0);
        let p_filesz = r.u64_at(base.saturating_add(32)).unwrap_or(0);
        let p_memsz = r.u64_at(base.saturating_add(40)).unwrap_or(0);

        let entry = push(
            b,
            Claim::new(
                Span::new(F, base, phentsize),
                ClaimKind::ProgramHeader { idx },
            )
            .child_of(table)
            .with_note(named(u64::from(p_type), elf::pt_name(p_type)).unwrap_or_default()),
        )?;

        for (off, flen, name, value) in [
            (0u64, 4u64, "p_type", Value::Unsigned(u64::from(p_type))),
            (
                4,
                4,
                "p_flags",
                Value::Flags(u64::from(r.u32_at(base.saturating_add(4)).unwrap_or(0))),
            ),
            (8, 8, "p_offset", Value::FileOffset(p_offset)),
            (
                16,
                8,
                "p_vaddr",
                Value::Address(r.u64_at(base.saturating_add(16)).unwrap_or(0)),
            ),
            (
                24,
                8,
                "p_paddr",
                Value::Address(r.u64_at(base.saturating_add(24)).unwrap_or(0)),
            ),
            (32, 8, "p_filesz", Value::Unsigned(p_filesz)),
            (40, 8, "p_memsz", Value::Unsigned(p_memsz)),
            (
                48,
                8,
                "p_align",
                Value::Unsigned(r.u64_at(base.saturating_add(48)).unwrap_or(0)),
            ),
        ] {
            if off.saturating_add(flen) > phentsize {
                break;
            }
            // The one field pair the whole project is about.
            let note = if name == "p_memsz" && p_memsz > p_filesz {
                Some(format!(
                    "{} bytes beyond p_filesz are zero-filled at load: .bss, present in no file",
                    p_memsz.saturating_sub(p_filesz)
                ))
            } else {
                None
            };
            field(
                b,
                entry,
                ClaimKind::ProgramHeaderField { idx, name },
                base.saturating_add(off),
                flen,
                value,
                note,
            )?;
        }

        summary.segments.push(crate::parse::Segment {
            p_type,
            flags: r.u32_at(base.saturating_add(4)).unwrap_or(0),
            offset: p_offset,
            vaddr: r.u64_at(base.saturating_add(16)).unwrap_or(0),
            filesz: p_filesz,
            memsz: p_memsz,
            align: r.u64_at(base.saturating_add(48)).unwrap_or(0),
        });

        if p_type == 2 {
            summary.has_dynamic = true;
        }
        if p_type == 3
            && summary.interp.is_none()
            && let Some(s) = r.cstr_at(p_offset, p_filesz)
        {
            summary.interp = core::str::from_utf8(s).ok().map(Into::into);
        }
    }
    let _ = sections;
    Ok(())
}

fn parse_shdrs(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    shoff: u64,
    shnum: u64,
    shentsize: u64,
    shstrndx: u64,
) -> Result<Vec<SectionInfo>, ParseError> {
    let mut out = Vec::new();
    if shoff == 0 || shnum == 0 || shentsize == 0 {
        return Ok(out);
    }
    let table_len = shnum.saturating_mul(shentsize);
    if r.slice_at(shoff, table_len).is_none() {
        return Err(ParseError::Truncated {
            what: "the section header table",
            off: shoff,
        });
    }

    let table = push(
        b,
        Claim::new(
            Span::new(F, shoff, table_len),
            ClaimKind::SectionHeaderTable,
        )
        .with_note("not loaded into memory; `strip` removes most of what it describes"),
    )?;

    // Two passes: a section header's name lives in a string table named by another
    // section header, so no name is knowable until every header has been read.
    for i in 0..shnum {
        let base = shoff.saturating_add(i.saturating_mul(shentsize));
        out.push(SectionInfo {
            name_off: r.u32_at(base).unwrap_or(0),
            sh_type: r.u32_at(base.saturating_add(4)).unwrap_or(0),
            offset: r.u64_at(base.saturating_add(24)).unwrap_or(0),
            size: r.u64_at(base.saturating_add(32)).unwrap_or(0),
            link: r.u32_at(base.saturating_add(40)).unwrap_or(0),
            entsize: r.u64_at(base.saturating_add(56)).unwrap_or(0),
        });
    }

    for i in 0..shnum {
        let base = shoff.saturating_add(i.saturating_mul(shentsize));
        let idx = u32::try_from(i).unwrap_or(u32::MAX);
        let Some(info) = usize::try_from(i).ok().and_then(|n| out.get(n)).copied() else {
            break;
        };
        let type_name =
            named(u64::from(info.sh_type), elf::sht_name(info.sh_type)).unwrap_or_default();
        let name = section_name(r, &out, shstrndx, info.name_off);

        let entry = push(
            b,
            Claim::new(
                Span::new(F, base, shentsize),
                ClaimKind::SectionHeader { idx },
            )
            .child_of(table)
            .with_note(if name.is_empty() {
                type_name
            } else {
                format!("{name}  {type_name}")
            }),
        )?;

        for (off, flen, name, value) in [
            (
                0u64,
                4u64,
                "sh_name",
                Value::Unsigned(u64::from(info.name_off)),
            ),
            (4, 4, "sh_type", Value::Unsigned(u64::from(info.sh_type))),
            (
                8,
                8,
                "sh_flags",
                Value::Flags(r.u64_at(base.saturating_add(8)).unwrap_or(0)),
            ),
            (
                16,
                8,
                "sh_addr",
                Value::Address(r.u64_at(base.saturating_add(16)).unwrap_or(0)),
            ),
            (24, 8, "sh_offset", Value::FileOffset(info.offset)),
            (32, 8, "sh_size", Value::Unsigned(info.size)),
            (40, 4, "sh_link", Value::Unsigned(u64::from(info.link))),
            (
                44,
                4,
                "sh_info",
                Value::Unsigned(u64::from(r.u32_at(base.saturating_add(44)).unwrap_or(0))),
            ),
            (
                48,
                8,
                "sh_addralign",
                Value::Unsigned(r.u64_at(base.saturating_add(48)).unwrap_or(0)),
            ),
            (56, 8, "sh_entsize", Value::Unsigned(info.entsize)),
        ] {
            if off.saturating_add(flen) > shentsize {
                break;
            }
            field(
                b,
                entry,
                ClaimKind::SectionHeaderField { idx, name },
                base.saturating_add(off),
                flen,
                value,
                None,
            )?;
        }
    }
    Ok(out)
}

fn section_name(r: &Reader<'_>, sections: &[SectionInfo], shstrndx: u64, name_off: u32) -> String {
    let Some(strtab) = usize::try_from(shstrndx).ok().and_then(|i| sections.get(i)) else {
        return String::new();
    };
    let at = strtab.offset.saturating_add(u64::from(name_off));
    r.cstr_at(at, strtab.size)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_owned()
}

fn parse_section_bodies(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    sections: &[SectionInfo],
    shstrndx: u64,
    summary: &mut Summary,
) -> Result<(), ParseError> {
    for (i, sec) in sections.iter().enumerate() {
        let idx = u32::try_from(i).unwrap_or(u32::MAX);
        // NOBITS occupies no file space — and its sh_offset deliberately overlaps the
        // next section, which is exactly the kind of thing the coverage invariant would
        // otherwise flag as a parser bug.
        if sec.sh_type == elf::SHT_NULL || sec.sh_type == elf::SHT_NOBITS || sec.size == 0 {
            continue;
        }
        if r.slice_at(sec.offset, sec.size).is_none() {
            continue;
        }
        let name = section_name(r, sections, shstrndx, sec.name_off);
        let span = Span::new(F, sec.offset, sec.size);

        let kind = match sec.sh_type {
            elf::SHT_STRTAB => ClaimKind::StringTable { table: idx },
            elf::SHT_SYMTAB => ClaimKind::SymbolTable { dynamic: false },
            elf::SHT_DYNSYM => ClaimKind::SymbolTable { dynamic: true },
            elf::SHT_RELA => ClaimKind::RelocationTable {
                kind: RelocTableKind::Rela,
            },
            elf::SHT_REL => ClaimKind::RelocationTable {
                kind: RelocTableKind::Rel,
            },
            elf::SHT_RELR => ClaimKind::RelocationTable {
                kind: RelocTableKind::Relr,
            },
            elf::SHT_DYNAMIC => ClaimKind::DynamicTable,
            elf::SHT_HASH => ClaimKind::HashTable { gnu: false },
            elf::SHT_GNU_HASH => ClaimKind::HashTable { gnu: true },
            elf::SHT_GNU_VERDEF => ClaimKind::VersionTable {
                kind: VersionTableKind::VerDef,
            },
            elf::SHT_GNU_VERNEED => ClaimKind::VersionTable {
                kind: VersionTableKind::VerNeed,
            },
            elf::SHT_GNU_VERSYM => ClaimKind::VersionTable {
                kind: VersionTableKind::VerSym,
            },
            _ if name == ".interp" => ClaimKind::Interp,
            _ => ClaimKind::SectionBody { idx },
        };

        let body = push(
            b,
            Claim::new(span, kind).with_note(if name.is_empty() {
                format!("section {i}")
            } else {
                name.clone()
            }),
        )?;

        match sec.sh_type {
            elf::SHT_STRTAB => parse_strtab(r, b, body, sec, idx)?,
            elf::SHT_SYMTAB | elf::SHT_DYNSYM => {
                parse_symtab(r, b, body, sec, sections, idx)?;
            }
            elf::SHT_RELA => {
                parse_relocs(r, b, body, sec, sections, idx, true, &name, summary)?;
            }
            elf::SHT_REL => {
                parse_relocs(r, b, body, sec, sections, idx, false, &name, summary)?;
            }
            elf::SHT_RELR => {
                summary.has_relr = true;
                parse_relr(r, b, body, sec, idx, summary)?;
            }
            elf::SHT_DYNAMIC => parse_dynamic(r, b, body, sec, sections, idx, summary)?,
            elf::SHT_NOTE => parse_notes(r, b, body, sec, idx)?,
            _ => {}
        }
    }
    Ok(())
}

fn parse_strtab(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    parent: ClaimId,
    sec: &SectionInfo,
    idx: u32,
) -> Result<(), ParseError> {
    let mut off = 0u64;
    while off < sec.size {
        let at = sec.offset.saturating_add(off);
        let remaining = sec.size.saturating_sub(off);
        let s = r.cstr_at(at, remaining).unwrap_or(&[]);
        let text_len = s.len() as u64;
        // Include the NUL, unless the table is truncated and there isn't one.
        let claim_len = if text_len < remaining {
            text_len.saturating_add(1)
        } else {
            remaining
        };
        let mut claim = Claim::new(
            Span::new(F, at, claim_len),
            ClaimKind::StringEntry {
                table: idx,
                offset: u32::try_from(off).unwrap_or(u32::MAX),
            },
        )
        .child_of(parent);
        if let Ok(text) = core::str::from_utf8(s)
            && !text.is_empty()
        {
            claim.value = Value::Text(text.into());
        }
        push(b, claim)?;
        off = off.saturating_add(claim_len.max(1));
    }
    Ok(())
}

fn strtab_for(sections: &[SectionInfo], link: u32) -> Option<SectionInfo> {
    usize::try_from(link)
        .ok()
        .and_then(|i| sections.get(i))
        .copied()
}

fn lookup(r: &Reader<'_>, strtab: Option<SectionInfo>, name_off: u32) -> String {
    let Some(st) = strtab else {
        return String::new();
    };
    r.cstr_at(st.offset.saturating_add(u64::from(name_off)), st.size)
        .and_then(|s| core::str::from_utf8(s).ok())
        .unwrap_or("")
        .to_owned()
}

fn parse_symtab(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    parent: ClaimId,
    sec: &SectionInfo,
    sections: &[SectionInfo],
    idx: u32,
) -> Result<(), ParseError> {
    let entsize = if sec.entsize == 0 {
        elf::SYM64_SIZE
    } else {
        sec.entsize
    };
    let strtab = strtab_for(sections, sec.link);
    let count = sec.size.checked_div(entsize).unwrap_or(0);

    for i in 0..count {
        let at = sec.offset.saturating_add(i.saturating_mul(entsize));
        let st_name = r.u32_at(at).unwrap_or(0);
        let st_info = r.u8_at(at.saturating_add(4)).unwrap_or(0);
        let st_value = r.u64_at(at.saturating_add(8)).unwrap_or(0);
        let name = lookup(r, strtab, st_name);
        let kind = elf::st_type_name(st_info).unwrap_or("?");

        push(
            b,
            Claim::new(
                Span::new(F, at, entsize),
                ClaimKind::SymbolEntry {
                    table: idx,
                    idx: u32::try_from(i).unwrap_or(u32::MAX),
                },
            )
            .child_of(parent)
            .with_value(Value::Address(st_value))
            .with_note(if name.is_empty() {
                format!("{kind} (unnamed)")
            } else {
                format!("{kind} {name}")
            }),
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn parse_relocs(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    parent: ClaimId,
    sec: &SectionInfo,
    sections: &[SectionInfo],
    idx: u32,
    rela: bool,
    name: &str,
    summary: &mut Summary,
) -> Result<(), ParseError> {
    // `.rela.plt` is DT_JMPREL: the same entry format, processed in its own pass and, on
    // a lazy binary, not processed at startup at all.
    let table = if name.ends_with(".plt") {
        RelocTableKind::JmpRel
    } else if rela {
        RelocTableKind::Rela
    } else {
        RelocTableKind::Rel
    };
    let default = if rela {
        elf::RELA64_SIZE
    } else {
        elf::REL64_SIZE
    };
    let entsize = if sec.entsize == 0 {
        default
    } else {
        sec.entsize
    };
    let count = sec.size.checked_div(entsize).unwrap_or(0);

    // sh_link on a relocation section names the symbol table its indices refer to.
    let symtab = strtab_for(sections, sec.link);
    let symstr = symtab.and_then(|s| strtab_for(sections, s.link));

    for i in 0..count {
        let at = sec.offset.saturating_add(i.saturating_mul(entsize));
        let r_offset = r.u64_at(at).unwrap_or(0);
        let r_info = r.u64_at(at.saturating_add(8)).unwrap_or(0);
        let r_type = u32::try_from(r_info & 0xffff_ffff).unwrap_or(0);
        let sym_idx = r_info >> 32;

        let type_name =
            elf::r_x86_64_name(r_type).map_or_else(|| format!("type {r_type}"), ToOwned::to_owned);

        let mut note = type_name;
        let mut sym_name: Option<Box<str>> = None;
        let mut sym_weak = false;
        if sym_idx != 0
            && let Some(st) = symtab
        {
            let sym_entsize = if st.entsize == 0 {
                elf::SYM64_SIZE
            } else {
                st.entsize
            };
            let sym_at = st
                .offset
                .saturating_add(sym_idx.saturating_mul(sym_entsize));
            let name = lookup(r, symstr, r.u32_at(sym_at).unwrap_or(0));
            if !name.is_empty() {
                note = format!("{note} → {name}");
                sym_name = Some(name.into());
                // st_info >> 4 is the binding; STB_WEAK is 2.
                let st_info = r.u8_at(sym_at.saturating_add(4)).unwrap_or(0);
                let shndx = r.u16_at(sym_at.saturating_add(6)).unwrap_or(0);
                sym_weak = (st_info >> 4) == 2 && shndx == 0;
            }
        }

        summary.relocs.push(Reloc {
            table,
            offset: r_offset,
            r_type,
            addend: if rela {
                r.i64_at(at.saturating_add(16)).unwrap_or(0)
            } else {
                0
            },
            symbol: sym_name,
            weak: sym_weak,
            file_span: Span::new(F, at, entsize),
        });

        push(
            b,
            Claim::new(
                Span::new(F, at, entsize),
                ClaimKind::RelocationEntry {
                    table: idx,
                    idx: u32::try_from(i).unwrap_or(u32::MAX),
                    r_type,
                },
            )
            .child_of(parent)
            .with_value(Value::Address(r_offset))
            .with_note(note),
        )?;
    }
    Ok(())
}

fn parse_relr(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    parent: ClaimId,
    sec: &SectionInfo,
    idx: u32,
    summary: &mut Summary,
) -> Result<(), ParseError> {
    let count = sec.size.checked_div(elf::RELR64_SIZE).unwrap_or(0);
    // RELR is a run-length scheme: an even word is an address, an odd word is a bitmap of
    // the 63 words that follow it. Expanded here because the loader applies each bit as
    // its own relocation, and a timeline showing "one bitmap word" shows nothing.
    let mut cursor = 0u64;
    for i in 0..count {
        let at = sec
            .offset
            .saturating_add(i.saturating_mul(elf::RELR64_SIZE));
        let word = r.u64_at(at).unwrap_or(0);
        let entry_span = Span::new(F, at, elf::RELR64_SIZE);
        if word & 1 == 0 {
            cursor = word;
            summary.relocs.push(Reloc {
                table: RelocTableKind::Relr,
                offset: cursor,
                r_type: 8, // R_X86_64_RELATIVE
                addend: 0,
                symbol: None,
                weak: false,
                file_span: entry_span,
            });
            cursor = cursor.saturating_add(8);
        } else {
            let mut bits = word >> 1;
            let mut addr = cursor;
            while bits != 0 {
                if bits & 1 != 0 {
                    summary.relocs.push(Reloc {
                        table: RelocTableKind::Relr,
                        offset: addr,
                        r_type: 8,
                        addend: 0,
                        symbol: None,
                        weak: false,
                        file_span: entry_span,
                    });
                }
                addr = addr.saturating_add(8);
                bits >>= 1;
            }
            cursor = cursor.saturating_add(63 * 8);
        }
        // Even words are addresses; odd words are bitmaps covering the following 63
        // words. One 8-byte word can encode 63 relocations that RELA would spend 1512
        // bytes on.
        let note = if word & 1 == 0 {
            format!("base address {word:#x}")
        } else {
            format!("bitmap, {} relocations", (word >> 1).count_ones())
        };
        push(
            b,
            Claim::new(
                Span::new(F, at, elf::RELR64_SIZE),
                ClaimKind::RelrWord {
                    table: idx,
                    idx: u32::try_from(i).unwrap_or(u32::MAX),
                },
            )
            .child_of(parent)
            .with_value(Value::Unsigned(word))
            .with_note(note),
        )?;
    }
    Ok(())
}

fn parse_dynamic(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    parent: ClaimId,
    sec: &SectionInfo,
    sections: &[SectionInfo],
    idx: u32,
    summary: &mut Summary,
) -> Result<(), ParseError> {
    let entsize = if sec.entsize == 0 {
        elf::DYN64_SIZE
    } else {
        sec.entsize
    };
    let count = sec.size.checked_div(entsize).unwrap_or(0);
    let strtab = strtab_for(sections, sec.link);
    let mut seen_null = false;

    for i in 0..count {
        let at = sec.offset.saturating_add(i.saturating_mul(entsize));
        let tag = r.u64_at(at).unwrap_or(0);
        let val = r.u64_at(at.saturating_add(8)).unwrap_or(0);
        let tag_name = elf::dt_name(tag).map_or_else(|| format!("{tag:#x}"), ToOwned::to_owned);

        let mut note = tag_name;
        match tag {
            elf::DT_NEEDED | elf::DT_SONAME | elf::DT_RPATH | elf::DT_RUNPATH => {
                let s = lookup(r, strtab, u32::try_from(val).unwrap_or(0));
                if !s.is_empty() {
                    note = format!("{note} {s}");
                    if tag == elf::DT_NEEDED {
                        summary.needed.push(s.into());
                    } else if tag == elf::DT_SONAME {
                        summary.soname = Some(s.into());
                    }
                }
            }
            elf::DT_FLAGS if val & elf::DF_BIND_NOW != 0 => {
                summary.bind_now = true;
                note = format!("{note} BIND_NOW");
            }
            elf::DT_INIT => summary.init = Some(val),
            elf::DT_INIT_ARRAY => {
                summary.init_array = Some((val, summary.init_array.map_or(0, |(_, s)| s)));
            }
            elf::DT_INIT_ARRAYSZ => {
                let base = summary.init_array.map_or(0, |(a, _)| a);
                summary.init_array = Some((base, val));
            }
            elf::DT_NULL => {
                if !seen_null {
                    note = format!("{note} — end of the table");
                    seen_null = true;
                } else {
                    note = format!("{note} (padding past the end)");
                }
            }
            _ => {}
        }

        push(
            b,
            Claim::new(
                Span::new(F, at, entsize),
                ClaimKind::DynamicEntry {
                    idx: u32::try_from(i).unwrap_or(u32::MAX),
                    tag,
                },
            )
            .child_of(parent)
            .with_value(Value::Unsigned(val))
            .with_note(note),
        )?;
    }
    let _ = idx;
    Ok(())
}

fn align4(v: u64) -> u64 {
    v.saturating_add(3) & !3
}

fn parse_notes(
    r: &Reader<'_>,
    b: &mut CoverageBuilder,
    parent: ClaimId,
    sec: &SectionInfo,
    idx: u32,
) -> Result<(), ParseError> {
    let mut off = 0u64;
    let mut n = 0u32;
    while off.saturating_add(12) <= sec.size {
        let at = sec.offset.saturating_add(off);
        let namesz = u64::from(r.u32_at(at).unwrap_or(0));
        let descsz = u64::from(r.u32_at(at.saturating_add(4)).unwrap_or(0));
        let ntype = r.u32_at(at.saturating_add(8)).unwrap_or(0);
        let total = 12u64
            .saturating_add(align4(namesz))
            .saturating_add(align4(descsz));
        if total == 0 || off.saturating_add(total) > sec.size {
            break;
        }
        let name = r
            .cstr_at(at.saturating_add(12), namesz)
            .and_then(|s| core::str::from_utf8(s).ok())
            .unwrap_or("")
            .to_owned();

        push(
            b,
            Claim::new(Span::new(F, at, total), ClaimKind::Note { idx: n })
                .child_of(parent)
                .with_value(Value::Unsigned(u64::from(ntype)))
                .with_note(format!("{name} type {ntype}")),
        )?;
        off = off.saturating_add(total);
        n = n.saturating_add(1);
    }
    let _ = idx;
    Ok(())
}
