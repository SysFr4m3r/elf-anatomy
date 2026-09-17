//! Claims — a byte span plus what those bytes mean.

use alloc::boxed::Box;
use core::fmt;

use crate::span::Span;

/// Index of a [`Claim`] within its [`Coverage`](crate::Coverage).
///
/// Ids are minted by [`CoverageBuilder::push`](crate::CoverageBuilder::push) and are only
/// meaningful against the coverage that produced them.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ClaimId(pub u32);

impl fmt::Display for ClaimId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// One byte range with one meaning.
///
/// Claims nest: a [`ClaimKind::ProgramHeader`] is the parent of its field claims. Only
/// *leaf* claims participate in the coverage partition — see the crate docs.
#[derive(Clone, Debug)]
pub struct Claim {
    pub span: Span,
    pub kind: ClaimKind,
    pub parent: Option<ClaimId>,
    pub value: Value,
    /// Short editorial note surfaced in the UI: "PT_INTERP, hence dynamically linked".
    pub note: Option<Box<str>>,
}

impl Claim {
    #[must_use]
    pub fn new(span: Span, kind: ClaimKind) -> Self {
        Self {
            span,
            kind,
            parent: None,
            value: Value::None,
            note: None,
        }
    }

    #[must_use]
    pub fn child_of(mut self, parent: ClaimId) -> Self {
        self.parent = Some(parent);
        self
    }

    #[must_use]
    pub fn with_value(mut self, value: Value) -> Self {
        self.value = value;
        self
    }

    #[must_use]
    pub fn with_note(mut self, note: impl Into<Box<str>>) -> Self {
        self.note = Some(note.into());
        self
    }
}

/// What a span of bytes is.
///
/// Field-level variants carry the field's name as a `&'static str` rather than a per-struct
/// enum: the set is large, entirely descriptive, and never matched on.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ClaimKind {
    FileHeader,
    FileHeaderField {
        name: &'static str,
    },

    ProgramHeaderTable,
    ProgramHeader {
        idx: u32,
    },
    ProgramHeaderField {
        idx: u32,
        name: &'static str,
    },

    SectionHeaderTable,
    SectionHeader {
        idx: u32,
    },
    SectionHeaderField {
        idx: u32,
        name: &'static str,
    },
    /// The bytes a section header points at, as opposed to the header itself.
    SectionBody {
        idx: u32,
    },

    DynamicTable,
    DynamicEntry {
        idx: u32,
        tag: u64,
    },

    RelocationTable {
        kind: RelocTableKind,
    },
    RelocationEntry {
        table: u32,
        idx: u32,
        r_type: u32,
    },
    /// One word of a `DT_RELR` bitmap. Expands to many relocations; see plan §5 L1.
    RelrWord {
        table: u32,
        idx: u32,
    },

    SymbolTable {
        dynamic: bool,
    },
    SymbolEntry {
        table: u32,
        idx: u32,
    },

    StringTable {
        table: u32,
    },
    StringEntry {
        table: u32,
        offset: u32,
    },

    HashTable {
        gnu: bool,
    },
    VersionTable {
        kind: VersionTableKind,
    },

    Note {
        idx: u32,
    },
    /// The interpreter path from `PT_INTERP` — the string that makes a program dynamic.
    Interp,

    Padding {
        reason: PadReason,
    },
    /// Bytes no structure accounts for. Produced by
    /// [`CoverageBuilder::fill_unclaimed`](crate::CoverageBuilder::fill_unclaimed), never
    /// by the parser directly.
    Unclaimed,
}

impl ClaimKind {
    /// Stable short label for UI and snapshot tests.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::FileHeader => "ehdr",
            Self::FileHeaderField { .. } => "ehdr.field",
            Self::ProgramHeaderTable => "phdr.table",
            Self::ProgramHeader { .. } => "phdr",
            Self::ProgramHeaderField { .. } => "phdr.field",
            Self::SectionHeaderTable => "shdr.table",
            Self::SectionHeader { .. } => "shdr",
            Self::SectionHeaderField { .. } => "shdr.field",
            Self::SectionBody { .. } => "section",
            Self::DynamicTable => "dynamic",
            Self::DynamicEntry { .. } => "dynamic.entry",
            Self::RelocationTable { .. } => "reloc.table",
            Self::RelocationEntry { .. } => "reloc",
            Self::RelrWord { .. } => "relr.word",
            Self::SymbolTable { .. } => "symtab",
            Self::SymbolEntry { .. } => "symbol",
            Self::StringTable { .. } => "strtab",
            Self::StringEntry { .. } => "string",
            Self::HashTable { .. } => "hash",
            Self::VersionTable { .. } => "version",
            Self::Note { .. } => "note",
            Self::Interp => "interp",
            Self::Padding { .. } => "padding",
            Self::Unclaimed => "unclaimed",
        }
    }

    /// The struct field this claim is, when it is one.
    ///
    /// `label` groups claims by kind, which is what a renderer colours by. This is what a
    /// reader needs: `e_phoff` and `e_shoff` are both `ehdr.field`, and the difference
    /// between them is the entire point of looking.
    #[must_use]
    pub const fn field_name(&self) -> Option<&'static str> {
        match self {
            Self::FileHeaderField { name }
            | Self::ProgramHeaderField { name, .. }
            | Self::SectionHeaderField { name, .. } => Some(name),
            _ => None,
        }
    }

    /// True for bytes that exist only to satisfy alignment or that nothing explains.
    /// These are the regions the byte river renders as absence.
    #[must_use]
    pub const fn is_filler(&self) -> bool {
        matches!(self, Self::Padding { .. } | Self::Unclaimed)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RelocTableKind {
    /// `DT_REL` / `SHT_REL` — implicit addend.
    Rel,
    /// `DT_RELA` / `SHT_RELA` — explicit addend.
    Rela,
    /// `DT_RELR` — compressed relative relocations, a bitmap rather than a table.
    Relr,
    /// `DT_JMPREL` — the PLT relocations, processed eagerly under `BIND_NOW`.
    JmpRel,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum VersionTableKind {
    VerDef,
    VerNeed,
    VerSym,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PadReason {
    /// Inserted to satisfy an alignment constraint we can name.
    Alignment { to: u64 },
    /// Between two sections, for reasons only the linker knows.
    LinkerGap,
    /// Inside a section, past its meaningful content.
    SectionSlack,
}

/// A decoded field value, alongside the raw bytes the claim already points at.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Value {
    None,
    Unsigned(u64),
    Signed(i64),
    /// A virtual address. Rendered differently from a file offset, because conflating the
    /// two is the single most common source of confusion about ELF.
    Address(u64),
    FileOffset(u64),
    Flags(u64),
    Text(Box<str>),
    /// Bulk content; read from the file through the claim's span when needed.
    Raw,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::span::FileId;

    #[test]
    fn builder_methods_compose() {
        let c = Claim::new(
            Span::new(FileId::PRIMARY, 0x18, 8),
            ClaimKind::FileHeaderField { name: "e_entry" },
        )
        .child_of(ClaimId(0))
        .with_value(Value::Address(0x1040))
        .with_note("where the kernel jumps, for a static binary");

        assert_eq!(c.parent, Some(ClaimId(0)));
        assert_eq!(c.value, Value::Address(0x1040));
        assert_eq!(c.kind.label(), "ehdr.field");
        assert!(!c.kind.is_filler());
    }

    #[test]
    fn filler_kinds_are_marked() {
        assert!(ClaimKind::Unclaimed.is_filler());
        assert!(
            ClaimKind::Padding {
                reason: PadReason::LinkerGap
            }
            .is_filler()
        );
        assert!(!ClaimKind::SectionBody { idx: 3 }.is_filler());
    }
}
