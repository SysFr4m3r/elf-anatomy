//! The claim tree and the invariant that keeps it honest.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use crate::claim::{Claim, ClaimId, ClaimKind};
use crate::index::IntervalIndex;
use crate::span::{FileId, Span};

/// Ways a claim set can fail to describe a file.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum CoverageError {
    /// A claim referenced a file that was never declared with
    /// [`CoverageBuilder::add_file`].
    UnknownFile {
        file: FileId,
    },
    /// A claim runs past the end of its file — almost always a bad size field.
    SpanExceedsFile {
        claim: ClaimId,
        span: Span,
        file_len: u64,
    },
    UnknownParent {
        claim: ClaimId,
        parent: ClaimId,
    },
    /// A child must lie within its parent. A violation means a structure's extent was
    /// computed one way and its contents another.
    ChildEscapesParent {
        claim: ClaimId,
        child: Span,
        parent: Span,
    },
    /// Two leaf claims cover the same byte. The parser double-counted.
    LeafOverlap {
        a: ClaimId,
        b: ClaimId,
        at: Span,
    },
    /// Bytes no leaf accounts for. Call [`CoverageBuilder::fill_unclaimed`] to turn these
    /// into explicit [`ClaimKind::Unclaimed`] claims — silence is not permitted.
    Gap {
        span: Span,
    },
}

impl fmt::Display for CoverageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFile { file } => write!(f, "claim references undeclared file {file}"),
            Self::SpanExceedsFile {
                claim,
                span,
                file_len,
            } => write!(
                f,
                "claim {claim} at {span:?} runs past end of file ({file_len} bytes)"
            ),
            Self::UnknownParent { claim, parent } => {
                write!(f, "claim {claim} names unknown parent {parent}")
            }
            Self::ChildEscapesParent {
                claim,
                child,
                parent,
            } => write!(
                f,
                "claim {claim} at {child:?} is not contained by its parent at {parent:?}"
            ),
            Self::LeafOverlap { a, b, at } => {
                write!(f, "leaf claims {a} and {b} both cover {at:?}")
            }
            Self::Gap { span } => write!(f, "no leaf claim covers {span:?}"),
        }
    }
}

impl core::error::Error for CoverageError {}

/// Accumulates claims, then validates them into a [`Coverage`].
///
/// Structural errors (bad parent, span past end of file) are caught eagerly at
/// [`push`](Self::push) so the parser fails near the bug. The coverage invariant is a
/// whole-file property and is checked at [`finish`](Self::finish).
#[derive(Clone, Debug, Default)]
pub struct CoverageBuilder {
    claims: Vec<Claim>,
    children: Vec<Vec<ClaimId>>,
    files: BTreeMap<FileId, u64>,
}

impl CoverageBuilder {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Declare a file and its length in bytes. Every claim must belong to one.
    pub fn add_file(&mut self, file: FileId, len: u64) {
        self.files.insert(file, len);
    }

    /// Add a claim, returning the id later claims use to parent themselves to it.
    pub fn push(&mut self, claim: Claim) -> Result<ClaimId, CoverageError> {
        let id = ClaimId(u32::try_from(self.claims.len()).unwrap_or(u32::MAX));

        let Some(&file_len) = self.files.get(&claim.span.file) else {
            return Err(CoverageError::UnknownFile {
                file: claim.span.file,
            });
        };
        if claim.span.end() > file_len {
            return Err(CoverageError::SpanExceedsFile {
                claim: id,
                span: claim.span,
                file_len,
            });
        }

        if let Some(parent) = claim.parent {
            let Some(p) = self.claims.get(parent.0 as usize) else {
                return Err(CoverageError::UnknownParent { claim: id, parent });
            };
            if !p.span.contains_span(claim.span) {
                return Err(CoverageError::ChildEscapesParent {
                    claim: id,
                    child: claim.span,
                    parent: p.span,
                });
            }
            if let Some(slot) = self.children.get_mut(parent.0 as usize) {
                slot.push(id);
            }
        }

        self.claims.push(claim);
        self.children.push(Vec::new());
        Ok(id)
    }

    /// Turn every hole in the leaf partition into an explicit [`ClaimKind::Unclaimed`]
    /// claim, parented to the innermost claim that contains it.
    ///
    /// This is what makes the invariant achievable in practice, and it is also where the
    /// interesting output comes from: run it and the leftovers *are* the alignment
    /// padding, the linker gaps, and the appended data.
    ///
    /// Returns the number of claims inserted.
    pub fn fill_unclaimed(&mut self) -> usize {
        let mut inserted = 0usize;
        let files: Vec<(FileId, u64)> = self.files.iter().map(|(f, l)| (*f, *l)).collect();

        for (file, len) in files {
            let mut cursor = 0u64;
            let mut holes: Vec<Span> = Vec::new();

            for span in self.sorted_leaf_spans(file) {
                if span.start > cursor {
                    holes.push(Span::new(file, cursor, span.start.saturating_sub(cursor)));
                }
                cursor = cursor.max(span.end());
            }
            if cursor < len {
                holes.push(Span::new(file, cursor, len.saturating_sub(cursor)));
            }

            for hole in holes {
                let parent = self.innermost_containing(hole);
                let mut claim = Claim::new(hole, ClaimKind::Unclaimed);
                claim.parent = parent;
                if self.push(claim).is_ok() {
                    inserted = inserted.saturating_add(1);
                }
            }
        }
        inserted
    }

    /// Validate the invariant and freeze into a queryable [`Coverage`].
    pub fn finish(self) -> Result<Coverage, CoverageError> {
        for (file, &len) in &self.files {
            let mut cursor = 0u64;
            let mut previous: Option<ClaimId> = None;

            for (span, id) in self.sorted_leaves(*file) {
                if span.start < cursor {
                    let overlap_start = span.start;
                    let overlap_end = cursor.min(span.end());
                    return Err(CoverageError::LeafOverlap {
                        a: previous.unwrap_or(id),
                        b: id,
                        at: Span::new(
                            *file,
                            overlap_start,
                            overlap_end.saturating_sub(overlap_start),
                        ),
                    });
                }
                if span.start > cursor {
                    return Err(CoverageError::Gap {
                        span: Span::new(*file, cursor, span.start.saturating_sub(cursor)),
                    });
                }
                cursor = span.end();
                previous = Some(id);
            }

            if cursor < len {
                return Err(CoverageError::Gap {
                    span: Span::new(*file, cursor, len.saturating_sub(cursor)),
                });
            }
        }

        let index = IntervalIndex::build(
            self.claims
                .iter()
                .enumerate()
                .map(|(i, c)| (c.span, ClaimId(u32::try_from(i).unwrap_or(u32::MAX)))),
        );

        let roots = self
            .claims
            .iter()
            .enumerate()
            .filter(|(_, c)| c.parent.is_none())
            .map(|(i, _)| ClaimId(u32::try_from(i).unwrap_or(u32::MAX)))
            .collect();

        Ok(Coverage {
            claims: self.claims,
            children: self.children,
            roots,
            files: self.files,
            index,
        })
    }

    fn is_leaf(&self, id: usize) -> bool {
        self.children.get(id).is_some_and(Vec::is_empty)
    }

    /// Leaf `(span, id)` pairs for one file, sorted by start. Empty spans are excluded:
    /// they cover no byte and so cannot participate in a partition.
    fn sorted_leaves(&self, file: FileId) -> Vec<(Span, ClaimId)> {
        let mut out: Vec<(Span, ClaimId)> = self
            .claims
            .iter()
            .enumerate()
            .filter(|(i, c)| c.span.file == file && !c.span.is_empty() && self.is_leaf(*i))
            .map(|(i, c)| (c.span, ClaimId(u32::try_from(i).unwrap_or(u32::MAX))))
            .collect();
        out.sort_unstable_by_key(|(s, _)| (s.start, s.end()));
        out
    }

    fn sorted_leaf_spans(&self, file: FileId) -> Vec<Span> {
        self.sorted_leaves(file)
            .into_iter()
            .map(|(s, _)| s)
            .collect()
    }

    /// Smallest claim that fully contains `span`. Linear; called once per hole, and holes
    /// number in the dozens even for large binaries.
    fn innermost_containing(&self, span: Span) -> Option<ClaimId> {
        self.claims
            .iter()
            .enumerate()
            .filter(|(_, c)| c.span.contains_span(span) && !c.span.is_empty())
            .min_by_key(|(_, c)| c.span.len)
            .map(|(i, _)| ClaimId(u32::try_from(i).unwrap_or(u32::MAX)))
    }
}

/// A validated, queryable claim tree.
#[derive(Clone, Debug)]
pub struct Coverage {
    claims: Vec<Claim>,
    children: Vec<Vec<ClaimId>>,
    roots: Vec<ClaimId>,
    files: BTreeMap<FileId, u64>,
    index: IntervalIndex,
}

impl Coverage {
    #[must_use]
    pub fn claim(&self, id: ClaimId) -> Option<&Claim> {
        self.claims.get(id.0 as usize)
    }

    #[must_use]
    pub fn span_of(&self, id: ClaimId) -> Option<Span> {
        self.claim(id).map(|c| c.span)
    }

    #[must_use]
    pub fn children(&self, id: ClaimId) -> &[ClaimId] {
        self.children
            .get(id.0 as usize)
            .map_or(&[][..], Vec::as_slice)
    }

    #[must_use]
    pub fn parent(&self, id: ClaimId) -> Option<ClaimId> {
        self.claim(id).and_then(|c| c.parent)
    }

    #[must_use]
    pub fn roots(&self) -> &[ClaimId] {
        &self.roots
    }

    #[must_use]
    pub fn file_len(&self, file: FileId) -> Option<u64> {
        self.files.get(&file).copied()
    }

    pub fn files(&self) -> impl Iterator<Item = (FileId, u64)> + '_ {
        self.files.iter().map(|(f, l)| (*f, *l))
    }

    /// Claims covering `off`, innermost first. The hover query.
    #[must_use]
    pub fn claims_at(&self, file: FileId, off: u64) -> Vec<ClaimId> {
        self.index.at(file, off)
    }

    #[must_use]
    pub fn innermost_at(&self, file: FileId, off: u64) -> Option<ClaimId> {
        self.index.innermost(file, off)
    }

    /// Claims intersecting `probe`, ascending. The viewport query.
    #[must_use]
    pub fn overlapping(&self, probe: Span) -> Vec<ClaimId> {
        self.index.overlapping(probe)
    }

    /// The path from a claim up to its root, innermost first. The UI breadcrumb.
    #[must_use]
    pub fn ancestry(&self, id: ClaimId) -> Vec<ClaimId> {
        let mut out = Vec::new();
        let mut cur = Some(id);
        // Depth is bounded by the claim count; the guard makes a cyclic parent link
        // terminate rather than hang, even though `push` cannot create one.
        let mut guard = self.claims.len().saturating_add(1);
        while let Some(c) = cur {
            if guard == 0 {
                break;
            }
            guard = guard.saturating_sub(1);
            out.push(c);
            cur = self.parent(c);
        }
        out
    }

    pub fn leaves(&self) -> impl Iterator<Item = ClaimId> + '_ {
        self.children
            .iter()
            .enumerate()
            .filter(|(_, kids)| kids.is_empty())
            .map(|(i, _)| ClaimId(u32::try_from(i).unwrap_or(u32::MAX)))
    }

    /// Spans no structure explained. After
    /// [`CoverageBuilder::fill_unclaimed`], this is the honest answer to "what is the rest
    /// of this file".
    pub fn unclaimed(&self) -> impl Iterator<Item = Span> + '_ {
        self.claims
            .iter()
            .filter(|c| c.kind == ClaimKind::Unclaimed)
            .map(|c| c.span)
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.claims.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.claims.is_empty()
    }

    #[must_use]
    pub fn stats(&self) -> CoverageStats {
        let total_bytes = self.files.values().copied().fold(0u64, u64::saturating_add);
        let mut filler_bytes = 0u64;
        let mut leaf_count = 0usize;

        for (i, kids) in self.children.iter().enumerate() {
            if !kids.is_empty() {
                continue;
            }
            leaf_count = leaf_count.saturating_add(1);
            if let Some(c) = self.claims.get(i)
                && c.kind.is_filler()
            {
                filler_bytes = filler_bytes.saturating_add(c.span.len);
            }
        }

        CoverageStats {
            files: self.files.len(),
            total_bytes,
            explained_bytes: total_bytes.saturating_sub(filler_bytes),
            filler_bytes,
            claim_count: self.claims.len(),
            leaf_count,
            max_depth: self
                .claims
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    self.ancestry(ClaimId(u32::try_from(i).unwrap_or(u32::MAX)))
                        .len()
                })
                .max()
                .unwrap_or(0),
        }
    }
}

/// Summary of a coverage, printed by `elfa verify` and used in snapshot tests.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct CoverageStats {
    pub files: usize,
    pub total_bytes: u64,
    /// Bytes attributed to a real structure.
    pub explained_bytes: u64,
    /// Bytes that are padding or unclaimed — the number the README is about.
    pub filler_bytes: u64,
    pub claim_count: usize,
    pub leaf_count: usize,
    pub max_depth: usize,
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::unwrap_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use crate::claim::{PadReason, Value};

    const F: FileId = FileId::PRIMARY;

    fn ehdr_only(len: u64) -> CoverageBuilder {
        let mut b = CoverageBuilder::new();
        b.add_file(F, len);
        let h = b
            .push(Claim::new(Span::new(F, 0, 64), ClaimKind::FileHeader))
            .unwrap();
        b.push(
            Claim::new(
                Span::new(F, 0, 24),
                ClaimKind::FileHeaderField {
                    name: "e_ident..e_version",
                },
            )
            .child_of(h),
        )
        .unwrap();
        b.push(
            Claim::new(
                Span::new(F, 24, 40),
                ClaimKind::FileHeaderField { name: "e_entry.." },
            )
            .child_of(h)
            .with_value(Value::Address(0x1040)),
        )
        .unwrap();
        b
    }

    #[test]
    fn interior_claims_may_overlap_their_children() {
        // The whole point: ehdr covers 0..64 and its fields tile the same bytes.
        let cov = ehdr_only(64).finish().unwrap();
        assert_eq!(cov.claims_at(F, 30).len(), 2);
        assert_eq!(cov.stats().leaf_count, 2);
    }

    #[test]
    fn a_hole_is_an_error_until_it_is_named() {
        let err = ehdr_only(4096).finish().unwrap_err();
        assert_eq!(
            err,
            CoverageError::Gap {
                span: Span::new(F, 64, 4096 - 64)
            }
        );
    }

    #[test]
    fn fill_unclaimed_closes_holes_and_parents_them_correctly() {
        let mut b = ehdr_only(4096);
        assert_eq!(b.fill_unclaimed(), 1);
        let cov = b.finish().unwrap();

        let holes: Vec<Span> = cov.unclaimed().collect();
        assert_eq!(holes, alloc::vec![Span::new(F, 64, 4096 - 64)]);
        // Outside every existing claim, so it parents to nothing.
        let id = cov.innermost_at(F, 100).unwrap();
        assert_eq!(cov.parent(id), None);
        assert_eq!(cov.stats().filler_bytes, 4096 - 64);
        assert_eq!(cov.stats().explained_bytes, 64);
    }

    #[test]
    fn an_interior_hole_parents_to_the_innermost_container() {
        let mut b = CoverageBuilder::new();
        b.add_file(F, 128);
        let table = b
            .push(Claim::new(
                Span::new(F, 0, 128),
                ClaimKind::ProgramHeaderTable,
            ))
            .unwrap();
        b.push(
            Claim::new(Span::new(F, 0, 56), ClaimKind::ProgramHeader { idx: 0 }).child_of(table),
        )
        .unwrap();
        b.push(
            Claim::new(Span::new(F, 64, 56), ClaimKind::ProgramHeader { idx: 1 }).child_of(table),
        )
        .unwrap();

        assert_eq!(b.fill_unclaimed(), 2); // the 56..64 gap and the 120..128 tail
        let cov = b.finish().unwrap();
        let hole = cov.innermost_at(F, 60).unwrap();
        assert_eq!(cov.parent(hole), Some(table));
        assert_eq!(cov.ancestry(hole).len(), 2);
    }

    #[test]
    fn overlapping_leaves_are_rejected_with_the_overlap_named() {
        let mut b = CoverageBuilder::new();
        b.add_file(F, 64);
        b.push(Claim::new(
            Span::new(F, 0, 40),
            ClaimKind::SectionBody { idx: 1 },
        ))
        .unwrap();
        b.push(Claim::new(
            Span::new(F, 32, 32),
            ClaimKind::SectionBody { idx: 2 },
        ))
        .unwrap();
        match b.finish().unwrap_err() {
            CoverageError::LeafOverlap { at, .. } => {
                assert_eq!(at, Span::new(F, 32, 8));
            }
            other => panic!("expected overlap, got {other:?}"),
        }
    }

    #[test]
    fn a_child_may_not_escape_its_parent() {
        let mut b = CoverageBuilder::new();
        b.add_file(F, 128);
        let p = b
            .push(Claim::new(Span::new(F, 0, 64), ClaimKind::FileHeader))
            .unwrap();
        let err = b
            .push(
                Claim::new(
                    Span::new(F, 60, 16),
                    ClaimKind::FileHeaderField { name: "e_shoff" },
                )
                .child_of(p),
            )
            .unwrap_err();
        assert!(matches!(err, CoverageError::ChildEscapesParent { .. }));
    }

    #[test]
    fn a_bad_size_field_is_caught_at_push() {
        let mut b = CoverageBuilder::new();
        b.add_file(F, 128);
        let err = b
            .push(Claim::new(
                Span::new(F, 64, u64::MAX),
                ClaimKind::SectionBody { idx: 3 },
            ))
            .unwrap_err();
        assert!(matches!(err, CoverageError::SpanExceedsFile { .. }));
    }

    #[test]
    fn undeclared_files_are_rejected() {
        let mut b = CoverageBuilder::new();
        let err = b
            .push(Claim::new(
                Span::new(FileId(7), 0, 1),
                ClaimKind::FileHeader,
            ))
            .unwrap_err();
        assert_eq!(err, CoverageError::UnknownFile { file: FileId(7) });
    }

    #[test]
    fn zero_length_claims_are_legal_and_ignored_by_the_partition() {
        let mut b = CoverageBuilder::new();
        b.add_file(F, 16);
        b.push(Claim::new(
            Span::new(F, 0, 16),
            ClaimKind::SectionBody { idx: 0 },
        ))
        .unwrap();
        // An empty .bss section header points at offset 16 with size 0.
        b.push(Claim::new(
            Span::empty_at(F, 16),
            ClaimKind::SectionBody { idx: 1 },
        ))
        .unwrap();
        assert!(b.finish().is_ok());
    }

    #[test]
    fn a_dependency_closure_is_covered_per_file() {
        let mut b = CoverageBuilder::new();
        b.add_file(FileId::PRIMARY, 32);
        b.add_file(FileId(1), 16);
        b.push(Claim::new(
            Span::new(FileId::PRIMARY, 0, 32),
            ClaimKind::SectionBody { idx: 0 },
        ))
        .unwrap();
        // libc is declared but unparsed — the gap must be reported against *its* file.
        match b.clone().finish().unwrap_err() {
            CoverageError::Gap { span } => assert_eq!(span.file, FileId(1)),
            other => panic!("expected gap in f1, got {other:?}"),
        }
        assert_eq!(b.fill_unclaimed(), 1);
        assert!(b.finish().is_ok());
    }

    #[test]
    fn padding_counts_as_filler() {
        let mut b = CoverageBuilder::new();
        b.add_file(F, 32);
        b.push(Claim::new(
            Span::new(F, 0, 24),
            ClaimKind::SectionBody { idx: 0 },
        ))
        .unwrap();
        b.push(Claim::new(
            Span::new(F, 24, 8),
            ClaimKind::Padding {
                reason: PadReason::Alignment { to: 16 },
            },
        ))
        .unwrap();
        let cov = b.finish().unwrap();
        assert_eq!(cov.stats().filler_bytes, 8);
    }
}
