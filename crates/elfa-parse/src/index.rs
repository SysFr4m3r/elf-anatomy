//! Point queries over a static set of nested spans.
//!
//! The UI asks one question constantly: *given a byte offset, which claims cover it?* At
//! hover rate, over a few million claims, against a set that never changes after parsing.
//!
//! That shape rules out a general interval tree. What it wants is the classic augmented
//! sorted array: entries sorted by start, plus a running maximum of `end`. A point query
//! binary-searches for the last entry that begins at or before the offset, then walks
//! backwards, stopping as soon as the running maximum proves no earlier entry can reach.
//!
//! Construction is one sort; queries are `O(log n + k)` with no pointer chasing and no
//! allocation per query.

use alloc::vec::Vec;

use crate::claim::ClaimId;
use crate::span::{FileId, Span};

#[derive(Clone, Copy, Debug)]
struct Entry {
    start: u64,
    end: u64,
    /// Running maximum of `end` over all entries up to and including this one.
    max_end: u64,
    id: ClaimId,
}

/// Immutable index over the spans of one [`Coverage`](crate::Coverage).
#[derive(Clone, Debug, Default)]
pub struct IntervalIndex {
    /// Per-file entry lists, sorted by `start`. Files are sparse and few, so a sorted
    /// `Vec` keyed by id beats a map.
    files: Vec<(FileId, Vec<Entry>)>,
}

impl IntervalIndex {
    /// Build from `(span, id)` pairs. Empty spans are skipped — they cover no byte and so
    /// can never satisfy a point query.
    #[must_use]
    pub fn build(spans: impl IntoIterator<Item = (Span, ClaimId)>) -> Self {
        let mut files: Vec<(FileId, Vec<Entry>)> = Vec::new();

        for (span, id) in spans {
            if span.is_empty() {
                continue;
            }
            let entry = Entry {
                start: span.start,
                end: span.end(),
                max_end: 0,
                id,
            };
            match files.iter_mut().find(|(f, _)| *f == span.file) {
                Some((_, list)) => list.push(entry),
                None => files.push((span.file, alloc::vec![entry])),
            }
        }

        for (_, list) in &mut files {
            list.sort_unstable_by_key(|e| (e.start, e.end));
            let mut running = 0u64;
            for e in list.iter_mut() {
                running = running.max(e.end);
                e.max_end = running;
            }
        }
        files.sort_unstable_by_key(|(f, _)| *f);

        Self { files }
    }

    fn entries(&self, file: FileId) -> &[Entry] {
        self.files
            .iter()
            .find(|(f, _)| *f == file)
            .map_or(&[][..], |(_, list)| list.as_slice())
    }

    /// Every claim whose span covers `off`, innermost first.
    ///
    /// "Innermost first" means shortest span first, which for a well-formed nesting is the
    /// deepest claim — the one the cursor is really pointing at. Ties break on id for
    /// determinism.
    #[must_use]
    pub fn at(&self, file: FileId, off: u64) -> Vec<ClaimId> {
        let entries = self.entries(file);
        let mut hits = Vec::new();

        // Entries beginning after `off` cannot contain it.
        let hi = entries.partition_point(|e| e.start <= off);
        let mut i = hi;
        while i > 0 {
            i = i.saturating_sub(1);
            let Some(e) = entries.get(i) else { break };
            // No entry at or before `i` reaches `off`; nothing earlier can either.
            if e.max_end <= off {
                break;
            }
            if e.end > off {
                hits.push((e.end.saturating_sub(e.start), e.id));
            }
        }

        hits.sort_unstable();
        hits.into_iter().map(|(_, id)| id).collect()
    }

    /// The innermost claim covering `off`, if any.
    #[must_use]
    pub fn innermost(&self, file: FileId, off: u64) -> Option<ClaimId> {
        self.at(file, off).first().copied()
    }

    /// Every claim whose span intersects `probe`, in ascending start order.
    ///
    /// This is the viewport query: the byte river asks for everything visible in the
    /// currently scrolled range.
    #[must_use]
    pub fn overlapping(&self, probe: Span) -> Vec<ClaimId> {
        if probe.is_empty() {
            return Vec::new();
        }
        let entries = self.entries(probe.file);
        let hi = entries.partition_point(|e| e.start < probe.end());
        let mut hits: Vec<(u64, ClaimId)> = Vec::new();
        let mut i = hi;
        while i > 0 {
            i = i.saturating_sub(1);
            let Some(e) = entries.get(i) else { break };
            if e.max_end <= probe.start {
                break;
            }
            if e.end > probe.start {
                hits.push((e.start, e.id));
            }
        }
        hits.sort_unstable();
        hits.into_iter().map(|(_, id)| id).collect()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.iter().map(|(_, l)| l.len()).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.iter().all(|(_, l)| l.is_empty())
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    const F: FileId = FileId::PRIMARY;

    fn idx() -> IntervalIndex {
        // A miniature ehdr: the header, one field inside it, and a later section body.
        IntervalIndex::build([
            (Span::new(F, 0, 64), ClaimId(0)),      // ehdr
            (Span::new(F, 24, 8), ClaimId(1)),      // e_entry
            (Span::new(F, 0x1000, 32), ClaimId(2)), // a section
        ])
    }

    #[test]
    fn nested_claims_come_back_innermost_first() {
        assert_eq!(idx().at(F, 26), alloc::vec![ClaimId(1), ClaimId(0)]);
        assert_eq!(idx().innermost(F, 26), Some(ClaimId(1)));
    }

    #[test]
    fn outside_a_field_only_the_parent_matches() {
        assert_eq!(idx().at(F, 8), alloc::vec![ClaimId(0)]);
    }

    #[test]
    fn gaps_and_ends_are_empty() {
        assert!(idx().at(F, 0x800).is_empty());
        assert_eq!(idx().innermost(F, 64), None);
        assert!(idx().at(FileId(9), 0).is_empty());
    }

    #[test]
    fn viewport_query_spans_a_range() {
        assert_eq!(
            idx().overlapping(Span::new(F, 0, 0x1010)),
            alloc::vec![ClaimId(0), ClaimId(1), ClaimId(2)]
        );
        // A window straddling the gap and the section start: only the section is visible.
        assert_eq!(
            idx().overlapping(Span::new(F, 0xF00, 0x200)),
            alloc::vec![ClaimId(2)]
        );
        // A window entirely inside the gap sees nothing at all.
        assert!(idx().overlapping(Span::new(F, 0x900, 0x200)).is_empty());
    }

    #[test]
    fn empty_spans_are_not_indexed() {
        let i = IntervalIndex::build([(Span::empty_at(F, 10), ClaimId(0))]);
        assert!(i.is_empty());
        assert!(i.at(F, 10).is_empty());
    }

    #[test]
    fn saturating_spans_do_not_panic() {
        let i = IntervalIndex::build([(Span::new(F, u64::MAX - 2, u64::MAX), ClaimId(0))]);
        assert_eq!(i.at(F, u64::MAX - 1), alloc::vec![ClaimId(0)]);
    }
}
