//! The ELF parser, fuzzed with arbitrary bytes.
//!
//! This is the surface that matters. `elfa` is pointed at files people did not write and
//! may not trust, and the eventual browser build takes whatever gets dropped into a tab.
//! An ELF file is a set of offsets pointing at each other, every one of them
//! attacker-controlled, so "never panics" has to be a property rather than an intention.
//!
//! Two things are asserted:
//!
//! 1. **No panic, no abort, for any input.** Malformed files produce a `ParseError` or a
//!    coverage failure, never an unwind.
//! 2. **A successful parse is a true partition.** If `parse` returns `Ok`, the leaves tile
//!    the file exactly: no gap, no overlap, and they end where the file ends. Checked here
//!    independently of the builder's own validation, so a bug in that validation cannot
//!    hide a bug in the parser.

#![no_main]

use elfa_parse::{FileId, Span, parse};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(parsed) = parse(data) else {
        return;
    };
    let cov = &parsed.coverage;

    let mut leaves: Vec<Span> = cov
        .leaves()
        .filter_map(|id| cov.span_of(id))
        .filter(|s| s.file == FileId::PRIMARY && !s.is_empty())
        .collect();
    leaves.sort_unstable_by_key(|s| s.start);

    let mut cursor = 0u64;
    for span in &leaves {
        assert_eq!(
            span.start, cursor,
            "leaves must tile the file: expected {cursor:#x}, found {span:?}"
        );
        cursor = span.end();
    }
    assert_eq!(
        cursor,
        data.len() as u64,
        "coverage must reach the end of the file"
    );

    // Every claim must lie inside its parent, and ancestry must terminate.
    for (i, span) in leaves.iter().enumerate() {
        let _ = i;
        let Some(id) = cov.innermost_at(FileId::PRIMARY, span.start) else {
            panic!("no claim at {:#x} despite a leaf starting there", span.start);
        };
        let chain = cov.ancestry(id);
        assert!(chain.len() <= cov.len());
        for pair in chain.windows(2) {
            let (Some(child), Some(parent)) = (cov.span_of(pair[0]), cov.span_of(pair[1])) else {
                continue;
            };
            assert!(
                parent.contains_span(child),
                "{child:?} escapes its parent {parent:?}"
            );
        }
    }
});
