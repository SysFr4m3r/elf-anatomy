//! The coverage invariant, fuzzed.
//!
//! `parse.rs` fuzzes the parser with real bytes. This one fuzzes the layer underneath it
//! with arbitrary claim sets, which reaches shapes a valid ELF file never produces —
//! deeply nested claims, parents that do not contain their children, spans at u16 extremes
//! — and pins two properties the parser relies on:
//!
//! 1. **No panic, ever.** The builder takes spans derived from untrusted header fields,
//!    and in the browser it takes them from a file the user dropped in. Malformed input
//!    must produce a `CoverageError`, not an abort.
//! 2. **A successful `finish()` means a true partition.** If the builder accepts a claim
//!    set, then every byte of every file is covered by exactly one leaf — checked here by
//!    brute force, which is why file lengths are kept small.

#![no_main]

use arbitrary::Arbitrary;
use elfa_parse::{Claim, ClaimKind, CoverageBuilder, FileId, Span};
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct RawClaim {
    start: u16,
    len: u16,
    /// Index into the claims pushed so far; taken modulo, so it is often valid and
    /// sometimes deliberately not.
    parent: Option<u16>,
    file: bool,
}

#[derive(Arbitrary, Debug)]
struct Plan {
    len_a: u16,
    len_b: u16,
    fill: bool,
    claims: Vec<RawClaim>,
}

const MAX_LEN: u64 = 4096;

fuzz_target!(|plan: Plan| {
    let len_a = u64::from(plan.len_a) % MAX_LEN;
    let len_b = u64::from(plan.len_b) % MAX_LEN;

    let mut builder = CoverageBuilder::new();
    builder.add_file(FileId::PRIMARY, len_a);
    builder.add_file(FileId(1), len_b);

    let mut ids = Vec::new();
    for raw in &plan.claims {
        let file = if raw.file { FileId(1) } else { FileId::PRIMARY };
        let span = Span::new(file, u64::from(raw.start), u64::from(raw.len));

        let mut claim = Claim::new(span, ClaimKind::SectionBody { idx: 0 });
        if let Some(p) = raw.parent
            && !ids.is_empty()
        {
            claim.parent = Some(ids[usize::from(p) % ids.len()]);
        }

        // Errors are the expected outcome for most inputs; panics are not.
        if let Ok(id) = builder.push(claim) {
            ids.push(id);
        }
    }

    if plan.fill {
        builder.fill_unclaimed();
    }

    let Ok(coverage) = builder.finish() else {
        return;
    };

    // Property 2: an accepted coverage is an exact partition, per file.
    for (file, len) in [(FileId::PRIMARY, len_a), (FileId(1), len_b)] {
        for off in 0..len {
            let covering = coverage.claims_at(file, off);
            let leaves = covering
                .iter()
                .filter(|id| coverage.children(**id).is_empty())
                .count();
            assert_eq!(
                leaves, 1,
                "byte {off:#x} of {file} is covered by {leaves} leaves, expected exactly 1"
            );
        }
    }

    // Ancestry terminates and starts where it was asked to.
    for id in coverage.leaves() {
        let chain = coverage.ancestry(id);
        assert_eq!(chain.first().copied(), Some(id));
        assert!(chain.len() <= coverage.len());
    }
});
