//! The parser against real files.
//!
//! Unit tests cover the data model; this covers the format. Fixtures are built by
//! `make -C fixtures`, and the test skips rather than fails when they are absent so a
//! fresh clone can still run `cargo test`.

// A failing assertion is the point of a test; the workspace's no-panic policy is for the
// library, which must survive whatever a browser hands it.
#![allow(
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::path::{Path, PathBuf};

use elfa_parse::{ClaimKind, parse};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/out")
}

fn specimens() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(fixture_dir())
        .into_iter()
        .flatten()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    out.sort();
    // A system binary is the specimen we did not build, and therefore the one most
    // likely to contain something the fixtures do not.
    for p in ["/bin/ls", "/bin/true"] {
        let p = PathBuf::from(p);
        if p.exists() {
            out.push(p);
        }
    }
    out
}

#[test]
fn every_specimen_is_fully_covered() {
    let specimens = specimens();
    if specimens.is_empty() {
        eprintln!("no specimens; run `make -C fixtures` to build them");
        return;
    }

    for path in specimens {
        let bytes = std::fs::read(&path).expect("read specimen");
        let parsed = match parse(&bytes) {
            Ok(p) => p,
            Err(e) => panic!("{}: {e}", path.display()),
        };

        let stats = parsed.coverage.stats();
        assert_eq!(
            stats.total_bytes,
            bytes.len() as u64,
            "{}: coverage does not span the file",
            path.display()
        );
        assert!(
            stats.claim_count > 0 && stats.leaf_count > 0,
            "{}: parsed to nothing",
            path.display()
        );

        // The invariant, checked independently of `finish()`: walk every byte and
        // require exactly one leaf. Slow and deliberately naive — it is the oracle.
        let mut off = 0u64;
        while off < stats.total_bytes {
            let stack = parsed.coverage.claims_at(elfa_parse::FileId::PRIMARY, off);
            let leaves = stack
                .iter()
                .filter(|id| parsed.coverage.children(**id).is_empty())
                .count();
            assert_eq!(
                leaves,
                1,
                "{}: byte {off:#x} covered by {leaves} leaves",
                path.display()
            );
            // Skip to the end of the innermost claim rather than stepping byte by byte.
            let step = stack
                .first()
                .and_then(|id| parsed.coverage.span_of(*id))
                .map_or(1, |s| s.len.max(1));
            off = off.saturating_add(step);
        }
    }
}

#[test]
fn a_dynamic_binary_reports_its_dependencies() {
    let path = fixture_dir().join("hello-dyn");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("no hello-dyn fixture; run `make -C fixtures`");
        return;
    };
    let parsed = parse(&bytes).expect("parse hello-dyn");

    assert_eq!(
        parsed.summary.interp.as_deref(),
        Some("/lib64/ld-linux-x86-64.so.2")
    );
    assert!(
        parsed
            .summary
            .needed
            .iter()
            .any(|n| n.starts_with("libc.so"))
    );
    assert!(parsed.summary.bind_now, "fixture is built with -z now");
    assert!(parsed.summary.has_dynamic);
}

#[test]
fn a_static_binary_has_no_interpreter_and_still_has_relocations() {
    let path = fixture_dir().join("hello-static");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("no hello-static fixture; run `make -C fixtures`");
        return;
    };
    let parsed = parse(&bytes).expect("parse hello-static");

    assert!(parsed.summary.interp.is_none());
    assert!(parsed.summary.needed.is_empty());

    // The point of the fixture: ifunc resolvers run at startup with no loader present.
    let irelative = count_kind(&parsed, |k| {
        matches!(k, ClaimKind::RelocationEntry { r_type: 37, .. })
    });
    assert!(
        irelative > 0,
        "expected R_X86_64_IRELATIVE relocations in a static binary, found none"
    );
}

#[test]
fn relr_words_are_claimed_when_the_linker_emits_them() {
    let path = fixture_dir().join("relr");
    let Ok(bytes) = std::fs::read(&path) else {
        eprintln!("no relr fixture; run `make -C fixtures`");
        return;
    };
    let parsed = parse(&bytes).expect("parse relr");

    assert!(parsed.summary.has_relr);
    assert!(count_kind(&parsed, |k| matches!(k, ClaimKind::RelrWord { .. })) > 0);
}

fn count_kind(parsed: &elfa_parse::Parsed, pred: impl Fn(&ClaimKind) -> bool) -> usize {
    (0..parsed.coverage.len())
        .filter_map(|i| parsed.coverage.claim(elfa_parse::ClaimId(i as u32)))
        .filter(|c| pred(&c.kind))
        .count()
}
