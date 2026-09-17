//! The morph, against a real specimen.
//!
//! Rendering is hard to assert on. What can be pinned down is that the geometry is fed
//! from a true partition of the file, and that the two endpoints say different things.

#![allow(clippy::expect_used, clippy::panic, clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

use elfa_model::MemImage;
use elfa_render::{Frame, morph_svg, runs};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/out")
        .join(name)
}

fn parsed(name: &str) -> Option<elfa_parse::Parsed> {
    let bytes = std::fs::read(fixture(name)).ok()?;
    Some(elfa_parse::parse(&bytes).expect("parse fixture"))
}

#[test]
fn runs_tile_the_file_exactly() {
    let Some(p) = parsed("hello-dyn") else {
        eprintln!("no fixtures; run `make -C fixtures`");
        return;
    };
    let total = p.coverage.stats().total_bytes;

    let mut cursor = 0u64;
    for run in runs(&p.coverage) {
        assert_eq!(run.span.start, cursor, "runs must be contiguous");
        cursor += run.span.len;
    }
    assert_eq!(cursor, total, "runs must cover the whole file");

    // Merging is the point: a thousand leaves must not become a thousand bands.
    assert!(
        runs(&p.coverage).len() < 60,
        "too many bands to render legibly"
    );
}

#[test]
fn the_endpoints_tell_different_stories() {
    let Some(p) = parsed("hello-dyn") else {
        eprintln!("no fixtures; run `make -C fixtures`");
        return;
    };
    let image = MemImage::from_segments(&p.summary.segments, p.coverage.stats().total_bytes);
    let frame = Frame {
        coverage: &p.coverage,
        image: &image,
        title: "hello-dyn",
        subtitle: "",
    };

    let start = morph_svg(&frame, 0.0);
    let end = morph_svg(&frame, 1.0);

    // .bss exists in no file, so it must not be drawn at t=0.
    assert!(!start.contains(".bss"), "bss must not exist at t=0");
    assert!(end.contains(".bss"), "bss must appear by t=1");

    // Debug info is in the file and never in memory: labelled at both ends.
    assert!(start.contains(".debug_info"));
    assert!(end.contains(".debug_info"));

    // The headline number is the argument, and it does not depend on t.
    assert!(start.contains("never loaded") && end.contains("never loaded"));

    // t outside [0,1] must clamp rather than fly off the canvas.
    assert_eq!(morph_svg(&frame, -5.0), start);
    assert_eq!(morph_svg(&frame, 9.0), end);
}

#[test]
fn a_static_binary_still_maps() {
    let Some(p) = parsed("hello-static") else {
        eprintln!("no fixtures; run `make -C fixtures`");
        return;
    };
    let image = MemImage::from_segments(&p.summary.segments, p.coverage.stats().total_bytes);
    assert!(!image.is_empty(), "a static binary has PT_LOADs too");
    assert!(image.zero_filled_bytes() > 0, "and it has .bss");
}
