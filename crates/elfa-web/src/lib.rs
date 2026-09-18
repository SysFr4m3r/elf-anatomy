//! The browser front end.
//!
//! Everything below this crate is `no_std` and knows nothing about the web: the parser,
//! the memory model, the timeline and the renderer are the same code the CLI runs. This
//! is the thinnest layer that can hold a parsed file across JavaScript calls.
//!
//! Frames are rendered on demand rather than pre-generated. The expensive step is parsing
//! — 6 ms for a 2 MB libc, 33 ms for an 11 MB gdb — and that happens once when the file is
//! dropped. Rendering a frame from the cached parse is fast enough to do on every tick of
//! a slider, which is what makes scrubbing an arbitrary binary possible at all.

// wasm-bindgen's generated glue contains `unsafe`, so this crate cannot inherit the
// workspace's `forbid(unsafe_code)`. It declares its own lints instead; everything it
// calls into keeps the forbid.
#![allow(unsafe_code)]

use elfa_model::{MemImage, Timeline};
use elfa_parse::{Parsed, elf, parse};
use elfa_render::{Frame, StepView, morph_svg};
use wasm_bindgen::prelude::*;

/// How many frames the file→memory morph is divided into.
const MORPH_FRAMES: usize = 36;

/// One parsed binary, held across calls.
#[wasm_bindgen]
#[derive(Debug)]
pub struct Session {
    parsed: Parsed,
    image: MemImage,
    timeline: Timeline,
    title: String,
    subtitle: String,
}

#[wasm_bindgen]
impl Session {
    /// Parse a file. The bytes are copied in by the caller and not retained.
    #[wasm_bindgen(constructor)]
    pub fn new(name: &str, bytes: &[u8]) -> Result<Session, JsError> {
        let parsed = parse(bytes).map_err(|e| JsError::new(&e.to_string()))?;
        let total = parsed.coverage.stats().total_bytes;
        let image = MemImage::from_segments(&parsed.summary.segments, total);
        if image.is_empty() {
            return Err(JsError::new(
                "no PT_LOAD segments — an object file or a core dump has nothing to map",
            ));
        }
        let timeline = Timeline::plan(&parsed.summary, &image);

        let s = &parsed.summary;
        let subtitle = format!(
            "{}  {}  entry {:#x}   {} bytes on disk",
            elf::et_name(s.e_type).unwrap_or("ET_?"),
            elf::em_name(s.machine).unwrap_or("EM_?"),
            s.entry,
            total
        );

        Ok(Session {
            parsed,
            image,
            timeline,
            title: name.to_owned(),
            subtitle,
        })
    }

    #[wasm_bindgen(js_name = morphFrames)]
    #[must_use]
    pub fn morph_frames(&self) -> usize {
        MORPH_FRAMES
    }

    #[wasm_bindgen(js_name = stepCount)]
    #[must_use]
    pub fn step_count(&self) -> usize {
        self.timeline.len()
    }

    /// One-line description of what was parsed, for the header.
    #[must_use]
    pub fn summary(&self) -> String {
        let s = &self.parsed.summary;
        let stats = self.parsed.coverage.stats();
        let resident = self.image.resident_bytes();
        let never = stats.total_bytes.saturating_sub(resident);
        let pct = if stats.total_bytes == 0 {
            0.0
        } else {
            never as f64 * 100.0 / stats.total_bytes as f64
        };
        let mut bits = vec![format!("{} claims", stats.claim_count)];
        bits.push(format!("{pct:.1}% never loaded"));
        if let Some(i) = &s.interp {
            bits.push(format!("interp {i}"));
        }
        if !s.needed.is_empty() {
            bits.push(format!("needs {}", s.needed.join(", ")));
        }
        if s.bind_now {
            bits.push("BIND_NOW".to_owned());
        }
        if s.has_relr {
            bits.push("DT_RELR".to_owned());
        }
        if !s.has_dynamic {
            bits.push("static".to_owned());
        }
        let double = self.image.double_mapped_bytes();
        if double > 0 {
            bits.push(format!("{double} bytes mapped twice"));
        }
        bits.join("   ·   ")
    }

    fn base(&self) -> Frame<'_> {
        Frame {
            coverage: &self.parsed.coverage,
            image: &self.image,
            title: &self.title,
            subtitle: &self.subtitle,
            step: None,
        }
    }

    /// The morph at frame `n` of `morphFrames()`.
    #[wasm_bindgen(js_name = renderMorph)]
    #[must_use]
    pub fn render_morph(&self, n: usize) -> String {
        let last = MORPH_FRAMES.saturating_sub(1).max(1) as f64;
        morph_svg(&self.base(), n as f64 / last)
    }

    /// Memory as of step `n` of the modelled load.
    #[wasm_bindgen(js_name = renderStep)]
    #[must_use]
    pub fn render_step(&self, n: usize) -> String {
        let n = n.min(self.timeline.len().saturating_sub(1));
        let state = self.timeline.state_at(n);
        let frame = Frame {
            step: Some(StepView {
                state: &state,
                narration: self
                    .timeline
                    .steps()
                    .get(n)
                    .map_or("", |s| s.narration.as_str()),
                n,
                total: self.timeline.len().saturating_sub(1),
            }),
            ..self.base()
        };
        morph_svg(&frame, 1.0)
    }
}
