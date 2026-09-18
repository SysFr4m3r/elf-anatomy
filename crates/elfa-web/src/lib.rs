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
use elfa_parse::{FileId, Parsed, Value, elf, parse};
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

    /// What is at a file offset, and who touches it.
    ///
    /// This is the query the whole data model was built for: `claims_at` answers in
    /// log time, and every `Step` already records the file spans it reads, so "which
    /// steps of the load care about this byte" costs one pass over a few dozen steps.
    ///
    /// Returns JSON: the claim path innermost-first, the innermost claim's value, the
    /// virtual address if the byte is loaded, and the steps that read or write it.
    ///
    /// The offset arrives as `f64` rather than `u64` on purpose: wasm-bindgen maps a
    /// Rust `u64` to a JavaScript BigInt, so an ordinary Number throws at the boundary.
    /// `f64` is exact to 2^53, which is every ELF file that will ever be dropped into a
    /// tab.
    #[must_use]
    #[allow(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "guarded above; f64 is exact well past any real file size"
    )]
    pub fn inspect(&self, offset: f64) -> String {
        let offset = if offset.is_finite() && offset >= 0.0 {
            offset as u64
        } else {
            0
        };
        let cov = &self.parsed.coverage;
        let stack = cov.claims_at(FileId::PRIMARY, offset);

        let mut path = Vec::new();
        for id in stack.iter().rev() {
            if let Some(c) = cov.claim(*id) {
                path.push(c.kind.field_name().unwrap_or(c.kind.label()).to_owned());
            }
        }

        let (detail, span) = stack.first().and_then(|id| cov.claim(*id)).map_or_else(
            || (String::new(), (offset, 0)),
            |c| {
                let v = match &c.value {
                    Value::Address(a) => format!("{a:#x}"),
                    Value::FileOffset(o) => format!("@{o:#x}"),
                    Value::Unsigned(u) => u.to_string(),
                    Value::Signed(i) => i.to_string(),
                    Value::Flags(f) => format!("{f:#x}"),
                    Value::Text(s) => format!("\u{22}{s}\u{22}"),
                    Value::Raw | Value::None => String::new(),
                };
                let note = c.note.as_deref().unwrap_or("");
                let detail = match (v.is_empty(), note.is_empty()) {
                    (false, false) => format!("{v}  —  {note}"),
                    (false, true) => v,
                    (true, false) => note.to_owned(),
                    (true, true) => String::new(),
                };
                (detail, (c.span.start, c.span.len))
            },
        );

        let vaddr = self.image.vaddr_of(offset);
        let mut steps = Vec::new();
        for (i, step) in self.timeline.steps().iter().enumerate() {
            let reads = step
                .reads
                .iter()
                .any(|s| offset >= s.start && offset < s.end());
            let writes = vaddr.is_some_and(|va| {
                step.effects.iter().any(|e| match e {
                    elfa_model::Effect::Write(p) => p.addr == va,
                    _ => false,
                })
            });
            if reads || writes {
                steps.push(i.to_string());
            }
        }

        format!(
            r#"{{"off":{},"len":{},"path":[{}],"detail":{},"va":{},"steps":[{}]}}"#,
            span.0,
            span.1,
            path.iter().map(|p| json_str(p)).collect::<Vec<_>>().join(","),
            json_str(&detail),
            vaddr.map_or_else(|| "null".to_owned(), |v| v.to_string()),
            steps.join(",")
        )
    }

    /// The file spans one step of the load reads, as JSON.
    ///
    /// Selecting a step and seeing which bytes caused it is the same relationship as
    /// selecting a byte and seeing which steps touch it, read the other way.
    #[wasm_bindgen(js_name = stepSpans)]
    #[must_use]
    pub fn step_spans(&self, n: usize) -> String {
        let spans = self
            .timeline
            .steps()
            .get(n)
            .map(|s| s.reads.as_slice())
            .unwrap_or_default();
        let body = spans
            .iter()
            .map(|s| format!(r#"{{"off":{},"len":{}}}"#, s.start, s.len))
            .collect::<Vec<_>>()
            .join(",");
        format!("[{body}]")
    }

    /// The narration for one step.
    #[wasm_bindgen(js_name = stepNarration)]
    #[must_use]
    pub fn step_narration(&self, n: usize) -> String {
        self.timeline
            .steps()
            .get(n)
            .map_or_else(String::new, |s| s.narration.clone())
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

/// Minimal JSON string escaping. The crate has no serde and does not need one: four
/// fields go out, and they are built here.
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            c if (c as u32) < 0x20 => out.push(' '),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}
