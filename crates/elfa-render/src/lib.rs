//! The morph, rendered headless.
//!
//! One picture, one slider. At `t = 0` the file is drawn in file order; at `t = 1` the
//! same bytes are drawn at the addresses the kernel maps them to. Everything in between is
//! interpolation, and the interpolation is the argument:
//!
//! - bands that are mapped slide across and land at their virtual addresses,
//! - bands that are **not** mapped — section headers, symbol tables, debug info, the
//!   padding between segments — drift left and fade, because nothing loads them,
//! - `.bss` grows from nothing on the right, because it is in `p_memsz` and in no file.
//!
//! SVG rather than a canvas, deliberately. If the idea only works with interactivity and
//! polish, it does not work; a flat frame sequence is the cheapest way to find that out.
//! See `PROJECT_PLAN.md` §0.4.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use elfa_model::{MapSource, MemImage};
use elfa_parse::{ClaimId, ClaimKind, Coverage, FileId, Span};

const W: f64 = 1200.0;
const H: f64 = 840.0;
const TOP: f64 = 124.0;
const PLOT_H: f64 = 600.0;
const COL_W: f64 = 200.0;
const X_FILE: f64 = 150.0;
const X_MEM: f64 = 720.0;

const BG: &str = "#0f1115";
const FG: &str = "#d7dde5";
const MUTED: &str = "#6b7482";

/// A contiguous stretch of file claimed by one top-level structure — in practice, one
/// section. Grouping at this level keeps a 1,200-claim binary to ~30 bands, which is what
/// makes the picture legible rather than a barcode.
#[derive(Clone, Debug)]
pub struct Run {
    pub span: Span,
    pub label: String,
    pub class: Class,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Class {
    Header,
    Code,
    ReadOnly,
    Data,
    Dynamic,
    Reloc,
    Symbols,
    Debug,
    Filler,
    Other,
    ZeroFill,
}

impl Class {
    #[must_use]
    pub const fn color(self) -> &'static str {
        match self {
            Self::Header => "#4c8dff",
            Self::Code => "#ff8b3d",
            Self::ReadOnly => "#2fb8a8",
            Self::Data => "#5fd38d",
            Self::Dynamic => "#e8c547",
            Self::Reloc => "#ef6ea8",
            Self::Symbols => "#a98bff",
            Self::Debug => "#5a6b82",
            Self::Filler => "#2b3038",
            Self::Other => "#8892a0",
            Self::ZeroFill => "#00d0c0",
        }
    }

    fn of(kind: &ClaimKind, label: &str) -> Self {
        if label.starts_with(".debug") || label == ".comment" {
            return Self::Debug;
        }
        match kind {
            ClaimKind::FileHeader
            | ClaimKind::ProgramHeaderTable
            | ClaimKind::SectionHeaderTable => Self::Header,
            ClaimKind::DynamicTable | ClaimKind::Interp => Self::Dynamic,
            ClaimKind::RelocationTable { .. } => Self::Reloc,
            ClaimKind::SymbolTable { .. }
            | ClaimKind::StringTable { .. }
            | ClaimKind::HashTable { .. }
            | ClaimKind::VersionTable { .. } => Self::Symbols,
            ClaimKind::Unclaimed | ClaimKind::Padding { .. } => Self::Filler,
            _ => match label {
                ".text" | ".init" | ".fini" | ".plt" | ".plt.got" | ".plt.sec" => Self::Code,
                ".rodata" | ".eh_frame" | ".eh_frame_hdr" => Self::ReadOnly,
                ".data" | ".got" | ".got.plt" | ".data.rel.ro" | ".init_array" | ".fini_array" => {
                    Self::Data
                }
                _ => Self::Other,
            },
        }
    }
}

/// Merge leaves into top-level bands, in file order.
#[must_use]
pub fn runs(cov: &Coverage) -> Vec<Run> {
    let mut leaves: Vec<(Span, ClaimId)> = cov
        .leaves()
        .filter_map(|id| Some((cov.span_of(id)?, id)))
        .filter(|(s, _)| s.file == FileId::PRIMARY && !s.is_empty())
        .collect();
    leaves.sort_unstable_by_key(|(s, _)| s.start);

    let mut out: Vec<Run> = Vec::new();
    let mut current: Option<(ClaimId, Run)> = None;

    for (span, id) in leaves {
        let top = cov.ancestry(id).last().copied().unwrap_or(id);
        match &mut current {
            Some((top_id, run)) if *top_id == top && run.span.end() == span.start => {
                run.span.len = run.span.len.saturating_add(span.len);
                continue;
            }
            _ => {}
        }
        if let Some((_, run)) = current.take() {
            out.push(run);
        }
        let (label, class) = cov.claim(top).map_or_else(
            || (String::new(), Class::Other),
            |c| {
                let note = c.note.as_deref().unwrap_or_default();
                // Section names are already the right label. Everything else carries
                // explanatory prose, which belongs in a tooltip, not on a 12px band.
                let label = match &c.kind {
                    ClaimKind::FileHeader => "ELF header".to_string(),
                    ClaimKind::ProgramHeaderTable => "program headers".to_string(),
                    ClaimKind::SectionHeaderTable => "section headers".to_string(),
                    ClaimKind::Unclaimed | ClaimKind::Padding { .. } => String::new(),
                    _ if note.starts_with('.') => note.to_string(),
                    other => other.label().to_string(),
                };
                let class = Class::of(&c.kind, note);
                (label, class)
            },
        );
        current = Some((top, Run { span, label, class }));
    }
    if let Some((_, run)) = current {
        out.push(run);
    }
    out
}

/// Everything a frame needs besides the geometry.
#[derive(Clone, Copy, Debug)]
pub struct Frame<'a> {
    pub coverage: &'a Coverage,
    pub image: &'a MemImage,
    pub title: &'a str,
    pub subtitle: &'a str,
}

fn lerp(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Render one frame of the morph at `t` in `[0, 1]`.
#[must_use]
pub fn morph_svg(frame: &Frame<'_>, t: f64) -> String {
    let t = t.clamp(0.0, 1.0);
    // Ease so the ends settle instead of stopping dead.
    let e = t * t * (3.0 - 2.0 * t);

    let file_len = frame.coverage.file_len(FileId::PRIMARY).unwrap_or(1).max(1) as f64;
    let (lo, hi) = frame.image.extent().unwrap_or((0, 1));
    let vspan = hi.saturating_sub(lo).max(1) as f64;

    let file_y = |off: u64| TOP + (off as f64) * PLOT_H / file_len;
    let mem_y = |va: u64| TOP + ((va.saturating_sub(lo)) as f64) * PLOT_H / vspan;

    let mut s = String::with_capacity(64 * 1024);
    s.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}" width="{W}" height="{H}" font-family="ui-monospace,SFMono-Regular,Menlo,monospace">
<rect width="{W}" height="{H}" fill="{BG}"/>
"#
    ));

    s.push_str(&format!(
        r#"<text x="40" y="46" fill="{FG}" font-size="21">{}</text>
<text x="40" y="70" fill="{MUTED}" font-size="13">{}</text>
"#,
        esc(frame.title),
        esc(frame.subtitle)
    ));

    // Column captions fade in and out as the morph crosses over.
    let file_op = (1.0 - e * 1.6).clamp(0.12, 1.0);
    let mem_op = (e * 1.6).clamp(0.12, 1.0);
    s.push_str(&format!(
        r#"<text x="{X_FILE}" y="{y}" fill="{FG}" font-size="13" opacity="{file_op:.2}">FILE</text>
<text x="{X_FILE}" y="{y2}" fill="{MUTED}" font-size="11" opacity="{file_op:.2}">0x0 … {flen:#x}</text>
<text x="{X_MEM}" y="{y}" fill="{FG}" font-size="13" opacity="{mem_op:.2}">MEMORY</text>
<text x="{X_MEM}" y="{y2}" fill="{MUTED}" font-size="11" opacity="{mem_op:.2}">{lo:#x} … {hi:#x}</text>
"#,
        y = TOP - 32.0,
        y2 = TOP - 16.0,
        flen = file_len as u64,
    ));

    // Measured on the image rather than accumulated per band: a band can straddle the
    // edge of a mapped page, and attributing it by its first byte would be wrong.
    let never_loaded = (file_len as u64).saturating_sub(frame.image.resident_bytes());
    // A band 3px tall still deserves its bytes counted, but not a label on top of its
    // neighbour's. Two floors, because the two columns are at different x and their
    // labels cannot collide with each other.
    let mut floor_mapped = f64::NEG_INFINITY;
    let mut floor_ghost = f64::NEG_INFINITY;

    for run in runs(frame.coverage) {
        let fy0 = file_y(run.span.start);
        let fy1 = file_y(run.span.end());
        let mapped = frame.image.vaddr_of(run.span.start);

        let is_mapped = mapped.is_some();
        let (x, y, h, opacity) = match mapped {
            Some(va) => {
                let my0 = mem_y(va);
                let my1 = mem_y(va.saturating_add(run.span.len));
                (
                    lerp(X_FILE, X_MEM, e),
                    lerp(fy0, my0, e),
                    lerp(fy1 - fy0, my1 - my0, e).max(1.0),
                    1.0,
                )
            }
            None => {
                // Left-behind bands must stay legible. They are the frame's argument:
                // this is what a binary carries that never becomes part of a process.
                (
                    X_FILE - 40.0 * e,
                    fy0,
                    (fy1 - fy0).max(1.0),
                    (1.0 - e * 0.72).max(0.28),
                )
            }
        };

        s.push_str(&format!(
            r#"<rect x="{x:.1}" y="{y:.1}" width="{COL_W}" height="{h:.1}" fill="{}" opacity="{opacity:.2}"/>
"#,
            run.class.color()
        ));

        let ly = y + h.min(14.0) - 2.0;
        let floor = if is_mapped {
            &mut floor_mapped
        } else {
            &mut floor_ghost
        };
        if h >= 9.0 && !run.label.is_empty() && ly >= *floor {
            *floor = ly + 14.0;
            s.push_str(&format!(
                r#"<text x="{lx:.1}" y="{ly:.1}" fill="{FG}" font-size="11" opacity="{:.2}">{}</text>
"#,
                if is_mapped { opacity * 0.85 } else { opacity * 0.95 },
                esc(&run.label),
                lx = x + COL_W + 8.0,
            ));
        }
    }

    // .bss: present only on the memory side, so it grows from nothing.
    for m in frame.image.mappings() {
        if m.source != MapSource::ZeroFill {
            continue;
        }
        let y0 = mem_y(m.vaddr);
        let y1 = mem_y(m.end());
        let h = ((y1 - y0) * e).max(if e > 0.02 { 1.0 } else { 0.0 });
        if h <= 0.0 {
            continue;
        }
        s.push_str(&format!(
            r#"<rect x="{X_MEM}" y="{y0:.1}" width="{COL_W}" height="{h:.1}" fill="{}" opacity="{e:.2}"/>
<rect x="{X_MEM}" y="{y0:.1}" width="{COL_W}" height="{h:.1}" fill="none" stroke="{}" stroke-width="1" stroke-dasharray="3 3" opacity="{e:.2}"/>
"#,
            Class::ZeroFill.color(),
            Class::ZeroFill.color(),
        ));
        if h >= 9.0 {
            s.push_str(&format!(
                r#"<text x="{lx:.1}" y="{ly:.1}" fill="{}" font-size="11" opacity="{e:.2}">.bss — zero-filled, in no file</text>
"#,
                Class::ZeroFill.color(),
                lx = X_MEM + COL_W + 8.0,
                ly = y0 + h.min(14.0) - 2.0,
            ));
        }
    }

    let pct = never_loaded as f64 * 100.0 / file_len;
    let zero = frame.image.zero_filled_bytes();
    s.push_str(&format!(
        r#"<text x="40" y="{cy}" fill="{MUTED}" font-size="13">{} of the file is never loaded   ·   {} bytes of memory come from no file</text>
<rect x="40" y="{by}" width="{tot}" height="3" fill="{FG}" opacity="0.12"/>
<rect x="40" y="{by}" width="{bw:.1}" height="3" fill="{FG}" opacity="0.55"/>
</svg>
"#,
        format_args!("{pct:.1}%"),
        zero,
        cy = TOP + PLOT_H + 56.0,
        by = TOP + PLOT_H + 76.0,
        bw = (W - 80.0) * t,
        tot = W - 80.0,
    ));
    s
}
