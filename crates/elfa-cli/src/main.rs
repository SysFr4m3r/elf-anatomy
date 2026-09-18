//! `elfa` — the command-line front end.
//!
//! Three subcommands, all of which answer the same question at different zoom levels:
//! what is in this file, and is any of it unaccounted for?
//!
//! Argument parsing is hand-rolled. The surface is three verbs and two flags; a
//! dependency would be larger than the code it replaced.

use std::process::ExitCode;

use elfa_model::{MapSource, MemImage, Prot, Timeline};
use elfa_parse::{ClaimId, ClaimKind, Coverage, Parsed, Span, Value, elf, parse};
use elfa_render::{Frame, StepView, Track, morph_svg, player_html};

/// `println!` that exits quietly when the reader goes away.
///
/// `elfa dump /bin/ls | head` closes the pipe as soon as it has ten lines. The standard
/// `println!` panics on the resulting `EPIPE` and prints a Rust backtrace note over the
/// user's terminal, for what is ordinary shell usage. `head`-ing a long listing is exactly
/// how someone explores a 1,200-claim tree.
macro_rules! outln {
    () => { outln!("") };
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if let Err(e) = writeln!(std::io::stdout(), $($arg)*)
            && e.kind() == std::io::ErrorKind::BrokenPipe
        {
            std::process::exit(0);
        }
    }};
}

/// `print!`, with the same treatment.
macro_rules! out {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        if let Err(e) = write!(std::io::stdout(), $($arg)*)
            && e.kind() == std::io::ErrorKind::BrokenPipe
        {
            std::process::exit(0);
        }
    }};
}

const USAGE: &str = "\
elfa — look at what is actually in an ELF file

USAGE
  elfa verify <file>...          check that every byte is accounted for
  elfa dump <file> [--depth N]   print the claim tree (default depth 2, --all for everything)
  elfa at <file> <offset>        what covers this byte? (offset may be decimal or 0x hex)
  elfa map <file>                what the kernel maps, and what it leaves behind
  elfa morph <file> [-o DIR]     the file→memory morph as SVG frames (--frames N, --t X)
                                 --step N renders the image as of one step of the load
  elfa trace <file> [-o FILE]    run it and record what the real loader did (--json)
  elfa steps <file>              the modelled load, step by step (--limit N, --phase P)
  elfa diff <file>               check the model against what the real loader does
  elfa process <file>            the whole dependency closure (--verify against a real load)
  elfa suspect <file>...         what the file cannot account for
  elfa play <file> [-o FILE]     one HTML file that scrubs through both animations
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(verb) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };

    let rest: Vec<&str> = args.iter().skip(1).map(String::as_str).collect();
    match verb.as_str() {
        "verify" => cmd_verify(&rest),
        "dump" => cmd_dump(&rest),
        "at" => cmd_at(&rest),
        "map" => cmd_map(&rest),
        "morph" => cmd_morph(&rest),
        "trace" => cmd_trace(&rest),
        "steps" => cmd_steps(&rest),
        "diff" => cmd_diff(&rest),
        "process" => cmd_process(&rest),
        "suspect" => cmd_suspect(&rest),
        "play" => cmd_play(&rest),
        "-h" | "--help" | "help" => {
            out!("{USAGE}");
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command `{other}`\n");
            eprint!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

fn load(path: &str) -> Option<Parsed> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("{path}: {e}");
            return None;
        }
    };
    match parse(&bytes) {
        Ok(p) => Some(p),
        Err(e) => {
            eprintln!("{path}: {e}");
            None
        }
    }
}

fn cmd_verify(args: &[&str]) -> ExitCode {
    if args.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    for path in args {
        match load(path) {
            Some(p) => report(path, &p),
            None => failed = true,
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn report(path: &str, p: &Parsed) {
    let s = &p.summary;
    let stats = p.coverage.stats();

    let etype = elf::et_name(s.e_type).unwrap_or("ET_?");
    let machine = elf::em_name(s.machine).unwrap_or("EM_?");
    outln!("{path}  {etype} {machine}  entry {:#x}", s.entry);

    let mut line2 = Vec::new();
    if let Some(i) = &s.interp {
        line2.push(format!("interp {i}"));
    }
    if !s.needed.is_empty() {
        line2.push(format!("needed {}", s.needed.join(", ")));
    }
    if s.bind_now {
        line2.push("BIND_NOW".to_owned());
    }
    if s.has_relr {
        line2.push("DT_RELR".to_owned());
    }
    if !s.has_dynamic {
        line2.push("static".to_owned());
    }
    if !line2.is_empty() {
        outln!("  {}", line2.join("   "));
    }

    let pct = |n: u64| -> f64 {
        if stats.total_bytes == 0 {
            0.0
        } else {
            (n as f64) * 100.0 / (stats.total_bytes as f64)
        }
    };

    outln!("");
    outln!("  coverage      ok — every byte claimed exactly once");
    outln!("  size          {} bytes", commas(stats.total_bytes));
    outln!(
        "  claims        {} ({} leaves, depth {})",
        commas(stats.claim_count as u64),
        commas(stats.leaf_count as u64),
        stats.max_depth
    );
    outln!(
        "  explained     {:>12}  {:5.1}%",
        commas(stats.explained_bytes),
        pct(stats.explained_bytes)
    );
    outln!(
        "  unexplained   {:>12}  {:5.1}%",
        commas(stats.filler_bytes),
        pct(stats.filler_bytes)
    );

    let mut holes: Vec<(Span, String)> = p
        .coverage
        .leaves()
        .filter(|id| {
            p.coverage
                .claim(*id)
                .is_some_and(|c| c.kind == ClaimKind::Unclaimed)
        })
        .filter_map(|id| {
            let c = p.coverage.claim(id)?;
            Some((c.span, context(&p.coverage, id)))
        })
        .collect();
    holes.sort_by_key(|(s, _)| std::cmp::Reverse(s.len));

    if !holes.is_empty() {
        outln!("\n  largest unexplained regions");
        for (span, ctx) in holes.iter().take(8) {
            outln!("    {:#010x}  {:>10}  {ctx}", span.start, commas(span.len));
        }
        if holes.len() > 8 {
            outln!("    … and {} more", holes.len().saturating_sub(8));
        }
    }
    outln!("");
}

/// Where a hole sits, named by its neighbours.
///
/// "between structures" is true and useless. What a reader wants is "after .rela.plt,
/// before .init" — which, once you see it, immediately explains the hole: those two are in
/// different segments, and segments are page-aligned in the file.
fn context(cov: &Coverage, id: ClaimId) -> String {
    let Some(span) = cov.span_of(id) else {
        return String::new();
    };

    // A hole inside something is described by what it is inside.
    if let Some(parent) = cov.parent(id)
        && let Some(name) = top_level_note(cov, parent)
    {
        return format!("inside {name}");
    }

    let before = span
        .start
        .checked_sub(1)
        .and_then(|prev| cov.innermost_at(elfa_parse::FileId::PRIMARY, prev))
        .and_then(|id| top_level_note(cov, id));
    let after = cov
        .innermost_at(elfa_parse::FileId::PRIMARY, span.end())
        .and_then(|id| top_level_note(cov, id));

    let mut s = match (before, after) {
        (Some(b), Some(a)) => format!("after {b}, before {a}"),
        (Some(b), None) => format!("after {b}, to end of file"),
        (None, Some(a)) => format!("before {a}"),
        (None, None) => "between structures".to_owned(),
    };
    // Page-aligned end is the signature of segment padding rather than a mystery.
    if span.end() % 0x1000 == 0 {
        s.push_str("  (page alignment)");
    }
    s
}

/// The name of the outermost structure a claim belongs to — in practice, its section.
fn top_level_note(cov: &Coverage, id: ClaimId) -> Option<String> {
    let outermost = *cov.ancestry(id).last()?;
    let note = cov.claim(outermost)?.note.as_deref()?;
    if note.is_empty() {
        None
    } else {
        Some(note.to_owned())
    }
}

fn cmd_dump(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let mut depth = 2usize;
    let mut i = 1;
    while let Some(arg) = args.get(i) {
        match *arg {
            "--all" => depth = usize::MAX,
            "--depth" => {
                depth = args
                    .get(i.saturating_add(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(depth);
                i = i.saturating_add(1);
            }
            other => {
                eprintln!("unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i = i.saturating_add(1);
    }

    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    for root in p.coverage.roots() {
        print_tree(&p.coverage, *root, 0, depth);
    }
    ExitCode::SUCCESS
}

fn print_tree(cov: &Coverage, id: ClaimId, level: usize, max: usize) {
    let Some(c) = cov.claim(id) else { return };
    let indent = "  ".repeat(level);
    let detail = match (&c.value, &c.note) {
        (Value::Text(t), _) => format!("\"{t}\""),
        (Value::Address(a), Some(n)) => format!("{a:#x}  {n}"),
        (Value::Address(a), None) => format!("{a:#x}"),
        (Value::FileOffset(o), _) => format!("@{o:#x}"),
        (Value::Unsigned(v), Some(n)) => format!("{v}  {n}"),
        (Value::Unsigned(v), None) => format!("{v}"),
        (Value::Flags(v), _) => format!("{v:#x}"),
        (_, Some(n)) => n.to_string(),
        _ => String::new(),
    };
    outln!(
        "{:#010x} {:>9}  {indent}{:<16} {detail}",
        c.span.start,
        commas(c.span.len),
        c.kind.field_name().unwrap_or_else(|| c.kind.label())
    );
    if level >= max {
        let kids = cov.children(id).len();
        if kids > 0 {
            outln!("{:>21}  {indent}  … {kids} children", "");
        }
        return;
    }
    for child in cov.children(id) {
        print_tree(cov, *child, level.saturating_add(1), max);
    }
}

fn cmd_at(args: &[&str]) -> ExitCode {
    let (Some(path), Some(off_str)) = (args.first(), args.get(1)) else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let off = match off_str.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => off_str.parse().ok(),
    };
    let Some(off) = off else {
        eprintln!("`{off_str}` is not an offset");
        return ExitCode::FAILURE;
    };
    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };

    let stack = p.coverage.claims_at(elfa_parse::FileId::PRIMARY, off);
    if stack.is_empty() {
        outln!("{off:#x} is past the end of the file");
        return ExitCode::SUCCESS;
    }
    outln!("byte {off:#x}, innermost first:\n");
    for (level, id) in stack.iter().enumerate() {
        let Some(c) = p.coverage.claim(*id) else {
            continue;
        };
        let note = c.note.as_deref().unwrap_or("");
        outln!(
            "{}{:<16} {:#010x}..{:#010x}  {note}",
            "  ".repeat(level),
            c.kind.field_name().unwrap_or_else(|| c.kind.label()),
            c.span.start,
            c.span.end()
        );
    }
    ExitCode::SUCCESS
}

fn cmd_map(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    let image = MemImage::from_segments(&p.summary.segments, p.coverage.stats().total_bytes);
    let total = p.coverage.stats().total_bytes;

    outln!("{path}  {} mappings\n", image.mappings().len());
    outln!("  {:<20} {:>12}  {:<5} source", "vaddr", "size", "prot");
    for m in image.mappings() {
        let source = match m.source {
            MapSource::FromFile(s) => format!("file {:#x}..{:#x}", s.start, s.end()),
            MapSource::ZeroFill => "zero-fill — in no file".to_owned(),
        };
        outln!(
            "  {:<20} {:>12}  {:<5} {source}",
            format!("{:#010x}", m.vaddr),
            commas(m.len),
            m.prot.as_str()
        );
    }

    outln!("\n  kernel mappings — page-rounded, as /proc/<pid>/maps would show");
    for v in image.vmas() {
        outln!(
            "    {:#010x}-{:#010x}  {}  {:>10} bytes",
            v.start,
            v.end,
            v.prot.as_str(),
            commas(v.end.saturating_sub(v.start))
        );
    }

    let resident = image.resident_bytes();
    let never = total.saturating_sub(resident);
    let double = image.double_mapped_bytes();
    let pct = |n: u64| -> f64 {
        if total == 0 {
            0.0
        } else {
            n as f64 * 100.0 / total as f64
        }
    };
    outln!("");
    outln!(
        "  in the process    {:>12}  {:5.1}%   including whatever shares a mapped page",
        commas(resident),
        pct(resident)
    );
    outln!(
        "  never loaded      {:>12}  {:5.1}%   section headers, symbols, debug info",
        commas(never),
        pct(never)
    );
    outln!(
        "  zero-filled       {:>12}          .bss — memory with no file behind it",
        commas(image.zero_filled_bytes())
    );
    if double > 0 {
        outln!(
            "  mapped twice      {:>12}          file pages shared by two segments",
            commas(double)
        );
    }
    outln!("");
    ExitCode::SUCCESS
}

fn cmd_morph(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let mut out_dir: Option<&str> = None;
    let mut frames = 48usize;
    let mut single: Option<f64> = None;
    let mut step: Option<usize> = None;

    let mut i = 1;
    while let Some(arg) = args.get(i) {
        match *arg {
            "-o" | "--out" => {
                out_dir = args.get(i.saturating_add(1)).copied();
                i = i.saturating_add(1);
            }
            "--frames" => {
                frames = args
                    .get(i.saturating_add(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(frames);
                i = i.saturating_add(1);
            }
            "--t" => {
                single = args.get(i.saturating_add(1)).and_then(|v| v.parse().ok());
                i = i.saturating_add(1);
            }
            "--step" => {
                step = args.get(i.saturating_add(1)).and_then(|v| v.parse().ok());
                i = i.saturating_add(1);
            }
            other => {
                eprintln!("unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i = i.saturating_add(1);
    }

    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    let image = MemImage::from_segments(&p.summary.segments, p.coverage.stats().total_bytes);
    if image.is_empty() {
        eprintln!("{path}: no PT_LOAD segments; nothing to map");
        return ExitCode::FAILURE;
    }

    let s = &p.summary;
    let subtitle = format!(
        "{}  {}  entry {:#x}   {} bytes on disk",
        elf::et_name(s.e_type).unwrap_or("ET_?"),
        elf::em_name(s.machine).unwrap_or("EM_?"),
        s.entry,
        commas(p.coverage.stats().total_bytes)
    );
    // The timeline is built either way: --step selects a moment in it, and without it
    // the frame is the finished load.
    let timeline = Timeline::plan(&p.summary, &image);
    let state = step.map(|n| timeline.state_at(n.min(timeline.len().saturating_sub(1))));
    let view = match (&state, step) {
        (Some(state), Some(n)) => {
            let n = n.min(timeline.len().saturating_sub(1));
            Some(StepView {
                state,
                narration: timeline.steps().get(n).map_or("", |s| s.narration.as_str()),
                n,
                total: timeline.len().saturating_sub(1),
            })
        }
        _ => None,
    };
    let frame = Frame {
        coverage: &p.coverage,
        image: &image,
        title: path,
        subtitle: &subtitle,
        step: view,
    };

    // A step frame is a picture of memory, so it is always drawn at the memory end.
    if step.is_some() {
        let svg = morph_svg(&frame, 1.0);
        return match out_dir {
            Some(dir) => write_file(std::path::Path::new(dir), &svg),
            None => {
                out!("{svg}");
                ExitCode::SUCCESS
            }
        };
    }

    if let Some(t) = single {
        let svg = morph_svg(&frame, t);
        return match out_dir {
            Some(dir) => write_file(std::path::Path::new(dir), &svg),
            None => {
                out!("{svg}");
                ExitCode::SUCCESS
            }
        };
    }

    let dir = out_dir.unwrap_or("frames");
    if let Err(e) = std::fs::create_dir_all(dir) {
        eprintln!("{dir}: {e}");
        return ExitCode::FAILURE;
    }
    let last = frames.saturating_sub(1).max(1) as f64;
    for n in 0..frames {
        let t = n as f64 / last;
        let svg = morph_svg(&frame, t);
        let out = std::path::Path::new(dir).join(format!("frame_{n:03}.svg"));
        if write_file(&out, &svg) == ExitCode::FAILURE {
            return ExitCode::FAILURE;
        }
    }
    outln!("{frames} frames in {dir}/");
    ExitCode::SUCCESS
}

fn cmd_steps(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let mut limit = usize::MAX;
    let mut phase: Option<&str> = None;
    let mut i = 1;
    while let Some(arg) = args.get(i) {
        match *arg {
            "--limit" => {
                limit = args
                    .get(i.saturating_add(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(limit);
                i = i.saturating_add(1);
            }
            "--phase" => {
                phase = args.get(i.saturating_add(1)).copied();
                i = i.saturating_add(1);
            }
            other => {
                eprintln!("unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i = i.saturating_add(1);
    }

    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    let image = MemImage::from_segments(&p.summary.segments, p.coverage.stats().total_bytes);
    let timeline = Timeline::plan(&p.summary, &image);

    outln!("{path}  {} steps modelled\n", timeline.len());

    let mut last_phase = None;
    let mut shown = 0usize;
    for step in timeline.steps() {
        if phase.is_some_and(|p| p != step.phase.as_str()) {
            continue;
        }
        if shown >= limit {
            outln!("    … {} more steps", timeline.len().saturating_sub(shown));
            break;
        }
        if last_phase != Some(step.phase) {
            outln!("  {} · {}", step.phase.as_str(), step.actor.as_str());
            last_phase = Some(step.phase);
        }
        outln!("    {:>4}  {}", step.n, step.narration);
        shown = shown.saturating_add(1);
    }

    let end = timeline.state_at(timeline.len());
    outln!(
        "\n  at the end: {} mappings, {} addresses written before the program ran",
        end.mappings.len(),
        end.poked.len()
    );
    outln!("");
    ExitCode::SUCCESS
}

/// A mapping as both sides describe it: base-relative range, protection, file offset.
type Row = (u64, u64, Prot, Option<u64>);

/// One comparison between the model and an observed load.
struct Check {
    name: &'static str,
    verdict: Verdict,
    detail: String,
}

enum Verdict {
    Match,
    Differ,
    /// The model does not claim anything here, so there is nothing to check. Said out
    /// loud rather than silently passing — an unchecked area that looks checked is worse
    /// than a gap you can see.
    NotModelled,
}

impl Verdict {
    const fn mark(&self) -> &'static str {
        match self {
            Self::Match => "ok  ",
            Self::Differ => "DIFF",
            Self::NotModelled => "--  ",
        }
    }
}

fn cmd_suspect(args: &[&str]) -> ExitCode {
    if args.is_empty() {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    }
    let mut flagged = 0usize;
    for path in args {
        let Ok(bytes) = std::fs::read(path) else {
            eprintln!("{path}: cannot read");
            continue;
        };
        let parsed = match elfa_parse::parse(&bytes) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("{path}: {e}");
                continue;
            }
        };
        let image = MemImage::from_segments(
            &parsed.summary.segments,
            parsed.coverage.stats().total_bytes,
        );
        let findings = elfa_audit::audit(&parsed, &image, &bytes);
        let explained = elfa_audit::explained_fraction(&parsed) * 100.0;

        outln!(
            "{path}  {} bytes, {explained:.1}% accounted for",
            commas(bytes.len() as u64)
        );
        if findings.is_empty() {
            outln!("  nothing to report\n");
            continue;
        }
        for f in &findings {
            if f.severity == elfa_audit::Severity::Suspicious {
                flagged = flagged.saturating_add(1);
            }
            outln!("  {:<8} {}", f.severity.as_str(), f.title);
            outln!("           {}", f.detail);
        }
        outln!();
    }
    // Findings are not verdicts, so the exit code reports whether anything was flagged
    // rather than whether anything is wrong.
    if flagged > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_process(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let verify = args.contains(&"--verify");

    let proc = match elfa_load::load(
        std::path::Path::new(path),
        &elfa_load::SearchPath::default(),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };

    let mapped = proc.total_mapped();
    let relocs = proc.total_relocations();
    outln!(
        "{path}  {} objects, {} mapped, {} startup relocations\n",
        proc.objects.len(),
        commas(mapped),
        commas(relocs as u64)
    );
    outln!(
        "  {:<2} {:<38} {:>10} {:>9}  {}",
        "#",
        "object",
        "mapped",
        "relocs",
        "needed by"
    );
    for o in &proc.objects {
        let by = o.needed_by.map_or_else(
            || "—".to_owned(),
            |n| {
                proc.objects
                    .get(n as usize)
                    .map_or_else(|| n.to_string(), |p| short(&p.path))
            },
        );
        outln!(
            "  {:<2} {:<38} {:>10} {:>9}  {by}",
            o.id,
            short(&o.path),
            commas(o.image.resident_bytes()),
            commas(o.startup_relocations() as u64)
        );
    }

    outln!("\n  relocation order — dependencies first");
    for o in proc.relocation_order() {
        outln!("    {}", short(&o.path));
    }

    // The number that justifies following the closure at all.
    if let Some(program) = proc.program()
        && relocs > 0
    {
        let share = program.startup_relocations() as f64 * 100.0 / relocs as f64;
        outln!("\n  the program is {share:.1}% of the relocations its own startup performs");
    }
    outln!();

    if !verify {
        return ExitCode::SUCCESS;
    }

    // Resolution is a claim about behaviour, so check it against the loader's own answer.
    if proc.objects.len() < 2 {
        outln!("  nothing to verify: no dependencies\n");
        return ExitCode::SUCCESS;
    }
    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    eprintln!("running {path} to observe its load…");
    let observed = match elfa_trace::capture(
        std::path::Path::new(path),
        p.summary.entry,
        p.summary.e_type == 3,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let aliases = observed.aliases();
    let mut wrong = 0usize;
    outln!("  resolution, ours against the loader's");
    // Compare by canonical path. On a usrmerge system /lib is a symlink to /usr/lib, so a
    // naive search and the loader's cache name the same inode by different paths, and a
    // string comparison calls that a divergence four times over.
    let canon = |s: &str| {
        std::fs::canonicalize(s).map_or_else(|_| s.to_owned(), |p| p.display().to_string())
    };
    for o in proc.objects.iter().skip(1) {
        let theirs = aliases.get(&o.requested);
        let ours = o.path.display().to_string();
        let verdict = match theirs {
            Some(t) if canon(t) == canon(&ours) => "ok  ",
            Some(_) => {
                wrong = wrong.saturating_add(1);
                "DIFF"
            }
            None => "--  ",
        };
        outln!(
            "    {verdict}  {:<24} {ours}{}",
            o.requested,
            theirs.map_or_else(
                || "   (the loader did not search for it)".to_owned(),
                |t| if canon(t) == canon(&ours) {
                    String::new()
                } else {
                    format!("\n              loader chose {t}")
                }
            )
        );
    }

    // Order. The model claims dependencies are relocated before the objects that need
    // them — a partial order, not a sequence. glibc also has a total order, produced by
    // its own sort of the link map, and it breaks ties between unrelated objects
    // differently: for /bin/ls it relocates libc before libpcre2, we discover libpcre2
    // first. Both satisfy the claim. Asserting the sequence would be asserting glibc's
    // tie-breaking, which is not modelled and not part of the claim.
    let theirs: Vec<&str> = observed
        .relocation_order()
        .into_iter()
        .filter(|o| !o.contains("ld-linux"))
        .collect();
    let rank = |needle: &std::path::Path| -> Option<usize> {
        let base = needle.file_name()?.to_string_lossy().into_owned();
        theirs.iter().position(|o| o.ends_with(&base))
    };

    let mut violations = Vec::new();
    for o in &proc.objects {
        let Some(parent) = o.needed_by.and_then(|n| proc.objects.get(n as usize)) else {
            continue;
        };
        if let (Some(dep), Some(user)) = (rank(&o.path), rank(&parent.path))
            && dep > user
        {
            violations.push(format!("{} after {}", short(&o.path), short(&parent.path)));
        }
    }

    let edges = proc
        .objects
        .iter()
        .filter(|o| o.needed_by.is_some())
        .count();
    outln!(
        "\n  relocation order      {}",
        if violations.is_empty() {
            format!("ok    {edges} dependency edge(s) respected; order {theirs:?}")
        } else {
            wrong = wrong.saturating_add(1);
            format!("DIFF  {violations:?}")
        }
    );

    outln!();
    if wrong > 0 {
        outln!("  {wrong} divergence(s); see docs/CONFORMANCE.md\n");
    }
    ExitCode::SUCCESS
}

/// Basename for library paths, full path for anything the user typed.
fn short(p: &std::path::Path) -> String {
    p.file_name().map_or_else(
        || p.display().to_string(),
        |n| n.to_string_lossy().into_owned(),
    )
}

fn cmd_play(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let mut out = "player.html";
    let mut frames = 36usize;
    let mut i = 1;
    while let Some(arg) = args.get(i) {
        match *arg {
            "-o" | "--out" => {
                out = args.get(i.saturating_add(1)).copied().unwrap_or(out);
                i = i.saturating_add(1);
            }
            "--frames" => {
                frames = args
                    .get(i.saturating_add(1))
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(frames);
                i = i.saturating_add(1);
            }
            other => {
                eprintln!("unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i = i.saturating_add(1);
    }

    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    let image = MemImage::from_segments(&p.summary.segments, p.coverage.stats().total_bytes);
    if image.is_empty() {
        eprintln!("{path}: no PT_LOAD segments; nothing to map");
        return ExitCode::FAILURE;
    }
    let timeline = Timeline::plan(&p.summary, &image);
    let s = &p.summary;
    let subtitle = format!(
        "{}  {}  entry {:#x}   {} bytes on disk",
        elf::et_name(s.e_type).unwrap_or("ET_?"),
        elf::em_name(s.machine).unwrap_or("EM_?"),
        s.entry,
        commas(p.coverage.stats().total_bytes)
    );

    let base = Frame {
        coverage: &p.coverage,
        image: &image,
        title: path,
        subtitle: &subtitle,
        step: None,
    };

    let last = frames.saturating_sub(1).max(1) as f64;
    let morph = Track {
        name: "file → memory".to_owned(),
        frames: (0..frames)
            .map(|n| morph_svg(&base, n as f64 / last))
            .collect(),
        captions: Vec::new(),
    };

    let total = timeline.len().saturating_sub(1);
    let steps = Track {
        name: format!("the load · {} steps", timeline.len()),
        frames: (0..timeline.len())
            .map(|n| {
                let state = timeline.state_at(n);
                let frame = Frame {
                    step: Some(StepView {
                        state: &state,
                        narration: timeline.steps().get(n).map_or("", |s| s.narration.as_str()),
                        n,
                        total,
                    }),
                    ..base
                };
                morph_svg(&frame, 1.0)
            })
            .collect(),
        captions: Vec::new(),
    };

    let html = player_html(path, &[morph, steps]);
    let written = write_file(std::path::Path::new(out), &html);
    if written == ExitCode::SUCCESS {
        outln!(
            "{out}  {}  ({} + {} frames)",
            human(html.len() as u64),
            frames,
            timeline.len()
        );
    }
    written
}

fn human(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{} KB", bytes / 1024)
    }
}

fn cmd_diff(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    if p.summary.interp.is_none() {
        eprintln!("{path}: static binary — no dynamic loader to compare against");
        return ExitCode::FAILURE;
    }

    let image = MemImage::from_segments(&p.summary.segments, p.coverage.stats().total_bytes);
    let timeline = Timeline::plan(&p.summary, &image);
    let modelled = timeline.state_at(timeline.len().saturating_sub(1));

    eprintln!("running {path} to observe its load…");
    let observed = match elfa_trace::capture(
        std::path::Path::new(path),
        p.summary.entry,
        p.summary.e_type == 3,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let checks = compare(path, &p, &modelled, &observed);
    outln!("\n{path}  model vs observed\n");
    let mut diverged = 0usize;
    for c in &checks {
        outln!("  {}  {:<22} {}", c.verdict.mark(), c.name, c.detail);
        if matches!(c.verdict, Verdict::Differ) {
            diverged = diverged.saturating_add(1);
        }
    }
    outln!("");
    if diverged > 0 {
        outln!(
            "  {diverged} divergence{}. A divergence is a fact about loading until it is\n  explained; see docs/CONFORMANCE.md.\n",
            if diverged == 1 { "" } else { "s" }
        );
    }
    ExitCode::SUCCESS
}

fn compare(
    path: &str,
    p: &Parsed,
    modelled: &elfa_model::State,
    observed: &elfa_trace::Trace,
) -> Vec<Check> {
    let mut checks = Vec::new();

    // The observed rows for the target itself, made base-relative so a PIE's randomised
    // load address does not read as a divergence.
    let stem = std::path::Path::new(path)
        .file_name()
        .map_or_else(String::new, |s| s.to_string_lossy().into_owned());
    // Rows for the object itself — plus any anonymous mapping that continues directly
    // from them. When .bss spills past the last file-backed page, the kernel gives it an
    // anonymous VMA with no path, and filtering on the path alone silently drops it: the
    // model is then accused of inventing a mapping that genuinely exists.
    let mut rows: Vec<&elfa_trace::MapRow> = Vec::new();
    let mut taking = false;
    for r in &observed.maps_at_entry {
        let mine = !stem.is_empty() && r.path.ends_with(&stem);
        let continues_mine =
            taking && r.path.is_empty() && rows.last().is_some_and(|last| last.end == r.start);
        if mine || continues_mine {
            rows.push(r);
            taking = true;
        } else if !r.path.is_empty() {
            taking = false;
        }
    }
    // Only a position-independent executable has a load base to subtract. An ET_EXEC is
    // mapped at the addresses written in its headers, and "normalising" those would turn
    // a perfect match into a whole-table divergence.
    let base = if p.summary.e_type == 3 {
        rows.iter().map(|r| r.start).min().unwrap_or(0)
    } else {
        0
    };

    // File offset is part of the comparison: it is what makes two adjacent mappings with
    // the same protection two VMAs instead of one.
    let obs: Vec<Row> = rows
        .iter()
        .map(|r| {
            (
                r.start.saturating_sub(base),
                r.end.saturating_sub(base),
                Prot::from_perms(&r.perms),
                if r.path.is_empty() {
                    None
                } else {
                    Some(r.offset)
                },
            )
        })
        .collect();
    let model: Vec<Row> = modelled
        .vmas()
        .iter()
        .map(|v| (v.start, v.end, v.prot, v.offset))
        .collect();

    checks.push(if obs.is_empty() {
        Check {
            name: "mappings",
            verdict: Verdict::NotModelled,
            detail: "gdb reported no mappings for the target".to_owned(),
        }
    } else if obs == model {
        Check {
            name: "mappings",
            verdict: Verdict::Match,
            detail: format!("{} vmas, identical base-relative", obs.len()),
        }
    } else {
        Check {
            name: "mappings",
            verdict: Verdict::Differ,
            detail: format!(
                "model {} vmas, observed {}\n{}",
                model.len(),
                obs.len(),
                side_by_side(&model, &obs)
            ),
        }
    });

    // Dependencies. The model knows SONAMEs, the trace knows resolved paths.
    //
    // A DT_NEEDED naming the interpreter is already satisfied: ld.so is in the process
    // before the first DT_NEEDED is read, so it is never searched for. libc.so.6 depends
    // on ld-linux and would otherwise be reported as a missing dependency of itself.
    let interp_base = p
        .summary
        .interp
        .as_deref()
        .and_then(|i| i.rsplit('/').next())
        .unwrap_or("");
    let wanted: Vec<&str> = p
        .summary
        .needed
        .iter()
        .map(AsRef::as_ref)
        .filter(|n: &&str| *n != interp_base)
        .collect();
    let resolved: Vec<String> = observed.aliases().keys().cloned().collect();
    let missing: Vec<&&str> = wanted
        .iter()
        .filter(|w| !resolved.iter().any(|r| r == **w))
        .collect();
    checks.push(Check {
        name: "DT_NEEDED",
        verdict: if wanted.is_empty() {
            Verdict::NotModelled
        } else if missing.is_empty() {
            Verdict::Match
        } else {
            Verdict::Differ
        },
        detail: if wanted.is_empty() {
            "nothing beyond the interpreter, which is loaded before any search happens".to_owned()
        } else if missing.is_empty() {
            format!("{} resolved: {}", wanted.len(), wanted.join(", "))
        } else {
            format!("never searched for: {missing:?}")
        },
    });

    // The model claims dependencies are relocated before the program. The trace can
    // confirm or refute that — but only when there are dependencies. Run a shared library
    // directly and it is the main object with nothing beneath it, so "first" is correct
    // and the check has nothing to say.
    let order = observed.relocation_order();
    let self_at = order.iter().position(|o| o.ends_with(&stem));
    checks.push(match self_at {
        _ if wanted.is_empty() => Check {
            name: "relocation order",
            verdict: Verdict::NotModelled,
            detail: "no dependencies, so nothing is required to precede it".to_owned(),
        },
        Some(i) if i > 0 => Check {
            name: "relocation order",
            verdict: Verdict::Match,
            detail: format!("{i} object(s) relocated before the program"),
        },
        Some(_) => Check {
            name: "relocation order",
            verdict: Verdict::Differ,
            detail: "the program was relocated first, before its dependencies".to_owned(),
        },
        None => Check {
            name: "relocation order",
            verdict: Verdict::NotModelled,
            detail: "the program does not appear in the observed order".to_owned(),
        },
    });

    // Initialisers: the program must be last. Again only when the loader treated the
    // target as a program at all — glibc emits "initialize program" for an executable,
    // and a library invoked directly never gets one.
    let init = observed.init_order();
    let ran_ours = init.iter().any(|o| o.ends_with(&stem));
    checks.push(match init.last() {
        _ if !ran_ours => Check {
            name: "initialiser order",
            verdict: Verdict::NotModelled,
            detail: "the loader ran no initialiser for this object".to_owned(),
        },
        Some(last) if last.ends_with(&stem) => Check {
            name: "initialiser order",
            verdict: Verdict::Match,
            detail: format!("program last, after {}", init.len().saturating_sub(1)),
        },
        Some(last) => Check {
            name: "initialiser order",
            verdict: Verdict::Differ,
            detail: format!("expected the program last, observed {last}"),
        },
        None => Check {
            name: "initialiser order",
            verdict: Verdict::NotModelled,
            detail: "no initialisers observed".to_owned(),
        },
    });

    // Binding mode: the model reads DT_FLAGS, the loader says what it actually did.
    checks.push(match observed.binds_lazily(&stem) {
        Some(lazy) if lazy == !p.summary.bind_now => Check {
            name: "binding mode",
            verdict: Verdict::Match,
            detail: if lazy {
                "lazy — PLT relocations deferred to first call".to_owned()
            } else {
                "BIND_NOW — PLT relocations applied before main".to_owned()
            },
        },
        Some(lazy) => Check {
            name: "binding mode",
            verdict: Verdict::Differ,
            detail: format!(
                "model says {}, loader reports {}",
                if p.summary.bind_now {
                    "BIND_NOW"
                } else {
                    "lazy"
                },
                if lazy { "lazy" } else { "BIND_NOW" }
            ),
        },
        None => Check {
            name: "binding mode",
            verdict: Verdict::NotModelled,
            detail: "the loader did not report relocating this object".to_owned(),
        },
    });

    // Symbol binds. The two sides count different things and forcing the numbers to
    // agree would be fitting the model to the measurement:
    //
    //   - The model has one entry per relocation that names a symbol. Some of those are
    //     weak and undefined — `__gmon_start__`, the `_ITM_*` pair — and the loader
    //     neither binds nor reports them; they resolve to zero and nothing happens.
    //   - The trace has one entry per lookup the loader performed for this object, which
    //     includes lookups no relocation asked for: `_r_debug`, and the malloc family,
    //     which ld.so resolves against the global scope so a program can interpose them.
    //
    // So the check is containment, not equality: every non-weak symbol the relocations
    // name must have been bound. The loader's extra lookups are reported, not judged.
    let model_syms: Vec<&str> = p
        .summary
        .relocs
        .iter()
        .filter(|r| {
            !r.weak && (p.summary.bind_now || r.table != elfa_parse::RelocTableKind::JmpRel)
        })
        .filter_map(|r| r.symbol.as_deref())
        .collect();
    let bound = observed.bound_symbols(&stem);
    let missing: Vec<&&str> = model_syms
        .iter()
        .filter(|s| !bound.iter().any(|b| b == **s))
        .collect();
    let extra = bound
        .len()
        .saturating_sub(model_syms.len().saturating_sub(missing.len()));

    checks.push(if bound.is_empty() {
        Check {
            name: "symbol binds",
            verdict: Verdict::NotModelled,
            detail: format!(
                "model names {}; the loader attributed no binds to this object",
                model_syms.len()
            ),
        }
    } else if missing.is_empty() {
        Check {
            name: "symbol binds",
            verdict: Verdict::Match,
            detail: format!(
                "all {} named by relocations were bound; the loader resolved {extra} more of its own",
                model_syms.len()
            ),
        }
    } else {
        Check {
            name: "symbol binds",
            verdict: Verdict::Differ,
            detail: format!("never bound: {missing:?}"),
        }
    });

    checks
}

fn side_by_side(model: &[Row], obs: &[Row]) -> String {
    let mut s = String::new();
    let rows = model.len().max(obs.len());
    let fmt = |v: Option<&Row>| -> String {
        v.map_or_else(
            || " ".repeat(33),
            |(a, b, p, off)| {
                format!(
                    "{a:#08x}-{b:#08x} {} off {}",
                    p.as_str(),
                    off.map_or_else(|| "anon".to_owned(), |o| format!("{o:#07x}"))
                )
            },
        )
    };
    for i in 0..rows {
        let m = fmt(model.get(i));
        let o = fmt(obs.get(i));
        let mark = if model.get(i) == obs.get(i) { " " } else { "*" };
        s.push_str(&format!("\n        {mark} {m}   {o}"));
    }
    s
}

fn cmd_trace(args: &[&str]) -> ExitCode {
    let Some(path) = args.first() else {
        eprint!("{USAGE}");
        return ExitCode::FAILURE;
    };
    let mut out: Option<&str> = None;
    let mut as_json = false;
    let mut i = 1;
    while let Some(arg) = args.get(i) {
        match *arg {
            "-o" | "--out" => {
                out = args.get(i.saturating_add(1)).copied();
                as_json = true;
                i = i.saturating_add(1);
            }
            "--json" => as_json = true,
            other => {
                eprintln!("unknown flag `{other}`");
                return ExitCode::FAILURE;
            }
        }
        i = i.saturating_add(1);
    }

    let Some(p) = load(path) else {
        return ExitCode::FAILURE;
    };
    if p.summary.interp.is_none() {
        eprintln!("{path}: no PT_INTERP — a static binary has no dynamic loader to observe");
        return ExitCode::FAILURE;
    }

    // Running the target is the whole point, and it is the one thing this tool does that
    // touches the outside world. Say so.
    eprintln!("running {path} to observe its load…");
    let trace = match elfa_trace::capture(
        std::path::Path::new(path),
        p.summary.entry,
        p.summary.e_type == 3,
    ) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("{path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if as_json {
        let json = elfa_trace::to_json(&trace);
        return match out {
            Some(f) => write_file(std::path::Path::new(f), &json),
            None => {
                out!("{json}");
                ExitCode::SUCCESS
            }
        };
    }

    report_trace(&trace);
    ExitCode::SUCCESS
}

fn report_trace(trace: &elfa_trace::Trace) {
    use elfa_trace::StepKind;

    outln!("{}  {} steps observed\n", trace.target, trace.steps.len());

    outln!("  objects, in the order the loader met them");
    for o in trace.objects() {
        outln!("    {o}");
    }

    let reloc = trace.relocation_order();
    if !reloc.is_empty() {
        outln!("\n  relocation order — dependencies first, the loader itself last");
        for o in &reloc {
            outln!("    {o}");
        }
    }

    let init = trace.init_order();
    if !init.is_empty() {
        outln!("\n  initialiser order — program last");
        for o in &init {
            outln!("    {o}");
        }
    }

    for step in &trace.steps {
        if let StepKind::Search { library, tried } = &step.kind {
            outln!("\n  search for {library}");
            for path in tried {
                outln!("    {path}");
            }
        }
    }

    outln!(
        "\n  {} symbols bound before the program ran",
        trace.bind_count()
    );
    outln!(
        "  mappings: {} at the interpreter's first instruction, {} at the program's entry",
        trace.maps_at_interp.len(),
        trace.maps_at_entry.len()
    );

    let grew = trace
        .maps_at_entry
        .len()
        .saturating_sub(trace.maps_at_interp.len());
    if grew > 0 {
        outln!("  the dynamic linker added {grew} mappings");
    }
    outln!("");
}

fn write_file(path: &std::path::Path, contents: &str) -> ExitCode {
    match std::fs::write(path, contents) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{}: {e}", path.display());
            ExitCode::FAILURE
        }
    }
}

/// Thousands separators. Byte counts are the whole output of this tool; they should be
/// readable at a glance.
fn commas(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, ch) in s.chars().enumerate() {
        if i > 0 && s.len().saturating_sub(i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}
