//! `elfa` — the command-line front end.
//!
//! Three subcommands, all of which answer the same question at different zoom levels:
//! what is in this file, and is any of it unaccounted for?
//!
//! Argument parsing is hand-rolled. The surface is three verbs and two flags; a
//! dependency would be larger than the code it replaced.

use std::process::ExitCode;

use elfa_parse::{ClaimId, ClaimKind, Coverage, Parsed, Span, Value, elf, parse};

const USAGE: &str = "\
elfa — look at what is actually in an ELF file

USAGE
  elfa verify <file>...          check that every byte is accounted for
  elfa dump <file> [--depth N]   print the claim tree (default depth 2, --all for everything)
  elfa at <file> <offset>        what covers this byte? (offset may be decimal or 0x hex)
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
        "-h" | "--help" | "help" => {
            print!("{USAGE}");
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
    println!("{path}  {etype} {machine}  entry {:#x}", s.entry);

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
        println!("  {}", line2.join("   "));
    }

    let pct = |n: u64| -> f64 {
        if stats.total_bytes == 0 {
            0.0
        } else {
            (n as f64) * 100.0 / (stats.total_bytes as f64)
        }
    };

    println!();
    println!("  coverage      ok — every byte claimed exactly once");
    println!("  size          {} bytes", commas(stats.total_bytes));
    println!(
        "  claims        {} ({} leaves, depth {})",
        commas(stats.claim_count as u64),
        commas(stats.leaf_count as u64),
        stats.max_depth
    );
    println!(
        "  explained     {:>12}  {:5.1}%",
        commas(stats.explained_bytes),
        pct(stats.explained_bytes)
    );
    println!(
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
        println!("\n  largest unexplained regions");
        for (span, ctx) in holes.iter().take(8) {
            println!("    {:#010x}  {:>10}  {ctx}", span.start, commas(span.len));
        }
        if holes.len() > 8 {
            println!("    … and {} more", holes.len().saturating_sub(8));
        }
    }
    println!();
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
    println!(
        "{:#010x} {:>9}  {indent}{:<16} {detail}",
        c.span.start,
        commas(c.span.len),
        c.kind.field_name().unwrap_or_else(|| c.kind.label())
    );
    if level >= max {
        let kids = cov.children(id).len();
        if kids > 0 {
            println!("{:>21}  {indent}  … {kids} children", "");
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
        println!("{off:#x} is past the end of the file");
        return ExitCode::SUCCESS;
    }
    println!("byte {off:#x}, innermost first:\n");
    for (level, id) in stack.iter().enumerate() {
        let Some(c) = p.coverage.claim(*id) else {
            continue;
        };
        let note = c.note.as_deref().unwrap_or("");
        println!(
            "{}{:<16} {:#010x}..{:#010x}  {note}",
            "  ".repeat(level),
            c.kind.field_name().unwrap_or_else(|| c.kind.label()),
            c.span.start,
            c.span.end()
        );
    }
    ExitCode::SUCCESS
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
