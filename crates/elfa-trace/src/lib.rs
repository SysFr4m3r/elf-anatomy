//! Observed mode: what a real loader did.
//!
//! The plan (§0.5) says a hand-written loader animation is a blog post with a `<canvas>`.
//! This crate is the other half of that argument — it captures a real load so the model
//! has ground truth to be checked against.
//!
//! Two sources, both already present on any Linux box with glibc:
//!
//! - **`LD_DEBUG=all`**, which is glibc narrating its own work: dependency resolution,
//!   search paths tried, link maps, scope construction, relocation order, symbol binding,
//!   and initialiser order.
//! - **gdb**, stopped twice — at the interpreter's first instruction (the kernel's work,
//!   finished; the loader's, not started) and at the program's entry (the loader's work,
//!   finished). The difference between those two snapshots *is* the dynamic linker.
//!
//! No `strace`, no ptrace of our own, no kernel module. Deliberately: a capture that
//! needs privileges is a capture nobody runs.
//!
//! Linux and glibc only. musl's loader does not narrate itself, and that is a known gap
//! rather than an oversight — see `docs/CONFORMANCE.md`.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum TraceError {
    Spawn { what: &'static str, detail: String },
    NoOutput { what: &'static str },
}

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Spawn { what, detail } => write!(f, "could not run {what}: {detail}"),
            Self::NoOutput { what } => write!(f, "{what} produced no usable output"),
        }
    }
}

impl std::error::Error for TraceError {}

/// Which part of the load a step belongs to. Mirrors the phases in `PROJECT_PLAN.md` §5.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Phase {
    Resolve,
    Map,
    Scope,
    Relocate,
    Init,
    Entry,
    Fini,
}

impl Phase {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Map => "map",
            Self::Scope => "scope",
            Self::Relocate => "relocate",
            Self::Init => "init",
            Self::Entry => "entry",
            Self::Fini => "fini",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum StepKind {
    /// `DT_NEEDED` seen: `file` is wanted by `needed_by`.
    Needed {
        file: String,
        needed_by: String,
    },
    /// The search for a library, in the order the paths were tried.
    Search {
        library: String,
        tried: Vec<String>,
    },
    /// A link map was built — the loader now knows where the object lives.
    LinkMap {
        file: String,
        base: u64,
        entry: u64,
        phnum: u32,
    },
    /// The symbol lookup order for one object. First definition wins.
    Scope {
        object: String,
        order: Vec<String>,
    },
    /// Relocations applied to one object.
    Relocate {
        object: String,
    },
    /// One symbol resolved: `symbol` in `from` bound to a definition in `to`.
    Bind {
        from: String,
        to: String,
        symbol: String,
    },
    Init {
        object: String,
    },
    InitializeProgram {
        object: String,
    },
    TransferControl {
        object: String,
    },
    Fini {
        object: String,
    },
}

impl StepKind {
    #[must_use]
    pub const fn phase(&self) -> Phase {
        match self {
            Self::Needed { .. } | Self::Search { .. } => Phase::Resolve,
            Self::LinkMap { .. } => Phase::Map,
            Self::Scope { .. } => Phase::Scope,
            Self::Relocate { .. } | Self::Bind { .. } => Phase::Relocate,
            Self::Init { .. } | Self::InitializeProgram { .. } => Phase::Init,
            Self::TransferControl { .. } => Phase::Entry,
            Self::Fini { .. } => Phase::Fini,
        }
    }

    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Needed { .. } => "needed",
            Self::Search { .. } => "search",
            Self::LinkMap { .. } => "link-map",
            Self::Scope { .. } => "scope",
            Self::Relocate { .. } => "relocate",
            Self::Bind { .. } => "bind",
            Self::Init { .. } => "init",
            Self::InitializeProgram { .. } => "initialize-program",
            Self::TransferControl { .. } => "transfer-control",
            Self::Fini { .. } => "fini",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Step {
    pub n: u32,
    pub kind: StepKind,
}

/// One row of `info proc mappings`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MapRow {
    pub start: u64,
    pub end: u64,
    pub offset: u64,
    pub perms: String,
    pub path: String,
}

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct Trace {
    pub target: String,
    pub steps: Vec<Step>,
    /// Mappings at the interpreter's first instruction: the kernel's work alone.
    pub maps_at_interp: Vec<MapRow>,
    /// Mappings at the program's entry: after the loader is done.
    pub maps_at_entry: Vec<MapRow>,
}

impl Trace {
    /// SONAME → resolved path, from the searches the loader performed.
    ///
    /// The loader names the same object two ways: `libc.so.6` when something asks for it,
    /// `/usr/lib/x86_64-linux-gnu/libc.so.6` once found. Listing both as separate objects
    /// is wrong, and matching a model against a trace needs one canonical name.
    ///
    /// Heuristic: the resolved path is the last real path in the search list. `LD_DEBUG`
    /// prints every path tried and does not mark which one succeeded, but a search that
    /// does not end in success ends the process.
    #[must_use]
    pub fn aliases(&self) -> BTreeMap<String, String> {
        let mut map = BTreeMap::new();
        for s in &self.steps {
            let StepKind::Search { library, tried } = &s.kind else {
                continue;
            };
            if let Some(found) = tried
                .iter()
                .rev()
                .find(|p| p.starts_with('/') && !p.contains("cache="))
            {
                map.insert(library.clone(), found.clone());
            }
        }
        map
    }

    /// The name this trace should be indexed under: a resolved path where one is known.
    #[must_use]
    pub fn canonical(&self, name: &str) -> String {
        self.aliases()
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_owned())
    }

    /// Objects in the order the loader first mentioned them, one entry each.
    ///
    /// Drawn from every step kind that names one, not just `LinkMap`: glibc emits
    /// "generating link map" only for objects it newly opens, so the executable itself
    /// and `ld.so` never appear there despite obviously being loaded.
    #[must_use]
    pub fn objects(&self) -> Vec<String> {
        let aliases = self.aliases();
        let mut seen: Vec<String> = Vec::new();
        let push = |name: &str, seen: &mut Vec<String>| {
            if name.is_empty() {
                return;
            }
            let name = aliases.get(name).map_or(name, String::as_str);
            if !seen.iter().any(|s| s == name) {
                seen.push(name.to_owned());
            }
        };
        for s in &self.steps {
            match &s.kind {
                StepKind::Needed { file, needed_by } => {
                    push(needed_by, &mut seen);
                    push(file, &mut seen);
                }
                StepKind::LinkMap { file, .. } => push(file, &mut seen),
                StepKind::Scope { object, .. }
                | StepKind::Relocate { object }
                | StepKind::Init { object }
                | StepKind::InitializeProgram { object }
                | StepKind::TransferControl { object } => push(object, &mut seen),
                _ => {}
            }
        }
        seen
    }

    /// Relocation order — the claim §5 phase L makes, as observed.
    #[must_use]
    pub fn relocation_order(&self) -> Vec<&str> {
        self.steps
            .iter()
            .filter_map(|s| match &s.kind {
                StepKind::Relocate { object } => Some(object.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Initialiser order, program last.
    #[must_use]
    pub fn init_order(&self) -> Vec<&str> {
        self.steps
            .iter()
            .filter_map(|s| match &s.kind {
                StepKind::Init { object } | StepKind::InitializeProgram { object } => {
                    Some(object.as_str())
                }
                _ => None,
            })
            .collect()
    }

    #[must_use]
    pub fn bind_count(&self) -> usize {
        self.steps
            .iter()
            .filter(|s| matches!(s.kind, StepKind::Bind { .. }))
            .count()
    }
}

fn strip_prefix(line: &str) -> &str {
    // Every line is "\t  NNNNN:\t<content>".
    line.split_once(":\t").map_or(line.trim(), |(_, rest)| rest)
}

fn after<'a>(s: &'a str, pat: &str) -> Option<&'a str> {
    s.split_once(pat).map(|(_, rest)| rest.trim())
}

/// Strip glibc's `[0]` namespace suffix and any trailing punctuation.
fn object_name(s: &str) -> String {
    s.trim()
        .trim_end_matches(';')
        .split(" [")
        .next()
        .unwrap_or(s)
        .trim()
        .to_owned()
}

fn hex(s: &str) -> Option<u64> {
    let s = s.trim();
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

/// Parse `LD_DEBUG=all` output into ordered steps.
///
/// Written against the real output of glibc 2.42 rather than from memory; the format is
/// not documented and not stable, so unrecognised lines are skipped rather than fought.
#[must_use]
pub fn parse_ld_debug(text: &str) -> Vec<Step> {
    let mut steps: Vec<StepKind> = Vec::new();
    let mut pending_search: Option<(String, Vec<String>)> = None;
    let mut pending_scope: Option<(String, Vec<String>)> = None;
    let mut pending_map: Option<String> = None;

    for raw in text.lines() {
        let line = strip_prefix(raw);
        let t = line.trim();

        if t.is_empty() {
            if let Some((library, tried)) = pending_search.take() {
                steps.push(StepKind::Search { library, tried });
            }
            if let Some((object, order)) = pending_scope.take() {
                steps.push(StepKind::Scope { object, order });
            }
            continue;
        }

        if let Some(rest) = after(t, "find library=") {
            let library = object_name(rest.split(';').next().unwrap_or(rest));
            pending_search = Some((library, Vec::new()));
            continue;
        }
        if let Some((_, tried)) = &mut pending_search
            && (t.starts_with("search ") || t.starts_with("trying file="))
        {
            tried.push(t.trim_start_matches("trying file=").trim().to_owned());
            continue;
        }

        if t.contains(";  needed by ")
            && let Some((file, by)) = t.split_once(";  needed by ")
        {
            steps.push(StepKind::Needed {
                file: object_name(file.trim_start_matches("file=")),
                needed_by: object_name(by),
            });
            continue;
        }

        if t.contains(";  generating link map") {
            pending_map = Some(object_name(
                t.split(';').next().unwrap_or(t).trim_start_matches("file="),
            ));
            continue;
        }
        if let Some(file) = pending_map.clone()
            && let Some(rest) = after(t, "base:")
        {
            let base = hex(rest.split_whitespace().next().unwrap_or("")).unwrap_or(0);
            steps.push(StepKind::LinkMap {
                file,
                base,
                entry: 0,
                phnum: 0,
            });
            continue;
        }
        if let Some(rest) = after(t, "entry:") {
            let entry = hex(rest.split_whitespace().next().unwrap_or("")).unwrap_or(0);
            let phnum = t
                .rsplit_once("phnum:")
                .and_then(|(_, v)| v.trim().parse().ok())
                .unwrap_or(0);
            if let Some(StepKind::LinkMap {
                entry: e, phnum: p, ..
            }) = steps.last_mut()
            {
                *e = entry;
                *p = phnum;
            }
            pending_map = None;
            continue;
        }

        if let Some(rest) = after(t, "object=") {
            pending_scope = Some((object_name(rest), Vec::new()));
            continue;
        }
        if let Some((_, order)) = &mut pending_scope
            && let Some(rest) = t.strip_prefix("scope ")
            && let Some((_, list)) = rest.split_once(':')
        {
            order.extend(list.split_whitespace().map(ToOwned::to_owned));
            continue;
        }

        if let Some(rest) = after(t, "relocation processing:") {
            steps.push(StepKind::Relocate {
                object: object_name(rest),
            });
            continue;
        }
        if let Some(rest) = t.strip_prefix("binding file ")
            && let Some((from, tail)) = rest.split_once(" to ")
            && let Some((to, sym)) = tail.split_once(": normal symbol `")
        {
            steps.push(StepKind::Bind {
                from: object_name(from),
                to: object_name(to),
                symbol: sym.split('\'').next().unwrap_or(sym).to_owned(),
            });
            continue;
        }

        if let Some(rest) = after(t, "calling init:") {
            steps.push(StepKind::Init {
                object: object_name(rest),
            });
        } else if let Some(rest) = after(t, "initialize program:") {
            steps.push(StepKind::InitializeProgram {
                object: object_name(rest),
            });
        } else if let Some(rest) = after(t, "transferring control:") {
            steps.push(StepKind::TransferControl {
                object: object_name(rest),
            });
        } else if let Some(rest) = after(t, "calling fini:") {
            steps.push(StepKind::Fini {
                object: object_name(rest),
            });
        }
    }

    if let Some((library, tried)) = pending_search {
        steps.push(StepKind::Search { library, tried });
    }
    if let Some((object, order)) = pending_scope {
        steps.push(StepKind::Scope { object, order });
    }

    steps
        .into_iter()
        .enumerate()
        .map(|(i, kind)| Step {
            n: u32::try_from(i).unwrap_or(u32::MAX),
            kind,
        })
        .collect()
}

/// Parse gdb's `info proc mappings` table.
#[must_use]
pub fn parse_maps(text: &str) -> Vec<MapRow> {
    let mut out = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // Start End Size Offset Perms [objfile]
        let (Some(start), Some(end), Some(offset)) = (
            f.first().and_then(|v| hex(v)),
            f.get(1).and_then(|v| hex(v)),
            f.get(3).and_then(|v| hex(v)),
        ) else {
            continue;
        };
        let perms = f.get(4).copied().unwrap_or("").to_owned();
        if !perms.starts_with(['r', '-']) {
            continue;
        }
        out.push(MapRow {
            start,
            end,
            offset,
            perms,
            path: f.get(5..).map_or_else(String::new, |r| r.join(" ")),
        });
    }
    out
}

/// Run the target under `LD_DEBUG=all` and capture what glibc says about itself.
pub fn capture_ld_debug(target: &Path) -> Result<String, TraceError> {
    let out = Command::new(target)
        .env("LD_DEBUG", "all")
        .output()
        .map_err(|e| TraceError::Spawn {
            what: "the target",
            detail: e.to_string(),
        })?;
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    if text.trim().is_empty() {
        return Err(TraceError::NoOutput {
            what: "LD_DEBUG (is this a static binary?)",
        });
    }
    Ok(text)
}

/// Stop twice under gdb and dump the mappings each time.
///
/// The second breakpoint is the *program's* entry, computed from the load base gdb
/// reports plus `e_entry` from our own parse. Using the entry rather than `main` keeps
/// this working on stripped binaries, where there is no `main` to break on.
pub fn capture_maps(
    target: &Path,
    entry: u64,
    position_independent: bool,
) -> Result<(Vec<MapRow>, Vec<MapRow>), TraceError> {
    let script = format!(
        r#"
import gdb
gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("starti", to_string=True)
a = gdb.execute("info proc mappings", to_string=True)
base = 0
if {pie}:
    for line in a.splitlines():
        f = line.split()
        if len(f) >= 6 and f[5].endswith("{name}"):
            base = int(f[0], 16)
            break
try:
    gdb.execute("tbreak *%d" % (base + {entry}), to_string=True)
    gdb.execute("continue", to_string=True)
except gdb.error as e:
    print("BREAK_FAILED", e)
b = gdb.execute("info proc mappings", to_string=True)
print("===ELFA_SNAP_A===")
print(a)
print("===ELFA_SNAP_B===")
print(b)
"#,
        pie = if position_independent {
            "True"
        } else {
            "False"
        },
        // Embedded in a Python string literal, so anything that could close it goes.
        name = target
            .file_name()
            .map_or_else(String::new, |s| s.to_string_lossy().into_owned())
            .replace(['"', '\\'], ""),
        entry = entry,
    );

    let dir = std::env::temp_dir().join(format!("elfa-trace-{}", std::process::id()));
    std::fs::create_dir_all(&dir).map_err(|e| TraceError::Spawn {
        what: "a temp dir",
        detail: e.to_string(),
    })?;
    let script_path = dir.join("snap.py");
    std::fs::write(&script_path, script).map_err(|e| TraceError::Spawn {
        what: "the gdb script",
        detail: e.to_string(),
    })?;

    let out = Command::new("gdb")
        .args(["-q", "-batch", "-x"])
        .arg(&script_path)
        .arg(target)
        .output()
        .map_err(|e| TraceError::Spawn {
            what: "gdb",
            detail: e.to_string(),
        })?;
    let _ = std::fs::remove_dir_all(&dir);

    let text = String::from_utf8_lossy(&out.stdout);
    let (_, rest) = text
        .split_once("===ELFA_SNAP_A===")
        .ok_or(TraceError::NoOutput { what: "gdb" })?;
    let (a, b) = rest
        .split_once("===ELFA_SNAP_B===")
        .ok_or(TraceError::NoOutput { what: "gdb" })?;
    Ok((parse_maps(a), parse_maps(b)))
}

/// Full capture. `entry` and `position_independent` come from parsing the file.
pub fn capture(target: &Path, entry: u64, position_independent: bool) -> Result<Trace, TraceError> {
    let steps = parse_ld_debug(&capture_ld_debug(target)?);
    let (maps_at_interp, maps_at_entry) =
        capture_maps(target, entry, position_independent).unwrap_or_default();
    Ok(Trace {
        target: target.display().to_string(),
        steps,
        maps_at_interp,
        maps_at_entry,
    })
}

fn json_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn json_list(items: &[String], out: &mut String) {
    out.push('[');
    for (i, s) in items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        json_str(s, out);
    }
    out.push(']');
}

fn maps_json(rows: &[MapRow], out: &mut String) {
    out.push('[');
    for (i, r) in rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let _ = write!(
            out,
            r#"{{"start":{},"end":{},"offset":{},"perms":"#,
            r.start, r.end, r.offset
        );
        json_str(&r.perms, out);
        out.push_str(r#","path":"#);
        json_str(&r.path, out);
        out.push('}');
    }
    out.push(']');
}

/// Serialise to `trace.json`.
///
/// Hand-rolled rather than derived. The schema is small, the crate has no dependencies,
/// and keeping it that way means the capture tool builds anywhere the target runs.
#[must_use]
pub fn to_json(trace: &Trace) -> String {
    let mut s = String::with_capacity(64 * 1024);
    s.push_str("{\"schema\":1,\"target\":");
    json_str(&trace.target, &mut s);
    s.push_str(",\"steps\":[");

    for (i, step) in trace.steps.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            r#"{{"n":{},"phase":"{}","kind":"{}""#,
            step.n,
            step.kind.phase().as_str(),
            step.kind.tag()
        );
        let field = |k: &str, v: &str, s: &mut String| {
            let _ = write!(s, ",\"{k}\":");
            json_str(v, s);
        };
        match &step.kind {
            StepKind::Needed { file, needed_by } => {
                field("file", file, &mut s);
                field("needed_by", needed_by, &mut s);
            }
            StepKind::Search { library, tried } => {
                field("library", library, &mut s);
                s.push_str(",\"tried\":");
                json_list(tried, &mut s);
            }
            StepKind::LinkMap {
                file,
                base,
                entry,
                phnum,
            } => {
                field("file", file, &mut s);
                let _ = write!(s, ",\"base\":{base},\"entry\":{entry},\"phnum\":{phnum}");
            }
            StepKind::Scope { object, order } => {
                field("object", object, &mut s);
                s.push_str(",\"order\":");
                json_list(order, &mut s);
            }
            StepKind::Relocate { object }
            | StepKind::Init { object }
            | StepKind::InitializeProgram { object }
            | StepKind::TransferControl { object }
            | StepKind::Fini { object } => field("object", object, &mut s),
            StepKind::Bind { from, to, symbol } => {
                field("from", from, &mut s);
                field("to", to, &mut s);
                field("symbol", symbol, &mut s);
            }
        }
        s.push('}');
    }

    s.push_str("],\"objects\":");
    json_list(&trace.objects(), &mut s);
    s.push_str(",\"aliases\":{");
    for (i, (k, v)) in trace.aliases().iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        json_str(k, &mut s);
        s.push(':');
        json_str(v, &mut s);
    }
    s.push_str("},\"maps_at_interp\":");
    maps_json(&trace.maps_at_interp, &mut s);
    s.push_str(",\"maps_at_entry\":");
    maps_json(&trace.maps_at_entry, &mut s);

    // A small digest so a reader can see the shape without parsing every step.
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for step in &trace.steps {
        let slot = counts.entry(step.kind.tag()).or_default();
        *slot = slot.saturating_add(1);
    }
    s.push_str(",\"counts\":{");
    for (i, (k, v)) in counts.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(s, "\"{k}\":{v}");
    }
    s.push_str("}}\n");
    s
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// A trimmed capture from glibc 2.42. Kept verbatim: the format is undocumented and
    /// unstable, and a paraphrase would test the paraphrase.
    const SAMPLE: &str = r#"
     36502:	file=libc.so.6 [0];  needed by ./hello-dyn [0]
     36502:	find library=libc.so.6 [0]; searching
     36502:	 search cache=/etc/ld.so.cache
     36502:	  trying file=/usr/lib/x86_64-linux-gnu/libc.so.6
     36502:	
     36502:	file=libc.so.6 [0];  generating link map
     36502:	  dynamic: 0x00007f4fc19f7940  base: 0x00007f4fc180f000   size: 0x00000000001f7e50
     36502:	    entry: 0x00007f4fc1839130  phdr: 0x00007f4fc180f040  phnum:                 15
     36502:	
     36502:	Initial object scopes
     36502:	object=./hello-dyn [0]
     36502:	 scope 0: ./hello-dyn /usr/lib/x86_64-linux-gnu/libc.so.6 /lib64/ld-linux-x86-64.so.2
     36502:	
     36502:	relocation processing: /usr/lib/x86_64-linux-gnu/libc.so.6
     36502:	binding file ./hello-dyn [0] to /usr/lib/x86_64-linux-gnu/libc.so.6 [0]: normal symbol `fputs' [GLIBC_2.2.5]
     36502:	relocation processing: ./hello-dyn
     36502:	calling init: /lib64/ld-linux-x86-64.so.2
     36502:	calling init: /usr/lib/x86_64-linux-gnu/libc.so.6
     36502:	initialize program: ./hello-dyn
     36502:	transferring control: ./hello-dyn
"#;

    #[test]
    fn dependency_resolution_is_recovered() {
        let steps = parse_ld_debug(SAMPLE);
        let needed = steps.iter().find_map(|s| match &s.kind {
            StepKind::Needed { file, needed_by } => Some((file.clone(), needed_by.clone())),
            _ => None,
        });
        assert_eq!(
            needed,
            Some(("libc.so.6".to_owned(), "./hello-dyn".to_owned()))
        );

        let search = steps.iter().find_map(|s| match &s.kind {
            StepKind::Search { library, tried } => Some((library.clone(), tried.clone())),
            _ => None,
        });
        let (lib, tried) = search.expect("a search step");
        assert_eq!(lib, "libc.so.6");
        // The cache is consulted before the filesystem, and the order is the point.
        assert!(tried[0].contains("ld.so.cache"));
        assert!(tried[1].ends_with("libc.so.6"));
    }

    #[test]
    fn the_link_map_carries_base_and_entry() {
        let steps = parse_ld_debug(SAMPLE);
        let map = steps.iter().find_map(|s| match &s.kind {
            StepKind::LinkMap {
                base, entry, phnum, ..
            } => Some((*base, *entry, *phnum)),
            _ => None,
        });
        assert_eq!(
            map,
            Some((0x0000_7f4f_c180_f000, 0x0000_7f4f_c183_9130, 15))
        );
    }

    #[test]
    fn relocation_comes_before_init_and_dependencies_come_first() {
        let trace = Trace {
            steps: parse_ld_debug(SAMPLE),
            ..Trace::default()
        };
        assert_eq!(
            trace.relocation_order(),
            vec!["/usr/lib/x86_64-linux-gnu/libc.so.6", "./hello-dyn"]
        );
        assert_eq!(
            trace.init_order(),
            vec![
                "/lib64/ld-linux-x86-64.so.2",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "./hello-dyn"
            ]
        );
        // The program is relocated before anything is initialised.
        let last_reloc = trace
            .steps
            .iter()
            .rposition(|s| matches!(s.kind, StepKind::Relocate { .. }))
            .expect("a relocate step");
        let first_init = trace
            .steps
            .iter()
            .position(|s| matches!(s.kind, StepKind::Init { .. }))
            .expect("an init step");
        assert!(last_reloc < first_init);
    }

    #[test]
    fn a_soname_and_its_resolved_path_are_one_object() {
        let trace = Trace {
            steps: parse_ld_debug(SAMPLE),
            ..Trace::default()
        };
        assert_eq!(
            trace.canonical("libc.so.6"),
            "/usr/lib/x86_64-linux-gnu/libc.so.6"
        );
        let objects = trace.objects();
        assert_eq!(
            objects.iter().filter(|o| o.contains("libc.so.6")).count(),
            1,
            "libc listed twice: {objects:?}"
        );
        // The ld.so.cache line is not a candidate path.
        assert!(!trace.canonical("libc.so.6").contains("cache"));
    }

    #[test]
    fn the_executable_and_the_loader_appear_despite_having_no_link_map() {
        let trace = Trace {
            steps: parse_ld_debug(SAMPLE),
            ..Trace::default()
        };
        let objects = trace.objects();
        assert!(objects.iter().any(|o| o.ends_with("hello-dyn")));
        assert!(objects.iter().any(|o| o.contains("libc.so.6")));
        assert!(objects.iter().any(|o| o.contains("ld-linux")));
    }

    #[test]
    fn symbol_binding_records_both_ends() {
        let steps = parse_ld_debug(SAMPLE);
        let bind = steps.iter().find_map(|s| match &s.kind {
            StepKind::Bind { from, to, symbol } => Some((from.clone(), to.clone(), symbol.clone())),
            _ => None,
        });
        assert_eq!(
            bind,
            Some((
                "./hello-dyn".to_owned(),
                "/usr/lib/x86_64-linux-gnu/libc.so.6".to_owned(),
                "fputs".to_owned()
            ))
        );
    }

    #[test]
    fn gdb_mapping_tables_parse() {
        let text = "\
          0x555555554000     0x555555555000     0x1000        0x0  r--p   /tmp/hello
          0x555555557000     0x555555559000     0x2000     0x2000  rw-p   /tmp/hello
        Mapped address spaces:";
        let rows = parse_maps(text);
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[1].offset, 0x2000);
        assert_eq!(rows[1].perms, "rw-p");
        // Both bottom rows share a file offset in a real capture; that is the
        // double-mapping the memory model reports.
        assert_eq!(rows[0].path, "/tmp/hello");
    }

    #[test]
    fn json_is_escaped_and_shaped() {
        let trace = Trace {
            target: "a\"weird\\name".to_owned(),
            steps: parse_ld_debug(SAMPLE),
            maps_at_interp: vec![MapRow {
                start: 0x1000,
                end: 0x2000,
                offset: 0,
                perms: "r--p".to_owned(),
                path: "/tmp/x".to_owned(),
            }],
            maps_at_entry: Vec::new(),
        };
        let json = to_json(&trace);
        assert!(json.starts_with("{\"schema\":1"));
        assert!(json.contains(r#"a\"weird\\name"#));
        assert!(json.contains(r#""kind":"transfer-control""#));
        assert!(json.contains(r#""counts":{"#));
    }
}
