//! The dependency closure: every object a program needs, resolved and parsed.
//!
//! Up to here the model has covered the main object, with `DT_NEEDED` named but never
//! followed. This crate follows it — which is what turns "a binary being mapped" into "a
//! process starting", because most of the relocations, most of the symbols and most of
//! the initialisers in a running program belong to libc rather than to the program.
//!
//! Resolution is the loader's search order, reimplemented. That is a claim about
//! behaviour like any other, so it is checkable: `elfa trace` records the paths the real
//! loader settled on, and `elfa process --verify` compares them.
//!
//! Filesystem access means this is the one crate the browser cannot use. A tab has the
//! file that was dropped into it and nothing else.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};

use elfa_model::MemImage;
use elfa_parse::{ParseError, Parsed, parse};

/// Where to look for a dependency, in the order glibc looks.
#[derive(Clone, Debug)]
pub struct SearchPath {
    /// `LD_LIBRARY_PATH`, split on `:`.
    pub env: Vec<PathBuf>,
    /// The default directories, after the cache.
    pub default: Vec<PathBuf>,
}

impl Default for SearchPath {
    fn default() -> Self {
        Self {
            env: std::env::var("LD_LIBRARY_PATH")
                .unwrap_or_default()
                .split(':')
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
                .collect(),
            // The cache sits between LD_LIBRARY_PATH and these. We do not read it — see
            // `Resolution::Guessed` and docs/CONFORMANCE.md — so these directories stand
            // in for it, which is right on a normal system and wrong on an unusual one.
            default: [
                "/lib/x86_64-linux-gnu",
                "/usr/lib/x86_64-linux-gnu",
                "/lib64",
                "/usr/lib64",
                "/lib",
                "/usr/lib",
            ]
            .iter()
            .map(PathBuf::from)
            .collect(),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum LoadError {
    Read { path: PathBuf, detail: String },
    Parse { path: PathBuf, detail: String },
    NotFound { soname: String, needed_by: PathBuf },
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, detail } => write!(f, "{}: {detail}", path.display()),
            Self::Parse { path, detail } => write!(f, "{}: {detail}", path.display()),
            Self::NotFound { soname, needed_by } => write!(
                f,
                "{soname}: not found on any search path (needed by {})",
                needed_by.display()
            ),
        }
    }
}

impl std::error::Error for LoadError {}

/// One loaded object.
#[derive(Debug)]
pub struct Object {
    pub id: u32,
    pub path: PathBuf,
    /// What the dependency was called before it was found.
    pub requested: String,
    /// Which object asked for it; `None` for the program itself.
    pub needed_by: Option<u32>,
    pub parsed: Parsed,
    pub image: MemImage,
    /// Address the object is placed at in this model.
    pub base: u64,
}

impl Object {
    /// Relocations this object applies at startup, deferred PLT entries excluded.
    ///
    /// Uses the model's own rule so the two cannot drift apart.
    #[must_use]
    pub fn startup_relocations(&self) -> usize {
        self.parsed
            .summary
            .relocs
            .iter()
            .filter(|r| !elfa_model::is_deferred(&self.parsed.summary, r))
            .count()
    }
}

/// A program and everything it needs.
#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
}

impl Process {
    /// The program itself.
    #[must_use]
    pub fn program(&self) -> Option<&Object> {
        self.objects.first()
    }

    #[must_use]
    pub fn total_relocations(&self) -> usize {
        self.objects.iter().map(Object::startup_relocations).sum()
    }

    #[must_use]
    pub fn total_mapped(&self) -> u64 {
        self.objects
            .iter()
            .map(|o| o.image.resident_bytes())
            .fold(0, u64::saturating_add)
    }

    /// Objects in the order the loader relocates them: dependencies before the objects
    /// that need them, which for a breadth-first closure is simply the reverse of the
    /// order they were discovered in.
    #[must_use]
    pub fn relocation_order(&self) -> Vec<&Object> {
        let mut out: Vec<&Object> = self.objects.iter().collect();
        out.reverse();
        out
    }
}

/// Space left between objects so a reader can tell them apart. The real loader's spacing
/// is whatever `mmap` returns and is not reproducible anyway.
const GAP: u64 = 0x10_0000;

/// Resolve and parse the closure, breadth-first, the way `ld.so` walks `DT_NEEDED`.
///
/// The interpreter is deliberately not followed. It is already in the process before the
/// first `DT_NEEDED` is read, and treating it as a dependency of libc produces a cycle.
pub fn load(path: &Path, search: &SearchPath) -> Result<Process, LoadError> {
    let mut objects: Vec<Object> = Vec::new();
    let mut queue: VecDeque<(String, PathBuf, Option<u32>)> = VecDeque::new();
    let mut next_base = 0u64;

    let program = read_object(path, path.display().to_string(), None, 0, 0)?;
    let interp_base = program
        .parsed
        .summary
        .interp
        .as_deref()
        .and_then(|i| i.rsplit('/').next())
        .unwrap_or("")
        .to_owned();
    next_base = advance(next_base, &program);
    for n in &program.parsed.summary.needed {
        queue.push_back((n.to_string(), path.to_path_buf(), Some(0)));
    }
    objects.push(program);

    while let Some((soname, asker, needed_by)) = queue.pop_front() {
        if soname == interp_base || objects.iter().any(|o| o.requested == soname) {
            continue;
        }
        let Some(found) = find(&soname, search) else {
            return Err(LoadError::NotFound {
                soname,
                needed_by: asker,
            });
        };
        let id = u32::try_from(objects.len()).unwrap_or(u32::MAX);
        let obj = read_object(&found, soname, needed_by, id, next_base)?;
        next_base = advance(next_base, &obj);
        for n in &obj.parsed.summary.needed {
            queue.push_back((n.to_string(), found.clone(), Some(id)));
        }
        objects.push(obj);
    }

    Ok(Process { objects })
}

fn advance(base: u64, obj: &Object) -> u64 {
    let span = obj
        .image
        .extent()
        .map_or(0, |(lo, hi)| hi.saturating_sub(lo));
    base.saturating_add(span).saturating_add(GAP) & !0xfff
}

fn read_object(
    path: &Path,
    requested: String,
    needed_by: Option<u32>,
    id: u32,
    base: u64,
) -> Result<Object, LoadError> {
    let bytes = std::fs::read(path).map_err(|e| LoadError::Read {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let parsed = parse(&bytes).map_err(|e: ParseError| LoadError::Parse {
        path: path.to_path_buf(),
        detail: e.to_string(),
    })?;
    let image = MemImage::from_segments(
        &parsed.summary.segments,
        parsed.coverage.stats().total_bytes,
    );
    Ok(Object {
        id,
        path: path.to_path_buf(),
        requested,
        needed_by,
        parsed,
        image,
        base,
    })
}

/// Search `LD_LIBRARY_PATH`, then the default directories.
fn find(soname: &str, search: &SearchPath) -> Option<PathBuf> {
    search
        .env
        .iter()
        .chain(search.default.iter())
        .map(|dir| dir.join(soname))
        .find(|p| p.is_file())
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/out")
            .join(name)
    }

    #[test]
    fn a_dynamic_program_pulls_in_libc() {
        let p = fixture("hello-dyn");
        if !p.exists() {
            eprintln!("no fixtures; run `make -C fixtures`");
            return;
        }
        let proc = load(&p, &SearchPath::default()).expect("load closure");

        assert_eq!(proc.objects.len(), 2, "the program and libc");
        assert_eq!(proc.objects[1].requested, "libc.so.6");
        assert_eq!(proc.objects[1].needed_by, Some(0));

        // Most of a process is not the program. That is the point of following the
        // closure at all.
        let prog = proc.objects[0].startup_relocations();
        let libc = proc.objects[1].startup_relocations();
        assert!(libc > prog * 10, "program {prog}, libc {libc}");
    }

    #[test]
    fn the_interpreter_is_not_followed() {
        let p = fixture("hello-dyn");
        if !p.exists() {
            return;
        }
        let proc = load(&p, &SearchPath::default()).expect("load closure");
        // libc lists ld-linux in its own DT_NEEDED; following it would loop.
        assert!(
            !proc
                .objects
                .iter()
                .any(|o| o.requested.contains("ld-linux")),
            "{:?}",
            proc.objects
                .iter()
                .map(|o| &o.requested)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn objects_do_not_overlap_in_the_address_space() {
        let p = fixture("hello-dyn");
        if !p.exists() {
            return;
        }
        let proc = load(&p, &SearchPath::default()).expect("load closure");
        let mut spans: Vec<(u64, u64)> = proc
            .objects
            .iter()
            .filter_map(|o| o.image.extent().map(|(lo, hi)| (o.base + lo, o.base + hi)))
            .collect();
        spans.sort_unstable();
        for w in spans.windows(2) {
            assert!(w[0].1 <= w[1].0, "objects overlap: {spans:?}");
        }
    }

    #[test]
    fn a_static_binary_is_a_closure_of_one() {
        let p = fixture("hello-static");
        if !p.exists() {
            return;
        }
        let proc = load(&p, &SearchPath::default()).expect("load static");
        assert_eq!(proc.objects.len(), 1);
    }
}
