//! Structural audit: the questions a total accounting makes cheap to ask.
//!
//! `readelf` prints the fields. It does not mind that `e_entry` points outside every
//! executable mapping, that two `PT_LOAD`s overlap, or that 400 KB of the file belongs to
//! no structure. Those are not parse errors — the file is well-formed — they are the file
//! disagreeing with itself.
//!
//! Every check here is derived from data the parser and the memory model already produce.
//! The coverage invariant does most of the work: a parser that accounts for every byte
//! knows exactly which bytes it could not account for, and that set is where appended
//! payloads, packers and patched-in data live.
//!
//! This reports; it does not judge. "Suspicious" means worth a look, not malicious — a
//! self-extracting installer and a packed sample look identical from here, and saying
//! otherwise would be pretending to knowledge the structure does not carry.

#![no_std]

extern crate alloc;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use elfa_model::{MemImage, PAGE_SIZE};
use elfa_parse::{ClaimKind, Parsed, Span};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Severity {
    /// True and worth knowing; not unusual.
    Note,
    /// Unusual. Legitimate binaries do this, but few of them.
    Odd,
    /// The file contradicts itself, or carries something it does not describe.
    Suspicious,
}

impl Severity {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Note => "note",
            Self::Odd => "odd",
            Self::Suspicious => "suspect",
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Finding {
    pub severity: Severity,
    pub title: &'static str,
    pub detail: String,
    /// Where in the file, when the finding has a location.
    pub span: Option<Span>,
}

/// Binary logarithm, without `std`.
///
/// `f64::log2` is a `std` method and this crate is `no_std` so the browser can run the
/// same audit. Rather than take a libm dependency for one function: split the float into
/// exponent and mantissa, which is exact, then take `ln` of the mantissa with the
/// `atanh` series. On `[1, 2)` the series argument stays under 1/3, so five terms land
/// well inside the precision any entropy threshold cares about.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "float arithmetic on a finite, positive argument checked above"
)]
fn log2(x: f64) -> f64 {
    if x <= 0.0 || !x.is_finite() {
        return f64::NEG_INFINITY;
    }
    let bits = x.to_bits();
    let exp = (((bits >> 52) & 0x7ff) as i64).saturating_sub(1023);
    let mantissa = f64::from_bits((bits & 0x000f_ffff_ffff_ffff) | 0x3ff0_0000_0000_0000);

    // ln(m) = 2·atanh((m−1)/(m+1))
    let z = (mantissa - 1.0) / (mantissa + 1.0);
    let z2 = z * z;
    let ln_m =
        2.0 * z * (1.0 + z2 / 3.0 + z2 * z2 / 5.0 + z2 * z2 * z2 / 7.0 + z2 * z2 * z2 * z2 / 9.0);

    exp as f64 + ln_m * core::f64::consts::LOG2_E
}

/// Shannon entropy in bits per byte.
///
/// Compressed and encrypted data sits near 8; text and code sit well below. The threshold
/// is a hint, not a verdict: a bitmap of random noise is high entropy and harmless.
#[must_use]
pub fn entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for b in bytes {
        if let Some(c) = counts.get_mut(*b as usize) {
            *c = c.saturating_add(1);
        }
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|c| **c > 0)
        .map(|c| {
            let p = f64::from(*c) / len;
            -p * log2(p)
        })
        .sum()
}

/// Thousands separators, without `std`'s formatting machinery.
///
/// Byte counts are most of what a finding says. Printing one of them as `402,859` and the
/// next as `171131` in the same sentence reads as two different tools talking.
#[must_use]
pub fn commas(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::with_capacity(digits.len().saturating_add(digits.len() / 3));
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && digits.len().saturating_sub(i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

/// Name what a run of bytes starts with, when it is something recognisable.
///
/// Appended data is far more useful with its container named: `/usr/bin/arj` carries an
/// `ARJ_SFX` marker followed by a whole second ELF file, which says "self-extracting
/// archive" rather than "171 KB of mystery".
#[must_use]
pub fn identify(bytes: &[u8]) -> Option<&'static str> {
    const MAGICS: &[(&[u8], &str)] = &[
        (b"\x7fELF", "an ELF file"),
        (b"ARJ_SFX", "an ARJ self-extracting stub"),
        (b"PK\x03\x04", "a zip archive"),
        (b"\x1f\x8b", "gzip data"),
        (b"7z\xbc\xaf\x27\x1c", "a 7-zip archive"),
        (b"\xfd7zXZ", "xz data"),
        (b"ustar", "a tar archive"),
        (b"MZ", "a PE/DOS executable"),
        (b"\xca\xfe\xba\xbe", "a Mach-O fat binary or Java class"),
    ];
    MAGICS
        .iter()
        .find(|(magic, _)| bytes.starts_with(magic))
        .map(|(_, name)| *name)
}

/// Run every check.
#[must_use]
pub fn audit(parsed: &Parsed, image: &MemImage, bytes: &[u8]) -> Vec<Finding> {
    let mut out = Vec::new();
    unexplained(parsed, bytes, &mut out);
    segments(parsed, &mut out);
    entry_point(parsed, image, &mut out);
    writable_code(parsed, image, &mut out);
    section_headers(parsed, &mut out);
    out.sort_by_key(|f| core::cmp::Reverse(f.severity));
    out
}

/// Bytes no structure accounts for.
fn unexplained(parsed: &Parsed, bytes: &[u8], out: &mut Vec<Finding>) {
    let cov = &parsed.coverage;
    let total = cov.stats().total_bytes;

    for id in cov.leaves() {
        let Some(claim) = cov.claim(id) else { continue };
        if claim.kind != ClaimKind::Unclaimed || claim.span.len < 256 {
            continue;
        }
        let span = claim.span;
        let slice = usize::try_from(span.start)
            .ok()
            .and_then(|s| usize::try_from(span.len).ok().map(|l| (s, l)))
            .and_then(|(s, l)| bytes.get(s..s.saturating_add(l)))
            .unwrap_or(&[]);
        let e = entropy(slice);

        // Everything past the last structure is appended: nothing in the file describes
        // it, and nothing in the file needs it. Self-extracting archives, embedded
        // payloads and signatures all live here.
        let at_end = span.end() >= total;
        if at_end && span.len >= 1024 {
            let what =
                identify(slice).map_or_else(String::new, |name| format!(", beginning with {name}"));
            out.push(Finding {
                severity: Severity::Suspicious,
                title: "data appended past the last structure",
                detail: format!(
                    "{} bytes at {:#x} that no header, section or segment describes{what} (entropy {e:.1})",
                    commas(span.len),
                    span.start
                ),
                span: Some(span),
            });
        } else if e > 7.2 && span.len >= 1024 {
            out.push(Finding {
                severity: Severity::Odd,
                title: "high-entropy region belongs to nothing",
                detail: format!(
                    "{} bytes at {:#x}, entropy {e:.1} — compressed, encrypted, or random",
                    commas(span.len),
                    span.start
                ),
                span: Some(span),
            });
        }
    }
}

const PT_LOAD: u32 = 1;

fn segments(parsed: &Parsed, out: &mut Vec<Finding>) {
    let loads: Vec<_> = parsed
        .summary
        .segments
        .iter()
        .filter(|s| s.p_type == PT_LOAD)
        .collect();

    for s in &loads {
        if s.filesz > s.memsz {
            out.push(Finding {
                severity: Severity::Suspicious,
                title: "segment claims more file than memory",
                detail: format!(
                    "p_filesz {:#x} exceeds p_memsz {:#x}; the loader cannot satisfy this",
                    s.filesz, s.memsz
                ),
                span: None,
            });
        }
        // mmap can only place a segment correctly when its offset and address agree
        // modulo the page size. A file that breaks this cannot be loaded as written.
        if s.filesz > 0 && (s.offset % PAGE_SIZE) != (s.vaddr % PAGE_SIZE) {
            out.push(Finding {
                severity: Severity::Suspicious,
                title: "segment offset and address are not page-congruent",
                detail: format!(
                    "p_offset {:#x} and p_vaddr {:#x} differ mod {PAGE_SIZE:#x}",
                    s.offset, s.vaddr
                ),
                span: None,
            });
        }
        if s.flags & 0b010 != 0 && s.flags & 0b001 != 0 {
            out.push(Finding {
                severity: Severity::Suspicious,
                title: "segment is writable and executable",
                detail: format!(
                    "{:#x}..{:#x} is mapped W+X; nothing a modern toolchain emits is",
                    s.vaddr,
                    s.vaddr.saturating_add(s.memsz)
                ),
                span: None,
            });
        }
    }

    for (i, a) in loads.iter().enumerate() {
        for b in loads.iter().skip(i.saturating_add(1)) {
            let (a_end, b_end) = (
                a.vaddr.saturating_add(a.memsz),
                b.vaddr.saturating_add(b.memsz),
            );
            if a.vaddr < b_end && b.vaddr < a_end {
                out.push(Finding {
                    severity: Severity::Suspicious,
                    title: "two PT_LOAD segments overlap in memory",
                    detail: format!(
                        "{:#x}..{a_end:#x} overlaps {:#x}..{b_end:#x}; the later mapping wins and the earlier one is partly unreachable",
                        a.vaddr, b.vaddr
                    ),
                    span: None,
                });
            }
        }
    }
}

fn entry_point(parsed: &Parsed, image: &MemImage, out: &mut Vec<Finding>) {
    let entry = parsed.summary.entry;
    if entry == 0 {
        return;
    }
    let Some(m) = image
        .mappings()
        .iter()
        .find(|m| entry >= m.vaddr && entry < m.end())
    else {
        out.push(Finding {
            severity: Severity::Suspicious,
            title: "entry point is not in any mapping",
            detail: format!("e_entry {entry:#x} lies outside every PT_LOAD"),
            span: None,
        });
        return;
    };
    if !m.prot.exec {
        out.push(Finding {
            severity: Severity::Suspicious,
            title: "entry point is not executable",
            detail: format!("e_entry {entry:#x} lands in a {} mapping", m.prot.as_str()),
            span: None,
        });
    }
}

/// Relocations that write into memory the loader will not make writable.
///
/// This is `DT_TEXTREL` observed rather than declared: if a relocation targets a segment
/// with no write bit, the loader has to make the page writable to apply it, which means
/// code pages that are briefly modifiable. Position-dependent shared objects do it;
/// almost nothing else should.
fn writable_code(parsed: &Parsed, image: &MemImage, out: &mut Vec<Finding>) {
    let mut count = 0usize;
    let mut first = 0u64;
    for r in &parsed.summary.relocs {
        let writable = image
            .mappings()
            .iter()
            .find(|m| r.offset >= m.vaddr && r.offset < m.end())
            .is_some_and(|m| m.prot.write);
        if !writable {
            if count == 0 {
                first = r.offset;
            }
            count = count.saturating_add(1);
        }
    }
    if count > 0 {
        out.push(Finding {
            severity: Severity::Odd,
            title: "relocations target non-writable memory",
            detail: format!(
                "{count} relocation(s), first at {first:#x} — the loader must unprotect the page to apply them"
            ),
            span: None,
        });
    }
}

fn section_headers(parsed: &Parsed, out: &mut Vec<Finding>) {
    if parsed.summary.shnum == 0 {
        out.push(Finding {
            severity: Severity::Odd,
            title: "no section headers",
            detail:
                "the file is loadable but describes none of itself; packers and hand-built binaries look like this"
                    .to_string(),
            span: None,
        });
    }
}

/// Bytes accounted for, as a fraction. A low number is the headline of any audit.
#[must_use]
pub fn explained_fraction(parsed: &Parsed) -> f64 {
    let s = parsed.coverage.stats();
    if s.total_bytes == 0 {
        return 1.0;
    }
    s.explained_bytes as f64 / s.total_bytes as f64
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;

    #[test]
    fn log2_is_accurate_enough_to_threshold_on() {
        for (x, want) in [
            (1.0, 0.0),
            (2.0, 1.0),
            (8.0, 3.0),
            (0.5, -1.0),
            (1.0 / 256.0, -8.0),
            (0.3, -1.736_965_594_166_206),
        ] {
            let got = log2(x);
            assert!((got - want).abs() < 1e-9, "log2({x}) = {got}, want {want}");
        }
        assert_eq!(log2(0.0), f64::NEG_INFINITY);
    }

    #[test]
    fn entropy_separates_noise_from_structure() {
        assert!(
            entropy(&[0u8; 4096]) < 0.1,
            "all zeroes carry no information"
        );
        let text = b"the quick brown fox jumps over the lazy dog".repeat(20);
        assert!(entropy(&text) < 5.0);
        // A byte-for-byte permutation is maximal entropy.
        let noise: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
        assert!(entropy(&noise) > 7.9, "{}", entropy(&noise));
        assert_eq!(entropy(&[]), 0.0);
    }

    #[test]
    fn byte_counts_read_the_same_everywhere() {
        assert_eq!(commas(0), "0");
        assert_eq!(commas(999), "999");
        assert_eq!(commas(1000), "1,000");
        assert_eq!(commas(171_131), "171,131");
        assert_eq!(commas(u64::MAX), "18,446,744,073,709,551,615");
    }

    #[test]
    fn containers_are_named_when_recognisable() {
        assert_eq!(identify(b"\x7fELF\x02\x01"), Some("an ELF file"));
        assert_eq!(
            identify(b"ARJ_SFX\x00rest"),
            Some("an ARJ self-extracting stub")
        );
        assert_eq!(identify(b"PK\x03\x04zip"), Some("a zip archive"));
        assert_eq!(identify(b"nothing in particular"), None);
        assert_eq!(identify(b""), None);
    }

    #[test]
    fn severity_orders_worst_first() {
        let mut v = [Severity::Note, Severity::Suspicious, Severity::Odd];
        v.sort_by(|a, b| b.cmp(a));
        assert_eq!(v, [Severity::Suspicious, Severity::Odd, Severity::Note]);
    }
}
