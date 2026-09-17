//! Span-addressed ELF parsing.
//!
//! The whole of `elf-anatomy` rests on one relationship: *a byte range in a file* means
//! *one specific thing*. A conventional ELF parser returns a decoded struct tree and
//! discards the offsets those fields came from. That is the correct design for a linker
//! and the wrong one here — the offsets are the product.
//!
//! So parsing produces a [`Coverage`]: a flat list of [`Claim`]s, each one a [`Span`] with
//! a meaning, arranged into a tree by `parent` links, and indexed for point queries.
//!
//! # The coverage invariant
//!
//! **Every byte of the file is claimed by exactly one leaf claim.**
//!
//! Interior claims nest freely — the file header claim covers `0x00..0x40` and its
//! `e_entry` field claim covers `0x18..0x20` — but the *leaves* form an exact partition of
//! the file. [`CoverageBuilder::finish`] refuses to produce a `Coverage` otherwise.
//!
//! This is not bookkeeping. It is the correctness test for the parser (an overlap means a
//! size calculation is wrong) and it generates the interesting content for free: whatever
//! is left over becomes [`ClaimKind::Unclaimed`], and those leftovers are the alignment
//! padding, the linker gaps, the sections nobody reads, and the appended data that explain
//! why a binary is the size it is.
//!
//! # Phase 0
//!
//! This crate currently defines the data model, the invariant, and the index. The ELF
//! parser itself lands in phase 1; see `PROJECT_PLAN.md` §9.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod claim;
mod coverage;
mod index;
mod span;

pub use claim::{Claim, ClaimId, ClaimKind, PadReason, RelocTableKind, Value, VersionTableKind};
pub use coverage::{Coverage, CoverageBuilder, CoverageError, CoverageStats};
pub use index::IntervalIndex;
pub use span::{FileId, Span};
