//! `mnemos-e-skill::bundle` — the package bundle layout
//! and its extraction-safety invariants.
//!
//! ## Overview
//!
//! A bundle is the on-disk shape of a package: the manifest, the
//! wasm/artifacts, the tests, the eval, the provenance, and the signature.
//! This module models the bundle as a flat list of [`BundleEntry`] (each a
//! relative path + a content hash + a size) and enforces the extraction-safety
//! rule: extraction **cannot** path-traverse, overwrite an existing file, or
//! hide a duplicate artifact name.
//!
//! - [`BundleLayout::validate`] — every entry path is relative + normalized
//!   (no leading `/`, no `..`, no `.`, no backslash, no drive letter, no
//!   NUL, non-empty); no two entries share a path (case-insensitively, so a
//!   `A.wasm` / `a.wasm` pair cannot hide a duplicate); and the total size
//!   is under [`MAX_BUNDLE_BYTES`].
//! - [`BundleLayout::artifact_digest_tree`] — the deterministic digest of
//!   the (path-sorted) entry tree. This is the `artifact_digest_32` of the
//!   wrapping package (the invariant that the bundle digest equals the
//!   artifact digest tree), and is stable regardless of input entry order.
//!
//! The layout never parses bytes from disk and never decompresses — that
//! belongs to a later stage behind a sandbox. Here it is a pure, panic-free
//! validator over already-measured entries.

#![deny(missing_docs)]

extern crate alloc;

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;

use crate::package::blake2b_256;

/// Domain tag for the artifact-digest-tree fold.
pub(crate) const DOMAIN_BUNDLE_TREE: &[u8] = b"mnemos.d.bundle_tree.v1";

/// Maximum total bundle size (sum of entry sizes). 64 MiB — generous for a
/// skill bundle, bounded so a crafted manifest cannot claim an unbounded
/// extraction footprint.
pub const MAX_BUNDLE_BYTES: u64 = 64 * 1024 * 1024;

/// Maximum number of entries in a bundle — bounds validation cost.
pub const MAX_BUNDLE_ENTRIES: usize = 4_096;

// ===========================================================================
// 1. BundleError — stable extraction-safety rejection reasons
// ===========================================================================

/// Why a [`BundleLayout`] is rejected. `Copy`, payload-light (the offending
/// path is never carried — only a stable class) so a crafted path cannot
/// reach a log surface through this channel.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum BundleError {
    /// The bundle has no entries.
    Empty,
    /// More than [`MAX_BUNDLE_ENTRIES`] entries.
    TooManyEntries,
    /// An entry path is absolute, contains `..`/`.`, a backslash, a drive
    /// letter, a NUL, or is empty (a path-traversal / escape attempt).
    PathTraversal,
    /// Two entries share a path (case-insensitively) — a hidden duplicate.
    DuplicatePath,
    /// The total bundle size exceeds [`MAX_BUNDLE_BYTES`].
    SizeCapExceeded,
}

impl BundleError {
    /// Stable class label namespaced under `bundle.*`.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Empty => "bundle.empty",
            Self::TooManyEntries => "bundle.too_many_entries",
            Self::PathTraversal => "bundle.path_traversal",
            Self::DuplicatePath => "bundle.duplicate_path",
            Self::SizeCapExceeded => "bundle.size_cap_exceeded",
        }
    }
}

// ===========================================================================
// 2. BundleEntry / BundleLayout
// ===========================================================================

/// One file in a package bundle: a relative path, a 32-byte content hash,
/// and a byte size. The bytes themselves live elsewhere; this is a measured
/// reference.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct BundleEntry {
    /// Relative, normalized path inside the bundle.
    pub path: String,
    /// Blake2b-256 of the entry contents.
    pub content_hash_32: [u8; 32],
    /// Entry size in bytes.
    pub size_bytes_u64: u64,
}

/// A package bundle: a flat list of measured entries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BundleLayout {
    /// The bundle entries (order-insensitive for the digest).
    pub entries: Vec<BundleEntry>,
}

/// `true` iff `path` is a safe relative bundle path (see module docs).
#[must_use]
pub fn is_safe_bundle_path(path: &str) -> bool {
    if path.is_empty() {
        return false;
    }
    // ASCII-only: a non-ASCII path could carry a Unicode look-alike of `.`
    // or `/` (e.g. U+FF0E / U+2024) that bypasses the component checks below
    // yet normalizes to a traversal on a real filesystem. Bundle paths are
    // ASCII by construction; anything else rejects fail-closed.
    if !path.is_ascii() {
        return false;
    }
    // No NUL, no backslash, no drive-letter colon.
    if path.contains('\0') || path.contains('\\') || path.contains(':') {
        return false;
    }
    // No absolute paths.
    if path.starts_with('/') {
        return false;
    }
    // No `~` home expansion.
    if path.starts_with('~') {
        return false;
    }
    // Component-wise: reject `..`, `.`, and empty components (which would
    // come from `//`, a leading `/`, or a trailing `/`).
    for component in path.split('/') {
        if component.is_empty() || component == ".." || component == "." {
            return false;
        }
    }
    true
}

impl BundleLayout {
    /// Validate the bundle's extraction-safety invariants.
    pub fn validate(&self) -> Result<(), BundleError> {
        if self.entries.is_empty() {
            return Err(BundleError::Empty);
        }
        if self.entries.len() > MAX_BUNDLE_ENTRIES {
            return Err(BundleError::TooManyEntries);
        }
        let mut seen: BTreeSet<String> = BTreeSet::new();
        let mut total: u64 = 0;
        for entry in &self.entries {
            if !is_safe_bundle_path(&entry.path) {
                return Err(BundleError::PathTraversal);
            }
            // Case-insensitive duplicate detection (a `A`/`a` pair hides a dup).
            if !seen.insert(entry.path.to_ascii_lowercase()) {
                return Err(BundleError::DuplicatePath);
            }
            total = match total.checked_add(entry.size_bytes_u64) {
                Some(t) => t,
                None => return Err(BundleError::SizeCapExceeded),
            };
            if total > MAX_BUNDLE_BYTES {
                return Err(BundleError::SizeCapExceeded);
            }
        }
        Ok(())
    }

    /// Deterministic artifact digest tree over the (path-sorted) entries.
    /// Stable regardless of input order: entries are sorted by path bytes
    /// before folding. This equals the package `artifact_digest_32`.
    ///
    /// Callers should [`Self::validate`] first; the digest is still
    /// well-defined for an invalid layout (it is a pure fold), but an
    /// invalid layout must never reach the catalog.
    #[must_use]
    pub fn artifact_digest_tree(&self) -> [u8; 32] {
        let mut sorted: Vec<&BundleEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
        for entry in sorted {
            let path_bytes = entry.path.as_bytes();
            buf.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
            buf.extend_from_slice(path_bytes);
            buf.extend_from_slice(&entry.content_hash_32);
            buf.extend_from_slice(&entry.size_bytes_u64.to_le_bytes());
        }
        blake2b_256(&[DOMAIN_BUNDLE_TREE, &buf])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn entry(path: &str, size: u64) -> BundleEntry {
        BundleEntry {
            path: String::from(path),
            content_hash_32: blake2b_256(&[path.as_bytes()]),
            size_bytes_u64: size,
        }
    }

    fn good_bundle() -> BundleLayout {
        BundleLayout {
            entries: vec![
                entry("manifest.toml", 100),
                entry("artifacts/skill.wasm", 4096),
                entry("tests/fixture_1.json", 200),
                entry("eval/score.toml", 64),
            ],
        }
    }

    #[test]
    fn well_formed_bundle_validates() {
        assert_eq!(good_bundle().validate(), Ok(()));
    }

    #[test]
    fn path_traversal_rejected() {
        // Parent-dir escape.
        assert!(!is_safe_bundle_path("../etc/passwd"));
        assert!(!is_safe_bundle_path("a/../../b"));
        // Absolute.
        assert!(!is_safe_bundle_path("/etc/passwd"));
        // Backslash (Windows traversal).
        assert!(!is_safe_bundle_path("a\\..\\b"));
        // Drive letter.
        assert!(!is_safe_bundle_path("C:/x"));
        // Home expansion + empty + double slash + trailing slash.
        assert!(!is_safe_bundle_path("~/x"));
        assert!(!is_safe_bundle_path(""));
        assert!(!is_safe_bundle_path("a//b"));
        assert!(!is_safe_bundle_path("a/"));
        // Non-ASCII (Unicode look-alike of `.` / `/`) rejects fail-closed.
        assert!(!is_safe_bundle_path("a\u{ff0e}\u{ff0e}/b")); // fullwidth ".."
        assert!(!is_safe_bundle_path("café/x"));
        // Safe ones.
        assert!(is_safe_bundle_path("a/b/c.wasm"));
        assert!(is_safe_bundle_path("manifest.toml"));

        let mut b = good_bundle();
        b.entries.push(entry("../escape", 1));
        assert_eq!(b.validate(), Err(BundleError::PathTraversal));
    }

    #[test]
    fn duplicate_file_rejected_case_insensitively() {
        let mut b = good_bundle();
        b.entries.push(entry("Manifest.TOML", 100)); // case-variant duplicate
        assert_eq!(b.validate(), Err(BundleError::DuplicatePath));
    }

    #[test]
    fn size_cap_enforced() {
        let mut b = BundleLayout {
            entries: vec![entry("big.bin", MAX_BUNDLE_BYTES)],
        };
        assert_eq!(b.validate(), Ok(())); // exactly at cap is allowed
        b.entries.push(entry("one_more.bin", 1));
        assert_eq!(b.validate(), Err(BundleError::SizeCapExceeded));
    }

    #[test]
    fn empty_bundle_rejected() {
        let b = BundleLayout { entries: vec![] };
        assert_eq!(b.validate(), Err(BundleError::Empty));
    }

    #[test]
    fn artifact_digest_tree_is_order_stable() {
        let b1 = good_bundle();
        let mut b2 = good_bundle();
        b2.entries.reverse();
        assert_eq!(
            b1.artifact_digest_tree(),
            b2.artifact_digest_tree(),
            "digest must be independent of entry order"
        );
        // Changing a content hash moves the tree digest.
        let mut b3 = good_bundle();
        b3.entries[0].content_hash_32[0] ^= 0x01;
        assert_ne!(b1.artifact_digest_tree(), b3.artifact_digest_tree());
    }
}
