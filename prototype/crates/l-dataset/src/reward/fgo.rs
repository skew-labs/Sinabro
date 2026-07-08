//! Fine-Grained Optimization (FGO) AST coverage mask.
//!
//! # Design
//!
//! The mask weights **executed** added tokens high and **unexecuted** added
//! tokens low, and is tied to the diff hash and the coverage evidence. The
//! signal collectors expose a diff hash (`diff::DiffSummary::patch_hash_32`) but
//! no AST or coverage data, so this builder derives both itself from the diff —
//! without adding any parser dependency. The `ast_hash` is a deterministic,
//! language-tagged digest of the whitespace-normalized added lines (a structural
//! token surrogate, not a compiler AST); the `mask_hash` binds the diff hash, the
//! AST hash, and the per-line executed/unexecuted weight vector. A diff whose
//! recomputed hash does not match a pinned expectation is rejected; a diff with
//! no coverage evidence produces no mask.
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::diff;
use crate::error::{DietError, DietResult};

/// Weight (basis points) for an executed added line.
pub const EXECUTED_WEIGHT_BPS: u16 = 10_000;
/// Weight (basis points) for an unexecuted added line.
pub const UNEXECUTED_WEIGHT_BPS: u16 = 1_000;

/// Language tag mixed into the AST hash so a Rust and a Move diff with identical
/// text yield distinct masks.
const LANG_RUST: u8 = 1;
const LANG_MOVE: u8 = 2;

/// An FGO coverage mask.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct FgoCoverageMask {
    /// The source atom.
    pub key: AtomDietKey,
    /// Language-tagged structural digest of the added code.
    pub ast_hash_32: [u8; 32],
    /// Digest binding the diff hash, the AST hash, and the weight vector.
    pub mask_hash_32: [u8; 32],
}

/// Collect the added lines of a unified diff (lines starting with a single `+`),
/// whitespace-normalized so cosmetic spacing does not change the structural hash.
fn normalized_added_lines(diff_text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in diff_text.lines() {
        if let Some(content) = line.strip_prefix('+') {
            if content.starts_with('+') {
                continue; // "+++ " header, not an added line
            }
            out.push(content.split_whitespace().collect::<Vec<_>>().join(" "));
        }
    }
    out
}

/// Compute the language-tagged AST hash over the normalized added lines.
fn ast_hash(lang_tag: u8, added: &[String]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + added.iter().map(|l| l.len() + 1).sum::<usize>());
    buf.push(lang_tag);
    for line in added {
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
    }
    crate::sha256(&buf)
}

/// Build an FGO coverage mask for a diff.
///
/// `expected_diff_hash_32` pins the diff identity; an all-zero value means
/// "unpinned" (skip the check). `executed_added_lines` lists the 0-based indices
/// of *executed* added lines; `None` means **no coverage evidence** ⇒ no mask
/// (`Ok(None)`). A pinned hash that disagrees with the recomputed diff hash is a
/// hard reject. Deterministic and allocation-bounded by the diff size.
pub fn build_mask(
    key: AtomDietKey,
    diff_text: &str,
    expected_diff_hash_32: [u8; 32],
    executed_added_lines: Option<&[u32]>,
) -> DietResult<Option<FgoCoverageMask>> {
    let summary = diff::parse(diff_text)?;
    if expected_diff_hash_32 != [0u8; 32] && expected_diff_hash_32 != summary.patch_hash_32 {
        return Err(DietError::HashMismatch {
            kind: DietFileKind::CodeDiff,
        });
    }
    let executed = match executed_added_lines {
        None => return Ok(None), // missing coverage ⇒ no mask
        Some(e) => e,
    };
    let lang_tag = if summary.has_move {
        LANG_MOVE
    } else {
        LANG_RUST
    };
    let added = normalized_added_lines(diff_text);
    let ast = ast_hash(lang_tag, &added);

    // weight vector: executed lines high, unexecuted low.
    let mut buf = Vec::with_capacity(64 + added.len() * 2);
    buf.extend_from_slice(&summary.patch_hash_32);
    buf.extend_from_slice(&ast);
    for i in 0..added.len() as u32 {
        let w = if executed.contains(&i) {
            EXECUTED_WEIGHT_BPS
        } else {
            UNEXECUTED_WEIGHT_BPS
        };
        buf.extend_from_slice(&w.to_le_bytes());
    }
    let mask_hash_32 = crate::sha256(&buf);

    Ok(Some(FgoCoverageMask {
        key,
        ast_hash_32: ast,
        mask_hash_32,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 391)
    }

    const RUST_DIFF: &str = "--- a/src/lib.rs\n+++ b/src/lib.rs\n@@ -1,2 +1,4 @@\n fn main() {\n+    let x = 1;\n+    let y = 2;\n }\n";
    const MOVE_DIFF: &str = "--- a/sources/m.move\n+++ b/sources/m.move\n@@ -1,2 +1,4 @@\n module m {\n+    let x = 1;\n+    let y = 2;\n }\n";

    fn require(m: Option<FgoCoverageMask>) -> DietResult<FgoCoverageMask> {
        m.ok_or(DietError::MissingEvidence {
            kind: DietFileKind::CodeDiff,
        })
    }

    #[test]
    fn rust_ast_mask_is_produced() -> DietResult<()> {
        let mask = require(build_mask(key(), RUST_DIFF, [0u8; 32], Some(&[0]))?)?;
        assert_ne!(mask.ast_hash_32, [0u8; 32]);
        assert_ne!(mask.mask_hash_32, [0u8; 32]);
        Ok(())
    }

    #[test]
    fn move_ast_mask_differs_from_rust() -> DietResult<()> {
        let r = require(build_mask(key(), RUST_DIFF, [0u8; 32], Some(&[0, 1]))?)?;
        let m = require(build_mask(key(), MOVE_DIFF, [0u8; 32], Some(&[0, 1]))?)?;
        // identical added text, different language tag ⇒ different AST hash.
        assert_ne!(r.ast_hash_32, m.ast_hash_32);
        Ok(())
    }

    #[test]
    fn missing_coverage_yields_no_mask() -> DietResult<()> {
        let m = build_mask(key(), RUST_DIFF, [0u8; 32], None)?;
        assert!(m.is_none());
        Ok(())
    }

    #[test]
    fn diff_hash_mismatch_is_rejected() {
        let wrong = [0xABu8; 32];
        assert_eq!(
            build_mask(key(), RUST_DIFF, wrong, Some(&[0])),
            Err(DietError::HashMismatch {
                kind: DietFileKind::CodeDiff
            })
        );
    }

    #[test]
    fn executed_vs_unexecuted_changes_the_mask() -> DietResult<()> {
        let exec_first = require(build_mask(key(), RUST_DIFF, [0u8; 32], Some(&[0]))?)?;
        let exec_both = require(build_mask(key(), RUST_DIFF, [0u8; 32], Some(&[0, 1]))?)?;
        // same diff/AST, different coverage ⇒ different mask hash.
        assert_eq!(exec_first.ast_hash_32, exec_both.ast_hash_32);
        assert_ne!(exec_first.mask_hash_32, exec_both.mask_hash_32);
        Ok(())
    }

    #[test]
    fn pinned_matching_hash_is_accepted() -> DietResult<()> {
        let summary = diff::parse(RUST_DIFF)?;
        let mask = require(build_mask(
            key(),
            RUST_DIFF,
            summary.patch_hash_32,
            Some(&[0]),
        )?)?;
        assert_ne!(mask.mask_hash_32, [0u8; 32]);
        Ok(())
    }
}
