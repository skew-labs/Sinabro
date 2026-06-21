//! `mnemos-e-skill::eval` — atom #245 · D.0.4 — the eval / tests digest
//! contract.
//!
//! ## Canonical OUT (§4.1 — ATOM_PLAN line 191-199)
//!
//! - [`SkillEvalScore`] — §4.1 six per-axis scores (`rust`, `move`,
//!   `prover`, `gas`, `security`, `korean`) plus a 32-byte
//!   `reproducible_command_hash_32`. An eval score is meaningless unless it
//!   links to the reproducible commands that produced it (§245 광기); so a
//!   score with an all-zero command hash is rejected, and any axis above
//!   [`MAX_EVAL_SCORE`] (`10_000`) is rejected.
//! - [`reproducible_command_hash`] — derive the command hash from the exact
//!   command strings. The hash changes whenever any command changes (§245
//!   criterion), so a forged "100%" score with a mismatched command set is
//!   catchable.
//! - [`tests_digest`] — derive the `tests_digest_32` field of a
//!   [`crate::package::SkillPackageV1`] from the skill's test-fixture bytes.
//!
//! The eval schema is documented in `ops/evidence/stage_d/eval_schema.md`.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::package::blake2b_256;

/// Domain tag for the [`SkillEvalScore`] fold digest.
pub(crate) const DOMAIN_EVAL: &[u8] = b"mnemos.d.skill_eval.v1";
/// Domain tag for the reproducible-command hash.
pub(crate) const DOMAIN_EVAL_COMMAND: &[u8] = b"mnemos.d.eval_command.v1";
/// Domain tag for the tests-corpus digest.
pub(crate) const DOMAIN_TESTS: &[u8] = b"mnemos.d.skill_tests.v1";

/// Maximum legal value for any eval axis. A score is expressed in basis
/// points of "100%": `10_000` is a perfect axis. Anything above is a
/// spoofed score and is rejected (§245 test list).
pub const MAX_EVAL_SCORE: u16 = 10_000;

// ===========================================================================
// 1. SkillEvalScore — §4.1 six axes + reproducible command hash
// ===========================================================================

/// Per-axis eval score for a skill (§4.1). Every axis is in basis points of
/// 100% (`0..=10_000`). `reproducible_command_hash_32` binds the score to
/// the exact commands that produced it; an all-zero hash means "no
/// reproducible command" and is rejected by [`Self::is_valid`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillEvalScore {
    /// Rust test/lint axis (basis points).
    pub rust_u16: u16,
    /// Move test axis (basis points).
    pub move_u16: u16,
    /// Move Prover axis (basis points).
    pub prover_u16: u16,
    /// Gas budget axis (basis points).
    pub gas_u16: u16,
    /// Security / malicious-fixture axis (basis points).
    pub security_u16: u16,
    /// Korean-output quality axis (basis points).
    pub korean_u16: u16,
    /// 32-byte hash of the reproducible commands that produced these
    /// scores. Must be non-zero.
    pub reproducible_command_hash_32: [u8; 32],
}

impl SkillEvalScore {
    /// The six axes in canonical order — used for stable iteration in the
    /// digest and in tests so the slot order can never silently drift.
    #[inline]
    #[must_use]
    pub const fn axes(&self) -> [u16; 6] {
        [
            self.rust_u16,
            self.move_u16,
            self.prover_u16,
            self.gas_u16,
            self.security_u16,
            self.korean_u16,
        ]
    }

    /// `true` iff every axis is `<= MAX_EVAL_SCORE` AND the reproducible
    /// command hash is non-zero. A score failing this is rejected before
    /// the package is catalog-visible.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        if self.reproducible_command_hash_32 == [0u8; 32] {
            return false;
        }
        self.axes().iter().all(|&axis| axis <= MAX_EVAL_SCORE)
    }

    /// 32-byte fold digest, folded into the package content digest.
    #[must_use]
    pub(crate) fn digest_32(&self) -> [u8; 32] {
        let mut buf: Vec<u8> = Vec::new();
        for axis in self.axes() {
            buf.extend_from_slice(&axis.to_le_bytes());
        }
        blake2b_256(&[DOMAIN_EVAL, &buf, &self.reproducible_command_hash_32])
    }
}

// ===========================================================================
// 2. reproducible_command_hash — score ⇄ command binding
// ===========================================================================

/// Derive the `reproducible_command_hash_32` from the exact command lines
/// that produced an eval score. The hash is order-sensitive and
/// length-prefixed, so changing, adding, removing, or reordering any
/// command moves the hash (§245 criterion).
#[must_use]
pub fn reproducible_command_hash(commands: &[&str]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(commands.len() as u32).to_le_bytes());
    for cmd in commands {
        let bytes = cmd.as_bytes();
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
    }
    blake2b_256(&[DOMAIN_EVAL_COMMAND, &buf])
}

/// Derive the `tests_digest_32` field of a package from the concatenated
/// test-fixture bytes (length-prefixed, order-sensitive).
#[must_use]
pub fn tests_digest(fixtures: &[&[u8]]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&(fixtures.len() as u32).to_le_bytes());
    for fx in fixtures {
        buf.extend_from_slice(&(fx.len() as u32).to_le_bytes());
        buf.extend_from_slice(fx);
    }
    blake2b_256(&[DOMAIN_TESTS, &buf])
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn valid_score() -> SkillEvalScore {
        SkillEvalScore {
            rust_u16: 9_800,
            move_u16: 10_000,
            prover_u16: 10_000,
            gas_u16: 9_500,
            security_u16: 10_000,
            korean_u16: 9_000,
            reproducible_command_hash_32: reproducible_command_hash(&[
                "cargo test --workspace",
                "cargo clippy -- -D warnings",
            ]),
        }
    }

    #[test]
    fn axes_slots_are_stable() {
        let s = valid_score();
        assert_eq!(s.axes(), [9_800, 10_000, 10_000, 9_500, 10_000, 9_000]);
    }

    #[test]
    fn missing_command_hash_rejected() {
        let mut s = valid_score();
        s.reproducible_command_hash_32 = [0u8; 32];
        assert!(!s.is_valid(), "all-zero command hash must reject");
    }

    #[test]
    fn score_over_10000_rejected() {
        let mut s = valid_score();
        s.rust_u16 = 10_001;
        assert!(!s.is_valid(), "axis > 10_000 must reject");
        // Boundary: exactly 10_000 is legal.
        s.rust_u16 = 10_000;
        assert!(s.is_valid());
    }

    #[test]
    fn command_hash_changes_when_command_changes() {
        let a = reproducible_command_hash(&["cargo test"]);
        let b = reproducible_command_hash(&["cargo test --release"]);
        assert_ne!(a, b, "command change must move the hash");
        // Reordering also moves the hash.
        let c = reproducible_command_hash(&["a", "b"]);
        let d = reproducible_command_hash(&["b", "a"]);
        assert_ne!(c, d, "command reorder must move the hash");
        // Identical commands → identical hash.
        assert_eq!(
            reproducible_command_hash(&["x", "y"]),
            reproducible_command_hash(&["x", "y"])
        );
    }

    #[test]
    fn eval_digest_is_stable_and_slot_sensitive() {
        let s = valid_score();
        assert_eq!(s.digest_32(), s.digest_32());
        let mut t = s;
        t.gas_u16 = 9_499;
        assert_ne!(s.digest_32(), t.digest_32(), "axis change must move digest");
    }

    #[test]
    fn tests_digest_is_order_sensitive() {
        assert_ne!(tests_digest(&[b"a", b"b"]), tests_digest(&[b"b", b"a"]));
        assert_eq!(tests_digest(&[b"x"]), tests_digest(&[b"x"]));
    }
}
