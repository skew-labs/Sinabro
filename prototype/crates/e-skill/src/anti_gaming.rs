//! `mnemos-e-skill::anti_gaming` — anti-gaming checks for
//! verified installs and active traces.
//!
//! The base [`fold_counters`] (#297) already deduplicates by replay key and
//! excludes revoked installs, which keeps the **weak** download signal honest.
//! The **strong** verified-install / active-user signals need more: repeated
//! downloads, self-install loops, install→reinstall loops, failed/forged eval
//! evidence, and revoked-then-reinstalled packages must not inflate verified
//! quality. [`anti_gamed_counters`] hardens the fold into the
//! [`AntiGamedCounters`] strong signal:
//!
//! - **duplicate identity** — identical receipts (same replay key) collapse to
//!   one; the extras are counted in `rejected_duplicate_u64`.
//! - **same-package loop** — a verified install counts at most once per
//!   `(installer, package)` identity; extra verified receipts for an
//!   already-counted pair are `rejected_same_package_loop_u64`.
//! - **forged eval** — a verified-install-state receipt with an all-zero eval
//!   hash carries no eval evidence and is `rejected_forged_eval_u64`.
//! - **revoked** — a revoked receipt is excluded *and* poisons its
//!   `(installer, package)` pair, so a revoked install can never be laundered
//!   back into the verified count by reinstalling under the same identity.
//! - **active threshold** — `active_users_u64` only counts pairs that are both
//!   verified and active, and is structurally capped at `verified_installs_u64`
//!   (you cannot have more active users than verified installs).
//!
//! The result is order-independent: it is computed from sets and counts over
//! the replay-deduplicated event stream, so a shuffled stream yields identical
//! [`AntiGamedCounters`].

#![deny(missing_docs)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use crate::catalog_counters::{VerifiedInstallReceipt, fold_counters};

/// The anti-gamed counters for one catalog entry, plus per-class rejection
/// tallies for audit (red-team precision).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
pub struct AntiGamedCounters {
    /// Weak signal: unique downloads (replay-deduplicated), identical to the
    /// base [`fold_counters`] download count.
    pub downloads_u64: u64,
    /// Strong signal: unique `(installer, package)` verified installs after
    /// excluding revoked pairs, forged-eval receipts, and same-package loops.
    pub verified_installs_u64: u64,
    /// Unique `(installer, package)` pairs that are both verified and
    /// active-trace. Structurally `<= verified_installs_u64`.
    pub active_users_u64: u64,
    /// Receipts dropped because they repeated an identical replay key.
    pub rejected_duplicate_u64: u64,
    /// Receipts dropped because they were in a revoked state.
    pub rejected_revoked_u64: u64,
    /// Verified-install-state receipts dropped because their eval hash was
    /// all-zero (no eval evidence).
    pub rejected_forged_eval_u64: u64,
    /// Verified-install-state receipts dropped because their `(installer,
    /// package)` pair was already counted or was revoked (install/reinstall
    /// loop).
    pub rejected_same_package_loop_u64: u64,
}

impl AntiGamedCounters {
    /// Total receipts rejected across every gaming class.
    #[must_use]
    pub const fn rejected_total_u64(&self) -> u64 {
        self.rejected_duplicate_u64
            .saturating_add(self.rejected_revoked_u64)
            .saturating_add(self.rejected_forged_eval_u64)
            .saturating_add(self.rejected_same_package_loop_u64)
    }
}

/// The installer identity a receipt is attributed to: the Stage-B trace id
/// folded into the receipt's [`mnemos_a_core::StageDTraceLink`]. Two receipts
/// from the same install session/actor share this id even when their per-event
/// sandbox-event ids (and therefore replay keys) differ.
#[must_use]
fn installer_id(receipt: &VerifiedInstallReceipt) -> u64 {
    receipt.trace.stage_c_trace().stage_b_trace().trace_id_u64
}

/// Compute the anti-gamed strong signal from a raw receipt stream.
///
/// Order-independent and panic-free. The download count reuses the base
/// [`fold_counters`]; the verified / active counts apply the gaming gates
/// described on [`AntiGamedCounters`].
#[must_use]
pub fn anti_gamed_counters(receipts: &[VerifiedInstallReceipt]) -> AntiGamedCounters {
    let base = fold_counters(receipts);

    // Pass 0: deduplicate by replay key. BTreeMap keeps a deterministic
    // (sorted-key) iteration order independent of input order.
    let mut unique: BTreeMap<[u8; 32], VerifiedInstallReceipt> = BTreeMap::new();
    for r in receipts {
        unique.entry(r.replay_key()).or_insert(*r);
    }
    let rejected_duplicate_u64 = (receipts.len() as u64).saturating_sub(unique.len() as u64);

    // Pass 1: any (installer, package) pair that was ever revoked is poisoned.
    let mut revoked_pairs: BTreeSet<(u64, [u8; 32])> = BTreeSet::new();
    for r in unique.values() {
        if r.state.is_revoked() {
            revoked_pairs.insert((installer_id(r), *r.package.as_bytes()));
        }
    }

    // Pass 2: count verified installs once per non-revoked pair with valid eval
    // evidence; mark active pairs.
    let mut verified_pairs: BTreeSet<(u64, [u8; 32])> = BTreeSet::new();
    let mut active_pairs: BTreeSet<(u64, [u8; 32])> = BTreeSet::new();
    let mut rejected_revoked_u64: u64 = 0;
    let mut rejected_forged_eval_u64: u64 = 0;
    let mut rejected_same_package_loop_u64: u64 = 0;

    for r in unique.values() {
        if r.state.is_revoked() {
            rejected_revoked_u64 = rejected_revoked_u64.saturating_add(1);
            continue;
        }
        if !r.state.is_verified_install() {
            // Bare download — a weak signal only, already in `downloads_u64`.
            continue;
        }
        if r.eval_hash_32 == [0u8; 32] {
            rejected_forged_eval_u64 = rejected_forged_eval_u64.saturating_add(1);
            continue;
        }
        let pair = (installer_id(r), *r.package.as_bytes());
        if revoked_pairs.contains(&pair) {
            // Revoked-then-reinstalled under the same identity — cannot relaunder.
            rejected_same_package_loop_u64 = rejected_same_package_loop_u64.saturating_add(1);
            continue;
        }
        if !verified_pairs.insert(pair) {
            // A later verified receipt for an already-counted pair adds no new
            // verified install (install/reinstall loop), but may still mark the
            // pair active below.
            rejected_same_package_loop_u64 = rejected_same_package_loop_u64.saturating_add(1);
        }
        if r.state.is_active() {
            active_pairs.insert(pair);
        }
    }

    let verified_installs_u64 = verified_pairs.len() as u64;
    // active_pairs ⊆ verified_pairs by construction; the explicit cap documents
    // the structural "active <= verified" threshold.
    let active_users_u64 = (active_pairs.len() as u64).min(verified_installs_u64);

    AntiGamedCounters {
        downloads_u64: base.downloads_u64,
        verified_installs_u64,
        active_users_u64,
        rejected_duplicate_u64,
        rejected_revoked_u64,
        rejected_forged_eval_u64,
        rejected_same_package_loop_u64,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::catalog_counters::VerifiedInstallState;
    use crate::manifest::SkillId;
    use crate::package::SkillPackageDigest32;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink, StageDTraceLink};

    fn trace(installer: u64, event: u16) -> StageDTraceLink {
        StageDTraceLink::new(
            StageCTraceLink::new(StageBTraceLink::new(installer, 307, 1), 307, 142),
            307,
            event,
        )
    }

    fn receipt(
        installer: u64,
        pkg: u8,
        state: VerifiedInstallState,
        eval: u8,
        event: u16,
    ) -> VerifiedInstallReceipt {
        VerifiedInstallReceipt::new(
            SkillId(u16::from(pkg)),
            SkillPackageDigest32::new([pkg; 32]),
            state,
            [eval; 32],
            trace(installer, event),
        )
    }

    #[test]
    fn duplicate_identity() {
        let r = receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 0x7E, 1);
        // Three byte-identical receipts (same replay key) collapse to one.
        let c = anti_gamed_counters(&[r, r, r]);
        assert_eq!(c.verified_installs_u64, 1);
        assert_eq!(c.downloads_u64, 1);
        assert_eq!(c.rejected_duplicate_u64, 2);
    }

    #[test]
    fn same_package_loop() {
        // One installer installs the same package three times (distinct events)
        // -> one verified install, two loop rejections.
        let rs = [
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 0x7E, 1),
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 0x7E, 2),
            receipt(1, 0xA0, VerifiedInstallState::ActiveTrace, 0x7E, 3),
        ];
        let c = anti_gamed_counters(&rs);
        assert_eq!(c.verified_installs_u64, 1);
        // The active-trace receipt still marks the pair active even though it is
        // a loop for the verified count.
        assert_eq!(c.active_users_u64, 1);
        assert!(c.rejected_same_package_loop_u64 >= 1);
    }

    #[test]
    fn failed_eval() {
        // EvalPassed with an all-zero eval hash is forged -> rejected.
        let c = anti_gamed_counters(&[receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 0x00, 1)]);
        assert_eq!(c.verified_installs_u64, 0);
        assert_eq!(c.rejected_forged_eval_u64, 1);
        // The bare download signal is unaffected.
        assert_eq!(c.downloads_u64, 1);
    }

    #[test]
    fn revoked_install() {
        // A verified install for a pair that is also revoked is excluded.
        let rs = [
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 0x7E, 1),
            receipt(1, 0xA0, VerifiedInstallState::Revoked, 0x00, 2),
        ];
        let c = anti_gamed_counters(&rs);
        assert_eq!(c.verified_installs_u64, 0);
        assert_eq!(c.rejected_revoked_u64, 1);
        assert!(c.rejected_same_package_loop_u64 >= 1);
        // Two unique downloads still count (weak signal).
        assert_eq!(c.downloads_u64, 2);
    }

    #[test]
    fn active_trace_threshold() {
        // Two installers active-trace the same package; one forged active.
        let rs = [
            receipt(1, 0xA0, VerifiedInstallState::ActiveTrace, 0x7E, 1),
            receipt(1, 0xA0, VerifiedInstallState::ActiveTrace, 0x7E, 2),
            receipt(2, 0xA0, VerifiedInstallState::ActiveTrace, 0x7E, 3),
            receipt(3, 0xA0, VerifiedInstallState::ActiveTrace, 0x00, 4),
        ];
        let c = anti_gamed_counters(&rs);
        // installers 1 and 2 are genuine verified+active; installer 3 is forged.
        assert_eq!(c.verified_installs_u64, 2);
        assert_eq!(c.active_users_u64, 2);
        assert!(c.active_users_u64 <= c.verified_installs_u64);
        assert_eq!(c.rejected_forged_eval_u64, 1);
    }

    #[test]
    fn order_independent() {
        let forward = [
            receipt(1, 0xA0, VerifiedInstallState::EvalPassed, 0x7E, 1),
            receipt(2, 0xA0, VerifiedInstallState::ActiveTrace, 0x7E, 2),
            receipt(1, 0xA0, VerifiedInstallState::Revoked, 0x00, 3),
            receipt(3, 0xB0, VerifiedInstallState::Downloaded, 0x00, 4),
        ];
        let mut reversed = forward;
        reversed.reverse();
        assert_eq!(
            anti_gamed_counters(&forward),
            anti_gamed_counters(&reversed)
        );
    }
}
