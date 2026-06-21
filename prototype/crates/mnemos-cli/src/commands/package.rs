//! `sinabro package publish|upgrade|gate` — package publish/upgrade gate
//! (F-WP-06A, atom #452 · F.6.1 package publish/upgrade/gate).
//!
//! A read-only projection of the mainnet publish/upgrade gate. Publish and
//! upgrade are **dry-run by default**: the view renders the Move
//! build/test/prover/gas-cap verdicts, the multisig roster requirement, and the
//! timelock policy, plus the package-lock evidence binding — without ever
//! executing a publish. Two structural invariants live here:
//!
//! * **Default dry-run, never a silent publish.** [`PackageGateView::is_dry_run`]
//!   is the invariant `true` in Stage F: the execution posture defaults to
//!   [`MainnetExecutionState::DryRunOnly`] and only `Executed` is executable,
//!   which Stage F never reaches.
//! * **No false-green gate.** [`PackageGateView::gate_truth`] is the worst-axis
//!   of the four Move verdicts: any [`RenderTruth::Red`] makes the gate Red, an
//!   unmeasured ([`RenderTruth::Unknown`]) verdict is never Green, and only an
//!   all-green gate passes. A real publish would additionally require the
//!   multisig approval the canonical mapping surfaces.
//!
//! Reuse (no reinvention): the package-lock evidence (bytecode / prover / gas
//! baseline digests) is the Stage C [`MainnetPackageLock`]; the multisig
//! roster and timelock policy are the canonical [`MultisigRoster`] /
//! [`TimelockPolicy`]; the execution posture is
//! [`mnemos_a_core::MainnetExecutionState`]; the per-line verdict and the gate
//! verdict are the cockpit [`crate::tui::RenderTruth`]; the approval gate is the
//! canonical [`approval_for`]`(`[`CommandRisk::ChainWrite`]`)` =
//! [`ApprovalRequirement::Multisig`]. This module mints no new gate type.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::hex32;
use crate::tui::RenderTruth;
use mnemos_a_core::MainnetExecutionState;
use mnemos_d_move::stage_c_package_lock::MainnetPackageLock;
use mnemos_g_wallet::{MultisigRoster, TimelockPolicy};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The package operation a gate is previewing. A closed enum: there is no
/// "execute now" variant — both operations are dry-run in Stage F.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackageOp {
    /// First-time mainnet package publish.
    Publish = 1,
    /// Upgrade of an already-published mainnet package.
    Upgrade = 2,
}

impl PackageOp {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// A read-only view of a publish/upgrade gate. Carries the package-lock evidence
/// binding, the four Move gate verdicts, the multisig + timelock requirements,
/// and the (dry-run) execution posture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackageGateView {
    /// The operation being gated (publish or upgrade).
    pub op: PackageOp,
    /// The package-lock evidence: package id + bytecode / prover / gas-baseline
    /// digests that must agree before a mainnet publish is trustworthy.
    pub lock: MainnetPackageLock,
    /// `sui move build` verdict.
    pub build: RenderTruth,
    /// `sui move test` verdict.
    pub test: RenderTruth,
    /// `sui-prover` verdict.
    pub prover: RenderTruth,
    /// Gas-cap (gas-baseline regression) verdict.
    pub gas_cap: RenderTruth,
    /// The multisig roster required to approve the publish.
    pub roster: MultisigRoster,
    /// The timelock policy the publish must wait out.
    pub timelock: TimelockPolicy,
    /// The mainnet execution posture (dry-run by default in Stage F).
    pub execution_state: MainnetExecutionState,
}

impl PackageGateView {
    /// Build a dry-run gate preview. The execution posture is
    /// [`MainnetExecutionState::DryRunOnly`] — there is no constructor that puts
    /// the gate in an executable state, so a publish preview can never execute.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn preview(
        op: PackageOp,
        lock: MainnetPackageLock,
        build: RenderTruth,
        test: RenderTruth,
        prover: RenderTruth,
        gas_cap: RenderTruth,
        roster: MultisigRoster,
        timelock: TimelockPolicy,
    ) -> Self {
        Self {
            op,
            lock,
            build,
            test,
            prover,
            gas_cap,
            roster,
            timelock,
            execution_state: MainnetExecutionState::DryRunOnly,
        }
    }

    /// Whether the gate is in dry-run (no execution). Always `true` in Stage F:
    /// only [`MainnetExecutionState::Executed`] is executable, and Stage F never
    /// reaches it.
    #[must_use]
    pub const fn is_dry_run(&self) -> bool {
        !self.execution_state.is_executable()
    }

    /// The worst-axis verdict of the four Move gate checks. Any `Red` makes the
    /// gate `Red`; an unmeasured (`Unknown`) verdict is never `Green`; a `Yellow`
    /// degrades a clean gate to `Yellow`; only all-`Green` is `Green`.
    #[must_use]
    pub fn gate_truth(&self) -> RenderTruth {
        let verdicts = [self.build, self.test, self.prover, self.gas_cap];
        if verdicts.contains(&RenderTruth::Red) {
            return RenderTruth::Red;
        }
        if verdicts.contains(&RenderTruth::Unknown) {
            return RenderTruth::Unknown;
        }
        if verdicts.contains(&RenderTruth::Yellow) {
            return RenderTruth::Yellow;
        }
        RenderTruth::Green
    }

    /// Whether the Move gate passes (all four verdicts green). A passing gate
    /// still does not execute in Stage F — a real publish would require the
    /// multisig approval gate.
    #[must_use]
    pub fn gate_passes(&self) -> bool {
        matches!(self.gate_truth(), RenderTruth::Green)
    }

    /// The approval gate a real publish/upgrade requires. Always
    /// [`ApprovalRequirement::Multisig`], via the canonical
    /// [`approval_for`]`(`[`CommandRisk::ChainWrite`]`)` mapping.
    #[must_use]
    pub fn approval(&self) -> ApprovalRequirement {
        approval_for(CommandRisk::ChainWrite)
    }

    /// Whether the publish/upgrade requires multisig approval. Always `true`.
    #[must_use]
    pub fn requires_multisig(&self) -> bool {
        matches!(self.approval(), ApprovalRequirement::Multisig)
    }

    /// Redacted, colorless gate lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("op_u8={}", self.op.tag()),
            format!("package={}", redact16(self.lock.package.as_bytes())),
            format!("bytecode={}", redact16(&self.lock.bytecode_hash_32)),
            format!("prover_hash={}", redact16(&self.lock.prover_hash_32)),
            format!("gas_baseline={}", redact16(&self.lock.gas_baseline_hash_32)),
            format!("build_u8={}", self.build as u8),
            format!("test_u8={}", self.test as u8),
            format!("prover_u8={}", self.prover as u8),
            format!("gas_cap_u8={}", self.gas_cap as u8),
            format!("gate_truth_u8={}", self.gate_truth() as u8),
            format!("gate_passes={}", self.gate_passes()),
            format!("multisig_threshold={}", self.roster.threshold_u8),
            format!("multisig_signers={}", self.roster.signer_count_u8),
            format!(
                "timelock_min_delay_secs={}",
                self.timelock.min_delay_secs_u32
            ),
            format!(
                "timelock_cancel_window_secs={}",
                self.timelock.cancel_window_secs_u32
            ),
            format!(
                "timelock_emergency_pause={}",
                self.timelock.emergency_pause_enabled
            ),
            format!("execution_state_u8={}", self.execution_state.as_u8()),
            format!("is_dry_run={}", self.is_dry_run()),
            format!("approval_u8={}", self.approval() as u8),
            format!("requires_multisig={}", self.requires_multisig()),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::repl::latency::p95_ms;
    use mnemos_d_move::{ObjectId, SuiAddress};

    fn lock() -> MainnetPackageLock {
        MainnetPackageLock::new(
            ObjectId::new([0x22; 32]),
            [0xAB; 32],
            [0xCD; 32],
            [0xEF; 32],
        )
        .expect("lock builds from non-zero hashes")
    }

    fn roster() -> MultisigRoster {
        MultisigRoster::from_signers(
            &[
                SuiAddress::new([1; 32]),
                SuiAddress::new([2; 32]),
                SuiAddress::new([3; 32]),
            ],
            2,
        )
        .expect("2-of-3 roster builds")
    }

    fn timelock() -> TimelockPolicy {
        TimelockPolicy::from_parts(86_400, 3_600, true).expect("timelock builds")
    }

    fn gate(
        build: RenderTruth,
        test: RenderTruth,
        prover: RenderTruth,
        gas_cap: RenderTruth,
    ) -> PackageGateView {
        PackageGateView::preview(
            PackageOp::Publish,
            lock(),
            build,
            test,
            prover,
            gas_cap,
            roster(),
            timelock(),
        )
    }

    fn all_green() -> PackageGateView {
        gate(
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Green,
        )
    }

    #[test]
    fn publish_and_upgrade_default_dry_run() {
        let publish = all_green();
        assert_eq!(publish.op, PackageOp::Publish);
        assert!(publish.is_dry_run(), "publish defaults to dry-run");
        let upgrade = PackageGateView::preview(
            PackageOp::Upgrade,
            lock(),
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Green,
            roster(),
            timelock(),
        );
        assert_eq!(upgrade.op, PackageOp::Upgrade);
        // Even a fully-green gate is still dry-run in Stage F (never executes).
        assert!(upgrade.is_dry_run());
        assert!(upgrade.gate_passes());
    }

    #[test]
    fn build_fail_makes_gate_red() {
        let g = gate(
            RenderTruth::Red,
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Green,
        );
        assert_eq!(g.gate_truth(), RenderTruth::Red);
        assert!(!g.gate_passes());
    }

    #[test]
    fn prover_fail_makes_gate_red() {
        let g = gate(
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Red,
            RenderTruth::Green,
        );
        assert_eq!(g.gate_truth(), RenderTruth::Red);
        assert!(!g.gate_passes());
    }

    #[test]
    fn gas_cap_fail_makes_gate_red() {
        let g = gate(
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Red,
        );
        assert_eq!(g.gate_truth(), RenderTruth::Red);
        assert!(!g.gate_passes());
    }

    #[test]
    fn unmeasured_prover_is_never_green() {
        let g = gate(
            RenderTruth::Green,
            RenderTruth::Green,
            RenderTruth::Unknown,
            RenderTruth::Green,
        );
        assert_eq!(g.gate_truth(), RenderTruth::Unknown);
        assert!(!g.gate_passes(), "an unmeasured prover gate is never green");
    }

    #[test]
    fn approval_required_is_multisig() {
        let g = all_green();
        assert_eq!(g.approval(), ApprovalRequirement::Multisig);
        assert!(g.requires_multisig());
    }

    #[test]
    fn render_redacts_hashes_and_is_bounded() {
        let g = all_green();
        // The full 64-hex digest never appears in the render.
        assert!(!g.render(64).iter().any(|l| l.contains(&hex32(&[0xAB; 32]))));
        assert!(g.render(3).len() <= 3);
    }

    #[test]
    fn package_gate_p95_within_100ms() {
        let g = all_green();
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = g.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 100, "package gate p95 {p95}ms exceeds 100ms budget");
    }
}
