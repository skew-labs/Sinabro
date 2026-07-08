//! Try-before-use dry-run surface.
//!
//! ## Surface
//!
//! - [`TryBeforeUseFixture`] — the declarative fixture envelope a dry-run
//!   may consume. Only a bundled [`FixtureSource::Sample`] or a user-approved
//!   [`FixtureSource::RedactedWorkspaceSlice`] (with a non-zero redaction token)
//!   is eligible; a [`FixtureSource::RawWorkspace`] slice is never eligible. The
//!   fixture is in-memory only — a dry-run performs **no persistence, no
//!   network, no wallet, no chain write, and no local state mutation**.
//! - [`TryBeforeUseRun`] — the dry-run result: skill, package digest,
//!   module id, fixture hash, decision, and trace link. It **cannot create
//!   install state** ([`TryBeforeUseRun::creates_install_state`] is always
//!   `false`), and its [`TryBeforeUseRun::trial_digest`] is deterministic, so a
//!   repeated run over the same inputs yields the same digest.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use mnemos_a_core::StageDTraceLink;

use crate::manifest::SkillId;
use crate::package::{SkillPackageDigest32, blake2b_256};
use crate::wasm_tier2::WasmSandboxDecision;
use crate::wasm_tier2::determinism::DeterministicContext;
use crate::wasm_tier2::module_id::WasmTier2ModuleId;

/// Domain tag for the try-before-use trial digest.
pub(crate) const DOMAIN_TRY: &[u8] = b"mnemos.d.try_before_use.v1";

/// The provenance of a dry-run fixture input.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FixtureSource {
    /// A bundled sample input — always eligible for a dry-run.
    Sample,
    /// A user-approved redacted workspace slice — eligible only when the
    /// redaction token is non-zero (i.e. the user approved the redaction).
    RedactedWorkspaceSlice,
    /// A raw, un-redacted real-workspace slice — never eligible.
    RawWorkspace,
}

/// Declarative fixture envelope for a dry-run. In-memory only; using it
/// mutates no local state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TryBeforeUseFixture {
    /// Content hash of the fixture input.
    pub fixture_hash_32: [u8; 32],
    /// Where the fixture came from.
    pub source: FixtureSource,
    /// Non-zero iff the user approved a redaction of a workspace slice.
    pub redaction_token_32: [u8; 32],
}

impl TryBeforeUseFixture {
    /// Whether this fixture may be used for a dry-run: a [`FixtureSource::Sample`]
    /// always; a [`FixtureSource::RedactedWorkspaceSlice`] only with a non-zero
    /// redaction token; a [`FixtureSource::RawWorkspace`] never.
    #[inline]
    #[must_use]
    pub fn is_eligible(&self) -> bool {
        match self.source {
            FixtureSource::Sample => true,
            FixtureSource::RedactedWorkspaceSlice => self.redaction_token_32 != [0u8; 32],
            FixtureSource::RawWorkspace => false,
        }
    }
}

/// Dry-run result. Records what was trialed and the decision/trace; it can
/// never create install state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TryBeforeUseRun {
    /// The skill that was trialed.
    pub skill: SkillId,
    /// The package digest that was trialed.
    pub package: SkillPackageDigest32,
    /// The module id that was trialed.
    pub module: WasmTier2ModuleId,
    /// The fixture hash the trial consumed.
    pub fixture_hash_32: [u8; 32],
    /// The sandbox decision for the trial.
    pub decision: WasmSandboxDecision,
    /// The trace stamp for the trial outcome.
    pub trace: StageDTraceLink,
}

impl TryBeforeUseRun {
    /// A try-before-use run **never** creates install state — a trial cannot
    /// promote itself to an install. Always `false`.
    #[inline]
    #[must_use]
    pub const fn creates_install_state(&self) -> bool {
        false
    }

    /// Deterministic trial digest over `(skill, package, module, fixture,
    /// decision, replay)`. The `ctx` supplies a replayable digest of the
    /// fixture so a repeated run over identical inputs yields the same value.
    #[must_use]
    pub fn trial_digest(&self, ctx: &DeterministicContext) -> [u8; 32] {
        let replay = ctx.replay_digest(&self.fixture_hash_32);
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&self.skill.0.to_le_bytes());
        buf.extend_from_slice(self.package.as_bytes());
        buf.extend_from_slice(self.module.bytes());
        buf.extend_from_slice(&self.fixture_hash_32);
        buf.push(self.decision.discriminant());
        buf.extend_from_slice(&replay);
        blake2b_256(&[DOMAIN_TRY, &buf])
    }
}

/// Run a try-before-use trial. A pure function — it mutates no local state,
/// performs no I/O, and only an *eligible* fixture (sample or approved-redacted
/// slice) reaches [`WasmSandboxDecision::Allow`]; an ineligible fixture (a raw
/// workspace slice, or a redacted slice without an approval token) denies.
#[must_use]
pub fn run_try_before_use(
    skill: SkillId,
    package: SkillPackageDigest32,
    module: WasmTier2ModuleId,
    fixture: &TryBeforeUseFixture,
    trace: StageDTraceLink,
) -> TryBeforeUseRun {
    let decision = if fixture.is_eligible() {
        WasmSandboxDecision::Allow
    } else {
        WasmSandboxDecision::Deny
    };
    TryBeforeUseRun {
        skill,
        package,
        module,
        fixture_hash_32: fixture.fixture_hash_32,
        decision,
        trace,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mnemos_a_core::{StageBTraceLink, StageCTraceLink};

    fn link() -> StageDTraceLink {
        let b = StageBTraceLink::new(0xD267_0001, 267, 0);
        let c = StageCTraceLink::new(b, 240, 9);
        StageDTraceLink::new(c, 267, 1)
    }

    fn fixture(source: FixtureSource, token: [u8; 32]) -> TryBeforeUseFixture {
        TryBeforeUseFixture {
            fixture_hash_32: [0x11; 32],
            source,
            redaction_token_32: token,
        }
    }

    fn run(f: &TryBeforeUseFixture) -> TryBeforeUseRun {
        run_try_before_use(
            SkillId(5),
            SkillPackageDigest32::new([0x22; 32]),
            WasmTier2ModuleId::from_bytes([0x33; 32]),
            f,
            link(),
        )
    }

    #[test]
    fn sample_fixture_accepted() {
        let r = run(&fixture(FixtureSource::Sample, [0u8; 32]));
        assert_eq!(r.decision, WasmSandboxDecision::Allow);
    }

    #[test]
    fn raw_workspace_denied() {
        let r = run(&fixture(FixtureSource::RawWorkspace, [0xFF; 32]));
        assert_eq!(r.decision, WasmSandboxDecision::Deny);
    }

    #[test]
    fn redacted_slice_requires_approval_token() {
        // Without a token: denied.
        let r0 = run(&fixture(FixtureSource::RedactedWorkspaceSlice, [0u8; 32]));
        assert_eq!(r0.decision, WasmSandboxDecision::Deny);
        // With a non-zero token: accepted.
        let r1 = run(&fixture(FixtureSource::RedactedWorkspaceSlice, [0xAB; 32]));
        assert_eq!(r1.decision, WasmSandboxDecision::Allow);
    }

    #[test]
    fn repeated_run_same_trial_digest() {
        let ctx = DeterministicContext::new(0xD267_0042, 1_000);
        let f = fixture(FixtureSource::Sample, [0u8; 32]);
        assert_eq!(run(&f).trial_digest(&ctx), run(&f).trial_digest(&ctx));
    }

    #[test]
    fn run_never_creates_install_state() {
        assert!(!run(&fixture(FixtureSource::Sample, [0u8; 32])).creates_install_state());
    }
}
