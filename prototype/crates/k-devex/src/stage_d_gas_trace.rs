//! atom #294 · D.2.18 — Stage D skill-registry / install gas trace + Gas Station
//! allowlist extension.
//!
//! This module EXTENDS the Stage C Gas Station to the eight bounded
//! skill-registry / install Move entries (the [`SkillPtbAction`] set built at
//! atom #290). It mints NO new canonical type and NO new sponsorable function:
//! the action identity is the e-skill [`SkillPtbAction`], the policy is the C
//! [`GasStationPolicy`], the verdict is the C [`GasStationDecision`], and the
//! per-action regression ladder reuses the C [`GasRegressionDecision`]. The only
//! Stage D surfaces are the per-action baseline ([`SkillGasBaseline`]) and the
//! append-only evidence line — both k-devex evidence tooling, parallel to the
//! Stage C [`build_gas_trace_line`](crate::stage_c_gas_jsonl::build_gas_trace_line).
//!
//! # No commerce
//!
//! Sponsorship covers only bounded registry / install-receipt writes after a
//! dry-run effect-shape check. It never pays a skill price, never unlocks paid
//! access, and never signs an arbitrary publish / upgrade. There is no price,
//! payment, checkout, refund, royalty, or revenue field anywhere in the record;
//! skill payment and gas sponsorship share no ledger, provider, or state. The
//! action set is the closed [`SkillPtbAction`] enum — an arbitrary transfer or
//! opaque call is unrepresentable, and a wildcard policy is rejected.
//!
//! # Dependency note (deliberate Stage D edge addition)
//!
//! Stage C deliberately kept k-devex WITHOUT a `k-devex -> g-wallet` edge by
//! consuming the single sponsor decision (#218) as a `bool` and binding it in
//! `o-stage-c-e2e` (see the comments in `lib.rs`). Atom #294 is different: a
//! TYPED eight-action allowlist evaluator over [`GasStationPolicy`] is not
//! bool-reducible, so this module takes a direct, ACYCLIC `k-devex -> g-wallet`
//! and `k-devex -> e-skill` edge (neither crate, nor its dependency closure,
//! depends on k-devex). The reuse is types only — no signing, no wallet, no
//! secret, no network, no chain action. Offline / read-only / status-only;
//! mainnet locked.

use core::fmt::Write;

use mnemos_a_core::RedactedLogValue;
use mnemos_a_core::trace::StageCTraceLink;
use mnemos_d_move::stage_c_effect_delta::EffectDelta;
use mnemos_d_move::stage_c_gas_baseline::GasRegressionDecision;
use mnemos_d_move::types::{GasBudgetMist, ObjectId};
use mnemos_e_skill::ptb::SkillPtbAction;
use mnemos_g_wallet::stage_c_gas_effect::GasStationDecision;
use mnemos_g_wallet::stage_c_gas_policy::{
    GasStationPolicy, GasStationRejectReason, OfficialTrustDecision, SafetyKernelAttestation,
};

/// The append-only schema id stamped on every Stage D skill-gas-trace record.
pub const STAGE_D_SKILL_GAS_TRACE_SCHEMA: &str = "mnemos.stage_d.skill_gas_trace.v1";

/// The number of bounded skill-registry / install actions (the full
/// [`SkillPtbAction`] set: publish / fork / update / record / enable / disable /
/// remove / revoke).
pub const SKILL_GAS_ACTION_COUNT: usize = 8;

/// The complete allowlist of JSON keys a skill-gas-trace record may contain.
/// A future JSON Schema pins `additionalProperties: false` to the same set; the
/// builder test asserts emitted-keys == this set (no unknown, no dropped).
pub const STAGE_D_SKILL_GAS_TRACE_KEYS: &[&str] = &[
    "schema",
    "event",
    "action_u8",
    "move_module",
    "move_function",
    "package_hex",
    "gas_budget_mist",
    "object_writes",
    "event_count",
    "event_bytes",
    "net_storage_mist",
    "baseline_max_mist",
    "regression_u8",
    "sponsor_accepted",
    "reject_u8",
    "trust_u8",
    "trace_id_u64",
    "atom_id_u16",
    "attempt_u8",
    "stage_c_atom_u16",
    "gate_id_u16",
    "note_class",
];

/// Lower-case hex of a 32-byte package id (64 chars, no `0x` prefix). A local
/// copy of the Stage C `stage_c_gas_jsonl` helper kept private to this module so
/// the green Stage C surface keeps its current (private) API.
fn hex32(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// The `#[repr(u8)]` discriminant of a [`GasRegressionDecision`]
/// (`Green=1`/`Warn=2`/`Red=3`), for the evidence record. The enum is fieldless
/// `#[repr(u8)]`, so the cast is its byte tag.
#[inline]
const fn regression_u8(decision: GasRegressionDecision) -> u8 {
    decision as u8
}

/// Per-package skill-action gas baseline: the maximum accepted gross spend (MIST)
/// for each of the eight [`SkillPtbAction`] entries, plus the number of samples
/// that produced it. Keyed by the action discriminant (`1..=8` → index `0..=7`).
///
/// This is the Stage D analogue of the Stage C
/// [`GasTraceBaseline`](mnemos_d_move::stage_c_gas_baseline::GasTraceBaseline),
/// which has only `add_chunk` / `audit` slots and cannot key a skill action.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SkillGasBaseline {
    /// The skill-registry package the baseline was measured against.
    pub package: ObjectId,
    /// Maximum accepted gross spend per action, indexed by
    /// `SkillPtbAction::as_u8() - 1`.
    pub per_action_max: [GasBudgetMist; SKILL_GAS_ACTION_COUNT],
    /// Number of samples that established the baseline.
    pub samples_u32: u32,
}

impl SkillGasBaseline {
    /// The maximum accepted gross spend for `action`. The closed enum guarantees
    /// a `1..=8` discriminant, so the index is always in bounds; a defensive
    /// `get` keeps this total (returns a zero budget for an impossible index).
    #[inline]
    #[must_use]
    pub fn max_for(&self, action: SkillPtbAction) -> GasBudgetMist {
        let idx = action.as_u8().saturating_sub(1) as usize;
        self.per_action_max
            .get(idx)
            .copied()
            .unwrap_or_else(|| GasBudgetMist::new(0))
    }

    /// Classify a measured gross spend for `action` against this baseline and an
    /// absolute hard cap, reusing the C [`GasRegressionDecision`] ladder:
    /// strictly above the hard cap → [`Red`](GasRegressionDecision::Red); else
    /// strictly above the baseline max → [`Warn`](GasRegressionDecision::Warn);
    /// else → [`Green`](GasRegressionDecision::Green). Saturating, never panics.
    #[inline]
    #[must_use]
    pub fn classify(
        &self,
        action: SkillPtbAction,
        gross_spent_mist: u64,
        hard_cap_mist: u64,
    ) -> GasRegressionDecision {
        let base = self.max_for(action).get();
        if gross_spent_mist > hard_cap_mist {
            GasRegressionDecision::Red
        } else if gross_spent_mist > base {
            GasRegressionDecision::Warn
        } else {
            GasRegressionDecision::Green
        }
    }
}

/// A sponsorship request for one bounded skill-registry / install action. Bundles
/// every input the evaluator needs so the call site stays a single typed
/// boundary. Carries no signing material, no wallet, no secret, no payment field.
#[derive(Clone, Copy, Debug)]
pub struct SkillSponsorshipRequest {
    /// The bounded action being sponsored (closed enum — arbitrary transfer is
    /// unrepresentable).
    pub action: SkillPtbAction,
    /// The skill-registry package object id the request presents.
    pub presented_package: ObjectId,
    /// The dry-run effect shape (object writes / events / storage) observed for
    /// this action (atom #290 `SkillPtbDryRun`).
    pub effect: EffectDelta,
    /// The requested per-tx gas budget.
    pub requested_gas: GasBudgetMist,
    /// The number of sponsored txs already spent this epoch (quota accounting).
    pub txs_this_epoch_u32: u32,
    /// The observed storage-byte footprint of this write (storage-bomb cap).
    pub storage_bytes_u32: u32,
    /// The safety-kernel attestation, if any (hosted-trust evaluation).
    pub attestation: Option<SafetyKernelAttestation>,
    /// The current epoch, for attestation-expiry checks.
    pub now_epoch_u64: u64,
}

/// Evaluate whether the Gas Station may sponsor one bounded skill action, reusing
/// the C [`GasStationPolicy`] checks and returning the C [`GasStationDecision`].
/// This never signs and never mutates anything.
///
/// Ordered checks (all before any signer boundary a caller might later cross):
/// 1. trust verdict (recorded even on reject);
/// 2. wildcard / reserved-bit allowlist → [`Wildcard`](GasStationRejectReason::Wildcard);
/// 3. package binding (a foreign package = an arbitrary transfer) →
///    [`PackageFunction`](GasStationRejectReason::PackageFunction);
/// 4. bounded effect shape (a registry / install write makes ≥1 object write and
///    ≥1 event) → [`EffectShape`](GasStationRejectReason::EffectShape);
/// 5. per-tx gas cap → [`Budget`](GasStationRejectReason::Budget);
/// 6. storage-byte cap (storage bomb) → [`Budget`](GasStationRejectReason::Budget);
/// 7. per-epoch tx quota → [`QuotaRisk`](GasStationRejectReason::QuotaRisk).
#[must_use]
pub fn evaluate_skill_sponsorship(
    policy: &GasStationPolicy,
    req: &SkillSponsorshipRequest,
    trace: StageCTraceLink,
) -> GasStationDecision {
    let trust = policy.evaluate_trust(req.attestation.as_ref(), req.now_epoch_u64);

    if let Err(reason) = policy.reject_if_wildcard() {
        return reject(reason, trust, trace);
    }
    if let Err(reason) = policy.check_package(req.presented_package) {
        return reject(reason, trust, trace);
    }
    if req.effect.object_writes_u16 == 0 || req.effect.event_count_u16 == 0 {
        return reject(GasStationRejectReason::EffectShape, trust, trace);
    }
    if let Err(reason) = policy.check_gas_budget(req.requested_gas) {
        return reject(reason, trust, trace);
    }
    if req.storage_bytes_u32 > policy.max_storage_bytes_u32 {
        return reject(GasStationRejectReason::Budget, trust, trace);
    }
    if req.txs_this_epoch_u32 >= policy.max_txs_per_epoch_u32 {
        return reject(GasStationRejectReason::QuotaRisk, trust, trace);
    }

    GasStationDecision {
        accepted: true,
        reject: None,
        trust,
        trace,
    }
}

/// Build a rejected [`GasStationDecision`] (the g-wallet inherent constructor is
/// private to its module, so this module composes the public struct literal).
#[inline]
fn reject(
    reason: GasStationRejectReason,
    trust: OfficialTrustDecision,
    trace: StageCTraceLink,
) -> GasStationDecision {
    GasStationDecision {
        accepted: false,
        reject: Some(reason),
        trust,
        trace,
    }
}

/// One per-action skill-gas evidence row: the action, the presented package, the
/// requested gas, the dry-run effect shape, the captured baseline maximum, the
/// regression verdict, and the sponsorship decision. Pure data; carries no
/// secret and no payment field.
#[derive(Clone, Copy, Debug)]
pub struct SkillGasTraceRecord {
    /// The bounded action measured.
    pub action: SkillPtbAction,
    /// The skill-registry package the call targeted.
    pub package: ObjectId,
    /// The requested per-tx gas budget.
    pub requested_gas: GasBudgetMist,
    /// The dry-run object / event / storage effect shape.
    pub effect: EffectDelta,
    /// The captured per-action baseline maximum gross spend.
    pub baseline_max: GasBudgetMist,
    /// The regression verdict for this sample against the baseline.
    pub regression: GasRegressionDecision,
    /// The Gas Station sponsorship decision (carries the trust verdict and the
    /// trace stamp).
    pub decision: GasStationDecision,
}

/// Build one append-only skill-gas-trace JSONL line from a record and a redacted
/// note. Every key is in [`STAGE_D_SKILL_GAS_TRACE_KEYS`]; the `note` contributes
/// only its redaction class label (`note_class`), never a raw value. There is no
/// price / payment / checkout / refund / royalty / revenue field.
#[must_use]
pub fn build_skill_gas_trace_line(record: &SkillGasTraceRecord, note: RedactedLogValue) -> String {
    let action = record.action;
    let effect = &record.effect;
    let decision = &record.decision;
    let reject_u8 = decision.reject.map_or(0, GasStationRejectReason::as_u8);
    let mut s = String::with_capacity(640);
    // `write!` into a String is infallible; mirror a-core logging by discarding
    // the formatter Result rather than unwrapping.
    let _ = write!(
        s,
        concat!(
            "{{\"schema\":\"{schema}\",\"event\":\"skill_gas_trace\",",
            "\"action_u8\":{action_u8},\"move_module\":\"{move_module}\",",
            "\"move_function\":\"{move_function}\",\"package_hex\":\"{package_hex}\",",
            "\"gas_budget_mist\":{gas_budget_mist},\"object_writes\":{object_writes},",
            "\"event_count\":{event_count},\"event_bytes\":{event_bytes},",
            "\"net_storage_mist\":{net_storage_mist},\"baseline_max_mist\":{baseline_max_mist},",
            "\"regression_u8\":{regression_u8},\"sponsor_accepted\":{sponsor_accepted},",
            "\"reject_u8\":{reject_u8},\"trust_u8\":{trust_u8},",
            "\"trace_id_u64\":{trace_id_u64},\"atom_id_u16\":{atom_id_u16},",
            "\"attempt_u8\":{attempt_u8},\"stage_c_atom_u16\":{stage_c_atom_u16},",
            "\"gate_id_u16\":{gate_id_u16},\"note_class\":\"{note_class}\"}}"
        ),
        schema = STAGE_D_SKILL_GAS_TRACE_SCHEMA,
        action_u8 = action.as_u8(),
        move_module = action.move_module(),
        move_function = action.move_function(),
        package_hex = hex32(record.package.as_bytes()),
        gas_budget_mist = record.requested_gas.get(),
        object_writes = effect.object_writes_u16,
        event_count = effect.event_count_u16,
        event_bytes = effect.event_bytes_u32,
        net_storage_mist = effect.net_storage_mist(),
        baseline_max_mist = record.baseline_max.get(),
        regression_u8 = regression_u8(record.regression),
        sponsor_accepted = decision.accepted,
        reject_u8 = reject_u8,
        trust_u8 = decision.trust.as_u8(),
        trace_id_u64 = decision.trace.trace.trace_id_u64,
        atom_id_u16 = decision.trace.trace.atom_id_u16,
        attempt_u8 = decision.trace.trace.attempt_u8,
        stage_c_atom_u16 = decision.trace.stage_c_atom_u16,
        gate_id_u16 = decision.trace.gate_id_u16,
        note_class = note.kind().class_label(),
    );
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use mnemos_a_core::trace::StageBTraceLink;
    use mnemos_a_core::{LogRedactionKind, redact_for_log};
    use mnemos_g_wallet::stage_c_gas_policy::{GasSponsorMode, GasStationPolicy};

    const PKG: [u8; 32] = [0x5A; 32];
    const FOREIGN: [u8; 32] = [0x6B; 32];

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA294, 294, 0), 294, 5)
    }

    fn policy() -> GasStationPolicy {
        GasStationPolicy {
            mode: GasSponsorMode::SelfHosted,
            package: ObjectId::new(PKG),
            max_gas_per_tx: GasBudgetMist::new(1_000_000),
            max_txs_per_epoch_u32: 100,
            max_storage_bytes_u32: 100_000,
            allowed_mask_u16: GasStationPolicy::INITIAL_ALLOWED_MASK,
            update_semantics_via_add_chunk: false,
            require_official_safety_kernel: false,
        }
    }

    fn bounded_effect() -> EffectDelta {
        EffectDelta::from_dev_inspect(true, 1, 1, 64, 20_000, 0).unwrap()
    }

    fn request(action: SkillPtbAction) -> SkillSponsorshipRequest {
        SkillSponsorshipRequest {
            action,
            presented_package: ObjectId::new(PKG),
            effect: bounded_effect(),
            requested_gas: GasBudgetMist::new(50_000),
            txs_this_epoch_u32: 0,
            storage_bytes_u32: 1_000,
            attestation: None,
            now_epoch_u64: 10,
        }
    }

    /// All eight bounded actions are sponsorable under an in-bounds request.
    #[test]
    fn all_eight_actions_sponsored() {
        let policy = policy();
        for action in SkillPtbAction::all() {
            let d = evaluate_skill_sponsorship(&policy, &request(action), trace());
            assert!(d.accepted, "action {} should be sponsored", action.as_u8());
            assert_eq!(d.reject, None);
        }
        assert_eq!(SkillPtbAction::all().len(), SKILL_GAS_ACTION_COUNT);
    }

    /// An arbitrary transfer is unrepresentable (the action enum is closed) and a
    /// foreign-package request is rejected with `PackageFunction`.
    #[test]
    fn arbitrary_transfer_unrepresentable_and_foreign_package_denied() {
        let policy = policy();
        let mut req = request(SkillPtbAction::Publish);
        req.presented_package = ObjectId::new(FOREIGN);
        let d = evaluate_skill_sponsorship(&policy, &req, trace());
        assert!(!d.accepted);
        assert_eq!(d.reject, Some(GasStationRejectReason::PackageFunction));
    }

    /// A storage-byte footprint over the cap is a storage bomb → `Budget`.
    #[test]
    fn storage_bomb_denied() {
        let policy = policy();
        let mut req = request(SkillPtbAction::RecordInstall);
        req.storage_bytes_u32 = policy.max_storage_bytes_u32 + 1;
        let d = evaluate_skill_sponsorship(&policy, &req, trace());
        assert!(!d.accepted);
        assert_eq!(d.reject, Some(GasStationRejectReason::Budget));
        // at the cap is accepted (cap parse).
        req.storage_bytes_u32 = policy.max_storage_bytes_u32;
        assert!(evaluate_skill_sponsorship(&policy, &req, trace()).accepted);
    }

    /// A per-epoch quota that is already full → `QuotaRisk`; one short is allowed.
    #[test]
    fn quota_denied() {
        let policy = policy();
        let mut req = request(SkillPtbAction::DisableInstall);
        req.txs_this_epoch_u32 = policy.max_txs_per_epoch_u32;
        let d = evaluate_skill_sponsorship(&policy, &req, trace());
        assert!(!d.accepted);
        assert_eq!(d.reject, Some(GasStationRejectReason::QuotaRisk));
        req.txs_this_epoch_u32 = policy.max_txs_per_epoch_u32 - 1;
        assert!(evaluate_skill_sponsorship(&policy, &req, trace()).accepted);
    }

    /// An over-budget gas request and a wildcard policy are rejected.
    #[test]
    fn budget_and_wildcard_denied() {
        let policy = policy();
        let mut req = request(SkillPtbAction::Fork);
        req.requested_gas = GasBudgetMist::new(9_999_999);
        assert_eq!(
            evaluate_skill_sponsorship(&policy, &req, trace()).reject,
            Some(GasStationRejectReason::Budget)
        );
        // A reserved/wildcard allowlist bit is denied before any action.
        let mut wild = policy;
        wild.allowed_mask_u16 = 0xFFFF;
        assert_eq!(
            evaluate_skill_sponsorship(&wild, &request(SkillPtbAction::Fork), trace()).reject,
            Some(GasStationRejectReason::Wildcard)
        );
    }

    /// A degenerate effect shape (no object write or no event) is rejected — a
    /// pure transfer smuggled in as a registry write does not match the shape.
    #[test]
    fn degenerate_effect_shape_denied() {
        let policy = policy();
        let mut req = request(SkillPtbAction::UpdateMetadata);
        req.effect = EffectDelta::from_dev_inspect(true, 0, 1, 0, 0, 0).unwrap();
        assert_eq!(
            evaluate_skill_sponsorship(&policy, &req, trace()).reject,
            Some(GasStationRejectReason::EffectShape)
        );
    }

    /// Each action captures a baseline maximum; the regression ladder is
    /// Green / Warn / Red against the baseline and an absolute hard cap.
    #[test]
    fn per_action_baseline_and_regression() {
        let baseline = SkillGasBaseline {
            package: ObjectId::new(PKG),
            per_action_max: [GasBudgetMist::new(600_000); SKILL_GAS_ACTION_COUNT],
            samples_u32: 12,
        };
        let hard_cap = 800_000;
        // each action has a captured baseline.
        for action in SkillPtbAction::all() {
            assert_eq!(baseline.max_for(action).get(), 600_000);
        }
        let pub_ = SkillPtbAction::Publish;
        assert_eq!(
            baseline.classify(pub_, 500_000, hard_cap),
            GasRegressionDecision::Green
        );
        assert_eq!(
            baseline.classify(pub_, 700_000, hard_cap),
            GasRegressionDecision::Warn
        );
        assert_eq!(
            baseline.classify(pub_, 800_001, hard_cap),
            GasRegressionDecision::Red
        );
        // saturating: an absurd spend is Red, never panics.
        assert_eq!(
            baseline.classify(pub_, u64::MAX, hard_cap),
            GasRegressionDecision::Red
        );
    }

    fn record(
        action: SkillPtbAction,
        accepted_decision: GasStationDecision,
    ) -> SkillGasTraceRecord {
        SkillGasTraceRecord {
            action,
            package: ObjectId::new(PKG),
            requested_gas: GasBudgetMist::new(50_000),
            effect: bounded_effect(),
            baseline_max: GasBudgetMist::new(600_000),
            regression: GasRegressionDecision::Green,
            decision: accepted_decision,
        }
    }

    /// The evidence line carries the schema, every allowlisted key, and no
    /// commerce / secret field.
    #[test]
    fn trace_line_keys_and_no_commerce() {
        let policy = policy();
        let decision =
            evaluate_skill_sponsorship(&policy, &request(SkillPtbAction::Publish), trace());
        let rec = record(SkillPtbAction::Publish, decision);
        let line =
            build_skill_gas_trace_line(&rec, redact_for_log("", LogRedactionKind::ProviderBody));
        assert!(line.contains("\"schema\":\"mnemos.stage_d.skill_gas_trace.v1\""));
        assert!(line.contains("\"event\":\"skill_gas_trace\""));
        assert!(line.contains("\"move_function\":\"publish_skill\""));
        assert!(line.contains("\"sponsor_accepted\":true"));
        assert!(line.contains("\"atom_id_u16\":294"));
        // No commerce / secret surface.
        for banned in [
            "price", "payment", "checkout", "refund", "royalty", "revenue", "secret",
        ] {
            assert!(!line.contains(banned), "line must not contain {banned}");
        }
        // one JSON object, one line (JSONL): no embedded newline.
        assert!(!line.contains('\n'));
    }

    /// A note carrying a raw secret is redacted at the call site; only the class
    /// label survives in the line.
    #[test]
    fn note_body_is_absent_only_the_class_survives() {
        let policy = policy();
        let decision =
            evaluate_skill_sponsorship(&policy, &request(SkillPtbAction::RevokeInstall), trace());
        let rec = record(SkillPtbAction::RevokeInstall, decision);
        let secret = "SECRET_SPONSOR_KEY_DEADBEEF";
        let line =
            build_skill_gas_trace_line(&rec, redact_for_log(secret, LogRedactionKind::SuiTxBytes));
        assert!(line.contains("\"note_class\":\"sui_tx_bytes\""));
        assert!(!line.contains("SECRET_SPONSOR_KEY"));
        assert!(!line.contains("DEADBEEF"));
    }

    /// Walk the JSON object keys (quote-aware) and confirm the emitted set equals
    /// the allowlist exactly — no unknown field, no dropped field.
    #[test]
    fn every_emitted_key_is_allowlisted() {
        let policy = policy();
        let decision = evaluate_skill_sponsorship(&policy, &request(SkillPtbAction::Fork), trace());
        let rec = record(SkillPtbAction::Fork, decision);
        let line =
            build_skill_gas_trace_line(&rec, redact_for_log("", LogRedactionKind::ProviderBody));
        let keys = object_keys(&line);
        for k in &keys {
            assert!(
                STAGE_D_SKILL_GAS_TRACE_KEYS.contains(&k.as_str()),
                "unexpected key: {k}"
            );
        }
        for expected in STAGE_D_SKILL_GAS_TRACE_KEYS {
            assert!(
                keys.iter().any(|k| k == expected),
                "missing key: {expected}"
            );
        }
        assert_eq!(keys.len(), STAGE_D_SKILL_GAS_TRACE_KEYS.len());
    }

    /// Quote-aware key walk: collect every `"token":` key, ignoring `:` inside
    /// string values.
    fn object_keys(s: &str) -> Vec<String> {
        let bytes = s.as_bytes();
        let mut keys = Vec::new();
        let mut i = 0usize;
        while i < bytes.len() {
            if bytes[i] == b'"' {
                let start = i + 1;
                let mut j = start;
                while j < bytes.len() && bytes[j] != b'"' {
                    j += 1;
                }
                let token = &s[start..j];
                let mut k = j + 1;
                while k < bytes.len() && (bytes[k] == b' ' || bytes[k] == b'\n') {
                    k += 1;
                }
                if k < bytes.len() && bytes[k] == b':' {
                    keys.push(token.to_string());
                }
                i = j + 1;
            } else {
                i += 1;
            }
        }
        keys
    }
}
