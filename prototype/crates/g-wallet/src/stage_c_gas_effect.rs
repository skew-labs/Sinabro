//! Stage C Gas Station dry-run / effect-shape checker.
//!
//! Primary type: [`GasStationDecision`].
//!
//! # Invariants
//!
//! * **Every check runs before the signer boundary.** [`evaluate_sponsorship`]
//!   decodes the intent, enforces the package/function allowlist, compares the
//!   dry-run effect shape, checks the safety-kernel attestation, the budget,
//!   the nonce/quota, and the gas-coin lease — and only a fully-passing request
//!   yields `accepted = true`. The function never signs anything; it returns a
//!   decision a caller consults *before* deciding to sponsor.
//! * **Opaque bytes and raw GasData are unrepresentable as accepted.** The
//!   intent is a typed [`GasIntent`]; an [`GasIntent::OpaqueBytes`] or
//!   [`GasIntent::RawGasData`] request is rejected with the matching reason
//!   before any other work.
//! * **Effect-shape mismatch is a reject.** The observed [`EffectDelta`]
//!   (dry-run) must equal the expected shape for the claimed
//!   function; otherwise [`GasStationRejectReason::EffectShape`].
//!
//! # Reuse
//!
//! * [`EffectDelta`](mnemos_d_move::stage_c_effect_delta::EffectDelta).
//! * [`GasStationPolicy`](crate::stage_c_gas_policy::GasStationPolicy) and the
//!   reject/trust enums.
//! * [`SuiCallBuilder`](mnemos_d_move::sdk::SuiCallBuilder) — the typed
//!   Move-call routing record; its `to_dry_run_bytes` is the decode step.
//! * [`StageCTraceLink`](mnemos_a_core::trace::StageCTraceLink) — the trace
//!   stamp carried on the decision.

use crate::stage_c_gas_policy::{
    GasStationPolicy, GasStationRejectReason, OfficialTrustDecision, SafetyKernelAttestation,
    SponsoredFunction,
};
use mnemos_a_core::trace::StageCTraceLink;
use mnemos_d_move::sdk::SuiCallBuilder;
use mnemos_d_move::stage_c_effect_delta::EffectDelta;
use mnemos_d_move::types::{GasBudgetMist, ObjectId};

/// The intent a sponsorship request carries. Only a typed Move call can be
/// sponsored; opaque bytes and pre-baked gas data are refused.
#[derive(Clone, Copy, Debug)]
pub enum GasIntent<'a> {
    /// A typed Move-call routing record (decoded, effect-shape-checkable).
    TypedCall(&'a SuiCallBuilder),
    /// An opaque byte payload offered for signing — always refused.
    OpaqueBytes,
    /// A pre-baked raw `GasData` offered for signing — always refused.
    RawGasData,
}

/// A Gas Station sponsorship request, bundling every input the checker needs so
/// the call site stays a single typed boundary.
#[derive(Clone, Copy, Debug)]
pub struct SponsorshipRequest<'a> {
    /// The (typed or refused) intent.
    pub intent: GasIntent<'a>,
    /// The function the request claims to invoke.
    pub function: SponsoredFunction,
    /// The package the request presents.
    pub presented_package: ObjectId,
    /// The effect shape observed from the dry-run.
    pub observed_effect: EffectDelta,
    /// The effect shape expected for the claimed function.
    pub expected_effect: EffectDelta,
    /// The safety-kernel attestation, if any.
    pub attestation: Option<SafetyKernelAttestation>,
    /// The current epoch for attestation-expiry checks.
    pub now_epoch_u64: u64,
    /// The requested per-tx gas budget.
    pub requested_gas: GasBudgetMist,
    /// Whether the request's nonce is fresh (not a replay).
    pub nonce_fresh: bool,
    /// Whether the request is within the per-identity quota.
    pub within_quota: bool,
    /// Whether a valid, uncontended gas-coin lease is held.
    pub lease_valid: bool,
}

/// The Gas Station decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasStationDecision {
    /// Whether the request passed every check.
    pub accepted: bool,
    /// The reject reason, when not accepted.
    pub reject: Option<GasStationRejectReason>,
    /// The official-trust verdict computed for the sponsor.
    pub trust: OfficialTrustDecision,
    /// The trace stamp for this decision.
    pub trace: StageCTraceLink,
}

impl GasStationDecision {
    #[inline]
    const fn reject(
        reason: GasStationRejectReason,
        trust: OfficialTrustDecision,
        trace: StageCTraceLink,
    ) -> Self {
        Self {
            accepted: false,
            reject: Some(reason),
            trust,
            trace,
        }
    }
}

/// Run the full ordered check sequence for a sponsorship request. Returns a
/// [`GasStationDecision`]; never signs and never mutates anything.
///
/// The ordering matters: opaque/raw payloads are refused first, then the
/// allowlist, then the effect shape, then attestation, then caps, then
/// nonce/quota/lease — all *before* any signer boundary a caller might cross.
pub fn evaluate_sponsorship(
    policy: &GasStationPolicy,
    req: &SponsorshipRequest<'_>,
    trace: StageCTraceLink,
) -> GasStationDecision {
    // The trust verdict is computed up-front so even a reject records it.
    let trust = policy.evaluate_trust(req.attestation.as_ref(), req.now_epoch_u64);

    // 1. Intent decode: only a typed, decodable call proceeds.
    let call = match req.intent {
        GasIntent::OpaqueBytes => {
            return GasStationDecision::reject(GasStationRejectReason::OpaqueBytes, trust, trace);
        }
        GasIntent::RawGasData => {
            return GasStationDecision::reject(GasStationRejectReason::RawGasData, trust, trace);
        }
        GasIntent::TypedCall(call) => call,
    };
    if call.to_dry_run_bytes().is_err() {
        return GasStationDecision::reject(GasStationRejectReason::Decode, trust, trace);
    }

    // 2. Wildcard allowlist.
    if let Err(reason) = policy.reject_if_wildcard() {
        return GasStationDecision::reject(reason, trust, trace);
    }

    // 3. Package: the policy package, the call package, and the presented
    //    package must all agree.
    if let Err(reason) = policy.check_package(req.presented_package) {
        return GasStationDecision::reject(reason, trust, trace);
    }
    if call.package() != &policy.package {
        return GasStationDecision::reject(GasStationRejectReason::PackageFunction, trust, trace);
    }

    // 4. Function allowlist.
    if let Err(reason) = policy.check_function(req.function) {
        return GasStationDecision::reject(reason, trust, trace);
    }

    // 5. Effect shape.
    if req.observed_effect != req.expected_effect {
        return GasStationDecision::reject(GasStationRejectReason::EffectShape, trust, trace);
    }

    // 6. Safety-kernel attestation: a hosted sponsor that is not officially
    //    trusted (missing / expired / forked kernel) is refused.
    if policy.require_official_safety_kernel && !trust.is_trusted() {
        return GasStationDecision::reject(
            GasStationRejectReason::SafetyKernelAttestation,
            trust,
            trace,
        );
    }

    // 7. Budget cap.
    if let Err(reason) = policy.check_gas_budget(req.requested_gas) {
        return GasStationDecision::reject(reason, trust, trace);
    }

    // 8. Replay / nonce.
    if !req.nonce_fresh {
        return GasStationDecision::reject(GasStationRejectReason::ReplayNonce, trust, trace);
    }
    // 9. Quota.
    if !req.within_quota {
        return GasStationDecision::reject(GasStationRejectReason::QuotaRisk, trust, trace);
    }
    // 10. Gas-coin lease.
    if !req.lease_valid {
        return GasStationDecision::reject(GasStationRejectReason::GasCoinLease, trust, trace);
    }

    GasStationDecision {
        accepted: true,
        reject: None,
        trust,
        trace,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::stage_c_gas_policy::{GasSponsorMode, SafetyKernelBuildRef};
    use mnemos_a_core::trace::StageBTraceLink;
    use mnemos_d_move::types::{MemoryRootArgs, SuiAddress};

    fn trace() -> StageCTraceLink {
        StageCTraceLink::new(StageBTraceLink::new(0xA17B_0218, 218, 0), 218, 43)
    }

    fn sample_call() -> SuiCallBuilder {
        let args = MemoryRootArgs {
            owner: SuiAddress::new([0x01; 32]),
            root_hash: [0x02; 32],
            epoch_u64: 1,
        };
        SuiCallBuilder::add_chunk(
            ObjectId::new([0x03; 32]),
            &args,
            GasBudgetMist::new(800_000),
        )
        .expect("call builds")
    }

    fn valid_att(expires: u64) -> SafetyKernelAttestation {
        SafetyKernelAttestation {
            build: SafetyKernelBuildRef {
                build_id_u64: 1,
                release_hash_32: [0x11; 32],
            },
            sbom_hash_32: [0x22; 32],
            reproducible_build_hash_32: [0x33; 32],
            sandbox_policy_hash_32: [0x44; 32],
            evidence_schema_hash_32: [0x55; 32],
            expires_epoch_u64: expires,
        }
    }

    fn effect() -> EffectDelta {
        EffectDelta::from_dev_inspect(true, 1, 1, 64, 1000, 0).expect("effect builds")
    }

    fn policy_for(call: &SuiCallBuilder) -> GasStationPolicy {
        GasStationPolicy {
            mode: GasSponsorMode::Hosted,
            package: *call.package(),
            max_gas_per_tx: GasBudgetMist::new(800_000),
            max_txs_per_epoch_u32: 1_000,
            max_storage_bytes_u32: 1_000_000,
            allowed_mask_u16: GasStationPolicy::INITIAL_ALLOWED_MASK,
            update_semantics_via_add_chunk: true,
            require_official_safety_kernel: true,
        }
    }

    fn base_req<'a>(call: &'a SuiCallBuilder) -> SponsorshipRequest<'a> {
        SponsorshipRequest {
            intent: GasIntent::TypedCall(call),
            function: SponsoredFunction::MemoryAddChunk,
            presented_package: *call.package(),
            observed_effect: effect(),
            expected_effect: effect(),
            attestation: Some(valid_att(100)),
            now_epoch_u64: 10,
            requested_gas: GasBudgetMist::new(800_000),
            nonce_fresh: true,
            within_quota: true,
            lease_valid: true,
        }
    }

    /// `c1_17_valid_add_chunk_accepted` — a fully-conforming add_chunk request
    /// is accepted and officially trusted.
    #[test]
    fn c1_17_valid_add_chunk_accepted() {
        let call = sample_call();
        let policy = policy_for(&call);
        let req = base_req(&call);
        let d = evaluate_sponsorship(&policy, &req, trace());
        assert!(d.accepted);
        assert_eq!(d.reject, None);
        assert_eq!(d.trust, OfficialTrustDecision::OfficialTrusted);
    }

    /// `c1_17_opaque_bytes_reject` / `c1_17_raw_gasdata_reject` — opaque and raw
    /// gas-data intents are refused first.
    #[test]
    fn c1_17_opaque_and_raw_reject() {
        let call = sample_call();
        let policy = policy_for(&call);

        let mut opaque = base_req(&call);
        opaque.intent = GasIntent::OpaqueBytes;
        let d = evaluate_sponsorship(&policy, &opaque, trace());
        assert!(!d.accepted);
        assert_eq!(d.reject, Some(GasStationRejectReason::OpaqueBytes));

        let mut raw = base_req(&call);
        raw.intent = GasIntent::RawGasData;
        let d = evaluate_sponsorship(&policy, &raw, trace());
        assert_eq!(d.reject, Some(GasStationRejectReason::RawGasData));
    }

    /// `c1_17_effect_shape_mismatch_reject` — a dry-run effect that differs from
    /// the expected shape is rejected.
    #[test]
    fn c1_17_effect_shape_mismatch_reject() {
        let call = sample_call();
        let policy = policy_for(&call);
        let mut req = base_req(&call);
        req.observed_effect = EffectDelta::from_dev_inspect(true, 2, 1, 64, 1000, 0).unwrap();
        let d = evaluate_sponsorship(&policy, &req, trace());
        assert_eq!(d.reject, Some(GasStationRejectReason::EffectShape));
    }

    /// `c1_17_attestation_mismatch_reject` — a hosted request with a
    /// missing/expired attestation is refused on the attestation check.
    #[test]
    fn c1_17_attestation_mismatch_reject() {
        let call = sample_call();
        let policy = policy_for(&call);

        let mut missing = base_req(&call);
        missing.attestation = None;
        let d = evaluate_sponsorship(&policy, &missing, trace());
        assert_eq!(
            d.reject,
            Some(GasStationRejectReason::SafetyKernelAttestation)
        );
        assert_eq!(d.trust, OfficialTrustDecision::Quarantined);

        let mut expired = base_req(&call);
        expired.attestation = Some(valid_att(5));
        expired.now_epoch_u64 = 10;
        let d = evaluate_sponsorship(&policy, &expired, trace());
        assert_eq!(
            d.reject,
            Some(GasStationRejectReason::SafetyKernelAttestation)
        );
        assert_eq!(d.trust, OfficialTrustDecision::Revoked);
    }

    /// `c1_17_budget_nonce_quota_lease_reject` — the late-stage caps each
    /// reject in order.
    #[test]
    fn c1_17_budget_nonce_quota_lease_reject() {
        let call = sample_call();
        let policy = policy_for(&call);

        let mut over = base_req(&call);
        over.requested_gas = GasBudgetMist::new(800_001);
        assert_eq!(
            evaluate_sponsorship(&policy, &over, trace()).reject,
            Some(GasStationRejectReason::Budget),
        );

        let mut replay = base_req(&call);
        replay.nonce_fresh = false;
        assert_eq!(
            evaluate_sponsorship(&policy, &replay, trace()).reject,
            Some(GasStationRejectReason::ReplayNonce),
        );

        let mut quota = base_req(&call);
        quota.within_quota = false;
        assert_eq!(
            evaluate_sponsorship(&policy, &quota, trace()).reject,
            Some(GasStationRejectReason::QuotaRisk),
        );

        let mut lease = base_req(&call);
        lease.lease_valid = false;
        assert_eq!(
            evaluate_sponsorship(&policy, &lease, trace()).reject,
            Some(GasStationRejectReason::GasCoinLease),
        );
    }
}
