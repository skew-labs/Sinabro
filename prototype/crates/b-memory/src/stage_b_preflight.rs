//! Stage B Walrus testnet **preflight** (atom #114 · B.2.13).
//!
//! This module mints the atom #114 canonical OUT: [`WalrusTestnetPreflightReport`]
//! — a content-free readiness assessment that answers "is a later atom allowed to
//! attempt a live Walrus testnet action?" across the five dimensions the plan
//! names, **without writing a single byte to any network**. It is exactly the "A
//! canonical을 조합하는 … evidence 타입" category that §4.0 permits Stage B to mint:
//! it composes earlier-atom canonicals and introduces no new wire, no new error
//! type, no new id/address newtype, and no dependency. The whole module is pure
//! and offline (`G-B-WALRUS-OFFLINE`): it opens no socket, resolves no DNS, and
//! pulls in no HTTP/TLS surface.
//!
//! # Madness invariant (`MNEMOS_STAGE_B_ATOM_PLAN.md` atom #114)
//!
//! > live network readiness is checked without writing: endpoint DNS, feature,
//! > payload class, timeout, trace.
//!
//! * **Five dimensions, all assessed, none written.** The report carries exactly
//!   the five readiness dimensions the plan names —
//!   [`endpoint_dns`](WalrusTestnetPreflightReport::endpoint_dns),
//!   [`feature`](WalrusTestnetPreflightReport::feature),
//!   [`payload_class`](WalrusTestnetPreflightReport::payload_class),
//!   [`timeout`](WalrusTestnetPreflightReport::timeout), and
//!   [`trace`](WalrusTestnetPreflightReport::trace) — each a content-free
//!   [`PreflightReadiness`] tag. [`is_ready`](WalrusTestnetPreflightReport::is_ready)
//!   is `true` **iff every** dimension is [`Ready`](PreflightReadiness::Ready):
//!   the preflight is a conjunction, so any single not-ready dimension fails the
//!   whole check closed (`b2_13_all_dims_must_be_ready`).
//!
//! * **DNS is assessed, never resolved here (offline).** The actual DNS resolve
//!   of the testnet host is a later `net-testnet` atom's job; this offline
//!   preflight takes the resolution outcome as an *injected* `dns_resolved`
//!   signal so the entire assessment is deterministic and testable with no socket
//!   (`b2_13_mock_dns_fail` injects a failed resolve). The endpoint itself is the
//!   atom #101 [`WalrusTestnetEndpoint`] — testnet by construction — so only the
//!   single sanctioned endpoint is ever preflightable (an arbitrary host is not
//!   even representable as input).
//!
//! * **Feature is the `net-testnet` compile gate.** [`feature_compiled`] reports
//!   whether the atom #102 `net-testnet` feature (the only seam that links the
//!   real `reqwest` transport) is compiled in. [`assess`](WalrusTestnetPreflightReport::assess)
//!   takes the feature readiness as an *injected* `feature_ready` flag so the
//!   "all green" path is testable under the default offline build; the real
//!   wiring atom passes `feature_compiled()`. Under the default build the feature
//!   is off, so `feature_compiled()` is `false` and a report built with the real
//!   gate is not ready (`b2_13_feature_disabled_fail`).
//!
//! * **Payload class reuses the atom #113 decision (R1, user-locked 2026-05-30).**
//!   The `payload_class` dimension is [`Ready`](PreflightReadiness::Ready) **iff**
//!   atom #113's [`stage_b_publish_decision`] returns
//!   [`Admit`](StageBPublishDecision::Admit). Both
//!   [`DenyClass`](StageBPublishDecision::DenyClass) and
//!   [`RequireOwnerSignature`](StageBPublishDecision::RequireOwnerSignature) map
//!   to [`NotReady`](PreflightReadiness::NotReady) — `RequireOwnerSignature` stays
//!   **fail-closed** in this atom exactly as it does at the #103 planner seam.
//!   No second payload-policy enum is minted, and this atom mints **no**
//!   owner-signature verifier, `StageBSealStubPolicy`, or wallet/seal/capability
//!   surface (that override is the §4.4 cluster, a later atom > #120).
//!
//! * **Timeout must be a usable bound.** The `timeout` dimension is
//!   [`Ready`](PreflightReadiness::Ready) iff the configured timeout is within
//!   `[`[`MIN_PREFLIGHT_TIMEOUT_MS`]`, `[`MAX_PREFLIGHT_TIMEOUT_MS`]`]` — a zero
//!   timeout (no time to act) and an absurd one are both not ready
//!   (`b2_13_timeout_bounds`).
//!
//! * **Trace reuses the atom #94 evidence (R1, user-locked 2026-05-30).** The
//!   `trace` dimension is [`Ready`](PreflightReadiness::Ready) iff a
//!   [`StageBTraceEvidence`] can be constructed from the supplied
//!   [`StageBTraceLink`] — i.e. [`from_trace`](StageBTraceEvidence::from_trace)
//!   accepts it. The missing/unstamped sentinel (`atom_id_u16 == 0`) yields
//!   [`NotReady`](PreflightReadiness::NotReady) fail-closed
//!   (`b2_13_trace_missing_not_ready`); no second trace-evidence type is minted.
//!
//! # Reuse map (atom contract `reuse: #101, #102` — reuse-headline expansion)
//!
//! The atom's `reuse` field headlines `#101, #102`, but the five named dimensions
//! require two further already-canonical surfaces, which are **reused, not
//! reinvented** (the user-locked R1 decision, following the #112 precedent where
//! the reuse headline was likewise incomplete):
//!
//! * #101 [`WalrusTestnetEndpoint`](crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint)
//!   — the only preflightable endpoint (testnet by construction); consumed by
//!   value so a caller must hold the sanctioned endpoint to even ask.
//! * #102 `net-testnet` feature — surfaced by [`feature_compiled`].
//! * #113 [`stage_b_publish_decision`](crate::stage_b_policy::stage_b_publish_decision)
//!   / [`StageBPublishDecision`](crate::stage_b_policy::StageBPublishDecision) —
//!   the `payload_class` dimension.
//! * #94 [`StageBTraceEvidence`](crate::trace_link::StageBTraceEvidence) — the
//!   `trace` dimension; #81 [`StageBTraceLink`](crate::stage_b_handoff::StageBTraceLink)
//!   is the stamp it binds.
//!
//! No new dependency, no new wire format, no new error type, no network.

use crate::chunk_schema::PublishPayloadClass;
use crate::stage_b_handoff::StageBTraceLink;
use crate::stage_b_policy::{StageBPublishDecision, stage_b_publish_decision};
use crate::stage_b_walrus_endpoint::WalrusTestnetEndpoint;
use crate::trace_link::StageBTraceEvidence;

/// The smallest usable preflight timeout, in milliseconds. A timeout below this
/// (notably `0`) leaves no time to perform the action and is **not ready**.
pub const MIN_PREFLIGHT_TIMEOUT_MS: u32 = 1;

/// The largest accepted preflight timeout, in milliseconds (ten minutes). A
/// timeout above this is treated as a misconfiguration and is **not ready**.
pub const MAX_PREFLIGHT_TIMEOUT_MS: u32 = 600_000;

/// Whether the atom #102 `net-testnet` feature — the only seam that links the
/// real Walrus `reqwest` transport — is compiled into this build.
///
/// `true` only when the crate is built with `--features net-testnet`. The
/// default (offline) build returns `false`. The real wiring atom passes this
/// into [`WalrusTestnetPreflightReport::assess`] as the `feature_ready` flag; the
/// assessment itself stays injectable so the all-ready path is testable offline.
#[inline]
pub const fn feature_compiled() -> bool {
    cfg!(feature = "net-testnet")
}

/// The readiness of a single Stage B Walrus preflight dimension.
///
/// A `#[repr(u8)]` enum so a dimension's readiness is a single fixed byte with
/// explicit, stable discriminants — content-free by construction (it can carry no
/// host, body, or provider string).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PreflightReadiness {
    /// The dimension is ready: a later atom may rely on it.
    Ready = 1,
    /// The dimension is not ready: the preflight fails closed on it.
    NotReady = 2,
}

impl PreflightReadiness {
    /// The one-byte wire tag for this readiness (the `#[repr(u8)]` discriminant).
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether this dimension is [`Ready`](Self::Ready).
    #[inline]
    pub const fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Map a plain readiness boolean onto the tag: `true` ->
    /// [`Ready`](Self::Ready), `false` -> [`NotReady`](Self::NotReady).
    #[inline]
    const fn from_ready(ready: bool) -> Self {
        if ready { Self::Ready } else { Self::NotReady }
    }
}

/// The atom #114 canonical OUT: a content-free Walrus testnet preflight readiness
/// report across the five plan-named dimensions.
///
/// Built by [`assess`](Self::assess), which performs **no** network I/O — it
/// composes the injected DNS / feature / timeout signals with the atom #113
/// payload-class decision and the atom #94 trace evidence to produce a per-
/// dimension [`PreflightReadiness`]. There is no field that could hold a host,
/// URL, payload body, owner address, or provider string, so the report is
/// redaction-safe by construction and `Copy`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusTestnetPreflightReport {
    /// Readiness of DNS resolution for the bound testnet endpoint (injected; the
    /// real resolve is a later `net-testnet` atom).
    endpoint_dns: PreflightReadiness,
    /// Readiness of the `net-testnet` feature gate (injected; the real wiring
    /// atom passes [`feature_compiled`]).
    feature: PreflightReadiness,
    /// Readiness of the payload content class (atom #113 decision: `Admit` only).
    payload_class: PreflightReadiness,
    /// Readiness of the configured timeout (within the accepted bounds).
    timeout: PreflightReadiness,
    /// Readiness of the per-action trace stamp (atom #94 evidence; fail-closed on
    /// the missing/unstamped sentinel).
    trace: PreflightReadiness,
}

impl WalrusTestnetPreflightReport {
    /// Assess Walrus testnet readiness across the five plan-named dimensions
    /// **without writing to any network**.
    ///
    /// * `endpoint` — the atom #101 [`WalrusTestnetEndpoint`]. Taken by value so a
    ///   caller must hold the sanctioned testnet endpoint to ask; its value
    ///   carries no host to store, so the report stays content-free.
    /// * `dns_resolved` — the injected DNS resolution outcome for that endpoint
    ///   (the real resolve happens in a later `net-testnet` atom; offline here).
    /// * `feature_ready` — whether the `net-testnet` transport feature is usable;
    ///   the real wiring atom passes [`feature_compiled`].
    /// * `class` — the payload content class; mapped through atom #113's
    ///   [`stage_b_publish_decision`] (`Admit` -> ready, `DenyClass` /
    ///   `RequireOwnerSignature` -> not ready, fail-closed).
    /// * `timeout_ms` — the configured action timeout; ready iff within
    ///   `[`[`MIN_PREFLIGHT_TIMEOUT_MS`]`, `[`MAX_PREFLIGHT_TIMEOUT_MS`]`]`.
    /// * `trace` — the atom #81 per-action stamp; ready iff atom #94's
    ///   [`StageBTraceEvidence::from_trace`] accepts it (`atom_id_u16 != 0`).
    pub const fn assess(
        endpoint: WalrusTestnetEndpoint,
        dns_resolved: bool,
        feature_ready: bool,
        class: PublishPayloadClass,
        timeout_ms: u32,
        trace: StageBTraceLink,
    ) -> Self {
        // #101 type-level proof: only the sanctioned testnet endpoint is
        // preflightable. The value carries no host to store (content-free
        // report), so it is intentionally not retained.
        let _ = endpoint;

        // Payload class via the atom #113 decision (R1 reuse, user-locked):
        // Admit is the only ready arm; both denial arms fail closed.
        let payload_class = match stage_b_publish_decision(class) {
            StageBPublishDecision::Admit => PreflightReadiness::Ready,
            StageBPublishDecision::DenyClass | StageBPublishDecision::RequireOwnerSignature => {
                PreflightReadiness::NotReady
            }
        };

        // Trace via the atom #94 evidence (R1 reuse, user-locked): a missing /
        // unstamped sentinel (atom_id_u16 == 0) is rejected fail-closed.
        let trace = match StageBTraceEvidence::from_trace(trace) {
            Some(_) => PreflightReadiness::Ready,
            None => PreflightReadiness::NotReady,
        };

        Self {
            endpoint_dns: PreflightReadiness::from_ready(dns_resolved),
            feature: PreflightReadiness::from_ready(feature_ready),
            payload_class,
            timeout: PreflightReadiness::from_ready(
                timeout_ms >= MIN_PREFLIGHT_TIMEOUT_MS && timeout_ms <= MAX_PREFLIGHT_TIMEOUT_MS,
            ),
            trace,
        }
    }

    /// Readiness of DNS resolution for the bound testnet endpoint.
    #[inline]
    pub const fn endpoint_dns(&self) -> PreflightReadiness {
        self.endpoint_dns
    }

    /// Readiness of the `net-testnet` feature gate.
    #[inline]
    pub const fn feature(&self) -> PreflightReadiness {
        self.feature
    }

    /// Readiness of the payload content class (atom #113 decision).
    #[inline]
    pub const fn payload_class(&self) -> PreflightReadiness {
        self.payload_class
    }

    /// Readiness of the configured timeout.
    #[inline]
    pub const fn timeout(&self) -> PreflightReadiness {
        self.timeout
    }

    /// Readiness of the per-action trace stamp (atom #94 evidence).
    #[inline]
    pub const fn trace(&self) -> PreflightReadiness {
        self.trace
    }

    /// Whether **every** dimension is [`Ready`](PreflightReadiness::Ready).
    ///
    /// The preflight is a conjunction: a single not-ready dimension fails the
    /// whole check closed, so a later atom may only proceed when all five are
    /// ready.
    #[inline]
    pub const fn is_ready(&self) -> bool {
        self.endpoint_dns.is_ready()
            && self.feature.is_ready()
            && self.payload_class.is_ready()
            && self.timeout.is_ready()
            && self.trace.is_ready()
    }
}

#[cfg(test)]
mod tests {
    // Test helpers prefer direct assertions over `Result`-bubbling; suppress the
    // prod-only clippy denies inside this module (b-memory #94/#109/#110/#112
    // precedent).
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// A stamped (non-sentinel) trace: `atom_id_u16 == 114 != 0`.
    const STAMPED_TRACE: StageBTraceLink = StageBTraceLink::new(7, 114, 0);
    /// The missing/unstamped sentinel: `atom_id_u16 == 0`.
    const MISSING_TRACE: StageBTraceLink = StageBTraceLink::new(7, 0, 0);
    /// A valid timeout inside the accepted bounds.
    const OK_TIMEOUT_MS: u32 = 30_000;

    /// `b2_13_mock_green` — with every dimension supplied ready (DNS resolved,
    /// feature on, admissible class, valid timeout, stamped trace) the report is
    /// ready and every dimension reads `Ready`. Runs under the default offline
    /// build because the feature readiness is injected, not read from `cfg!`.
    #[test]
    fn b2_13_mock_green() {
        let report = WalrusTestnetPreflightReport::assess(
            WalrusTestnetEndpoint::testnet(),
            true,
            true,
            PublishPayloadClass::SyntheticPublicFixture,
            OK_TIMEOUT_MS,
            STAMPED_TRACE,
        );
        assert!(report.is_ready());
        assert!(report.endpoint_dns().is_ready());
        assert!(report.feature().is_ready());
        assert!(report.payload_class().is_ready());
        assert!(report.timeout().is_ready());
        assert!(report.trace().is_ready());
    }

    /// `b2_13_mock_dns_fail` — an unresolved endpoint (injected `dns_resolved =
    /// false`) makes the `endpoint_dns` dimension not ready and the whole report
    /// not ready, with every other dimension still ready.
    #[test]
    fn b2_13_mock_dns_fail() {
        let report = WalrusTestnetPreflightReport::assess(
            WalrusTestnetEndpoint::testnet(),
            false,
            true,
            PublishPayloadClass::SyntheticPublicFixture,
            OK_TIMEOUT_MS,
            STAMPED_TRACE,
        );
        assert_eq!(report.endpoint_dns(), PreflightReadiness::NotReady);
        assert!(!report.is_ready());
        assert!(report.feature().is_ready());
        assert!(report.payload_class().is_ready());
        assert!(report.timeout().is_ready());
        assert!(report.trace().is_ready());
    }

    /// `b2_13_feature_disabled_fail` — a disabled feature gate makes the report
    /// not ready. The injected-`false` path is asserted directly, and the real
    /// `feature_compiled()` gate is checked against the build profile: in the
    /// default offline build it is `false` (so the real wiring would be not
    /// ready); with `net-testnet` on it is `true`.
    #[test]
    fn b2_13_feature_disabled_fail() {
        let report = WalrusTestnetPreflightReport::assess(
            WalrusTestnetEndpoint::testnet(),
            true,
            false,
            PublishPayloadClass::SyntheticPublicFixture,
            OK_TIMEOUT_MS,
            STAMPED_TRACE,
        );
        assert_eq!(report.feature(), PreflightReadiness::NotReady);
        assert!(!report.is_ready());

        // The real compile gate matches the build profile.
        #[cfg(not(feature = "net-testnet"))]
        assert!(!feature_compiled());
        #[cfg(feature = "net-testnet")]
        assert!(feature_compiled());

        // A report built from the real gate is ready on the feature dimension iff
        // the feature is compiled in.
        let real = WalrusTestnetPreflightReport::assess(
            WalrusTestnetEndpoint::testnet(),
            true,
            feature_compiled(),
            PublishPayloadClass::SyntheticPublicFixture,
            OK_TIMEOUT_MS,
            STAMPED_TRACE,
        );
        assert_eq!(real.feature().is_ready(), feature_compiled());
    }

    /// `b2_13_readiness_repr_width` — the `#[repr(u8)]` readiness is one byte with
    /// the locked discriminants 1 / 2.
    #[test]
    fn b2_13_readiness_repr_width() {
        assert_eq!(core::mem::size_of::<PreflightReadiness>(), 1);
        assert_eq!(PreflightReadiness::Ready.tag(), 1);
        assert_eq!(PreflightReadiness::NotReady.tag(), 2);
    }

    /// `b2_13_payload_class_reuse_binding` — the `payload_class` dimension is
    /// `Ready` **iff** atom #113's `stage_b_publish_decision` returns `Admit`,
    /// across the full Stage A class set. Binds the preflight to #113 so the two
    /// cannot drift; proves `RequireOwnerSignature` (user-owned) is fail-closed
    /// here.
    #[test]
    fn b2_13_payload_class_reuse_binding() {
        for class in [
            PublishPayloadClass::SyntheticPublicFixture,
            PublishPayloadClass::RealUserMemory,
            PublishPayloadClass::PromptOrProviderText,
            PublishPayloadClass::ToolOutput,
            PublishPayloadClass::SecretLike,
            PublishPayloadClass::PrivateProvenance,
        ] {
            let report = WalrusTestnetPreflightReport::assess(
                WalrusTestnetEndpoint::testnet(),
                true,
                true,
                class,
                OK_TIMEOUT_MS,
                STAMPED_TRACE,
            );
            let admit = stage_b_publish_decision(class) == StageBPublishDecision::Admit;
            assert_eq!(
                report.payload_class().is_ready(),
                admit,
                "payload_class readiness must match #113 Admit for {}",
                class.class_label(),
            );
        }
        // RequireOwnerSignature (RealUserMemory) is explicitly not ready here.
        let user_owned = WalrusTestnetPreflightReport::assess(
            WalrusTestnetEndpoint::testnet(),
            true,
            true,
            PublishPayloadClass::RealUserMemory,
            OK_TIMEOUT_MS,
            STAMPED_TRACE,
        );
        assert_eq!(user_owned.payload_class(), PreflightReadiness::NotReady);
        assert!(!user_owned.is_ready());
    }

    /// `b2_13_trace_missing_not_ready` — the missing/unstamped trace sentinel
    /// (`atom_id_u16 == 0`) makes the `trace` dimension not ready (reusing the
    /// atom #94 `from_trace` fail-closed reject) and the whole report not ready.
    #[test]
    fn b2_13_trace_missing_not_ready() {
        let report = WalrusTestnetPreflightReport::assess(
            WalrusTestnetEndpoint::testnet(),
            true,
            true,
            PublishPayloadClass::SyntheticPublicFixture,
            OK_TIMEOUT_MS,
            MISSING_TRACE,
        );
        assert_eq!(report.trace(), PreflightReadiness::NotReady);
        assert!(!report.is_ready());
        // The stamped trace is, by contrast, ready.
        assert!(StageBTraceEvidence::from_trace(MISSING_TRACE).is_none());
        assert!(StageBTraceEvidence::from_trace(STAMPED_TRACE).is_some());
    }

    /// `b2_13_timeout_bounds` — a zero timeout and an over-cap timeout are not
    /// ready; the min, max, and an interior value are ready.
    #[test]
    fn b2_13_timeout_bounds() {
        let mk = |timeout_ms: u32| {
            WalrusTestnetPreflightReport::assess(
                WalrusTestnetEndpoint::testnet(),
                true,
                true,
                PublishPayloadClass::SyntheticPublicFixture,
                timeout_ms,
                STAMPED_TRACE,
            )
        };
        assert_eq!(mk(0).timeout(), PreflightReadiness::NotReady);
        assert_eq!(
            mk(MAX_PREFLIGHT_TIMEOUT_MS + 1).timeout(),
            PreflightReadiness::NotReady
        );
        assert!(mk(MIN_PREFLIGHT_TIMEOUT_MS).timeout().is_ready());
        assert!(mk(MAX_PREFLIGHT_TIMEOUT_MS).timeout().is_ready());
        assert!(mk(OK_TIMEOUT_MS).timeout().is_ready());
        // The over-cap report is not ready overall.
        assert!(!mk(0).is_ready());
    }

    /// `b2_13_all_dims_must_be_ready` — `is_ready()` is a conjunction: flipping
    /// any single dimension to not-ready (while the other four are ready) makes
    /// the whole report not ready.
    #[test]
    fn b2_13_all_dims_must_be_ready() {
        let ep = WalrusTestnetEndpoint::testnet();
        // All ready -> ready.
        assert!(
            WalrusTestnetPreflightReport::assess(
                ep,
                true,
                true,
                PublishPayloadClass::SyntheticPublicFixture,
                OK_TIMEOUT_MS,
                STAMPED_TRACE,
            )
            .is_ready()
        );
        // DNS off.
        assert!(
            !WalrusTestnetPreflightReport::assess(
                ep,
                false,
                true,
                PublishPayloadClass::SyntheticPublicFixture,
                OK_TIMEOUT_MS,
                STAMPED_TRACE,
            )
            .is_ready()
        );
        // Feature off.
        assert!(
            !WalrusTestnetPreflightReport::assess(
                ep,
                true,
                false,
                PublishPayloadClass::SyntheticPublicFixture,
                OK_TIMEOUT_MS,
                STAMPED_TRACE,
            )
            .is_ready()
        );
        // Class denied.
        assert!(
            !WalrusTestnetPreflightReport::assess(
                ep,
                true,
                true,
                PublishPayloadClass::SecretLike,
                OK_TIMEOUT_MS,
                STAMPED_TRACE,
            )
            .is_ready()
        );
        // Timeout invalid.
        assert!(
            !WalrusTestnetPreflightReport::assess(
                ep,
                true,
                true,
                PublishPayloadClass::SyntheticPublicFixture,
                0,
                STAMPED_TRACE,
            )
            .is_ready()
        );
        // Trace missing.
        assert!(
            !WalrusTestnetPreflightReport::assess(
                ep,
                true,
                true,
                PublishPayloadClass::SyntheticPublicFixture,
                OK_TIMEOUT_MS,
                MISSING_TRACE,
            )
            .is_ready()
        );
    }
}
