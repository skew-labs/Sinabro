//! Stage C Walrus mainnet read/preflight (C-WP-06A · atom #222 · C.2.3).
//!
//! Canonical OUT: [`WalrusMainnetPreflight`] — a **read-only** preflight check
//! for a [`MainnetWalrusEndpoint`] (atom #220). It validates the policy that a
//! later synthetic-PUT ceremony would have to satisfy — payload class, body
//! cap, timeout, and a mainnet-PUT feature gate — **without** issuing any PUT.
//! No socket is opened.
//!
//! # Madness invariants (atom #222)
//!
//! * **No PUT.** This atom is read-only/preflight. It produces an evidence
//!   record, never a network write.
//! * **Feature-gated.** A preflight where the mainnet-PUT feature is off is
//!   rejected ([`PreflightReject::FeatureOff`]): the live ceremony is
//!   disabled by default and only the explicit ceremony rail (atom #223 +
//!   operator approval) can enable it.
//! * **Synthetic-only policy reuse (no re-mint).** The preflight reuses the
//!   atom #8 [`PublishPayloadClass`] policy (only
//!   [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture)
//!   is admissible) and the atom #8 body cap
//!   [`PUBLIC_PUBLISHER_BODY_CAP_BYTES`]. A private payload class is rejected
//!   ([`PreflightReject::NonSyntheticClass`]); an over-cap body is rejected
//!   ([`PreflightReject::BodyOverCap`]). It does **not** import the b-memory
//!   `WalrusMainnetPrepare` type (that would form a `c-walrus -> b-memory`
//!   cycle); it reuses the shared c-walrus policy primitives instead.

use crate::publisher::{PUBLIC_PUBLISHER_BODY_CAP_BYTES, PublishPayloadClass};
use crate::stage_c_mainnet_endpoint::{MainnetEndpointMode, MainnetWalrusEndpoint};

/// The mainnet preflight request timeout, in seconds. Latency/policy info only;
/// no request is actually issued in this atom.
pub const MAINNET_PREFLIGHT_TIMEOUT_SECS: u32 = 30;

/// Read-only preflight evidence for a mainnet Walrus endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusMainnetPreflight {
    /// The endpoint mode the preflight was run against.
    pub mode: MainnetEndpointMode,
    /// The request timeout the ceremony would use (info only).
    pub timeout_secs_u32: u32,
    /// The atom #8 public body cap, in bytes.
    pub body_cap_bytes_u32: u32,
    /// The observed prepared-payload size, in bytes (`<= body_cap_bytes_u32`).
    pub observed_body_bytes_u32: u32,
    /// The admitted payload class (always
    /// [`SyntheticPublicFixture`](PublishPayloadClass::SyntheticPublicFixture)).
    pub payload_class: PublishPayloadClass,
}

/// Preflight rejection reason. Data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PreflightReject {
    /// The mainnet-PUT feature is off — the ceremony is disabled by default.
    FeatureOff = 1,
    /// The payload class is not the only admissible synthetic public fixture.
    NonSyntheticClass = 2,
    /// The observed body exceeds the atom #8 public body cap.
    BodyOverCap = 3,
}

impl core::fmt::Display for PreflightReject {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::FeatureOff => "mainnet preflight: mainnet-PUT feature off (disabled by default)",
            Self::NonSyntheticClass => "mainnet preflight: only SyntheticPublicFixture is admitted",
            Self::BodyOverCap => "mainnet preflight: body exceeds public publisher cap",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for PreflightReject {}

/// Run the read-only preflight for `endpoint`.
///
/// Issues no network request. `mainnet_put_feature_on` models the
/// disabled-by-default ceremony gate (atom #223 / operator approval); when
/// `false`, the preflight refuses.
///
/// # Errors
///
/// [`PreflightReject`] for a feature-off gate, a non-synthetic payload class,
/// or an over-cap body.
pub fn preflight_mainnet_endpoint(
    endpoint: &MainnetWalrusEndpoint,
    payload_class: PublishPayloadClass,
    observed_body_bytes: u32,
    mainnet_put_feature_on: bool,
) -> Result<WalrusMainnetPreflight, PreflightReject> {
    if !mainnet_put_feature_on {
        return Err(PreflightReject::FeatureOff);
    }
    if payload_class != PublishPayloadClass::SyntheticPublicFixture {
        return Err(PreflightReject::NonSyntheticClass);
    }
    let cap = PUBLIC_PUBLISHER_BODY_CAP_BYTES;
    if observed_body_bytes > cap {
        return Err(PreflightReject::BodyOverCap);
    }
    Ok(WalrusMainnetPreflight {
        mode: endpoint.mode(),
        timeout_secs_u32: MAINNET_PREFLIGHT_TIMEOUT_SECS,
        body_cap_bytes_u32: cap,
        observed_body_bytes_u32: observed_body_bytes,
        payload_class,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use mnemos_a_core::{MainnetExecutionState, SealedMainnetConfig, StageCChainEnv};

    fn endpoint() -> MainnetWalrusEndpoint {
        let cfg = SealedMainnetConfig {
            chain_env: StageCChainEnv::MainnetPrepared,
            execution_state: MainnetExecutionState::Locked,
            checklist_receipt_hash_32: [0x11u8; 32],
        };
        MainnetWalrusEndpoint::from_sealed_config(
            &cfg,
            MainnetEndpointMode::OfficialMainnet,
            None,
            None,
        )
        .expect("official endpoint")
    }

    /// `c2_3_feature_off_reject` — preflight refuses when the mainnet-PUT
    /// feature is off (disabled by default).
    #[test]
    fn c2_3_feature_off_reject() {
        let ep = endpoint();
        assert_eq!(
            preflight_mainnet_endpoint(&ep, PublishPayloadClass::SyntheticPublicFixture, 64, false,),
            Err(PreflightReject::FeatureOff),
        );
    }

    /// `c2_3_mock_mainnet_ok` — a synthetic, within-cap payload with the
    /// feature on yields a preflight record (no PUT issued).
    #[test]
    fn c2_3_mock_mainnet_ok() {
        let ep = endpoint();
        let report =
            preflight_mainnet_endpoint(&ep, PublishPayloadClass::SyntheticPublicFixture, 64, true)
                .expect("preflight ok");
        assert_eq!(report.mode, MainnetEndpointMode::OfficialMainnet);
        assert_eq!(report.timeout_secs_u32, MAINNET_PREFLIGHT_TIMEOUT_SECS);
        assert_eq!(report.observed_body_bytes_u32, 64);
        assert!(report.observed_body_bytes_u32 <= report.body_cap_bytes_u32);
        assert_eq!(
            report.payload_class,
            PublishPayloadClass::SyntheticPublicFixture
        );

        // An over-cap body is rejected.
        assert_eq!(
            preflight_mainnet_endpoint(
                &ep,
                PublishPayloadClass::SyntheticPublicFixture,
                report.body_cap_bytes_u32 + 1,
                true,
            ),
            Err(PreflightReject::BodyOverCap),
        );
    }

    /// `c2_3_private_payload_red` — a non-synthetic payload class is rejected.
    #[test]
    fn c2_3_private_payload_red() {
        let ep = endpoint();
        for class in [
            PublishPayloadClass::RealUserMemory,
            PublishPayloadClass::PromptOrProviderText,
            PublishPayloadClass::ToolOutput,
            PublishPayloadClass::SecretLike,
            PublishPayloadClass::PrivateProvenance,
        ] {
            assert_eq!(
                preflight_mainnet_endpoint(&ep, class, 64, true),
                Err(PreflightReject::NonSyntheticClass),
                "class {class:?} must be rejected",
            );
        }
    }
}
