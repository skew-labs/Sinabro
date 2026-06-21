//! `sinabro wallet sign` — sign / simulate **preview** (F-WP-05C, atom #447 ·
//! F.5.4 sign/simulate preview).
//!
//! Blind signing is structurally impossible: an opaque byte payload cannot
//! construct a preview, and the only way to refuse one is the canonical g-wallet
//! signer-boundary refusal ([`mnemos_g_wallet::SignerIsolationBoundary::reject_opaque_request`]).
//! Before any signature the user sees the decoded intent, the dry-run simulate
//! result, and the cost. **Zero live signing happens in Stage F**:
//! [`SignSimulatePreview::live_signing_enabled`] is the invariant `false`, and a
//! real signature would require the [`ApprovalRequirement::TypedPhrase`] gate
//! (the canonical [`CommandRisk::WalletSign`] mapping).
//!
//! Reuse (no reinvention): the opaque-payload refusal and the signer backend
//! taxonomy are g-wallet canonical surfaces; the four human-checkable fields
//! mirror the canonical `SignerDisplayFields` (package / tx digest / policy hash
//! / timelock ETA), projected here as redacted display values + a `u64` ETA.

use crate::command::{ApprovalRequirement, CommandRisk, approval_for};
use crate::hex32;
use mnemos_g_wallet::{SignerBackendKind, SignerBoundaryError, SignerIsolationBoundary};

/// First 16 hex characters of a 32-byte digest — a redacted, display-only prefix.
#[must_use]
fn redact16(bytes: &[u8; 32]) -> String {
    hex32(bytes).chars().take(16).collect()
}

/// The outcome of the local dry-run simulation that must precede any signature.
/// Only [`SimulateOutcome::Ok`] is signable; a mismatch or decode failure blocks
/// the (future, approval-gated) signature.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SimulateOutcome {
    /// Dry-run succeeded and the observed effect shape matched the claimed call.
    Ok = 1,
    /// The dry-run effect shape did not match the claimed call — not signable.
    EffectShapeMismatch = 2,
    /// The intent could not be decoded — not signable (blind signing refused).
    DecodeFailed = 3,
}

impl SimulateOutcome {
    /// Stable u8 tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Whether this outcome permits proceeding toward a signature.
    #[must_use]
    pub const fn is_signable(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// A decoded, human-checkable view of the intent to be signed. There is no
/// opaque-bytes constructor: every field is a decoded, redacted display value, so
/// a preview cannot represent an undecoded payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedIntentView {
    /// Redacted 16-hex prefix of the target package id.
    pub package_redacted: String,
    /// Human-readable function label (e.g. `memory::add_chunk`).
    pub function_label: String,
    /// The gas budget in MIST (public count, no secret).
    pub gas_budget_mist: u64,
    /// Redacted 16-hex prefix of the transaction digest.
    pub tx_digest_redacted: String,
    /// Redacted 16-hex prefix of the bound policy hash.
    pub policy_hash_redacted: String,
    /// The timelock ETA (seconds) after which the signed action could execute.
    pub timelock_eta_secs: u64,
}

impl DecodedIntentView {
    /// Build a decoded intent view from the four canonical signer fields
    /// (package / tx digest / policy hash / timelock ETA) plus the function label
    /// and gas budget. Hashes are redacted on the way in.
    #[must_use]
    pub fn new(
        package_32: &[u8; 32],
        function_label: &str,
        gas_budget_mist: u64,
        tx_digest_32: &[u8; 32],
        policy_hash_32: &[u8; 32],
        timelock_eta_secs: u64,
    ) -> Self {
        Self {
            package_redacted: redact16(package_32),
            function_label: function_label.to_string(),
            gas_budget_mist,
            tx_digest_redacted: redact16(tx_digest_32),
            policy_hash_redacted: redact16(policy_hash_32),
            timelock_eta_secs,
        }
    }

    /// Redacted, colorless decoded-intent lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("package={}", self.package_redacted),
            format!("function={}", self.function_label),
            format!("gas_budget_mist={}", self.gas_budget_mist),
            format!("tx_digest={}", self.tx_digest_redacted),
            format!("policy_hash={}", self.policy_hash_redacted),
            format!("timelock_eta_secs={}", self.timelock_eta_secs),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

/// The full sign/simulate preview shown before any signature. Built only from a
/// decoded intent + a dry-run result, so blind signing cannot be represented.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignSimulatePreview {
    /// The decoded, human-checkable intent.
    pub decoded: DecodedIntentView,
    /// The dry-run simulate result.
    pub simulate: SimulateOutcome,
    /// The cost (gas) the user would pay/sponsor, in MIST.
    pub cost_mist: u64,
    /// Where the signature would be produced (KMS / HSM / TEE / daemon).
    pub signer_backend: SignerBackendKind,
    /// The approval gate a real signature requires (always
    /// [`ApprovalRequirement::TypedPhrase`]).
    pub approval: ApprovalRequirement,
    /// Invariant `false`: no live signing happens in Stage F.
    pub live_signing_enabled: bool,
}

impl SignSimulatePreview {
    /// Build a preview from a decoded intent, a dry-run result, the cost and the
    /// signer backend. The approval gate is the canonical
    /// [`CommandRisk::WalletSign`] mapping; live signing is always disabled.
    #[must_use]
    pub fn from_decoded(
        decoded: DecodedIntentView,
        simulate: SimulateOutcome,
        cost_mist: u64,
        signer_backend: SignerBackendKind,
    ) -> Self {
        Self {
            decoded,
            simulate,
            cost_mist,
            signer_backend,
            approval: approval_for(CommandRisk::WalletSign),
            live_signing_enabled: false,
        }
    }

    /// Whether the preview permits proceeding to a (future, approval-gated)
    /// signature: the dry-run must be `Ok`. Live signing remains disabled.
    #[must_use]
    pub const fn is_signable(&self) -> bool {
        self.simulate.is_signable()
    }

    /// Redacted, colorless preview lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let mut lines = self.decoded.render(rows);
        lines.push(format!("simulate_u8={}", self.simulate.tag()));
        lines.push(format!("cost_mist={}", self.cost_mist));
        lines.push(format!("signer_backend_u8={}", self.signer_backend as u8));
        lines.push(format!("approval_u8={}", self.approval as u8));
        lines.push(format!(
            "live_signing_enabled={}",
            self.live_signing_enabled
        ));
        lines.push(format!("signable={}", self.is_signable()));
        lines.into_iter().take(rows as usize).collect()
    }
}

/// Refuse an opaque byte payload offered for signing — blind signing is
/// impossible. Reuses the canonical g-wallet signer-boundary refusal so the CLI
/// and the (future) mainnet signer agree byte-for-byte on the refusal.
#[must_use]
pub fn preview_opaque_denied(payload: &[u8]) -> SignerBoundaryError {
    SignerIsolationBoundary::reject_opaque_request(payload)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::repl::latency::p95_ms;

    fn decoded() -> DecodedIntentView {
        DecodedIntentView::new(
            &[0x03; 32],
            "memory::add_chunk",
            800_000,
            &[0x04; 32],
            &[0x05; 32],
            3_600,
        )
    }

    #[test]
    fn opaque_bytes_deny() {
        // Any opaque payload is refused via the canonical boundary.
        assert!(matches!(
            preview_opaque_denied(b"\x00\x01\x02 opaque ptb bytes"),
            SignerBoundaryError::OpaquePayloadRejected
        ));
        assert!(matches!(
            preview_opaque_denied(&[]),
            SignerBoundaryError::OpaquePayloadRejected
        ));
    }

    #[test]
    fn decoded_intent_display() {
        let d = decoded();
        let lines = d.render(16);
        assert!(
            lines
                .iter()
                .any(|l| l.contains("function=memory::add_chunk"))
        );
        assert!(lines.iter().any(|l| l.contains("gas_budget_mist=800000")));
        // Hashes are redacted to 16 hex chars (not the full 64).
        assert!(d.package_redacted.len() == 16);
        assert!(d.tx_digest_redacted.len() == 16);
    }

    #[test]
    fn simulate_result_gates_signability() {
        let ok = SignSimulatePreview::from_decoded(
            decoded(),
            SimulateOutcome::Ok,
            800_000,
            SignerBackendKind::Kms,
        );
        assert!(ok.is_signable());

        let mismatch = SignSimulatePreview::from_decoded(
            decoded(),
            SimulateOutcome::EffectShapeMismatch,
            800_000,
            SignerBackendKind::Kms,
        );
        assert!(!mismatch.is_signable());

        let decode_failed = SignSimulatePreview::from_decoded(
            decoded(),
            SimulateOutcome::DecodeFailed,
            0,
            SignerBackendKind::Hsm,
        );
        assert!(!decode_failed.is_signable());
    }

    #[test]
    fn approval_required_and_no_live_signing() {
        let p = SignSimulatePreview::from_decoded(
            decoded(),
            SimulateOutcome::Ok,
            800_000,
            SignerBackendKind::Tee,
        );
        assert_eq!(p.approval, ApprovalRequirement::TypedPhrase);
        assert!(!p.live_signing_enabled, "Stage F never signs live");
    }

    #[test]
    fn preview_p95_within_100ms() {
        let p = SignSimulatePreview::from_decoded(
            decoded(),
            SimulateOutcome::Ok,
            800_000,
            SignerBackendKind::SigningDaemon,
        );
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let lines = p.render(32);
            std::hint::black_box(&lines);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 100, "sign preview p95 {p95}ms exceeds 100ms budget");
    }
}
