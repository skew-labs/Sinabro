//! Stage B wallet trace redaction.
//!
//! A redacted wallet trace event: traces include the address suffix, gas, and
//! tx digest only; key material never enters a trace, log, or metrics record.
//!
//! # Invariants
//!
//! * **Allowlist by construction.** [`StageBWalletTrace`] has exactly four
//!   fields — a short public address suffix, the gas in MIST, an optional
//!   public tx digest, and the [`StageBTraceLink`] — and **no**
//!   field that could carry a passphrase, seed, secret key, ciphertext, or
//!   raw transport body. A secret therefore has no field to inhabit; the
//!   redaction holds structurally, not by a runtime scrub.
//! * **Address is truncated to a non-identifying suffix.** Only the trailing
//!   [`STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES`] bytes of the owner address are
//!   carried (the conventional Sui short-suffix), never the secret key the
//!   address derives from (the derivation is one-way regardless).
//! * **`Debug` and the redacted summary print only allowlisted keys.** The
//!   manual `Debug` and [`StageBWalletTrace::redacted_summary`] emit the four
//!   allowlisted fields and nothing else.
//!
//! # Reuse
//!
//! * [`StageBTraceLink`] (`b-memory/src/stage_b_handoff.rs`) — the canonical
//!   per-action trace stamp.
//! * **Stage A redaction** — the same posture as the network and owner
//!   modules: no field carries raw secret/attacker bytes onward.

use mnemos_b_memory::stage_b_handoff::StageBTraceLink;
use mnemos_d_move::types::{GasBudgetMist, SuiAddress};

/// Number of trailing address bytes carried in a wallet trace. Four bytes is
/// the conventional Sui short-suffix — enough to correlate an action to a
/// wallet in evidence, far too few to be a standalone identifier, and never
/// the secret key.
pub const STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES: usize = 4;

/// A redacted wallet trace event.
///
/// Every field is public, non-secret information. There is deliberately no
/// constructor or field that accepts secret material — the type cannot become
/// a key-leak channel. `Debug` is implemented manually (redacting) so the
/// derived form cannot accidentally widen what is printed.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct StageBWalletTrace {
    /// Trailing [`STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES`] of the owner Sui
    /// address (public; one-way-derived from the key).
    address_suffix: [u8; STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES],
    /// Gas spent / budgeted for the action, in MIST (public).
    gas_mist: u64,
    /// Optional public transaction digest (32 bytes) once an action lands.
    tx_digest: Option<[u8; 32]>,
    /// The per-action trace stamp.
    trace: StageBTraceLink,
}

impl StageBWalletTrace {
    /// Build a redacted wallet trace from public action data: the owner
    /// `address` (only its suffix is retained), the `gas` budget/spend, an
    /// optional public `tx_digest`, and the action `trace` stamp.
    ///
    /// No secret is accepted; the owner address is already a one-way
    /// derivation of the key and only its suffix is kept.
    #[must_use]
    pub fn new(
        address: SuiAddress,
        gas: GasBudgetMist,
        tx_digest: Option<[u8; 32]>,
        trace: StageBTraceLink,
    ) -> Self {
        let full = address.as_bytes();
        let mut address_suffix = [0u8; STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES];
        // Copy the trailing N bytes; `full` is 32 bytes and N == 4, so the
        // range is in-bounds by construction.
        address_suffix
            .copy_from_slice(&full[full.len() - STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES..]);
        Self {
            address_suffix,
            gas_mist: gas.get(),
            tx_digest,
            trace,
        }
    }

    /// The trailing address-suffix bytes.
    #[inline]
    #[must_use]
    pub fn address_suffix(&self) -> &[u8; STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES] {
        &self.address_suffix
    }

    /// The gas in MIST.
    #[inline]
    #[must_use]
    pub fn gas_mist(&self) -> u64 {
        self.gas_mist
    }

    /// The optional public tx digest.
    #[inline]
    #[must_use]
    pub fn tx_digest(&self) -> Option<[u8; 32]> {
        self.tx_digest
    }

    /// The linked trace stamp.
    #[inline]
    #[must_use]
    pub fn trace(&self) -> StageBTraceLink {
        self.trace
    }

    /// A single-line redacted summary for metrics / log evidence. Emits only
    /// the four allowlisted fields as lowercase-hex / decimal — never any
    /// secret (there is none to emit).
    #[must_use]
    pub fn redacted_summary(&self) -> String {
        let suffix_hex = hex_lower(&self.address_suffix);
        let digest_field = match self.tx_digest {
            Some(d) => hex_lower(&d),
            None => "none".to_string(),
        };
        format!(
            "addr_suffix={suffix_hex} gas_mist={} tx_digest={digest_field} trace={:?}",
            self.gas_mist, self.trace,
        )
    }
}

impl core::fmt::Debug for StageBWalletTrace {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Redacting: print only the allowlisted public fields. No secret can
        // appear because no secret field exists.
        f.debug_struct("StageBWalletTrace")
            .field("address_suffix", &hex_lower(&self.address_suffix))
            .field("gas_mist", &self.gas_mist)
            .field("tx_digest", &self.tx_digest.map(|d| hex_lower(&d)))
            .field("trace", &self.trace)
            .finish()
    }
}

/// Lowercase-hex encode a byte slice (allocation per call; trace emission is
/// off the hot path). Local, panic-free, no external hex crate.
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// `b4_6_key_canary_not_logged` — a distinctive "secret" byte pattern is
    /// never passed into the trace (there is no field for it), and cannot
    /// appear in the `Debug` or summary rendering. We feed a known address /
    /// gas / digest and assert the render contains exactly those and not the
    /// canary.
    #[test]
    fn b4_6_key_canary_not_logged() {
        // A canary that would be a catastrophe to see in a log.
        let secret_canary_hex = "deadbeefdeadbeefdeadbeefdeadbeef";
        let addr = SuiAddress::new([
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, //
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, //
            0xCA, 0xFE, 0xBA, 0xBE, 0xAB, 0xCD, 0xEF, 0x42, //
        ]);
        let trace = StageBWalletTrace::new(
            addr,
            GasBudgetMist::new(123_456),
            Some([0x9Au8; 32]),
            StageBTraceLink::new(152, 152, 0),
        );

        let rendered = format!("{trace:?} {}", trace.redacted_summary());
        assert!(
            !rendered.contains(secret_canary_hex),
            "the secret canary must never appear: {rendered}",
        );
        // The allowlisted public suffix IS present (last 4 bytes of addr).
        assert!(
            rendered.contains("abcdef42"),
            "address suffix must be shown: {rendered}"
        );
        assert!(rendered.contains("123456"), "gas must be shown: {rendered}");
    }

    /// `b4_6_allowlist_keys_only` — the redacted summary contains exactly the
    /// four allowlisted keys and no other `key=` token.
    #[test]
    fn b4_6_allowlist_keys_only() {
        let trace = StageBWalletTrace::new(
            SuiAddress::new([0x07; 32]),
            GasBudgetMist::new(1),
            None,
            StageBTraceLink::new(152, 152, 1),
        );
        let summary = trace.redacted_summary();
        for key in ["addr_suffix=", "gas_mist=", "tx_digest=", "trace="] {
            assert!(
                summary.contains(key),
                "summary must contain {key}: {summary}"
            );
        }
        // No forbidden key names leak in.
        for forbidden in ["seed=", "secret=", "privkey=", "passphrase=", "ciphertext="] {
            assert!(
                !summary.contains(forbidden),
                "summary must not contain {forbidden}: {summary}",
            );
        }
    }

    /// `b4_6_trace_linked` — the trace stamp round-trips verbatim and
    /// the address suffix is the trailing 4 bytes.
    #[test]
    fn b4_6_trace_linked() {
        let link = StageBTraceLink::new(152, 200, 3);
        let trace = StageBWalletTrace::new(
            SuiAddress::new([
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //
                0xAA, 0xAA, 0xAA, 0xAA, 0x01, 0x02, 0x03, 0x04, //
            ]),
            GasBudgetMist::new(42),
            None,
            link,
        );
        assert_eq!(trace.trace(), link, "trace link must round-trip");
        assert_eq!(trace.address_suffix(), &[0x01, 0x02, 0x03, 0x04]);
        assert_eq!(trace.gas_mist(), 42);
    }
}
