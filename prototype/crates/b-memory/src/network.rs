//! Stage B testnet network typed boundary.
//!
//! Stage B touches a live chain exactly once — Sui/Walrus **testnet** — and
//! never a production network. This module makes that invariant *unrepresentable
//! to violate*: the only network type is
//!
//! ```text
//! #[repr(u8)] pub enum StageBNetwork { Testnet = 1 }
//! ```
//!
//! a one-variant enum. There is deliberately **no** variant that names a
//! production network, so no code path — present or future — can select one by
//! constructing this type. Network selection therefore has a single typed
//! degree of freedom, and the typed network guard is
//! satisfied by construction rather than by a runtime check that could be
//! bypassed.
//!
//! # Invariants
//!
//! * **No production-network variant is minted.** The enum has one inhabitant,
//!   [`StageBNetwork::Testnet`]. Adding any other variant is the failure mode
//!   the atom forbids.
//! * **String parsing rejects everything but testnet.** [`parse_label`] accepts
//!   only the canonical label `testnet` (ASCII-case-insensitive, surrounding
//!   whitespace trimmed) and returns `None` for every other label — including
//!   any production-network label, `devnet`, and arbitrary custom strings. The
//!   reject is *fail-closed*: an unrecognized label never resolves to a usable
//!   network.
//! * **No canonical error type is minted for the reject.** The design declares a
//!   network-parse error nowhere (its error enums are `WalrusClientError` /
//!   `BlobIdError`, both downstream of this boundary). Consistent with the
//!   surrounding convention (no handoff error enum → reject expressed as a
//!   predicate, not a new canonical type), the reject here is an `Option`
//!   (`None` = rejected) — a *checker*, not an invented canonical enum.
//! * **An override value is never echoed.** [`resolve_override`] takes an
//!   optional raw label (conceptually the value of [`NETWORK_OVERRIDE_ENV_KEY`])
//!   and yields only a typed network or a data-free rejection. The raw value is
//!   not embedded in the result, so a secret accidentally placed in the
//!   override cannot leak into a `Debug`/log diagnostic. Redaction is by
//!   construction: there is no field that could carry the raw bytes onward.
//!
//! # Reuse map
//!
//! * **Trace reuse** — [`StageBTraceLink`](crate::stage_b_handoff::StageBTraceLink)
//!   is the canonical per-action trace stamp. This is a *parse-only*
//!   boundary with **zero** external action, so it does not consume a trace
//!   here; the trace enters the live network types
//!   (`WalrusPutPlan` / `WalrusGetPlan` carry `StageBTraceLink`). This unconsumed
//!   reuse is flagged, not forced — pulling a trace into a pure string parser
//!   would be premature.
//! * No Stage A wire/address/gas/secret type is reused here either; the chunk
//!   schema and the Walrus/Sui surfaces introduce those.

/// Environment-variable key by convention used to override the Stage B network
/// label. The value is parsed by [`resolve_override`]; an unset key resolves to
/// the single supported network ([`StageBNetwork::Testnet`]), and any value
/// other than the canonical `testnet` label is rejected fail-closed.
///
/// The key name is exposed so callers and tests share one spelling; reading the
/// process environment is a runtime concern intentionally left out of this pure
/// module (no `std::env` access here keeps the parse deterministic and
/// side-effect free).
pub const NETWORK_OVERRIDE_ENV_KEY: &str = "MNEMOS_STAGE_B_NETWORK";

/// The Stage B live network. One variant by design — Stage B is testnet-only,
/// and a production-network value is deliberately *not representable*.
///
/// `#[repr(u8)]` with an explicit discriminant so the byte tag is stable for
/// any future tabular/wire form (mirrors the `Evidence*Class` enums).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageBNetwork {
    /// Sui/Walrus testnet — the only network Stage B may select.
    Testnet = 1,
}

impl StageBNetwork {
    /// The canonical lowercase label for the one supported network. Parsing is
    /// ASCII-case-insensitive against this string after trimming whitespace.
    pub const CANONICAL_LABEL: &'static str = "testnet";

    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Parse a network label, accepting **only** the canonical `testnet` label
    /// (ASCII-case-insensitive, surrounding whitespace trimmed) and rejecting
    /// every other label fail-closed.
    ///
    /// Returns `Some(StageBNetwork::Testnet)` for an accepted label and `None`
    /// for any reject. `None` carries no data, so the rejected raw label cannot
    /// leak through the return value (see the module-level redaction
    /// invariant). There is intentionally no canonical error type — the design
    /// declares none — so the reject is a predicate, not a new enum.
    #[inline]
    pub fn parse_label(label: &str) -> Option<Self> {
        if label.trim().eq_ignore_ascii_case(Self::CANONICAL_LABEL) {
            Some(Self::Testnet)
        } else {
            None
        }
    }

    /// Resolve the Stage B network from an optional override label
    /// (conceptually the value of [`NETWORK_OVERRIDE_ENV_KEY`]).
    ///
    /// * `None` (override unset) resolves to [`StageBNetwork::Testnet`] — the
    ///   sole supported network; an unset override can never select anything
    ///   else because nothing else is representable.
    /// * `Some(label)` is parsed by [`parse_label`]; any non-`testnet` label is
    ///   rejected (`None`).
    ///
    /// The raw override value is never embedded in the result: the only
    /// observable outputs are a typed network or a data-free `None`, so a secret
    /// placed in the override cannot reach a diagnostic. Redaction holds by
    /// construction.
    #[inline]
    pub fn resolve_override(override_label: Option<&str>) -> Option<Self> {
        match override_label {
            None => Some(Self::Testnet),
            Some(label) => Self::parse_label(label),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// `b1_1_testnet_accepted` — the canonical label (and case/whitespace
    /// variants of it) resolves to `Testnet`, and the stable byte tag is `1`.
    #[test]
    fn b1_1_testnet_accepted() {
        assert_eq!(
            StageBNetwork::parse_label("testnet"),
            Some(StageBNetwork::Testnet)
        );
        // ASCII-case-insensitive + trimmed.
        assert_eq!(
            StageBNetwork::parse_label("Testnet"),
            Some(StageBNetwork::Testnet)
        );
        assert_eq!(
            StageBNetwork::parse_label("TESTNET"),
            Some(StageBNetwork::Testnet)
        );
        assert_eq!(
            StageBNetwork::parse_label("  testnet \t"),
            Some(StageBNetwork::Testnet)
        );

        assert_eq!(StageBNetwork::Testnet.tag(), 1);
        assert_eq!(StageBNetwork::CANONICAL_LABEL, "testnet");
    }

    /// `b1_1_nontestnet_rejected` — every non-testnet label is rejected
    /// fail-closed: the forbidden production label, `devnet`, `localnet`, an
    /// empty label, and arbitrary custom strings all yield `None`. (The
    /// forbidden production label appears only here, inside `#[cfg(test)]`, as
    /// reject *evidence* — never on the production parse path, which only ever
    /// compares against the canonical `testnet` label.)
    #[test]
    fn b1_1_nontestnet_rejected() {
        for bad in [
            "mainnet",
            "Mainnet",
            "MAINNET",
            "devnet",
            "localnet",
            "custom-rpc",
            "test",
            "testnett",
            "",
            "   ",
        ] {
            assert_eq!(
                StageBNetwork::parse_label(bad),
                None,
                "label {bad:?} must be rejected fail-closed",
            );
        }
    }

    /// `b1_1_env_override_redacted` — an unset override defaults to `Testnet`;
    /// a recognized override resolves; an unrecognized/secret-bearing override
    /// is rejected and its raw bytes never appear in the result's `Debug`
    /// rendering (redaction-by-construction).
    #[test]
    fn b1_1_env_override_redacted() {
        // Unset → the single supported network (never a production network).
        assert_eq!(
            StageBNetwork::resolve_override(None),
            Some(StageBNetwork::Testnet)
        );
        // Recognized override resolves.
        assert_eq!(
            StageBNetwork::resolve_override(Some("testnet")),
            Some(StageBNetwork::Testnet),
        );

        // A secret-bearing, non-testnet override is rejected, and none of its
        // distinctive substrings can be recovered from the result.
        let secret_override = "mainnet://0xDEADBEEFprivkey?token=s3cr3t";
        let got = StageBNetwork::resolve_override(Some(secret_override));
        assert_eq!(got, None, "non-testnet override must be rejected");

        let rendered = format!("{got:?}");
        for leaked in ["DEADBEEF", "privkey", "s3cr3t", "mainnet", "0x"] {
            assert!(
                !rendered.contains(leaked),
                "rejected override must not leak {leaked:?} into Debug output ({rendered:?})",
            );
        }
        // The key name is a shared constant, not derived from the raw value.
        assert_eq!(NETWORK_OVERRIDE_ENV_KEY, "MNEMOS_STAGE_B_NETWORK");
    }

    /// `b1_1_single_inhabitant` — the typed guard: the enum's only value is
    /// `Testnet`, so neither a parse nor an override can ever produce a
    /// production network. (Construction-level proof; there is no other variant
    /// to assert against.)
    #[test]
    fn b1_1_single_inhabitant() {
        let n = StageBNetwork::Testnet;
        assert_eq!(n, StageBNetwork::Testnet);
        assert_eq!(n.tag(), 1u8);
        // Round-trip through both resolution paths only ever yields Testnet.
        assert_eq!(
            StageBNetwork::parse_label("testnet").map(|x| x.tag()),
            Some(1)
        );
        assert_eq!(
            StageBNetwork::resolve_override(None).map(StageBNetwork::tag),
            Some(1),
        );
    }
}
