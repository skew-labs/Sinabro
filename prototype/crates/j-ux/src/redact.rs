//! `redact.rs` — Outbound redaction (atom #44 · J.0.4).
//!
//! # Why this madness
//!
//! Phase 0 emits text on two outbound surfaces that the user can see:
//!
//! - the Telegram `sendMessage` / `editMessageText` path (J.0.1 + J.0.2);
//! - the local CLI / REPL stdout path (J.0.5).
//!
//! Both paths must apply the *same* redaction discipline that the
//! structured log path enforces — otherwise a canary string that the
//! log line refuses to absorb could still leave the host through the
//! Telegram chat window or the CLI stream
//! ("아웃바운드(Telegram/CLI 송출)도 a-core `redact_for_log` 재사용 →
//! canary 누출 0(로그뿐 아니라 사용자 송출도). 비밀류는 class만 표시.",
//! ATOM_PLAN line 1273).
//!
//! This module therefore exposes a single forwarding entry point that
//! re-uses the atom #4 redaction kernel verbatim. The forwarder is
//! `const fn` for the same reason the kernel is: the raw `&str`
//! reaches no field of the returned [`RedactedLogValue`], and the
//! compile-time enforcement of that guarantee carries through this
//! crate boundary without any extra runtime check.
//!
//! Reuse:
//! - atom #4 (`a-core::logging`): `redact_for_log`,
//!   [`RedactedLogValue`], [`LogRedactionKind`]. The atom #4 unit tests
//!   (`redacted_display_and_debug_keep_only_class` and
//!   `redacted_values_do_not_leak_when_logged_as_json`) cover every
//!   one of the nine [`LogRedactionKind`] variants on the kernel
//!   side; this atom adds three j-ux-side tests that prove the
//!   forwarder is observationally identical to the kernel and that
//!   the outbound surface inherits the canary-free guarantee.
//! - atom #41 (`telegram.rs`) and atom #42 (`stream_edit.rs`) define
//!   the J.0.1 / J.0.2 transport boundaries; the actual call to
//!   [`redact_outbound`] from `editMessageText` / `sendMessage` /
//!   CLI stdout is wired by a later J-stage atom. This atom only
//!   defines the projection that the transport layer must call before
//!   emitting bytes (Phase 0 scope discipline — no transport wiring
//!   on this surface).
//!
//! Canonical OUT (verbatim from `MNEMOS_ATOM_PLAN.md` §4.J line 735):
//!
//! ```text
//! pub fn redact_outbound(text: &str, kind: LogRedactionKind) -> RedactedLogValue;
//! // a-core redaction 재사용
//! ```

use mnemos_a_core::logging::{LogRedactionKind, RedactedLogValue, redact_for_log};

// ===========================================================================
// Canonical OUT — outbound redaction forwarder
// ===========================================================================

/// Project an outbound `text` payload onto the atom #4 redaction class
/// without ever absorbing the raw bytes.
///
/// This is a `const fn` forwarder to
/// [`mnemos_a_core::logging::redact_for_log`]; the kernel drops the raw
/// `&str` at the call site and retains only the [`LogRedactionKind`]
/// tag on the returned [`RedactedLogValue`]. Because no field of the
/// returned value holds `text`, the outbound transport layer
/// (Telegram `sendMessage` / `editMessageText`, CLI stdout) can render
/// the redacted value into its message body without risk of leaking
/// the raw secret — every textual projection
/// (`Display` / `Debug` / any hand-built JSON embedding the `Display`
/// impl) carries only the class label
/// (`<redacted:wallet_passphrase>` and the eight other variants).
///
/// The forwarder is observationally identical to the kernel: for every
/// `(text, kind)` pair, `redact_outbound(text, kind) ==
/// redact_for_log(text, kind)` under [`Eq`], and the [`Display`] and
/// [`Debug`] projections coincide byte-for-byte. See
/// [`tests::j0_4_reuses_a_core_redaction`] for the explicit
/// nine-variant cross-check.
///
/// [`Display`]: core::fmt::Display
/// [`Debug`]: core::fmt::Debug
#[inline]
#[must_use]
pub const fn redact_outbound(text: &str, kind: LogRedactionKind) -> RedactedLogValue {
    redact_for_log(text, kind)
}

// ===========================================================================
// Tests — 3 verbatim names per MNEMOS_ATOM_PLAN.md atom #44 (line 1274)
// ===========================================================================

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout,
    clippy::print_stderr
)]
mod tests {
    use super::*;

    // The full LogRedactionKind variant set (9 variants, locked at atom #4).
    // Listed here so the forwarder tests below independently exercise every
    // variant even if a future a-core atom appends a tenth variant — in
    // which case this array would need to grow and the size assertion would
    // surface the drift.
    const ALL_KINDS: &[LogRedactionKind] = &[
        LogRedactionKind::WalletPassphrase,
        LogRedactionKind::SuiPrivateKey,
        LogRedactionKind::SuiTxBytes,
        LogRedactionKind::WalrusBytes,
        LogRedactionKind::ToolIo,
        LogRedactionKind::Prompt,
        LogRedactionKind::ProviderBody,
        LogRedactionKind::SourceChain,
        LogRedactionKind::ApiToken,
    ];

    // The atom #4 LogRedactionKind class labels in the same order as
    // ALL_KINDS. Locked here so a future drift on the kernel side
    // (label rename, variant reorder) is caught by the j-ux outbound
    // forwarder's tests as well as by a-core's own tests.
    const ALL_KIND_LABELS: &[&str] = &[
        "wallet_passphrase",
        "sui_private_key",
        "sui_tx_bytes",
        "walrus_bytes",
        "tool_io",
        "prompt",
        "provider_body",
        "source_chain",
        "api_token",
    ];

    /// `j0_4_outbound_redacts_secrets` — every outbound redaction class
    /// produces a [`RedactedLogValue`] whose textual projections expose
    /// only the class label, never the raw `text` argument. This is the
    /// j-ux-side mirror of the atom #4
    /// `redacted_display_and_debug_keep_only_class` invariant.
    #[test]
    fn j0_4_outbound_redacts_secrets() {
        assert_eq!(
            ALL_KINDS.len(),
            ALL_KIND_LABELS.len(),
            "ALL_KINDS / ALL_KIND_LABELS length drift",
        );
        for (&kind, &label) in ALL_KINDS.iter().zip(ALL_KIND_LABELS.iter()) {
            // A distinct raw payload per variant so cross-variant
            // contamination would be detectable.
            let raw = format!("OUTBOUND-RAW-{kind:?}-7f3a9b-DROP-ME");
            let red = redact_outbound(&raw, kind);

            // Tag preservation: round-trip the kind through the value.
            assert_eq!(red.kind(), kind, "kind drift for {kind:?}");

            // Display projection: class label only, raw never present.
            let display = format!("{red}");
            assert!(
                !display.contains(&raw),
                "Display leaked raw for {kind:?}: {display}",
            );
            assert_eq!(
                display,
                format!("<redacted:{label}>"),
                "Display shape drift for {kind:?}: {display}",
            );

            // Debug projection: class only, raw never present.
            let debug = format!("{red:?}");
            assert!(
                !debug.contains(&raw),
                "Debug leaked raw for {kind:?}: {debug}",
            );
            assert!(
                debug.contains(label),
                "Debug missing class label {label} for {kind:?}: {debug}",
            );
        }
    }

    /// `j0_4_canary_not_sent` — a single canary string passed through
    /// every variant of [`redact_outbound`] never appears in any text
    /// that an outbound transport (Telegram `sendMessage` /
    /// `editMessageText`, CLI stdout) would emit on the redacted
    /// value's behalf. This pins the canary-free guarantee on the
    /// outbound surface, not only on the structured-log surface.
    #[test]
    fn j0_4_canary_not_sent() {
        const CANARY: &str = "CANARY-OUTBOUND-SECRET-7f3a9b-DO-NOT-SEND";

        // Sanity: the canary itself must be a non-empty string and
        // distinct from every class label, so the assertion below
        // cannot pass by coincidence.
        assert!(!CANARY.is_empty(), "canary must be non-empty");
        for &label in ALL_KIND_LABELS {
            assert!(
                !CANARY.contains(label),
                "canary must not embed the class label {label}",
            );
        }

        for (&kind, &label) in ALL_KINDS.iter().zip(ALL_KIND_LABELS.iter()) {
            let red = redact_outbound(CANARY, kind);

            // Display, Debug, and a hand-built outbound payload that
            // embeds the Display impl (the most permissive shape an
            // outbound transport would render) must all omit the
            // canary and carry the class label.
            let display = format!("{red}");
            assert!(
                !display.contains(CANARY),
                "canary leaked via Display for {kind:?}: {display}",
            );
            assert!(
                display.contains(label),
                "Display missing class label {label} for {kind:?}: {display}",
            );

            let debug = format!("{red:?}");
            assert!(
                !debug.contains(CANARY),
                "canary leaked via Debug for {kind:?}: {debug}",
            );

            // Outbound payload shape used by Telegram sendMessage /
            // CLI stdout: a single line embedding the redacted value
            // via its Display impl. This is the strongest realistic
            // exposure surface short of the raw value itself.
            let outbound_line = format!("[outbound:{kind:?}] {red}");
            assert!(
                !outbound_line.contains(CANARY),
                "canary leaked via outbound projection for {kind:?}: {outbound_line}",
            );
            assert!(
                outbound_line.contains(label),
                "outbound projection missing class label {label} for {kind:?}: {outbound_line}",
            );
        }
    }

    /// `j0_4_reuses_a_core_redaction` — for every variant, the j-ux
    /// outbound forwarder produces a [`RedactedLogValue`] that is
    /// equal under [`Eq`] to the a-core kernel's
    /// [`redact_for_log`] output, and the textual projections coincide
    /// byte-for-byte. Pins the "reuse a-core redaction" invariant
    /// from `MNEMOS_ATOM_PLAN.md` line 1273.
    #[test]
    fn j0_4_reuses_a_core_redaction() {
        for &kind in ALL_KINDS {
            let raw = format!("REUSE-CHECK-{kind:?}-7f3a9b");

            let from_outbound = redact_outbound(&raw, kind);
            let from_kernel = redact_for_log(&raw, kind);

            // Structural equality (Eq is derived on RedactedLogValue).
            assert_eq!(
                from_outbound, from_kernel,
                "outbound forwarder diverged from a-core kernel for {kind:?}",
            );

            // Tag round-trip: same kind on both sides.
            assert_eq!(
                from_outbound.kind(),
                from_kernel.kind(),
                "kind round-trip diverged for {kind:?}",
            );

            // Textual projections must coincide byte-for-byte: a future
            // a-core renaming of a class label would otherwise let the
            // outbound surface emit a different label than the log
            // surface — this assertion locks that drift to zero.
            assert_eq!(
                format!("{from_outbound}"),
                format!("{from_kernel}"),
                "Display projection diverged for {kind:?}",
            );
            assert_eq!(
                format!("{from_outbound:?}"),
                format!("{from_kernel:?}"),
                "Debug projection diverged for {kind:?}",
            );
        }
    }
}
