//! Redacted output envelope with a deterministic size cap.
//!
//! A sandbox run's output is summarised into an [`OutputEnvelope`] that **never
//! carries the raw bytes**: it holds only lengths, a `truncated` / `redacted`
//! flag pair, and a content digest. A try-before-use result can therefore prove
//! usefulness (the digest is stable and the length is known) without leaking
//! file contents, secrets, or package internals. Output beyond the cap
//! truncates deterministically, and a secret-shaped run (a long hex blob) is
//! redacted before the digest is taken.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::package::blake2b_256;

/// Domain tag for the output-envelope content digest.
pub(crate) const DOMAIN_OUTPUT: &[u8] = b"mnemos.d.wasm_output.v1";

/// Marker substituted for a redacted secret-shaped run.
const REDACTION_MARKER: &[u8] = b"[REDACTED]";
/// Minimum length of a contiguous hex run treated as secret-shaped (covers a
/// 32-byte key/hash rendered as 64 hex chars, with headroom below).
const SECRET_HEX_RUN_MIN: usize = 48;

/// Summary of a sandbox run's output. Carries no raw output bytes — only
/// lengths, the truncated/redacted flags, and a content digest — so it cannot
/// leak file contents or secrets by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct OutputEnvelope {
    /// Length of the run's original output before any cap/redaction.
    pub original_len_u32: u32,
    /// Length of the bytes that were actually digested (post-cap, post-redact).
    pub emitted_len_u32: u32,
    /// Whether the original output exceeded the cap and was truncated.
    pub truncated: bool,
    /// Whether a secret-shaped run was detected and redacted before digesting.
    pub redacted: bool,
    /// Blake2b-256 of the emitted (capped, possibly-redacted) bytes — stable
    /// for identical input, and never the raw secret.
    pub digest_32: [u8; 32],
}

/// Replace every contiguous run of >= [`SECRET_HEX_RUN_MIN`] ASCII hex digits
/// with [`REDACTION_MARKER`]. Returns the rewritten bytes and whether any
/// redaction occurred.
fn redact_secret_runs(bytes: &[u8]) -> (Vec<u8>, bool) {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut redacted = false;
    let mut i = 0usize;
    while i < bytes.len() {
        // Measure a hex run starting at i.
        let mut j = i;
        while j < bytes.len() && bytes[j].is_ascii_hexdigit() {
            j += 1;
        }
        if j - i >= SECRET_HEX_RUN_MIN {
            out.extend_from_slice(REDACTION_MARKER);
            redacted = true;
            i = j;
        } else {
            // Copy a single byte and advance; the run (if any) was too short.
            out.push(bytes[i]);
            i += 1;
        }
    }
    (out, redacted)
}

/// Build an output envelope from `raw` output bytes under a `cap_bytes` size
/// cap. Truncation is deterministic (first `cap_bytes` bytes); a secret-shaped
/// run is redacted before the digest is computed. Never panics.
#[must_use]
pub fn build_output_envelope(raw: &[u8], cap_bytes: u32) -> OutputEnvelope {
    let original_len_u32 = u32::try_from(raw.len()).unwrap_or(u32::MAX);
    let cap = cap_bytes as usize;
    let truncated = raw.len() > cap;
    let capped: &[u8] = if truncated { &raw[..cap] } else { raw };
    let (emitted, redacted) = redact_secret_runs(capped);
    let emitted_len_u32 = u32::try_from(emitted.len()).unwrap_or(u32::MAX);
    let digest_32 = blake2b_256(&[DOMAIN_OUTPUT, &emitted]);
    OutputEnvelope {
        original_len_u32,
        emitted_len_u32,
        truncated,
        redacted,
        digest_32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn size_cap_truncates_deterministically() {
        let raw = [b'a'; 100];
        let e = build_output_envelope(&raw, 10);
        assert_eq!(e.original_len_u32, 100);
        assert_eq!(e.emitted_len_u32, 10);
        assert!(e.truncated);
        // Same input ⇒ identical envelope.
        assert_eq!(build_output_envelope(&raw, 10), e);
    }

    #[test]
    fn stable_digest_for_identical_input() {
        let raw = b"hello world useful output";
        assert_eq!(
            build_output_envelope(raw, 1024).digest_32,
            build_output_envelope(raw, 1024).digest_32
        );
    }

    #[test]
    fn secret_like_hex_run_redacted() {
        // 64 hex chars (a 32-byte key/hash) embedded in otherwise-normal output.
        let secret =
            b"result=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef done";
        let e = build_output_envelope(secret, 1024);
        assert!(e.redacted, "a long hex run must be redacted");
        // The redacted digest differs from a digest over the raw secret.
        let raw_digest = blake2b_256(&[DOMAIN_OUTPUT, secret]);
        assert_ne!(
            e.digest_32, raw_digest,
            "digest must be over the redacted form"
        );
    }

    #[test]
    fn short_hex_not_redacted() {
        let e = build_output_envelope(b"id=deadbeef ok", 1024);
        assert!(!e.redacted);
    }

    #[test]
    fn binary_output_does_not_panic_and_is_stable() {
        let raw = [0u8, 1, 2, 255, 254, 0, 7, 9];
        let e = build_output_envelope(&raw, 1024);
        assert!(!e.truncated);
        assert_eq!(build_output_envelope(&raw, 1024), e);
    }
}
