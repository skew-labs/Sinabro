//! Operational provider-body redaction gate + receipt (atom #494 · G.1.3).
//!
//! Stage F minted the secret scanners ([`crate::secrets::scan_inline_secret`],
//! [`crate::repl::history::classify`]) and the Stage-B-tombstone reuse pattern
//! (a deleted-id slice — F precedent `model_compress::assemble_context`). Stage A
//! minted the [`RedactionClass`] taxonomy. Stage G composes them into one
//! **before-send gate**: private memory and any tombstoned (deleted) memory id
//! deny the whole send; secret-shaped fragments are dropped (denied per-fragment);
//! and a stable [`RedactionReceipt`] is returned.
//!
//! Secret custody (`G-G-SECRET-ZERO`, `G-G-PII0`): this gate is pure (no I/O); it
//! never stores, clones, `Debug`-prints, or transmits any raw secret — secret
//! fragments are counted and dropped, never hashed or retained. The receipt
//! proves [`RedactionReceipt::provider_body_stored`] is the invariant `false`.
//!
//! Reuse (no reinvention): [`scan_inline_secret`](crate::secrets::scan_inline_secret),
//! [`classify`](crate::repl::history::classify), [`RedactionClass`] from
//! `mnemos_a_core`, and [`crate::sha256_32`].

use mnemos_a_core::RedactionClass;

use crate::repl::history::classify;
use crate::secrets::scan_inline_secret;
use crate::sha256_32;

/// Why the redaction gate denied the whole send (fail-closed).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RedactionReject {
    /// Private memory was requested in the outbound payload (default deny).
    PrivateMemoryIncluded = 1,
    /// A tombstoned (deleted) memory id appeared among the candidates
    /// (no resurrection).
    TombstonedMemoryIncluded = 2,
}

/// The outbound content to be gated before any external send.
#[derive(Clone, Copy, Debug)]
pub struct RedactionRequest<'a> {
    /// The candidate text fragments to send.
    pub fragments: &'a [&'a str],
    /// The candidate memory ids referenced by the payload.
    pub candidate_memory_ids: &'a [[u8; 32]],
    /// The tombstoned (deleted) memory ids (Stage B delete/replay truth).
    pub deleted_ids: &'a [[u8; 32]],
    /// Whether private memory is requested in the payload (default deny).
    pub include_private_memory: bool,
}

/// The receipt of a successful before-send redaction. Carries only hashes and
/// counts — never a raw fragment or secret.
///
/// # SI-2 — the unforgeable receipt (the single egress choke)
///
/// Every field is **private** and the ONLY constructor is [`redact`]. A
/// `RedactionReceipt` therefore cannot exist unless it came out of the redaction
/// gate — so anything that requires one ([`RedactedConsult`] /
/// [`RedactedTelegramSend`]) is transitively `redact()`-only. The "outbound byte
/// that never passed redaction" state is UNREPRESENTABLE (PD-4), not
/// runtime-checked. Egress codecs read the fields through `pub(crate)` accessors.
///
/// A hand-forged struct literal does NOT compile (private fields, no public ctor):
/// ```compile_fail
/// let _forged = sinabro::provider::redaction::RedactionReceipt {
///     outgoing_fragment_count_u32: 1,
///     secret_fragments_denied_u32: 0,
///     redacted_payload_hash_32: [0u8; 32],
///     provider_body_stored: false,
///     strongest_class: mnemos_a_core::RedactionClass::PublicSafe,
/// };
/// ```
/// Nor can a field be read or mutated directly — the fields are private; read the
/// value through the `pub` accessors instead:
/// ```compile_fail
/// let req = sinabro::provider::redaction::RedactionRequest {
///     fragments: &[],
///     candidate_memory_ids: &[],
///     deleted_ids: &[],
///     include_private_memory: false,
/// };
/// let receipt = sinabro::provider::redaction::redact(&req).expect("public input");
/// let _read = receipt.provider_body_stored; // private field → does NOT compile
/// ```
///
/// [`RedactedConsult`]: crate::provider::egress::RedactedConsult
/// [`RedactedTelegramSend`]: crate::telegram::egress::RedactedTelegramSend
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RedactionReceipt {
    /// The number of fragments that passed (carried no secret).
    outgoing_fragment_count_u32: u32,
    /// The number of fragments dropped because they were secret-shaped.
    secret_fragments_denied_u32: u32,
    /// SHA-256 of the redacted (secret-free) payload — stable for equal input.
    redacted_payload_hash_32: [u8; 32],
    /// Invariant `false`: the raw provider body is never stored.
    provider_body_stored: bool,
    /// The strongest redaction class applied (`SecretLikeRedacted` if any
    /// fragment was dropped, else `PublicSafe`).
    strongest_class: RedactionClass,
}

impl RedactionReceipt {
    /// The number of fragments that passed (carried no secret).
    #[must_use]
    pub const fn outgoing_fragment_count_u32(&self) -> u32 {
        self.outgoing_fragment_count_u32
    }

    /// The number of fragments dropped because they were secret-shaped.
    #[must_use]
    pub const fn secret_fragments_denied_u32(&self) -> u32 {
        self.secret_fragments_denied_u32
    }

    /// SHA-256 of the redacted (secret-free) payload — the only content reference
    /// that ever leaves.
    #[must_use]
    pub const fn redacted_payload_hash_32(&self) -> [u8; 32] {
        self.redacted_payload_hash_32
    }

    /// Invariant `false`: the raw provider body is never stored.
    #[must_use]
    pub const fn provider_body_stored(&self) -> bool {
        self.provider_body_stored
    }
}

/// TEST-ONLY forge. Builds a receipt with arbitrary fields so cross-module tests
/// can exercise downstream reject paths (e.g.
/// [`RedactedConsult::new`](crate::provider::egress::RedactedConsult::new)
/// rejecting a `provider_body_stored == true` receipt — a state [`redact`] never
/// emits). Gated `#[cfg(test)]`: NEVER compiled into any shipping or feature
/// build, so production keeps the SI-2 invariant that the ONLY constructor is
/// [`redact`].
#[cfg(test)]
impl RedactionReceipt {
    pub(crate) const fn forge_for_test(
        outgoing_fragment_count_u32: u32,
        secret_fragments_denied_u32: u32,
        redacted_payload_hash_32: [u8; 32],
        provider_body_stored: bool,
        strongest_class: RedactionClass,
    ) -> Self {
        Self {
            outgoing_fragment_count_u32,
            secret_fragments_denied_u32,
            redacted_payload_hash_32,
            provider_body_stored,
            strongest_class,
        }
    }
}

/// Run the before-send redaction gate. Denies the whole send (fail-closed) when
/// private memory is requested or any candidate id is tombstoned; otherwise drops
/// secret-shaped fragments and returns a [`RedactionReceipt`].
pub fn redact(req: &RedactionRequest<'_>) -> Result<RedactionReceipt, RedactionReject> {
    if req.include_private_memory {
        return Err(RedactionReject::PrivateMemoryIncluded);
    }
    if req
        .candidate_memory_ids
        .iter()
        .any(|id| req.deleted_ids.contains(id))
    {
        return Err(RedactionReject::TombstonedMemoryIncluded);
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut passed: u32 = 0;
    let mut denied: u32 = 0;
    for &frag in req.fragments {
        if scan_inline_secret(frag) || classify(frag).is_some() {
            denied += 1;
        } else {
            passed += 1;
            buf.extend_from_slice(frag.as_bytes());
            buf.push(b'\n');
        }
    }
    let strongest_class = if denied > 0 {
        RedactionClass::SecretLikeRedacted
    } else {
        RedactionClass::PublicSafe
    };
    Ok(RedactionReceipt {
        outgoing_fragment_count_u32: passed,
        secret_fragments_denied_u32: denied,
        redacted_payload_hash_32: sha256_32(&buf),
        provider_body_stored: false,
        strongest_class,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    const SECRET: &str = "key = \"suiprivkey1qexamplenotreal\"";

    fn request<'a>(
        fragments: &'a [&'a str],
        candidate_memory_ids: &'a [[u8; 32]],
        deleted_ids: &'a [[u8; 32]],
        include_private_memory: bool,
    ) -> RedactionRequest<'a> {
        RedactionRequest {
            fragments,
            candidate_memory_ids,
            deleted_ids,
            include_private_memory,
        }
    }

    #[test]
    fn private_memory_deny() {
        let frags: [&str; 1] = ["route=advisory"];
        let r = redact(&request(&frags, &[], &[], true));
        assert_eq!(r, Err(RedactionReject::PrivateMemoryIncluded));
    }

    #[test]
    fn tombstone_deny() {
        let frags: [&str; 1] = ["route=advisory"];
        let deleted = [[7u8; 32]];
        let candidates = [[7u8; 32]];
        let r = redact(&request(&frags, &candidates, &deleted, false));
        assert_eq!(r, Err(RedactionReject::TombstonedMemoryIncluded));
    }

    #[test]
    fn secret_pattern_denied_per_fragment() {
        let frags: [&str; 2] = ["route=advisory", SECRET];
        let r = redact(&request(&frags, &[], &[], false));
        assert!(
            r.is_ok(),
            "non-private, non-tombstoned send proceeds with secrets dropped"
        );
        if let Ok(receipt) = r {
            assert_eq!(
                receipt.secret_fragments_denied_u32, 1,
                "the secret fragment is dropped"
            );
            assert_eq!(
                receipt.outgoing_fragment_count_u32, 1,
                "only the benign fragment passes"
            );
            assert_eq!(receipt.strongest_class, RedactionClass::SecretLikeRedacted);
        }
    }

    #[test]
    fn redacted_hash_stable() {
        let frags: [&str; 2] = ["a-fragment", "b-fragment"];
        let r1 = redact(&request(&frags, &[], &[], false));
        let r2 = redact(&request(&frags, &[], &[], false));
        assert!(r1.is_ok() && r2.is_ok());
        if let (Ok(a), Ok(b)) = (r1, r2) {
            assert_eq!(a.redacted_payload_hash_32, b.redacted_payload_hash_32);
            assert_eq!(a.strongest_class, RedactionClass::PublicSafe);
        }
    }

    #[test]
    fn provider_body_zero() {
        let frags: [&str; 1] = ["route=advisory"];
        let r = redact(&request(&frags, &[], &[], false));
        assert!(r.is_ok());
        if let Ok(receipt) = r {
            assert!(
                !receipt.provider_body_stored,
                "the raw provider body is never stored"
            );
        }
    }

    #[test]
    fn redaction_p95_within_50ms() {
        let frags: [&str; 3] = ["route=advisory", SECRET, "evidence=hash"];
        let req = request(&frags, &[], &[], false);
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let r = redact(&req);
            std::hint::black_box(&r);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 50, "redaction p95 {p95}ms exceeds 50ms");
    }
}
