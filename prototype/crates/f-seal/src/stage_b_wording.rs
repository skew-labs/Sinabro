//! atom #157 · B.4.11 — Seal wording guard.
//!
//! ATOM_PLAN line 1303-1312 canonical OUT — a guard against misleading
//! encryption claims. The madness line: "any UX/log/doc phrase claiming real
//! Seal encryption in Stage B is a failure" (line 1307). Stage B has **no real
//! encryption** (the Seal path is a stub, atom #156); any user-facing string,
//! log line, or doc that says otherwise is a safety failure because it would
//! make a user trust a confidentiality property that does not yet exist.
//!
//! This module is a pure string predicate: it carries no secrets, performs no
//! I/O, and returns the frozen [`StageBSealStubError::MisleadingEncryptionClaim`]
//! when a banned affirmative-encryption phrase appears. The canonical safe
//! phrasing is [`STAGE_B_SEAL_STUB_BOUNDARY_PHRASE`] (`"stub boundary"`); the
//! companion runbook `ops/runbooks/stage_b_seal_stub.md` must contain it.

use crate::stage_b_stub::StageBSealStubError;

/// The canonical safe phrasing for the Stage B Seal stub. UX / log / doc copy
/// describing the Seal surface must use boundary-marker language like this and
/// must never assert that bytes are encrypted. The atom #157 runbook
/// (`ops/runbooks/stage_b_seal_stub.md`) is required to contain this phrase.
pub const STAGE_B_SEAL_STUB_BOUNDARY_PHRASE: &str = "stub boundary";

/// Banned affirmative-encryption claim phrases (stored lowercase; matched
/// case-insensitively as substrings). These are full *claims that encryption is
/// happening* — the word "encrypted" alone is NOT banned, so honest negative
/// copy ("no encryption", "not encrypted", "Seal is stubbed, not encrypted")
/// passes. Only phrases asserting an active confidentiality guarantee are
/// rejected.
const BANNED_ENCRYPTION_CLAIMS: &[&str] = &[
    "end-to-end encrypted",
    "end to end encrypted",
    "fully encrypted",
    "encrypted with seal",
    "seal encryption",
    "sealed and encrypted",
    "cryptographically sealed",
    "your memory is encrypted",
    "your data is encrypted",
    "your memories are encrypted",
    "zero-knowledge",
    "zero knowledge",
    "threshold decryption",
    "threshold encryption active",
    "key server protects",
    "aead protected",
    "confidential by encryption",
];

/// Check whether `phrase` is free of misleading real-encryption claims.
///
/// Returns `Ok(())` if no banned affirmative-encryption phrase appears
/// (case-insensitive substring match), otherwise
/// [`StageBSealStubError::MisleadingEncryptionClaim`]. The comparison is
/// ASCII-case-insensitive; the banned list holds full claim phrases so honest
/// negative copy ("no encryption", "not encrypted") is accepted.
#[inline]
pub fn stage_b_wording_ok(phrase: &str) -> Result<(), StageBSealStubError> {
    let lowered = phrase.to_ascii_lowercase();
    for banned in BANNED_ENCRYPTION_CLAIMS {
        if lowered.contains(banned) {
            return Err(StageBSealStubError::MisleadingEncryptionClaim);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test #1 (grep banned phrases): affirmative-encryption claims are rejected
    /// with `MisleadingEncryptionClaim`, case-insensitively.
    #[test]
    fn b4_11_banned_phrases_rejected() {
        for claim in [
            "Your memory is encrypted end-to-end.",
            "ENCRYPTED WITH SEAL — fully private.",
            "Cryptographically Sealed storage.",
            "zero-knowledge guarantees apply",
        ] {
            assert_eq!(
                stage_b_wording_ok(claim),
                Err(StageBSealStubError::MisleadingEncryptionClaim),
                "phrase should be banned: {claim}"
            );
        }
    }

    /// test #2 (docs contain "stub boundary"): the canonical safe phrasing is
    /// accepted, and honest negative copy that mentions "encryption" without
    /// claiming it is active also passes.
    #[test]
    fn b4_11_safe_phrasing_accepted() {
        assert_eq!(
            stage_b_wording_ok(STAGE_B_SEAL_STUB_BOUNDARY_PHRASE),
            Ok(())
        );
        for ok in [
            "Stage B Seal is a stub boundary — no encryption is performed.",
            "This path is not encrypted; it only marks the publish boundary.",
            "Seal is stubbed in Stage B. No key server, no encryption.",
        ] {
            assert_eq!(stage_b_wording_ok(ok), Ok(()), "phrase should pass: {ok}");
        }
    }

    /// The canonical safe phrase is exactly `"stub boundary"`.
    #[test]
    fn b4_11_boundary_phrase_pinned() {
        assert_eq!(STAGE_B_SEAL_STUB_BOUNDARY_PHRASE, "stub boundary");
    }
}
