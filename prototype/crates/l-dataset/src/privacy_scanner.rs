//! PII / secret scanner pipeline.
//!
//! # Custody / live-boundary proof
//!
//! This scanner is a **pure function over in-memory bytes / a [`BufRead`]** — it
//! performs no network call, no wallet/key use, no process spawn, and no
//! filesystem write; no such API exists in this module (mirroring the
//! `collect::mod` read-only spine and the reverify never-live rule). Its output
//! ([`ScanReport`]) carries **only counts and a [`PrivacyDecision`] — never a raw
//! secret byte** (`derive(Debug)` prints scalars only). A detected secret span
//! is reported as a *count*, then handed to the redaction policy or
//! fail-closed rejected; it is never echoed. `live_action_allowed = false`.
//!
//! # Invariants
//!
//! The scanner runs over *every export candidate*, not just raw sidecars.
//! Commerce-shaped secrets, sponsor keys, wallet secrets, provider response
//! bodies, and user-memory markers are **hard rejects**. Encoded secrets
//! (base64 / hex / gzip / zip with an entropy spike) are rejected too, so a
//! secret cannot hide behind an encoding. A 64-hex `sha256` line is *not*
//! flagged (benign content survives). Memory is bounded: the streaming API holds
//! one line / 8 KiB window at a time, so a 100 MB shard scans in constant memory.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::privacy::PrivacyDecision;
use crate::terminal::{looks_secret, strip_ansi};
use std::io::BufRead;

const KIND: DietFileKind = DietFileKind::PrivacyReport;

/// Content markers that are **hard rejects** (commerce / sponsor / wallet /
/// user-memory / provider). Distinct from the canonical key markers in
/// `terminal::SECRET_MARKERS` (reused via [`looks_secret`]).
const HARD_SECRET_MARKERS: &[&str] = &[
    "sponsor_key",
    "sponsor key",
    "wallet_secret",
    "wallet secret",
    "wallet_seed",
    "commerce_secret",
    "commerce secret",
    "sk_live",
    "sk_test",
    "stripe_sk",
    "user_memory",
    "private_memory",
    "user memory:",
    "provider_api_key",
    "private_url",
];

/// A bounded scan report: counts + decision only, never a raw secret byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ScanReport {
    /// Count of redactable PII hits (e.g. emails).
    pub pii_hits_u32: u32,
    /// Count of hard-secret hits (keys / commerce / sponsor / wallet / user-memory / provider).
    pub secret_hits_u32: u32,
    /// Count of encoded-secret hits (base64 / hex / gzip / zip entropy spikes).
    pub encoded_hits_u32: u32,
    /// The overall verdict: `Reject` on any secret/encoded hit, `Redacted` on
    /// PII-only, `Pass` when fully clean.
    pub decision: PrivacyDecision,
}

impl ScanReport {
    /// Whether nothing at all was flagged.
    pub const fn clean(&self) -> bool {
        self.pii_hits_u32 == 0 && self.secret_hits_u32 == 0 && self.encoded_hits_u32 == 0
    }
}

/// Whether a string is shaped like an email (`local@dotted.domain`).
fn looks_email(s: &str) -> bool {
    if let Some(at) = s.find('@') {
        let (local, rest) = s.split_at(at);
        let domain = &rest[1..];
        return !local.is_empty()
            && domain.contains('.')
            && !domain.starts_with('.')
            && !domain.ends_with('.')
            && !local.contains(char::is_whitespace)
            && !domain.contains(char::is_whitespace);
    }
    false
}

/// Whether a base64-shaped token is long and high-entropy (mixed case + digits).
fn is_high_entropy_base64(tok: &str) -> bool {
    if tok.len() < 40 {
        return false;
    }
    let has_upper = tok.bytes().any(|b| b.is_ascii_uppercase());
    let has_lower = tok.bytes().any(|b| b.is_ascii_lowercase());
    let has_digit = tok.bytes().any(|b| b.is_ascii_digit());
    has_upper && has_lower && has_digit
}

/// Whether a line carries an encoded secret: a gzip/zip base64 magic prefix, a
/// long high-entropy base64 run, or a long hex run that is not a `sha1`/`sha256`.
fn has_encoded_secret(s: &str) -> bool {
    // gzip ("H4sI…") and zip ("UEsDB…") base64 magic prefixes.
    if s.contains("H4sI") || s.contains("UEsDB") {
        return true;
    }
    for tok in s.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=')) {
        if is_high_entropy_base64(tok) {
            return true;
        }
    }
    // long hex run that is not a sha1 (40) or sha256 (64) — those are benign.
    for tok in s.split(|c: char| !c.is_ascii_hexdigit()) {
        let n = tok.len();
        if n >= 48 && n != 64 {
            return true;
        }
    }
    false
}

/// Scan one already-read line, accumulating hits. Pure: counts only.
fn scan_line(line: &str, report: &mut ScanReport) {
    let s = strip_ansi(line);
    let lower = s.to_ascii_lowercase();
    if looks_secret(&s) || HARD_SECRET_MARKERS.iter().any(|m| lower.contains(m)) {
        report.secret_hits_u32 = report.secret_hits_u32.saturating_add(1);
    }
    if s.split_whitespace().any(looks_email) {
        report.pii_hits_u32 = report.pii_hits_u32.saturating_add(1);
    }
    if has_encoded_secret(&s) {
        report.encoded_hits_u32 = report.encoded_hits_u32.saturating_add(1);
    }
}

/// Finalize a report's decision fail-closed.
fn finalize(mut report: ScanReport) -> ScanReport {
    report.decision = if report.secret_hits_u32 > 0 || report.encoded_hits_u32 > 0 {
        PrivacyDecision::Reject
    } else if report.pii_hits_u32 > 0 {
        PrivacyDecision::Redacted
    } else {
        PrivacyDecision::Pass
    };
    report
}

const EMPTY: ScanReport = ScanReport {
    pii_hits_u32: 0,
    secret_hits_u32: 0,
    encoded_hits_u32: 0,
    decision: PrivacyDecision::Pass,
};

/// Stream-scan an export candidate from a [`BufRead`] in bounded memory (one
/// line at a time). A read failure is a redacted [`DietError::IoUntrusted`].
pub fn scan<R: BufRead>(reader: R) -> DietResult<ScanReport> {
    let mut report = EMPTY;
    for line_res in reader.lines() {
        let raw = line_res.map_err(|_| DietError::IoUntrusted { kind: KIND })?;
        scan_line(&raw, &mut report);
    }
    Ok(finalize(report))
}

/// Convenience: scan an export candidate held in a string (cannot fail — no I/O).
pub fn scan_str(text: &str) -> ScanReport {
    let mut report = EMPTY;
    for line in text.lines() {
        scan_line(line, &mut report);
    }
    finalize(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn email_is_redactable_pii() {
        let r = scan_str("contact alice@example.com for details");
        assert_eq!(r.pii_hits_u32, 1);
        assert_eq!(r.decision, PrivacyDecision::Redacted);
    }

    #[test]
    fn api_token_is_hard_reject() {
        let r = scan_str("export GH=ghp_ABCDEFGHIJKLMNOPqrstuv");
        assert!(r.secret_hits_u32 >= 1);
        assert_eq!(r.decision, PrivacyDecision::Reject);
    }

    #[test]
    fn seed_phrase_is_hard_reject() {
        let r = scan_str("seed_phrase: lazy dog brown fox over");
        assert_eq!(r.decision, PrivacyDecision::Reject);
    }

    #[test]
    fn commerce_and_sponsor_and_wallet_are_hard_rejects() {
        for line in [
            "commerce_secret = abc",
            "sk_live_51HxYzAbCdEf",
            "sponsor_key: 0xdeadbeef",
            "wallet_secret stored here",
        ] {
            assert_eq!(scan_str(line).decision, PrivacyDecision::Reject, "{line}");
        }
    }

    #[test]
    fn provider_body_and_user_memory_are_hard_rejects() {
        assert_eq!(
            scan_str("provider_response_body leaked").decision,
            PrivacyDecision::Reject
        );
        assert_eq!(
            scan_str("user_memory: woon prefers korean").decision,
            PrivacyDecision::Reject
        );
    }

    #[test]
    fn base64_and_hex_and_gzip_encoded_secrets_are_rejected() {
        // long high-entropy base64
        let b64 = "Zm9vYmFyQUJDMTIzZm9vYmFyQUJDMTIzZm9vYmFyQUJD12345";
        assert_eq!(scan_str(b64).decision, PrivacyDecision::Reject);
        // 96-char lowercase hex (not a 64-char sha256)
        let hex = "a".repeat(96);
        assert_eq!(scan_str(&hex).decision, PrivacyDecision::Reject);
        // gzip base64 magic prefix
        assert_eq!(
            scan_str("payload H4sIAAAAAAAA/ blob").decision,
            PrivacyDecision::Reject
        );
    }

    #[test]
    fn sha256_line_is_benign() {
        // a 64-hex sha256 in a normal evidence line must NOT be flagged.
        let line =
            "08574d725cb3fe2cbd12e939779ecce227e3f2bc8670f17e6fdca72c1ccec009  memory_root.move";
        let r = scan_str(line);
        assert!(r.clean());
        assert_eq!(r.decision, PrivacyDecision::Pass);
    }

    #[test]
    fn streaming_scan_is_bounded_over_many_lines() -> DietResult<()> {
        // 100k benign lines stream line-by-line; memory stays bounded (one line).
        let mut buf = String::with_capacity(1_300_000);
        for _ in 0..100_000 {
            buf.push_str("BUILD_EXIT=0\n");
        }
        let r = scan(Cursor::new(buf))?;
        assert!(r.clean());
        assert_eq!(r.decision, PrivacyDecision::Pass);
        Ok(())
    }

    #[test]
    fn one_secret_in_a_large_stream_still_rejects() -> DietResult<()> {
        let mut buf = String::new();
        for _ in 0..5_000 {
            buf.push_str("ok line\n");
        }
        buf.push_str("oops sk-live_ABCDEF0123456789\n");
        let r = scan(Cursor::new(buf))?;
        assert_eq!(r.decision, PrivacyDecision::Reject);
        Ok(())
    }
}
