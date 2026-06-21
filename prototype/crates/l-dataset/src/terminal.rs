//! `terminal_redacted.jsonl` redaction parser (atom #340 · E.0.9).
//!
//! Raw terminal output is never exported. This scanner streams the JSONL log
//! line-by-line in bounded memory, strips ANSI control sequences, and **rejects
//! any secret-like residue** — a private-key block, an API secret-key prefix, a
//! seed-phrase marker, a provider response body — regardless of what the per-
//! line `redaction` marker claims. Benign content (compiler messages, `sha256`
//! hashes, test PASS lines) is left untouched.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use serde_json::Value;
use std::io::BufRead;

const KIND: DietFileKind = DietFileKind::TerminalRedacted;

/// High-signal secret markers. These are specific enough that they do not occur
/// in benign build output (a 64-hex `sha256` line is *not* flagged), but match
/// real key material and the test canary.
const SECRET_MARKERS: &[&str] = &[
    "-----BEGIN ",
    "PRIVATE KEY-----",
    "BEGIN OPENSSH PRIVATE KEY",
    "sk-live_",
    "sk-proj-",
    "sk-ant-api",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "seed_phrase:",
    "mnemonic_phrase:",
    "CANARY-SECRET",
    "provider_response_body",
];

/// A bounded summary of one terminal log (no line text retained).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TerminalScan {
    /// Number of non-blank records scanned.
    pub records_u32: u32,
    /// Number of records whose `redaction` marker was `redacted`.
    pub redacted_u32: u32,
    /// Longest ANSI-stripped `line` length seen (bytes).
    pub max_line_len_u32: u32,
}

/// Remove ANSI escape sequences (`ESC [ … final-byte`) while preserving all
/// other characters, including multi-byte UTF-8 (Korean log lines survive).
pub fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                while let Some(&n) = chars.peek() {
                    chars.next();
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break;
                    }
                }
            }
            // lone ESC (or ESC not starting a CSI) is dropped.
        } else {
            out.push(c);
        }
    }
    out
}

/// Whether an ANSI-stripped line contains high-signal secret residue.
pub fn looks_secret(stripped: &str) -> bool {
    SECRET_MARKERS.iter().any(|m| stripped.contains(m))
}

/// Stream-scan a `terminal_redacted.jsonl` reader. Secret residue in any `line`
/// field is a hard [`DietError::SecretResidue`], regardless of the `redaction`
/// marker (a claim of redaction does not excuse residue actually present).
pub fn scan_terminal<R: BufRead>(reader: R) -> DietResult<TerminalScan> {
    let mut records = 0u32;
    let mut redacted = 0u32;
    let mut max_line_len = 0u32;
    for line_res in reader.lines() {
        let raw = line_res.map_err(|_| DietError::IoUntrusted { kind: KIND })?;
        if raw.trim().is_empty() {
            continue;
        }
        records = records.saturating_add(1);
        let v: Value = serde_json::from_str(&raw).map_err(|_| DietError::MalformedJsonl {
            kind: KIND,
            record_u32: records,
        })?;
        let obj = v.as_object().ok_or(DietError::MalformedJsonl {
            kind: KIND,
            record_u32: records,
        })?;
        let red_state = obj
            .get("redaction")
            .and_then(|x| x.as_str())
            .unwrap_or("none");
        if red_state.eq_ignore_ascii_case("redacted") {
            redacted = redacted.saturating_add(1);
        }
        if let Some(text) = obj.get("line").and_then(|x| x.as_str()) {
            let stripped = strip_ansi(text);
            max_line_len = max_line_len.max(stripped.len().min(u32::MAX as usize) as u32);
            if looks_secret(&stripped) {
                return Err(DietError::SecretResidue { kind: KIND });
            }
        }
    }
    Ok(TerminalScan {
        records_u32: records,
        redacted_u32: redacted,
        max_line_len_u32: max_line_len,
    })
}

/// Convenience: scan a `terminal_redacted.jsonl` document held in a string.
pub fn scan_terminal_str(text: &str) -> DietResult<TerminalScan> {
    scan_terminal(text.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_output_passes_and_counts() -> DietResult<()> {
        let doc = concat!(
            r#"{"n":1,"line":"BUILD_EXIT=0","redaction":"none"}"#,
            "\n",
            r#"{"n":2,"line":"08574d725cb3fe2cbd12e939779ecce227e3f2bc8670f17e6fdca72c1ccec009  memory_root.move","redaction":"none"}"#,
            "\n",
            r#"{"summary":"24 records; 0 leak"}"#,
            "\n",
        );
        let scan = scan_terminal_str(doc)?;
        assert_eq!(scan.records_u32, 3);
        assert_eq!(scan.redacted_u32, 0);
        Ok(())
    }

    #[test]
    fn plain_secret_line_is_rejected() {
        let doc = r#"{"n":1,"line":"sk-live_ABCDEF0123456789abcdef","redaction":"none"}"#;
        assert!(matches!(
            scan_terminal_str(doc),
            Err(DietError::SecretResidue {
                kind: DietFileKind::TerminalRedacted
            })
        ));
    }

    #[test]
    fn ansi_stripped_secret_is_detected() {
        // ANSI color codes around a secret must not hide it: strip then detect.
        let painted = "\u{1b}[31msk-live_ABCDEF0123456789abcdef\u{1b}[0m";
        assert!(looks_secret(&strip_ansi(painted)));
        assert!(!looks_secret(&strip_ansi(
            "\u{1b}[32mBUILD_EXIT=0\u{1b}[0m"
        )));
    }

    #[test]
    fn seed_phrase_marker_is_rejected() {
        let doc = r#"{"n":1,"line":"seed_phrase: lazy dog brown fox ...","redaction":"none"}"#;
        assert!(matches!(
            scan_terminal_str(doc),
            Err(DietError::SecretResidue { .. })
        ));
    }

    #[test]
    fn provider_body_marker_is_rejected_even_if_marked_redacted() {
        // A claim of `redacted` does not excuse residue actually present.
        let doc = r#"{"n":1,"line":"provider_response_body leaked here","redaction":"redacted"}"#;
        assert!(matches!(
            scan_terminal_str(doc),
            Err(DietError::SecretResidue { .. })
        ));
    }

    #[test]
    fn strip_ansi_preserves_utf8() {
        let s = "\u{1b}[1m한국어 로그\u{1b}[0m";
        assert_eq!(strip_ansi(s), "한국어 로그");
    }

    #[test]
    fn redaction_marker_counts() -> DietResult<()> {
        let doc = concat!(
            r#"{"n":1,"line":"REDACTED token here","redaction":"redacted"}"#,
            "\n",
            r#"{"n":2,"line":"plain line","redaction":"none"}"#,
            "\n",
        );
        let scan = scan_terminal_str(doc)?;
        assert_eq!(scan.records_u32, 2);
        assert_eq!(scan.redacted_u32, 1);
        Ok(())
    }
}
