//! Redaction policy engine.
//!
//! Redaction is **binary and irreversible**: either a sensitive span is removed
//! and replaced by a marker plus a `sha256` of the removed bytes (so the removal
//! is provable but the bytes are gone), or the input is **rejected** — there is
//! no "masked enough" middle state. Binary / non-UTF-8 input is a reject
//! ([`DietError::SecretResidue`]). After redaction the output is re-scanned; if
//! any residue remains the whole input rejects rather than ship a partial mask.
//! Reuses the canonical terminal scanner for detection.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::terminal::{looks_secret, strip_ansi};

const KIND: DietFileKind = DietFileKind::TerminalRedacted;

/// The marker substituted for a removed sensitive span.
pub const MARKER: &str = "[REDACTED]";

/// The outcome of a redaction attempt over UTF-8 text.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RedactionOutcome {
    /// The text was already clean; nothing was removed.
    Clean {
        /// The (unchanged) text.
        text: String,
    },
    /// One or more spans were removed and replaced by [`MARKER`].
    Redacted {
        /// The redacted text (secret-free by construction + post-check).
        text: String,
        /// Number of spans removed.
        spans_u32: u32,
        /// `sha256` of the concatenated removed bytes (provable, irreversible).
        removed_hash_32: [u8; 32],
    },
}

impl RedactionOutcome {
    /// The redacted (or clean) text.
    pub fn text(&self) -> &str {
        match self {
            Self::Clean { text } | Self::Redacted { text, .. } => text.as_str(),
        }
    }

    /// Whether any span was redacted.
    pub const fn was_redacted(&self) -> bool {
        matches!(self, Self::Redacted { .. })
    }
}

/// Redact secret-bearing lines from UTF-8 `text`, replacing each with [`MARKER`].
/// Infallible at the string level: a line that looks secret is removed wholesale
/// (the span is the line), so the output is clean by construction.
pub fn redact(text: &str) -> RedactionOutcome {
    let mut out = String::with_capacity(text.len());
    let mut removed: Vec<u8> = Vec::new();
    let mut spans = 0u32;
    for (i, line) in text.lines().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        if looks_secret(&strip_ansi(line)) {
            removed.extend_from_slice(line.as_bytes());
            removed.push(b'\n');
            out.push_str(MARKER);
            spans = spans.saturating_add(1);
        } else {
            out.push_str(line);
        }
    }
    if spans == 0 {
        RedactionOutcome::Clean { text: out }
    } else {
        RedactionOutcome::Redacted {
            text: out,
            spans_u32: spans,
            removed_hash_32: crate::sha256(&removed),
        }
    }
}

/// Redact raw bytes. Non-UTF-8 / binary input is **unredactable** and rejects.
/// After redaction the output is re-scanned; any residual secret rejects rather
/// than ship a partial mask ("never masks enough without proof").
pub fn redact_bytes(bytes: &[u8]) -> DietResult<RedactionOutcome> {
    let s = std::str::from_utf8(bytes).map_err(|_| DietError::SecretResidue { kind: KIND })?;
    let outcome = redact(s);
    for line in outcome.text().lines() {
        if looks_secret(&strip_ansi(line)) {
            return Err(DietError::SecretResidue { kind: KIND });
        }
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "token sk-live_ABCDEF0123456789abcdef";

    #[test]
    fn redacts_secret_span_with_marker() {
        let input = format!("line one\n{SECRET}\nline three");
        let out = redact(&input);
        assert!(out.was_redacted());
        assert!(out.text().contains(MARKER));
        // irreversible: the secret is gone from the output.
        assert!(!out.text().contains("sk-live_"));
        if let RedactionOutcome::Redacted { spans_u32, .. } = out {
            assert_eq!(spans_u32, 1);
        }
    }

    #[test]
    fn removed_hash_anchors_the_removed_bytes() {
        let out = redact(SECRET);
        let mut expected = SECRET.as_bytes().to_vec();
        expected.push(b'\n');
        assert_eq!(
            out,
            RedactionOutcome::Redacted {
                text: MARKER.to_string(),
                spans_u32: 1,
                removed_hash_32: crate::sha256(&expected),
            }
        );
    }

    #[test]
    fn clean_text_passes_through_unchanged() {
        let out = redact("hello\nworld");
        assert!(!out.was_redacted());
        assert_eq!(out.text(), "hello\nworld");
    }

    #[test]
    fn binary_input_is_unredactable_reject() {
        // invalid UTF-8 bytes cannot be redacted ⇒ reject.
        let bytes = [0xff, 0xfe, 0x00, 0x80];
        assert!(matches!(
            redact_bytes(&bytes),
            Err(DietError::SecretResidue {
                kind: DietFileKind::TerminalRedacted
            })
        ));
    }

    #[test]
    fn redact_bytes_proves_output_clean() -> DietResult<()> {
        let input = format!("ok\n{SECRET}\nok2");
        let out = redact_bytes(input.as_bytes())?;
        assert!(out.was_redacted());
        assert!(!out.text().contains("sk-live_"));
        Ok(())
    }
}
