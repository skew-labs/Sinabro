//! SFT chat JSONL formatter for the supervised fine-tuning (SFT) smoke test.
//!
//! # Rationale
//!
//! A sample carries the system task, atom context, relevant evidence, the final
//! patch summary, and the verification — but **no raw secrets or private
//! memory**. Each sample is scanned with the canonical privacy scanner and
//! rejected on any secret/PII/encoded-secret hit; bilingual (Korean + English)
//! rationale is preserved. Samples are formatted one JSONL line at a time, so a
//! whole dataset never needs to live in memory.
//!
//! ## Secret custody
//!
//! [`to_jsonl`] runs `privacy_scanner::scan_str` (a pure function over the
//! sample text — no network/wallet/process/filesystem-write API) over the full
//! assembled content and rejects unless the report is clean. No raw secret /
//! private-memory byte is ever materialized into the JSONL line.
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::{DietError, DietResult};
use crate::privacy_scanner;
use serde_json::json;

use super::ExportKind;

const KIND: DietFileKind = DietFileKind::SftChat;

/// Approximate token budget per sample (≈ 4 bytes/token heuristic).
pub const TOKEN_CAP: u32 = 8192;

/// A chat role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ChatRole {
    /// System / task instruction.
    System = 1,
    /// User turn.
    User = 2,
    /// Assistant turn.
    Assistant = 3,
}

impl ChatRole {
    /// The canonical lower-case role label used in the JSONL.
    pub const fn as_label(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::User => "user",
            Self::Assistant => "assistant",
        }
    }

    /// Parse a role label; `None` if unrecognized.
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "system" => Some(Self::System),
            "user" => Some(Self::User),
            "assistant" => Some(Self::Assistant),
            _ => None,
        }
    }
}

/// One chat turn.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChatTurn {
    /// The role of the turn.
    pub role: ChatRole,
    /// The turn content.
    pub content: String,
}

/// Build a chat turn from a role label, rejecting an unknown role.
pub fn build_turn(role_label: &str, content: &str) -> DietResult<ChatTurn> {
    let role = ChatRole::from_label(role_label).ok_or(DietError::MissingField {
        kind: KIND,
        field: "role",
    })?;
    Ok(ChatTurn {
        role,
        content: content.to_string(),
    })
}

/// An SFT chat sample.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SftSample {
    /// The source atom.
    pub key: AtomDietKey,
    /// The ordered chat turns.
    pub turns: Vec<ChatTurn>,
    /// Export tag (always [`ExportKind::SftChat`]).
    pub export: ExportKind,
}

impl SftSample {
    /// Construct an SFT sample.
    pub fn new(key: AtomDietKey, turns: Vec<ChatTurn>) -> Self {
        Self {
            key,
            turns,
            export: ExportKind::SftChat,
        }
    }
}

/// Approximate token count for `s` (≈ 4 bytes per token).
fn estimate_tokens(s: &str) -> u32 {
    (s.len() / 4) as u32
}

/// Format a sample as one JSONL line. Fails closed on any secret/PII hit
/// (privacy scan) and on exceeding [`TOKEN_CAP`]. A bilingual flag (Hangul +
/// ASCII) is derived via the canonical Korean signal.
pub fn to_jsonl(sample: &SftSample) -> DietResult<String> {
    let mut all = String::new();
    for t in &sample.turns {
        all.push_str(&t.content);
        all.push('\n');
    }

    // secret custody: scan the full assembled text, reject on any hit.
    let scan = privacy_scanner::scan_str(&all);
    if !scan.clean() {
        return Err(DietError::SecretResidue { kind: KIND });
    }

    let tokens = estimate_tokens(&all);
    if tokens > TOKEN_CAP {
        return Err(DietError::SftTokenBudgetExceeded { tokens_u32: tokens });
    }

    let bilingual = crate::korean::collect(sample.key, &all).mixed_script;
    let messages: Vec<serde_json::Value> = sample
        .turns
        .iter()
        .map(|t| json!({ "role": t.role.as_label(), "content": t.content }))
        .collect();
    let obj = json!({
        "source": sample.key.source.as_u8(),
        "atom_u16": sample.key.atom_u16,
        "bilingual": bilingual,
        "messages": messages,
    });
    Ok(obj.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 393)
    }

    fn sample(turns: Vec<ChatTurn>) -> SftSample {
        SftSample::new(key(), turns)
    }

    #[test]
    fn valid_jsonl_is_single_line_object() -> DietResult<()> {
        let s = sample(vec![
            build_turn("system", "fix the borrow checker error")?,
            build_turn("user", "atom #393 context")?,
            build_turn("assistant", "patch summary; cargo test exit 0")?,
        ]);
        let line = to_jsonl(&s)?;
        assert!(!line.contains('\n')); // single physical JSONL line
        assert!(line.contains("\"role\":\"system\""));
        assert!(line.contains("\"messages\""));
        Ok(())
    }

    #[test]
    fn missing_role_is_rejected() {
        assert_eq!(
            build_turn("wizard", "content"),
            Err(DietError::MissingField {
                kind: KIND,
                field: "role"
            })
        );
    }

    #[test]
    fn token_cap_is_enforced() {
        // ~10000 tokens (40000 bytes) > TOKEN_CAP.
        let big = "x ".repeat(20_000);
        let s = sample(vec![ChatTurn {
            role: ChatRole::Assistant,
            content: big,
        }]);
        assert!(matches!(
            to_jsonl(&s),
            Err(DietError::SftTokenBudgetExceeded { .. })
        ));
    }

    #[test]
    fn korean_and_english_fields_are_bilingual() -> DietResult<()> {
        let s = sample(vec![build_turn(
            "assistant",
            "borrow checker 설명: ownership 이동 때문에 실패합니다",
        )?]);
        let line = to_jsonl(&s)?;
        assert!(line.contains("\"bilingual\":true"));
        // the canonical Korean signal agrees the rationale is exportable.
        let sig = crate::korean::collect(key(), "ownership 이동 설명");
        assert!(sig.has_hangul && sig.sft_exportable);
        Ok(())
    }

    #[test]
    fn secret_scan_rejects_wallet_secret() {
        let s = sample(vec![ChatTurn {
            role: ChatRole::Assistant,
            content: "here is the wallet_secret to use".to_string(),
        }]);
        assert_eq!(to_jsonl(&s), Err(DietError::SecretResidue { kind: KIND }));
    }
}
