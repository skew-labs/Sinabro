//! Korean rationale extractor.
//!
//! Korean rationale, comments, and reviews are preserved for **bilingual SFT
//! only after a privacy scan and source linkage** — translation is metadata, not
//! a replacement for the original. This collector detects Hangul, records a
//! source-content hash for linkage, and marks the text exportable only when it
//! carries no secret residue: a Korean rationale that still contains a secret is
//! not exportable.
use crate::diet_kind::AtomDietKey;
use crate::terminal::looks_secret;

/// A Korean rationale extraction signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct KoreanRationaleSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// Hangul was detected.
    pub has_hangul: bool,
    /// Both Hangul and ASCII letters are present (mixed Korean/English).
    pub mixed_script: bool,
    /// No secret residue was detected (privacy gate for export).
    pub privacy_clean: bool,
    /// `sha256` of the source text (linkage anchor; original is not replaced).
    pub source_hash_32: [u8; 32],
    /// Exportable to bilingual SFT: `has_hangul ∧ privacy_clean`.
    pub sft_exportable: bool,
}

/// Whether a char is a Hangul syllable or jamo.
fn is_hangul(c: char) -> bool {
    matches!(c,
        '\u{1100}'..='\u{11FF}'   // Hangul Jamo
        | '\u{3130}'..='\u{318F}' // Hangul Compatibility Jamo
        | '\u{A960}'..='\u{A97F}' // Hangul Jamo Extended-A
        | '\u{AC00}'..='\u{D7A3}' // Hangul Syllables
        | '\u{D7B0}'..='\u{D7FF}' // Hangul Jamo Extended-B
    )
}

/// Collect a [`KoreanRationaleSignal`] from rationale text. The text is hashed
/// for linkage and privacy-scanned; only Hangul-bearing, privacy-clean text is
/// SFT-exportable.
pub fn collect(key: AtomDietKey, text: &str) -> KoreanRationaleSignal {
    let has_hangul = text.chars().any(is_hangul);
    let has_ascii_alpha = text.chars().any(|c| c.is_ascii_alphabetic());
    let privacy_clean = !looks_secret(text);
    KoreanRationaleSignal {
        key,
        has_hangul,
        mixed_script: has_hangul && has_ascii_alpha,
        privacy_clean,
        source_hash_32: crate::sha256(text.as_bytes()),
        sft_exportable: has_hangul && privacy_clean,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 379)
    }

    #[test]
    fn korean_rationale_parses_and_exports() {
        let s = collect(key(), "이 변경은 브리지 불변식을 고친다");
        assert!(s.has_hangul);
        assert!(!s.mixed_script);
        assert!(s.privacy_clean);
        assert!(s.sft_exportable);
    }

    #[test]
    fn mixed_korean_english_is_flagged_mixed() {
        let s = collect(key(), "버그 fix in error.rs");
        assert!(s.has_hangul);
        assert!(s.mixed_script);
        assert!(s.sft_exportable);
    }

    #[test]
    fn english_only_has_no_hangul() {
        let s = collect(key(), "plain english rationale");
        assert!(!s.has_hangul);
        assert!(!s.sft_exportable);
    }

    #[test]
    fn secret_in_korean_blocks_export() {
        let s = collect(key(), "키 노출: sk-live_ABCDEF0123456789 입니다");
        assert!(s.has_hangul);
        assert!(!s.privacy_clean);
        assert!(!s.sft_exportable);
    }

    #[test]
    fn source_hash_anchors_text() {
        let s = collect(key(), "근거");
        assert_eq!(s.source_hash_32, crate::sha256("근거".as_bytes()));
    }
}
