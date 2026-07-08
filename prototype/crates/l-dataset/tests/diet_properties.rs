//! Property-test corpus for the AtomDiet schema (atom #349 · E.0.18).
//!
//! Arbitrary malformed sidecars must either *reject* or become *partial
//! no-reward* — they never silently become reward-eligible. Secret residue is a
//! denied fixture only; it can never become positive reward or emitted training
//! text. These live in `tests/` (a standalone crate) so the production parser
//! surface carries zero `proptest` dependency.
use mnemos_l_dataset::atom_record;
use mnemos_l_dataset::command_manifest::{self, CommandExitClass};
use mnemos_l_dataset::{
    AtomDietKey, AtomDietManifest, DietCompleteness, DietFileKind, DietFileRef, DietSourceStage,
    StageETraceLink, artifacts, completeness, hex32_encode, privacy, terminal,
};
use proptest::prelude::*;

fn trace() -> StageETraceLink {
    StageETraceLink::new([1u8; 32], 349, 18)
}

fn key() -> AtomDietKey {
    AtomDietKey::new(DietSourceStage::StageD, 349)
}

proptest! {
    /// File-kind discriminant is a total map: `Some` exactly on `1..=21`.
    #[test]
    fn file_kind_u8_roundtrip(v in 0u8..=255) {
        match DietFileKind::from_u8(v) {
            Some(k) => prop_assert_eq!(k.as_u8(), v),
            None => prop_assert!(v == 0 || v > 21),
        }
    }

    /// Hex round-trips for any 32 bytes; the encoding is always 64 chars.
    #[test]
    fn hex_roundtrip(bytes in proptest::array::uniform32(any::<u8>())) {
        let enc = hex32_encode(&bytes);
        prop_assert_eq!(enc.len(), 64);
        let back = artifacts::parse_stored_hash(DietFileKind::EnvLock, &enc);
        prop_assert!(matches!(back, Ok(b) if b == bytes));
    }

    /// Any hex string that is not exactly 64 chars rejects.
    #[test]
    fn hex_rejects_wrong_length(s in "[0-9a-f]{0,63}") {
        prop_assert!(artifacts::parse_stored_hash(DietFileKind::EnvLock, &s).is_err());
    }

    /// Completeness partitions cleanly and partial/rejected always block reward.
    #[test]
    fn completeness_partition(n in 0usize..=21, unknown in 0u32..5) {
        let present: Vec<DietFileKind> = DietFileKind::ALL.into_iter().take(n).collect();
        let c = completeness::classify(&present, unknown);
        if unknown > 0 {
            prop_assert_eq!(c, DietCompleteness::Rejected);
        } else if n == 21 {
            prop_assert_eq!(c, DietCompleteness::Complete);
        } else {
            prop_assert_eq!(c, DietCompleteness::PartialNoReward);
        }
        if c != DietCompleteness::Complete {
            prop_assert!(c.reward_blocked());
        }
    }

    /// A duplicate file kind in a manifest always rejects.
    #[test]
    fn duplicate_kind_always_rejects(v in 1u8..=21) {
        let k = DietFileKind::from_u8(v).unwrap_or(DietFileKind::EnvLock);
        let refs = vec![
            DietFileRef::new(k, [1u8; 32], [2u8; 32], 1),
            DietFileRef::new(k, [3u8; 32], [4u8; 32], 1),
        ];
        let m = AtomDietManifest::current(key(), refs, DietCompleteness::PartialNoReward, trace());
        prop_assert!(m.validate().is_err());
    }

    /// Command exit classification: 0 ⇒ Pass, anything else ⇒ Fail.
    #[test]
    fn command_exit_classifies(code in any::<i32>()) {
        let doc = format!(r#"{{"commands":[{{"cmd":"x","exit":{code}}}]}}"#);
        let r = command_manifest::parse(&doc);
        prop_assert!(r.is_ok());
        if let Ok(v) = r {
            prop_assert_eq!(v.len(), 1);
            let expected = if code == 0 { CommandExitClass::Pass } else { CommandExitClass::Fail };
            prop_assert_eq!(v[0].exit_class, expected);
        }
    }

    /// A terminal line carrying a high-signal secret marker always rejects.
    #[test]
    fn terminal_secret_marker_always_rejects(prefix in "[a-z ]{0,20}") {
        let doc = format!(r#"{{"line":"{prefix}sk-live_AAAAAAAAAAAAAAAA","redaction":"none"}}"#);
        prop_assert!(terminal::scan_terminal_str(&doc).is_err());
    }

    /// A `Pass` privacy verdict with any positive hit is inconsistent and rejects.
    #[test]
    fn privacy_pass_with_hits_rejects(count in 1u32..1000) {
        let doc = format!(
            r#"{{"verdict":"PASS","checks":{{"wallet_secret_present":{{"count":{count}}}}}}}"#
        );
        prop_assert!(privacy::parse(key(), &doc).is_err());
    }

    /// Every assembled record is non-training-eligible, whatever the evidence.
    #[test]
    fn assembled_record_never_training_eligible(seed in any::<u8>()) {
        let refs: Vec<DietFileRef> = DietFileKind::ALL
            .into_iter()
            .map(|k| {
                let content = k.as_u8().wrapping_add(seed).max(1);
                DietFileRef::new(k, [k.as_u8().wrapping_add(50).max(1); 32], [content; 32], 1)
            })
            .collect();
        let r = atom_record::assemble(key(), trace(), refs, DietCompleteness::Complete);
        prop_assert!(r.is_ok());
        if let Ok(rec) = r {
            prop_assert!(!rec.training_eligible());
        }
    }
}

/// Public-API smoke: a malformed JSON body never panics and always returns a
/// typed error (no information leak, no silent acceptance).
#[test]
fn malformed_bodies_reject_without_panic() {
    assert!(command_manifest::parse("{ not json").is_err());
    assert!(privacy::parse(key(), "}{").is_err());
    assert!(mnemos_l_dataset::diff::parse("no headers at all").is_err());
}
