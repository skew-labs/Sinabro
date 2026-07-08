//! GRPO rollout sample builder — locked.
//!
//! # Rationale
//!
//! Stage E may export GRPO rollout *data*, but every manifest declares
//! `grpo_locked = true`: there is no executable training command and no way to
//! flip the lock here. GRPO unlock waits for the Stage G SFT smoke / eval. The
//! group id is a stable digest of the group seed, so the same rollout group
//! hashes identically on every run.
use crate::diet_kind::AtomDietKey;
use serde_json::json;

use super::ExportKind;
use super::preference::PreferencePair;

/// A GRPO rollout sample (always locked in Stage E).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GrpoRollout {
    /// The source atom.
    pub key: AtomDietKey,
    /// Stable group id (digest of the group seed).
    pub group_id_hash_32: [u8; 32],
    /// `sha256` content hashes of the rollout samples (text-free).
    pub sample_hashes: Vec<[u8; 32]>,
    /// Always `true` in Stage E — GRPO is locked until Stage G.
    pub grpo_locked: bool,
    /// Export tag (always [`ExportKind::GrpoRollout`]).
    pub export: ExportKind,
}

impl GrpoRollout {
    /// Whether GRPO is locked (always `true` for a Stage E rollout).
    pub const fn is_locked(&self) -> bool {
        self.grpo_locked
    }
}

/// Build a GRPO rollout from a group seed and sample content hashes. The lock is
/// hard-coded `true`; no parameter can unlock it.
pub fn build_rollout(
    key: AtomDietKey,
    group_seed: &[u8],
    sample_hashes: Vec<[u8; 32]>,
) -> GrpoRollout {
    GrpoRollout {
        key,
        group_id_hash_32: crate::sha256(group_seed),
        sample_hashes,
        grpo_locked: true,
        export: ExportKind::GrpoRollout,
    }
}

/// Build a GRPO rollout group from preference pairs: each pair contributes its
/// chosen and rejected content hashes (reuses the preference builder).
pub fn from_preferences(
    key: AtomDietKey,
    group_seed: &[u8],
    pairs: &[PreferencePair],
) -> GrpoRollout {
    let mut sample_hashes = Vec::with_capacity(pairs.len() * 2);
    for p in pairs {
        sample_hashes.push(p.chosen_hash_32);
        sample_hashes.push(p.rejected_hash_32);
    }
    build_rollout(key, group_seed, sample_hashes)
}

/// Format a rollout as one JSONL line. Infallible: it carries only hashes,
/// counts, and the lock flag — never an executable command.
pub fn to_jsonl(rollout: &GrpoRollout) -> String {
    let samples: Vec<String> = rollout
        .sample_hashes
        .iter()
        .map(crate::hex32_encode)
        .collect();
    let obj = json!({
        "source": rollout.key.source.as_u8(),
        "atom_u16": rollout.key.atom_u16,
        "group_id": crate::hex32_encode(&rollout.group_id_hash_32),
        "sample_count": rollout.sample_hashes.len(),
        "samples": samples,
        "grpo_locked": rollout.grpo_locked,
        "stage_g_unlock_required": true,
    });
    obj.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::Phase0, 394)
    }

    #[test]
    fn rollout_jsonl_declares_locked() {
        let r = build_rollout(key(), b"group-seed-1", vec![[1u8; 32], [2u8; 32]]);
        let line = to_jsonl(&r);
        assert!(line.contains("\"grpo_locked\":true"));
        assert!(line.contains("\"sample_count\":2"));
    }

    #[test]
    fn locked_flag_is_always_true() {
        let r = build_rollout(key(), b"seed", vec![]);
        assert!(r.grpo_locked);
        assert!(r.is_locked());
        assert_eq!(r.export, ExportKind::GrpoRollout);
    }

    #[test]
    fn no_executable_train_command_in_jsonl() {
        let r = build_rollout(key(), b"seed", vec![[9u8; 32]]);
        let line = to_jsonl(&r);
        for forbidden in [
            "cargo",
            "python",
            "torchrun",
            "accelerate",
            "vllm",
            "deepspeed",
        ] {
            assert!(
                !line.contains(forbidden),
                "rollout must carry no train command: {forbidden}"
            );
        }
    }

    #[test]
    fn group_id_is_stable() {
        let a = build_rollout(key(), b"same-seed", vec![[1u8; 32]]);
        let b = build_rollout(key(), b"same-seed", vec![[7u8; 32]]);
        assert_eq!(a.group_id_hash_32, b.group_id_hash_32);
        let c = build_rollout(key(), b"other-seed", vec![[1u8; 32]]);
        assert_ne!(a.group_id_hash_32, c.group_id_hash_32);
    }
}
