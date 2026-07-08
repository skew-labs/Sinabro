//! Command replay verifier.
//!
//! Stage E *prepares* replay classifications and reads existing replay output; it
//! never runs a live network call or a destructive command. Each command from a
//! `command_manifest.json` is classified fail-closed: a destructive command
//! (`rm -rf`, `git push`, `git reset --hard`, …) is denied, a live/on-chain
//! command (`mainnet`, `sui client publish/call`, `transfer`, `curl`, …) is
//! denied, an infra-masked command is held, and only a plain local command is
//! marked replayable. Only a replayable command is reward-relevant.
use crate::diet_kind::{AtomDietKey, DietFileKind};
use crate::error::DietResult;
use crate::{as_object, opt_str, parse_json, req_array, req_str};

const KIND: DietFileKind = DietFileKind::CommandManifest;

/// How a recorded command may be replayed for ground-truth reverify.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ReplayClass {
    /// A plain local command that can be safely re-run for verification.
    Replayable = 1,
    /// The original run was masked by infrastructure (tool/host), not the model.
    InfraMasked = 2,
    /// A live / on-chain / network command — denied (never run in Stage E).
    LiveDenied = 3,
    /// A destructive command — denied (never run in Stage E).
    DestructiveDenied = 4,
}

impl ReplayClass {
    /// Numeric discriminant (`1..=4`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Only a replayable command is reward-relevant.
    pub const fn reward_relevant(self) -> bool {
        matches!(self, Self::Replayable)
    }
}

/// One classified replay plan for a recorded command.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReverifyPlan {
    /// The source atom.
    pub key: AtomDietKey,
    /// `sha256` of the exact command string.
    pub command_hash_32: [u8; 32],
    /// The replay classification.
    pub class: ReplayClass,
    /// Whether this plan is reward-relevant (replayable only).
    pub reward_relevant: bool,
}

fn is_destructive(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "rm -rf",
        "rm -r ",
        "git push",
        "git reset --hard",
        "git checkout",
        "git clean",
        "drop table",
        "truncate ",
        "--force",
        "force-push",
        "mkfs",
        "dd if=",
        "shutdown",
        "> /dev/sd",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

fn is_live(lower: &str) -> bool {
    const MARKERS: &[&str] = &[
        "mainnet",
        "sui client publish",
        "sui client call",
        "sui client transfer",
        "transfer-sui",
        "wallet sign",
        "keytool sign",
        "curl ",
        "wget ",
        "http://",
        "https://",
        "faucet",
        "--network mainnet",
    ];
    MARKERS.iter().any(|m| lower.contains(m))
}

/// Classify a single command string fail-closed. Destructive is checked first,
/// then live, then the infra-masked hint, else replayable.
pub fn classify_command(cmd: &str, infra_masked: bool) -> ReplayClass {
    let lower = cmd.to_ascii_lowercase();
    if is_destructive(&lower) {
        ReplayClass::DestructiveDenied
    } else if is_live(&lower) {
        ReplayClass::LiveDenied
    } else if infra_masked {
        ReplayClass::InfraMasked
    } else {
        ReplayClass::Replayable
    }
}

/// Classify every command in a `command_manifest.json` document into a replay
/// plan. The infra-masked hint is read from an explicit per-command `status`.
pub fn classify_manifest(
    key: AtomDietKey,
    command_manifest_json: &str,
) -> DietResult<Vec<ReverifyPlan>> {
    let v = parse_json(KIND, command_manifest_json)?;
    let obj = as_object(&v, KIND, "$root")?;
    let commands = req_array(obj, KIND, "commands")?;
    let mut out = Vec::with_capacity(commands.len());
    for c in commands {
        let co = as_object(c, KIND, "commands[]")?;
        let cmd = req_str(co, KIND, "cmd")?;
        let infra = opt_str(co, "status").is_some_and(|s| s.to_ascii_lowercase().contains("infra"));
        let class = classify_command(cmd, infra);
        out.push(ReverifyPlan {
            key,
            command_hash_32: crate::sha256(cmd.as_bytes()),
            class,
            reward_relevant: class.reward_relevant(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageD, 366)
    }

    #[test]
    fn plain_command_is_replayable() {
        assert_eq!(
            classify_command("cargo test --workspace --locked --offline", false),
            ReplayClass::Replayable
        );
    }

    #[test]
    fn infra_masked_is_held() {
        assert_eq!(
            classify_command("sui move test", true),
            ReplayClass::InfraMasked
        );
    }

    #[test]
    fn live_command_is_denied() {
        assert_eq!(
            classify_command("sui client publish --network mainnet --gas-budget 1", false),
            ReplayClass::LiveDenied
        );
        assert_eq!(
            classify_command("curl https://example.invalid/api", false),
            ReplayClass::LiveDenied
        );
    }

    #[test]
    fn destructive_command_is_denied() {
        assert_eq!(
            classify_command("git push origin main", false),
            ReplayClass::DestructiveDenied
        );
        assert_eq!(
            classify_command("rm -rf target", false),
            ReplayClass::DestructiveDenied
        );
    }

    #[test]
    fn destructive_beats_live_when_both_present() {
        // a destructive on-chain command classifies destructive (most dangerous).
        assert_eq!(
            classify_command("git push && sui client publish --network mainnet", false),
            ReplayClass::DestructiveDenied
        );
    }

    #[test]
    fn manifest_classification_marks_reward_relevance() -> DietResult<()> {
        let doc = r#"{"commands":[{"cmd":"cargo build","exit":0},{"cmd":"sui client publish --network mainnet","exit":0},{"cmd":"sui move test","exit":1,"status":"InfraMasked"}]}"#;
        let plans = classify_manifest(key(), doc)?;
        assert_eq!(plans.len(), 3);
        assert_eq!(plans[0].class, ReplayClass::Replayable);
        assert!(plans[0].reward_relevant);
        assert_eq!(plans[1].class, ReplayClass::LiveDenied);
        assert!(!plans[1].reward_relevant);
        assert_eq!(plans[2].class, ReplayClass::InfraMasked);
        assert!(!plans[2].reward_relevant);
        Ok(())
    }
}
