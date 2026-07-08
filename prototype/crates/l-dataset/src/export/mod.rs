//! Dataset export builders + tamper-evident shard layer.
//!
//! [`preference`] builds preference pairs (verified fix over failed attempt,
//! safe deny over unsafe success, privacy-clean over contaminated);
//! [`sft_chat`] formats privacy-clean chat samples as JSONL for the Stage G SFT
//! smoke; [`grpo`] emits GRPO rollout samples that always carry
//! `grpo_locked = true`. [`shard`] streams these records into content-addressed,
//! merkle-rooted, signer-bound shards linked to an `EvidenceLakeReceipt`;
//! [`card`] renders the dataset card; [`stage_g`] computes the Stage G unlock
//! packet (GRPO + self-evolution promotion stay locked). Every export kind is
//! the `ExportKind` tag.
pub mod card;
pub mod grpo;
pub mod preference;
pub mod sft_chat;
pub mod shard;
pub mod stage_g;

/// The kind of an export shard / sample (`ExportKind`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum ExportKind {
    /// Chat / SFT JSONL sample.
    SftChat = 1,
    /// Preference pair.
    Preference = 2,
    /// GRPO rollout sample (always locked in Stage E).
    GrpoRollout = 3,
    /// Evaluation sample.
    Eval = 4,
}

impl ExportKind {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=4`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::SftChat),
            2 => Some(Self::Preference),
            3 => Some(Self::GrpoRollout),
            4 => Some(Self::Eval),
            _ => None,
        }
    }
}
