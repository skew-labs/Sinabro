//! Source-stage, file-kind, and atom-key enums for the AtomDiet model
//! (atom #333 · E.0.2, §4.1 canonical registry).
//!
//! The 21-file sidecar set is **closed and repr-locked**: [`DietFileKind`] has
//! exactly 21 discriminants (`1..=21`) in the §0.1 contract order. An unknown
//! file name *rejects* (returns `None` / [`DietError::UnknownFileKind`]) instead
//! of being silently ignored, so a 22nd file or a typo can never enter the
//! dataset unnoticed.
use crate::error::{DietError, DietResult};

/// Which build stage a source atom came from (§4.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum DietSourceStage {
    /// Stage A / Phase 0 (`ops/training/phase_0/`).
    Phase0 = 1,
    /// Stage B (`ops/training/stage_b/`).
    StageB = 2,
    /// Stage C (`ops/training/stage_c/`).
    StageC = 3,
    /// Stage D (`ops/training/stage_d/`).
    StageD = 4,
    /// Stage I interactive / CLI corpus.
    StageI = 5,
    /// An external audit corpus.
    ExternalAudit = 6,
}

impl DietSourceStage {
    /// All six source stages in discriminant order.
    pub const ALL: [DietSourceStage; 6] = [
        DietSourceStage::Phase0,
        DietSourceStage::StageB,
        DietSourceStage::StageC,
        DietSourceStage::StageD,
        DietSourceStage::StageI,
        DietSourceStage::ExternalAudit,
    ];

    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if out of range.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Phase0),
            2 => Some(Self::StageB),
            3 => Some(Self::StageC),
            4 => Some(Self::StageD),
            5 => Some(Self::StageI),
            6 => Some(Self::ExternalAudit),
            _ => None,
        }
    }

    /// Map a `ops/training/<dir>/` stage directory name to a source stage.
    pub fn from_dir_name(name: &str) -> Option<Self> {
        match name {
            "phase_0" => Some(Self::Phase0),
            "stage_b" => Some(Self::StageB),
            "stage_c" => Some(Self::StageC),
            "stage_d" => Some(Self::StageD),
            "stage_i" => Some(Self::StageI),
            "external_audit" => Some(Self::ExternalAudit),
            _ => None,
        }
    }

    /// The canonical training subdirectory name.
    pub const fn dir_name(self) -> &'static str {
        match self {
            Self::Phase0 => "phase_0",
            Self::StageB => "stage_b",
            Self::StageC => "stage_c",
            Self::StageD => "stage_d",
            Self::StageI => "stage_i",
            Self::ExternalAudit => "external_audit",
        }
    }
}

/// File-format class of a sidecar kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum FileFormat {
    /// One JSON object per file.
    Json,
    /// One JSON object per line.
    Jsonl,
    /// A unified-diff patch (non-JSON).
    Patch,
}

/// One of the 21 closed sidecar file kinds (§4.1, §0.1 contract order).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum DietFileKind {
    /// `input_context.jsonl`
    InputContext = 1,
    /// `action_trace.jsonl`
    ActionTrace = 2,
    /// `command_manifest.json`
    CommandManifest = 3,
    /// `terminal_redacted.jsonl`
    TerminalRedacted = 4,
    /// `env_lock.json`
    EnvLock = 5,
    /// `artifact_hashes.json`
    ArtifactHashes = 6,
    /// `code_diff.patch`
    CodeDiff = 7,
    /// `failed_attempts.jsonl`
    FailedAttempts = 8,
    /// `no_op_decisions.jsonl`
    NoOpDecisions = 9,
    /// `test_results.json`
    TestResults = 10,
    /// `gate_results.json`
    GateResults = 11,
    /// `review_5pack.json`
    Review5Pack = 12,
    /// `deny_audit.json`
    DenyAudit = 13,
    /// `redteam_decision.json`
    RedteamDecision = 14,
    /// `human_review.jsonl`
    HumanReview = 15,
    /// `approval_events.jsonl`
    ApprovalEvents = 16,
    /// `privacy_report.json`
    PrivacyReport = 17,
    /// `sft_chat.jsonl`
    SftChat = 18,
    /// `preference_pairs.jsonl`
    PreferencePairs = 19,
    /// `reward_labels.json`
    RewardLabels = 20,
    /// `eval_summary.json`
    EvalSummary = 21,
}

impl DietFileKind {
    /// All 21 kinds in §0.1 contract order.
    pub const ALL: [DietFileKind; 21] = [
        Self::InputContext,
        Self::ActionTrace,
        Self::CommandManifest,
        Self::TerminalRedacted,
        Self::EnvLock,
        Self::ArtifactHashes,
        Self::CodeDiff,
        Self::FailedAttempts,
        Self::NoOpDecisions,
        Self::TestResults,
        Self::GateResults,
        Self::Review5Pack,
        Self::DenyAudit,
        Self::RedteamDecision,
        Self::HumanReview,
        Self::ApprovalEvents,
        Self::PrivacyReport,
        Self::SftChat,
        Self::PreferencePairs,
        Self::RewardLabels,
        Self::EvalSummary,
    ];

    /// Numeric discriminant (`1..=21`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=21`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::InputContext),
            2 => Some(Self::ActionTrace),
            3 => Some(Self::CommandManifest),
            4 => Some(Self::TerminalRedacted),
            5 => Some(Self::EnvLock),
            6 => Some(Self::ArtifactHashes),
            7 => Some(Self::CodeDiff),
            8 => Some(Self::FailedAttempts),
            9 => Some(Self::NoOpDecisions),
            10 => Some(Self::TestResults),
            11 => Some(Self::GateResults),
            12 => Some(Self::Review5Pack),
            13 => Some(Self::DenyAudit),
            14 => Some(Self::RedteamDecision),
            15 => Some(Self::HumanReview),
            16 => Some(Self::ApprovalEvents),
            17 => Some(Self::PrivacyReport),
            18 => Some(Self::SftChat),
            19 => Some(Self::PreferencePairs),
            20 => Some(Self::RewardLabels),
            21 => Some(Self::EvalSummary),
            _ => None,
        }
    }

    /// The canonical file name.
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::InputContext => "input_context.jsonl",
            Self::ActionTrace => "action_trace.jsonl",
            Self::CommandManifest => "command_manifest.json",
            Self::TerminalRedacted => "terminal_redacted.jsonl",
            Self::EnvLock => "env_lock.json",
            Self::ArtifactHashes => "artifact_hashes.json",
            Self::CodeDiff => "code_diff.patch",
            Self::FailedAttempts => "failed_attempts.jsonl",
            Self::NoOpDecisions => "no_op_decisions.jsonl",
            Self::TestResults => "test_results.json",
            Self::GateResults => "gate_results.json",
            Self::Review5Pack => "review_5pack.json",
            Self::DenyAudit => "deny_audit.json",
            Self::RedteamDecision => "redteam_decision.json",
            Self::HumanReview => "human_review.jsonl",
            Self::ApprovalEvents => "approval_events.jsonl",
            Self::PrivacyReport => "privacy_report.json",
            Self::SftChat => "sft_chat.jsonl",
            Self::PreferencePairs => "preference_pairs.jsonl",
            Self::RewardLabels => "reward_labels.json",
            Self::EvalSummary => "eval_summary.json",
        }
    }

    /// Parse from a file name; `None` if not one of the 21 kinds.
    pub fn from_file_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.file_name() == name)
    }

    /// Classify a file name, rejecting unknowns with a typed error.
    pub fn require_from_file_name(name: &str) -> DietResult<Self> {
        Self::from_file_name(name).ok_or(DietError::UnknownFileKind)
    }

    /// The file-format class (9 jsonl + 11 json + 1 patch).
    pub const fn format(self) -> FileFormat {
        match self {
            Self::InputContext
            | Self::ActionTrace
            | Self::TerminalRedacted
            | Self::FailedAttempts
            | Self::NoOpDecisions
            | Self::HumanReview
            | Self::ApprovalEvents
            | Self::SftChat
            | Self::PreferencePairs => FileFormat::Jsonl,
            Self::CodeDiff => FileFormat::Patch,
            _ => FileFormat::Json,
        }
    }
}

/// A source atom identity: `(source stage, atom number)` (§4.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct AtomDietKey {
    /// Which build stage the atom came from.
    pub source: DietSourceStage,
    /// The atom number (e.g. `331`).
    pub atom_u16: u16,
}

impl AtomDietKey {
    /// Construct an atom key.
    pub const fn new(source: DietSourceStage, atom_u16: u16) -> Self {
        Self { source, atom_u16 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_kind_round_trips_all_21() {
        assert_eq!(DietFileKind::ALL.len(), 21);
        for (i, k) in DietFileKind::ALL.into_iter().enumerate() {
            let disc = (i + 1) as u8;
            assert_eq!(k.as_u8(), disc);
            assert_eq!(DietFileKind::from_u8(disc), Some(k));
            assert_eq!(DietFileKind::from_file_name(k.file_name()), Some(k));
        }
    }

    #[test]
    fn file_kind_rejects_unknown() {
        assert_eq!(DietFileKind::from_u8(0), None);
        assert_eq!(DietFileKind::from_u8(22), None);
        assert_eq!(DietFileKind::from_file_name("subatom_records.json"), None);
        assert!(matches!(
            DietFileKind::require_from_file_name("nope.txt"),
            Err(DietError::UnknownFileKind)
        ));
    }

    #[test]
    fn format_partition_is_9_json11_patch1() {
        let mut jsonl = 0;
        let mut json = 0;
        let mut patch = 0;
        for k in DietFileKind::ALL {
            match k.format() {
                FileFormat::Jsonl => jsonl += 1,
                FileFormat::Json => json += 1,
                FileFormat::Patch => patch += 1,
            }
        }
        assert_eq!((jsonl, json, patch), (9, 11, 1));
    }

    #[test]
    fn source_stage_round_trip_and_dirs() {
        for s in DietSourceStage::ALL {
            assert_eq!(DietSourceStage::from_u8(s.as_u8()), Some(s));
            assert_eq!(DietSourceStage::from_dir_name(s.dir_name()), Some(s));
        }
        assert_eq!(DietSourceStage::from_dir_name("stage_z"), None);
        assert_eq!(DietSourceStage::from_u8(0), None);
        assert_eq!(DietSourceStage::from_u8(7), None);
    }

    #[test]
    fn atom_key_holds_full_width() {
        let k = AtomDietKey::new(DietSourceStage::StageD, u16::MAX);
        assert_eq!(k.atom_u16, u16::MAX);
        assert_eq!(k.source, DietSourceStage::StageD);
    }
}
