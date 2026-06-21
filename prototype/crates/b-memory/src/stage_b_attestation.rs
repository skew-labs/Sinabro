//! Stage B trust-boundary attestation surface (atom #116 · B.2.15, §4.0
//! canonical registry).
//!
//! # What this module is
//!
//! The §4.0 canonical registry declares three attestation types
//! ([`StageBTrustMode`], [`SafetyKernelBuildRef`], [`StageBTrustBoundaryReceipt`])
//! that were deferred from atom #81's handoff to "the first
//! `G-B-SAFETY-ATTESTATION` atom". Atom #116 (the first live Walrus testnet PUT)
//! is that atom: a live testnet action must record *which client build* spoke to
//! the network and *who owns* the resulting memory, so this module mints the
//! minimal data-free surface the gate needs. The live PUT evidence itself is the
//! atom's primary canonical OUT (`tests/stage_b_live_put.rs`); this module is the
//! required attestation companion.
//!
//! # Madness invariants (§4.0 `G-B-SAFETY-ATTESTATION`)
//!
//! 1. **Data-free / fixed-size only.** Every field is a fixed-size hash array, a
//!    one-byte trust mode, a 32-byte owner address, or a fixed trace link. There
//!    is no URL, no endpoint body, no private key, no mnemonic, no wallet secret,
//!    and no provider body anywhere in the surface — a secret is not expressible.
//! 2. **The memory owner is the user key.** [`StageBTrustBoundaryReceipt::owner`]
//!    is a user-controlled [`SuiAddress`] (Stage A d-move §4.D, reused verbatim).
//!    A server / helper / forked client address must never be recorded here as
//!    the owner; the receipt names the human owner of the memory, not the relay
//!    that carried the bytes.
//! 3. **No pretended attestation.** [`SafetyKernelBuildRef::unattested_local`]
//!    is the honest constructor for a local CLI run that cannot derive an
//!    official safety-kernel attestation: it records zero/unknown hash sentinels
//!    and [`StageBTrustMode::LocalOnly`]. It does **not** claim
//!    [`StageBTrustMode::OfficialTestClient`]; [`SafetyKernelBuildRef::is_official_attested`]
//!    returns `false` for it. The type is named honestly so a reader is never
//!    misled into thinking an unattested local build was officially attested.
//! 4. **Labels, not field dumps.** No `Display` impl reproduces the hash bytes;
//!    only [`StageBTrustMode::class_label`] exposes a stable `&'static str` label.
//!    The hash fields are `pub` (per the §4.0 registry shape) so a caller can
//!    record them, but the module emits no rendering that could smuggle anything
//!    beyond the labels and the hashes themselves.

use mnemos_d_move::SuiAddress;

use crate::stage_b_handoff::StageBTraceLink;

// ===========================================================================
// 1. StageBTrustMode
// ===========================================================================

/// How much the recorded client build is trusted for a Stage B live action.
///
/// Tag values are pinned (`§4.0` canonical registry) so the one-byte wire form
/// is stable across the project. There is no `#[non_exhaustive]` — the §4.0
/// registry fixes exactly these four modes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum StageBTrustMode {
    /// A local developer build with no external attestation. The default for a
    /// local CLI run; the weakest trust mode.
    LocalOnly = 1,
    /// A self-hosted build the operator runs themselves, still without official
    /// attestation.
    SelfHostedOnly = 2,
    /// An official, attested test client build.
    OfficialTestClient = 3,
    /// A build that has been flagged and must not be trusted for live actions.
    Quarantined = 4,
}

impl StageBTrustMode {
    /// One-byte wire tag for this trust mode (`1..=4`).
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// Stable `&'static str` label for this trust mode; namespaced
    /// `stage_b_trust_mode.*`. The only textual rendering the surface offers.
    #[inline]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::LocalOnly => "stage_b_trust_mode.local_only",
            Self::SelfHostedOnly => "stage_b_trust_mode.self_hosted_only",
            Self::OfficialTestClient => "stage_b_trust_mode.official_test_client",
            Self::Quarantined => "stage_b_trust_mode.quarantined",
        }
    }
}

// ===========================================================================
// 2. SafetyKernelBuildRef
// ===========================================================================

/// A fixed-size reference to the safety-relevant build identity of the client
/// that performed a Stage B live action.
///
/// Every field is a 32-byte hash (content-addressed identity, never a secret)
/// plus the [`StageBTrustMode`]. The struct is `Copy` because every field is
/// `Copy`; equality and hashing are byte-equal on the underlying arrays.
///
/// For an unattested local CLI run, build with
/// [`unattested_local`](Self::unattested_local) — it records zero/unknown
/// sentinels honestly rather than fabricating an attestation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SafetyKernelBuildRef {
    /// Hash of the released agent version identity.
    pub release_version_hash_32: [u8; 32],
    /// Hash of the source commit the build came from (zero/unknown when the
    /// build tree is not a tracked commit — mnemos is not a git repo this phase).
    pub git_commit_hash_32: [u8; 32],
    /// Hash of the safety-kernel definition the client enforces.
    pub safety_kernel_hash_32: [u8; 32],
    /// Hash of the command-grammar the client admits.
    pub command_grammar_hash_32: [u8; 32],
    /// Hash of the capability-policy the client enforces.
    pub capability_policy_hash_32: [u8; 32],
    /// Hash of the redaction-policy the client enforces.
    pub redaction_policy_hash_32: [u8; 32],
    /// How much this build is trusted for a live action.
    pub trust_mode: StageBTrustMode,
}

impl SafetyKernelBuildRef {
    /// Construct a build reference from its six component hashes and a trust
    /// mode. Callers that cannot derive an official attestation should prefer
    /// [`unattested_local`](Self::unattested_local) rather than passing zeros to
    /// this constructor with [`StageBTrustMode::OfficialTestClient`].
    #[inline]
    pub const fn new(
        release_version_hash_32: [u8; 32],
        git_commit_hash_32: [u8; 32],
        safety_kernel_hash_32: [u8; 32],
        command_grammar_hash_32: [u8; 32],
        capability_policy_hash_32: [u8; 32],
        redaction_policy_hash_32: [u8; 32],
        trust_mode: StageBTrustMode,
    ) -> Self {
        Self {
            release_version_hash_32,
            git_commit_hash_32,
            safety_kernel_hash_32,
            command_grammar_hash_32,
            capability_policy_hash_32,
            redaction_policy_hash_32,
            trust_mode,
        }
    }

    /// The honest build reference for an **unattested local CLI run**: every
    /// hash is the all-zero unknown sentinel and the trust mode is
    /// [`StageBTrustMode::LocalOnly`]. This does not claim any official
    /// attestation — [`is_official_attested`](Self::is_official_attested)
    /// returns `false`.
    #[inline]
    pub const fn unattested_local() -> Self {
        Self {
            release_version_hash_32: [0u8; 32],
            git_commit_hash_32: [0u8; 32],
            safety_kernel_hash_32: [0u8; 32],
            command_grammar_hash_32: [0u8; 32],
            capability_policy_hash_32: [0u8; 32],
            redaction_policy_hash_32: [0u8; 32],
            trust_mode: StageBTrustMode::LocalOnly,
        }
    }

    /// Whether this build claims an official test-client attestation
    /// ([`StageBTrustMode::OfficialTestClient`]). A local or self-hosted build
    /// returns `false`; an unattested local build never silently reads as
    /// attested.
    #[inline]
    pub const fn is_official_attested(&self) -> bool {
        matches!(self.trust_mode, StageBTrustMode::OfficialTestClient)
    }
}

// ===========================================================================
// 3. StageBTrustBoundaryReceipt
// ===========================================================================

/// The trust-boundary receipt recorded for a Stage B live action: which client
/// build spoke to the network ([`SafetyKernelBuildRef`]), who owns the memory
/// ([`SuiAddress`], the user key), and the trace link ([`StageBTraceLink`]) the
/// action belongs to.
///
/// Fields are `pub` per the §4.0 canonical registry; [`new`](Self::new) is
/// provided for ergonomic construction. The receipt is data-free: it carries no
/// bytes of the payload, no endpoint URL, and no key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBTrustBoundaryReceipt {
    /// The safety-relevant build identity of the client that acted.
    pub build: SafetyKernelBuildRef,
    /// The user-controlled owner of the memory (never a server / helper key).
    pub owner: SuiAddress,
    /// The trace link the recorded action belongs to.
    pub trace: StageBTraceLink,
}

impl StageBTrustBoundaryReceipt {
    /// Construct a trust-boundary receipt from its three components.
    #[inline]
    pub const fn new(
        build: SafetyKernelBuildRef,
        owner: SuiAddress,
        trace: StageBTraceLink,
    ) -> Self {
        Self {
            build,
            owner,
            trace,
        }
    }
}

// ===========================================================================
// 4. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trust_mode_tags_are_pinned() {
        assert_eq!(StageBTrustMode::LocalOnly.tag(), 1);
        assert_eq!(StageBTrustMode::SelfHostedOnly.tag(), 2);
        assert_eq!(StageBTrustMode::OfficialTestClient.tag(), 3);
        assert_eq!(StageBTrustMode::Quarantined.tag(), 4);
    }

    #[test]
    fn trust_mode_labels_are_distinct_and_namespaced() {
        let labels = [
            StageBTrustMode::LocalOnly.class_label(),
            StageBTrustMode::SelfHostedOnly.class_label(),
            StageBTrustMode::OfficialTestClient.class_label(),
            StageBTrustMode::Quarantined.class_label(),
        ];
        let mut seen = std::collections::HashSet::new();
        for label in labels {
            assert!(label.starts_with("stage_b_trust_mode."));
            seen.insert(label);
        }
        assert_eq!(seen.len(), 4);
    }

    #[test]
    fn unattested_local_is_honest() {
        let build = SafetyKernelBuildRef::unattested_local();
        assert_eq!(build.trust_mode, StageBTrustMode::LocalOnly);
        assert_eq!(build.release_version_hash_32, [0u8; 32]);
        assert_eq!(build.git_commit_hash_32, [0u8; 32]);
        assert_eq!(build.safety_kernel_hash_32, [0u8; 32]);
        assert_eq!(build.command_grammar_hash_32, [0u8; 32]);
        assert_eq!(build.capability_policy_hash_32, [0u8; 32]);
        assert_eq!(build.redaction_policy_hash_32, [0u8; 32]);
        // An unattested local build never silently reads as officially attested.
        assert!(!build.is_official_attested());
    }

    #[test]
    fn official_attestation_is_only_true_for_official_mode() {
        let official = SafetyKernelBuildRef::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            StageBTrustMode::OfficialTestClient,
        );
        assert!(official.is_official_attested());
        assert_eq!(official.safety_kernel_hash_32, [3u8; 32]);

        let self_hosted = SafetyKernelBuildRef::new(
            [1u8; 32],
            [0u8; 32],
            [3u8; 32],
            [4u8; 32],
            [5u8; 32],
            [6u8; 32],
            StageBTrustMode::SelfHostedOnly,
        );
        assert!(!self_hosted.is_official_attested());
    }

    #[test]
    fn safety_kernel_build_ref_is_fixed_size() {
        // 6 hash arrays (6 * 32) + a one-byte repr(u8) trust mode, all align-1,
        // so the layout is a fixed 193 bytes with no padding.
        assert_eq!(core::mem::size_of::<SafetyKernelBuildRef>(), 6 * 32 + 1);
        assert_eq!(core::mem::align_of::<SafetyKernelBuildRef>(), 1);
    }

    #[test]
    fn receipt_records_owner_build_and_trace() {
        let owner = SuiAddress::new([0xAB; 32]);
        let build = SafetyKernelBuildRef::unattested_local();
        let trace = StageBTraceLink::new(0xB215_0001, 116, 0);
        let receipt = StageBTrustBoundaryReceipt::new(build, owner, trace);
        assert_eq!(receipt.owner.as_bytes(), &[0xAB; 32]);
        assert_eq!(receipt.build.trust_mode, StageBTrustMode::LocalOnly);
        assert_eq!(receipt.trace.atom_id_u16, 116);
        // Copy semantics: the receipt is a value type with no heap content.
        let copy = receipt;
        assert_eq!(copy, receipt);
    }
}
