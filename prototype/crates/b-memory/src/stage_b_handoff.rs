//! Stage B handoff lock.
//!
//! Stage B does not begin until Stage A has left behind verifiable evidence.
//! This module carries the canonical *value carriers* for that hand-off — it
//! does **not** itself recompute the Stage A hashes (that population is a
//! runtime/integration concern). The three canonical types are:
//!
//! * [`StageAHandoffDigest`] — the 11 evidence hashes that pin the Stage A
//!   surface (build-state, architecture plan, canonical registry, and the
//!   a-core / c-walrus / d-move / b-memory / g-wallet / f-seal / j-ux /
//!   k-devex gate evidence). All slots are 32 bytes; a slot left as the
//!   all-zero hash is treated as *missing evidence*.
//! * [`StageBTraceLink`] — the `(trace_id_u64, atom_id_u16, attempt_u8)`
//!   triple stamped onto every Stage B external action so the evidence
//!   trail is greppable by trace id, atom and attempt.
//! * [`EvidenceBundleManifestV1`] — a *local-only* evidence hook. It records
//!   sidecar / replay-command / env-lock hashes plus a redaction class and a
//!   rights class. By construction it carries `training_eligibility = false`
//!   and *no* remote storage locator: Stage B is not a remote archive stage,
//!   and consent to train is never the default.
//!
//! # Invariants
//!
//! * **No Stage B without Stage A evidence.** A digest is only "complete"
//!   when every one of its 11 evidence slots is a non-zero 32-byte hash.
//!   [`StageAHandoffDigest::missing_evidence_mask`] reports exactly which
//!   slots are still the all-zero sentinel; the gate layer refuses to start
//!   Stage B while that mask is non-zero. No error enum is minted here; the
//!   "reject" is expressed as a bitmask + a boolean predicate (a *checker*,
//!   not a new type).
//! * **Evidence manifest is a local hook, never a training/consent grant.**
//!   [`EvidenceBundleManifestV1::new_local_hook`] hard-codes
//!   `training_eligibility = false` and an all-zero
//!   `optional_storage_locator_hash_32` (= "no remote locator"). The public
//!   field stays writable for a future stage, but the only constructor in
//!   Stage B emits the safe defaults.
//! * **Remote locator absence is the byte default.** An all-zero
//!   `optional_storage_locator_hash_32` means "no remote CID / deal / archive
//!   locator". [`EvidenceBundleManifestV1::remote_locator_present`] is the
//!   single predicate over that invariant.
//! * **Trace widths are fixed.** `atom_id` is a `u16` and `attempt` is a
//!   `u8` by type; the round-trip tests pin that the full width of each
//!   field survives.
//!
//! # Reuse map
//!
//! This module composes only primitive byte/integer types. It deliberately
//! reuses **no** Stage A wire/address/gas/secret type — those enter Stage B
//! at a later stage (the network typed boundary, then the chunk schema).
//! Pulling a Stage A canonical type here would be premature and is out of scope.

// ===========================================================================
// 0. Shared byte helpers
// ===========================================================================

/// The all-zero 32-byte hash, used as the "evidence missing" / "no remote
/// locator" sentinel throughout this module.
const ZERO_HASH_32: [u8; 32] = [0u8; 32];

/// `const`-evaluable "is this 32-byte hash the all-zero sentinel?" check.
/// Hand-rolled byte loop because `[u8; 32]: PartialEq` is not usable in a
/// `const fn` context on this toolchain.
#[inline]
const fn is_zero_hash(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

// ===========================================================================
// 1. StageBTraceLink — (trace_id, atom_id, attempt)  [relocated to a-core]
// ===========================================================================

/// Per-action Stage B trace stamp — re-exported verbatim from its relocation
/// home in the dependency root, [`mnemos_a_core::trace::StageBTraceLink`].
///
/// The `(trace_id_u64, atom_id_u16, attempt_u8)` triple is unchanged. The
/// *definition* was moved down to `a-core` so the lower crates `d-move` (gas
/// trace) and `k-devex` (evidence ref) can compose it through
/// [`StageCTraceLink`](mnemos_a_core::trace::StageCTraceLink)
/// without taking a cyclic dependency on `b-memory`. The type, its derives, and
/// its byte layout are identical, and every existing path — including
/// `crate::stage_b_handoff::StageBTraceLink` and the `crate::StageBTraceLink`
/// re-export — keeps resolving to the same type, so the chunk signing preimage
/// and every replay digest are byte-for-byte unchanged.
pub use mnemos_a_core::trace::StageBTraceLink;

// ===========================================================================
// 2. StageAHandoffDigest — 11 evidence hashes
// ===========================================================================

/// Number of evidence slots in a [`StageAHandoffDigest`]. Drives the
/// `to_bytes` / `from_bytes` length and the `missing_evidence_mask` width.
pub const HANDOFF_SLOT_COUNT: usize = 11;

/// Total serialized byte length of a [`StageAHandoffDigest`]
/// (`HANDOFF_SLOT_COUNT * 32`).
pub const HANDOFF_DIGEST_BYTES: usize = HANDOFF_SLOT_COUNT * 32;

/// The frozen Stage A → Stage B evidence digest. Each field is a 32-byte
/// hash; an all-zero field means "this evidence is missing" and blocks the
/// start of Stage B (see [`missing_evidence_mask`](Self::missing_evidence_mask)).
///
/// All fields are `pub`. The byte order used by
/// [`to_bytes`](Self::to_bytes) / [`from_bytes`](Self::from_bytes) and by the
/// missing-evidence bitmask is exactly the field declaration order below
/// (slot 0 = `build_state_hash_32` … slot 10 = `k_devex_gate_hash_32`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageAHandoffDigest {
    /// Hash of the Stage A build-state manifest. Slot 0.
    pub build_state_hash_32: [u8; 32],
    /// Hash of the Stage A architecture plan. Slot 1.
    pub atom_plan_hash_32: [u8; 32],
    /// Hash of the canonical type registry. Slot 2.
    pub canonical_registry_hash_32: [u8; 32],
    /// Hash of the a-core gate evidence (error/runtime/logging). Slot 3.
    pub a_core_gate_hash_32: [u8; 32],
    /// Hash of the c-walrus gate evidence (codec/blob-id/transport). Slot 4.
    pub c_walrus_gate_hash_32: [u8; 32],
    /// Hash of the d-move gate evidence (anchor/bindings). Slot 5.
    pub d_move_gate_hash_32: [u8; 32],
    /// Hash of the b-memory gate evidence (chunk/store/persist/replay). Slot 6.
    pub b_memory_gate_hash_32: [u8; 32],
    /// Hash of the g-wallet gate evidence (keystore/sign/rotate). Slot 7.
    pub g_wallet_gate_hash_32: [u8; 32],
    /// Hash of the f-seal gate evidence (capability/stub). Slot 8.
    pub f_seal_gate_hash_32: [u8; 32],
    /// Hash of the j-ux gate evidence (Telegram/CLI). Slot 9.
    pub j_ux_gate_hash_32: [u8; 32],
    /// Hash of the k-devex gate evidence (CI/bootstrap/metrics). Slot 10.
    pub k_devex_gate_hash_32: [u8; 32],
}

impl StageAHandoffDigest {
    /// Construct a digest from its 11 evidence hashes (field declaration
    /// order). `const` so it can seed compile-time fixtures.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        build_state_hash_32: [u8; 32],
        atom_plan_hash_32: [u8; 32],
        canonical_registry_hash_32: [u8; 32],
        a_core_gate_hash_32: [u8; 32],
        c_walrus_gate_hash_32: [u8; 32],
        d_move_gate_hash_32: [u8; 32],
        b_memory_gate_hash_32: [u8; 32],
        g_wallet_gate_hash_32: [u8; 32],
        f_seal_gate_hash_32: [u8; 32],
        j_ux_gate_hash_32: [u8; 32],
        k_devex_gate_hash_32: [u8; 32],
    ) -> Self {
        Self {
            build_state_hash_32,
            atom_plan_hash_32,
            canonical_registry_hash_32,
            a_core_gate_hash_32,
            c_walrus_gate_hash_32,
            d_move_gate_hash_32,
            b_memory_gate_hash_32,
            g_wallet_gate_hash_32,
            f_seal_gate_hash_32,
            j_ux_gate_hash_32,
            k_devex_gate_hash_32,
        }
    }

    /// An all-missing digest (every slot the all-zero sentinel). Useful as a
    /// starting point that [`missing_evidence_mask`](Self::missing_evidence_mask)
    /// reports as fully incomplete.
    pub const ALL_MISSING: Self = Self::new(
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
        ZERO_HASH_32,
    );

    /// The 11 slots in canonical (declaration) order, for `to_bytes` /
    /// `missing_evidence_mask` to iterate without re-listing field names.
    #[inline]
    const fn slots(&self) -> [&[u8; 32]; HANDOFF_SLOT_COUNT] {
        [
            &self.build_state_hash_32,
            &self.atom_plan_hash_32,
            &self.canonical_registry_hash_32,
            &self.a_core_gate_hash_32,
            &self.c_walrus_gate_hash_32,
            &self.d_move_gate_hash_32,
            &self.b_memory_gate_hash_32,
            &self.g_wallet_gate_hash_32,
            &self.f_seal_gate_hash_32,
            &self.j_ux_gate_hash_32,
            &self.k_devex_gate_hash_32,
        ]
    }

    /// Bitmask of *missing* evidence slots: bit `i` is set iff slot `i`
    /// (declaration order) is the all-zero hash. A complete digest returns
    /// `0`. Width is `u16` (11 slots ⇒ bits 0..=10 used).
    #[inline]
    pub const fn missing_evidence_mask(&self) -> u16 {
        let slots = self.slots();
        let mut mask: u16 = 0;
        let mut i = 0;
        while i < HANDOFF_SLOT_COUNT {
            if is_zero_hash(slots[i]) {
                mask |= 1u16 << i;
            }
            i += 1;
        }
        mask
    }

    /// `true` iff every evidence slot is non-zero (i.e. Stage A handoff is
    /// complete and Stage B may begin). Equivalent to
    /// `self.missing_evidence_mask() == 0`.
    #[inline]
    pub const fn all_evidence_present(&self) -> bool {
        self.missing_evidence_mask() == 0
    }

    /// Serialize to the canonical `HANDOFF_DIGEST_BYTES`-long buffer
    /// (slot 0 first, big-end-of-struct last). Pairs with
    /// [`from_bytes`](Self::from_bytes).
    #[inline]
    pub const fn to_bytes(&self) -> [u8; HANDOFF_DIGEST_BYTES] {
        let slots = self.slots();
        let mut out = [0u8; HANDOFF_DIGEST_BYTES];
        let mut s = 0;
        while s < HANDOFF_SLOT_COUNT {
            let slot = slots[s];
            let mut b = 0;
            while b < 32 {
                out[s * 32 + b] = slot[b];
                b += 1;
            }
            s += 1;
        }
        out
    }

    /// Parse a digest from a canonical `HANDOFF_DIGEST_BYTES`-long buffer
    /// (inverse of [`to_bytes`](Self::to_bytes)). Total infallible — the
    /// fixed-width buffer cannot under-/over-run; *missing* evidence is
    /// surfaced afterwards by [`missing_evidence_mask`](Self::missing_evidence_mask),
    /// not by a parse error.
    #[inline]
    pub const fn from_bytes(buf: &[u8; HANDOFF_DIGEST_BYTES]) -> Self {
        // Copy each 32-byte window out of the buffer.
        let mut slot = [[0u8; 32]; HANDOFF_SLOT_COUNT];
        let mut s = 0;
        while s < HANDOFF_SLOT_COUNT {
            let mut b = 0;
            while b < 32 {
                slot[s][b] = buf[s * 32 + b];
                b += 1;
            }
            s += 1;
        }
        Self::new(
            slot[0], slot[1], slot[2], slot[3], slot[4], slot[5], slot[6], slot[7], slot[8],
            slot[9], slot[10],
        )
    }
}

// ===========================================================================
// 3. Evidence classification enums
// ===========================================================================

/// Redaction class of an evidence bundle. `#[repr(u8)]` with explicit
/// discriminants so the byte is stable for any future tabular form.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EvidenceRedactionClass {
    /// Contents are public-safe as-is (no redaction needed).
    PublicSafe = 1,
    /// Contents were redacted (secrets/private bodies removed) and are safe
    /// to keep locally.
    Redacted = 2,
    /// Contents contained private material that was *excluded* rather than
    /// redacted in place.
    PrivateExcluded = 3,
    /// A secret-like payload was *rejected* outright (must not appear in any
    /// evidence artifact).
    SecretRejected = 4,
}

impl EvidenceRedactionClass {
    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

/// Rights class of an evidence bundle (who may consume it). `#[repr(u8)]`
/// with explicit discriminants.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum EvidenceRightsClass {
    /// Internal build/debug only.
    InternalOnly = 1,
    /// The local user may consume it; not for contribution/publication.
    LocalUserOnly = 2,
    /// May be contributed in redacted form (downstream consent gate still
    /// applies).
    ContributeRedactedAllowed = 3,
    /// May be published publicly.
    PublicAllowed = 4,
}

impl EvidenceRightsClass {
    /// Stable u8 tag — mirrors the `#[repr(u8)]` discriminant.
    #[inline]
    pub const fn tag(self) -> u8 {
        self as u8
    }
}

// ===========================================================================
// 4. EvidenceBundleManifestV1 — local-only evidence hook
// ===========================================================================

/// Local-only evidence manifest (schema v1). It records the hashes of the
/// sidecar, the replay command and the env-lock, plus a redaction
/// class and a rights class, and a `not_verified` bitmask for gates that
/// could not be run. It is **not** a remote archive locator and **not** a
/// training-consent grant — see the field docs and
/// [`new_local_hook`](Self::new_local_hook).
///
/// All fields are `pub`; the Stage B constructor
/// emits the safe defaults (`training_eligibility = false`, no remote locator).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EvidenceBundleManifestV1 {
    /// Atom this manifest belongs to.
    pub atom_id_u16: u16,
    /// Creation time in milliseconds since the Unix epoch (caller-supplied;
    /// this crate never reads the clock).
    pub created_at_ms_u64: u64,
    /// Hash over the sidecar directory contents.
    pub sidecar_hash_32: [u8; 32],
    /// Hash of the exact replay command used to reproduce the atom.
    pub replay_command_hash_32: [u8; 32],
    /// Hash of the recorded environment lock.
    pub env_lock_hash_32: [u8; 32],
    /// Redaction class of the bundle.
    pub redaction_class: EvidenceRedactionClass,
    /// Rights class of the bundle.
    pub rights_class: EvidenceRightsClass,
    /// Whether this bundle is eligible to be used as training data. The
    /// Stage B constructor always sets this `false`.
    pub training_eligibility: bool,
    /// Optional remote storage locator hash. All-zero means "no remote
    /// locator" — Stage B never points a manifest at a live archive.
    pub optional_storage_locator_hash_32: [u8; 32],
    /// Bitmask of gates that could not be verified (e.g. miri / live testnet
    /// skipped). `0` = everything in scope was verified.
    pub not_verified_mask_u32: u32,
    /// Trace stamp tying the manifest to a run/atom/attempt.
    pub trace: StageBTraceLink,
}

impl EvidenceBundleManifestV1 {
    /// Construct a local-only evidence hook with the Stage B safe defaults:
    /// `training_eligibility = false` and an all-zero (= absent) remote
    /// storage locator. This is the *only* constructor Stage B uses; a future
    /// stage that genuinely archives remotely would set the public fields
    /// directly and own that decision.
    #[inline]
    #[allow(clippy::too_many_arguments)]
    pub const fn new_local_hook(
        atom_id_u16: u16,
        created_at_ms_u64: u64,
        sidecar_hash_32: [u8; 32],
        replay_command_hash_32: [u8; 32],
        env_lock_hash_32: [u8; 32],
        redaction_class: EvidenceRedactionClass,
        rights_class: EvidenceRightsClass,
        not_verified_mask_u32: u32,
        trace: StageBTraceLink,
    ) -> Self {
        Self {
            atom_id_u16,
            created_at_ms_u64,
            sidecar_hash_32,
            replay_command_hash_32,
            env_lock_hash_32,
            redaction_class,
            rights_class,
            training_eligibility: false,
            optional_storage_locator_hash_32: ZERO_HASH_32,
            not_verified_mask_u32,
            trace,
        }
    }

    /// `true` iff a remote storage locator is present (i.e. the locator hash
    /// is not the all-zero sentinel). Stage B manifests always return
    /// `false`.
    #[inline]
    pub const fn remote_locator_present(&self) -> bool {
        !is_zero_hash(&self.optional_storage_locator_hash_32)
    }
}

// ===========================================================================
// 5. Compile-time pins — discriminants and slot count
// ===========================================================================

// Pin the evidence-class discriminants exactly as declared. Any drift
// fails the build via a zero-length array index.
const _REDACTION_TAGS_ARE_STABLE: [(); 0 - !(EvidenceRedactionClass::PublicSafe.tag() == 1
    && EvidenceRedactionClass::Redacted.tag() == 2
    && EvidenceRedactionClass::PrivateExcluded.tag() == 3
    && EvidenceRedactionClass::SecretRejected.tag() == 4)
    as usize] = [];
const _RIGHTS_TAGS_ARE_STABLE: [(); 0 - !(EvidenceRightsClass::InternalOnly.tag() == 1
    && EvidenceRightsClass::LocalUserOnly.tag() == 2
    && EvidenceRightsClass::ContributeRedactedAllowed.tag() == 3
    && EvidenceRightsClass::PublicAllowed.tag() == 4)
    as usize] = [];
// Pin the slot count / serialized width so `to_bytes`/`from_bytes` and the
// `u16` mask stay in lock-step with the 11 declared fields.
const _SLOT_COUNT_IS_11: [(); 0 - !(HANDOFF_SLOT_COUNT == 11) as usize] = [];
const _DIGEST_BYTES_IS_352: [(); 0 - !(HANDOFF_DIGEST_BYTES == 352) as usize] = [];

// ===========================================================================
// 6. Inline unit tests
// ===========================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// Distinct non-zero 32-byte hash keyed by `seed` so each slot is
    /// distinguishable in round-trip tests.
    fn h(seed: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            a[i] = seed.wrapping_add(i as u8).wrapping_add(1); // never all-zero
            i += 1;
        }
        a
    }

    /// A fully-populated (all-present) handoff digest fixture.
    fn complete_digest() -> StageAHandoffDigest {
        StageAHandoffDigest::new(
            h(0),
            h(10),
            h(20),
            h(30),
            h(40),
            h(50),
            h(60),
            h(70),
            h(80),
            h(90),
            h(100),
        )
    }

    /// `to_bytes` → `from_bytes` is an identity round-trip over all 11 slots,
    /// and the buffer width is exactly 352.
    #[test]
    fn b1_0_handoff_hash_parse() {
        let d = complete_digest();
        let bytes = d.to_bytes();
        assert_eq!(bytes.len(), HANDOFF_DIGEST_BYTES);
        assert_eq!(bytes.len(), 352);
        let parsed = StageAHandoffDigest::from_bytes(&bytes);
        assert_eq!(parsed, d, "from_bytes(to_bytes(d)) must equal d");
        // Slot 0 occupies the first 32 bytes; slot 10 the last 32 bytes.
        assert_eq!(&bytes[0..32], &d.build_state_hash_32);
        assert_eq!(&bytes[320..352], &d.k_devex_gate_hash_32);
    }

    /// An all-missing digest reports every slot missing and is not complete; a
    /// complete digest reports `0` and is complete; a single zeroed slot is
    /// pinpointed by its bit.
    #[test]
    fn b1_0_missing_evidence_reject() {
        let none = StageAHandoffDigest::ALL_MISSING;
        assert_eq!(none.missing_evidence_mask(), 0b111_1111_1111); // 11 bits set
        assert!(!none.all_evidence_present());

        let all = complete_digest();
        assert_eq!(all.missing_evidence_mask(), 0);
        assert!(all.all_evidence_present());

        // Zero out exactly slot 6 (b_memory_gate) — bit 6 must be the only
        // set bit, and the digest is no longer complete.
        let mut one_missing = complete_digest();
        one_missing.b_memory_gate_hash_32 = [0u8; 32];
        assert_eq!(one_missing.missing_evidence_mask(), 1u16 << 6);
        assert!(!one_missing.all_evidence_present());

        // Zero out slot 0 as well — bits 0 and 6 set.
        one_missing.build_state_hash_32 = [0u8; 32];
        assert_eq!(
            one_missing.missing_evidence_mask(),
            (1u16 << 0) | (1u16 << 6)
        );
    }

    /// Every field carries its full type width with no truncation, and the
    /// constructor preserves all three components.
    #[test]
    fn b1_0_trace_id_width() {
        let t = StageBTraceLink::new(u64::MAX, u16::MAX, u8::MAX);
        assert_eq!(t.trace_id_u64, u64::MAX);
        assert_eq!(t.atom_id_u16, u16::MAX);
        assert_eq!(t.attempt_u8, u8::MAX);

        // A small atom id fits in the u16 field with vast headroom.
        let t81 = StageBTraceLink::new(7, 81, 0);
        assert_eq!(t81.atom_id_u16, 81);
        assert_eq!(t81.attempt_u8, 0);
    }

    /// The Stage B constructor always emits `training_eligibility = false`,
    /// regardless of class inputs.
    #[test]
    fn b1_0_manifest_default_false() {
        let m = EvidenceBundleManifestV1::new_local_hook(
            81,
            1_700_000_000_000,
            h(1),
            h(2),
            h(3),
            EvidenceRedactionClass::Redacted,
            EvidenceRightsClass::LocalUserOnly,
            0,
            StageBTraceLink::new(7, 81, 0),
        );
        assert!(
            !m.training_eligibility,
            "Stage B evidence manifests must default training_eligibility=false"
        );
        // Class inputs are carried through verbatim.
        assert_eq!(
            m.redaction_class.tag(),
            EvidenceRedactionClass::Redacted.tag()
        );
        assert_eq!(
            m.rights_class.tag(),
            EvidenceRightsClass::LocalUserOnly.tag()
        );
        assert_eq!(m.atom_id_u16, 81);
    }

    /// The Stage B constructor leaves the remote storage locator all-zero
    /// (= absent); flipping any byte makes the predicate report "present".
    #[test]
    fn b1_0_remote_locator_absent() {
        let mut m = EvidenceBundleManifestV1::new_local_hook(
            81,
            1_700_000_000_000,
            h(1),
            h(2),
            h(3),
            EvidenceRedactionClass::PublicSafe,
            EvidenceRightsClass::InternalOnly,
            0,
            StageBTraceLink::new(7, 81, 0),
        );
        assert_eq!(m.optional_storage_locator_hash_32, [0u8; 32]);
        assert!(
            !m.remote_locator_present(),
            "fresh Stage B manifest must have no remote locator"
        );

        // A non-zero locator (hypothetical future stage) flips the predicate.
        m.optional_storage_locator_hash_32 = h(9);
        assert!(m.remote_locator_present());
    }

    /// Discriminants match the declared values exactly (mirrors the
    /// compile-time pins as a runtime witness).
    #[test]
    fn b1_0_evidence_class_tags_stable() {
        assert_eq!(EvidenceRedactionClass::PublicSafe.tag(), 1);
        assert_eq!(EvidenceRedactionClass::Redacted.tag(), 2);
        assert_eq!(EvidenceRedactionClass::PrivateExcluded.tag(), 3);
        assert_eq!(EvidenceRedactionClass::SecretRejected.tag(), 4);

        assert_eq!(EvidenceRightsClass::InternalOnly.tag(), 1);
        assert_eq!(EvidenceRightsClass::LocalUserOnly.tag(), 2);
        assert_eq!(EvidenceRightsClass::ContributeRedactedAllowed.tag(), 3);
        assert_eq!(EvidenceRightsClass::PublicAllowed.tag(), 4);
    }
}
