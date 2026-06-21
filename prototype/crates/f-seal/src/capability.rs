//! atom #37 · F.0.1 — capability check stub.
//!
//! ATOM_PLAN §4.F (line 690-697) canonical OUT — `Capability` /
//! `CapabilityKind` / `check_capability` / `CapabilityError`. Phase 0 is
//! the *ownership gate* surface only: a fixed-width `#[repr(u8)] enum`
//! discriminant identifies which capability is being asserted, a
//! `Capability` token binds that discriminant to a Sui owner address,
//! and [`check_capability`] is a by-construction equality check that
//! both the required kind matches and the actor equals the bound
//! owner. There is no encryption, no key server and no threshold
//! cryptography on this path — those land in Phase 1 per §3.4 master
//! ("custody 인접이라 *지금* 안 건드림"). The 광기 line in ATOM_PLAN is
//! direct: "Phase 0 는 capability *체크*만; capability 는 고정폭 enum
//! tag" (line 1195).
//!
//! Canonical IN — [`SuiAddress`](mnemos_d_move::SuiAddress) from atom
//! #15 · D.0.1 is reused byte-for-byte: a `Capability.owner` and a
//! `MemoryRoot.owner` are the same 32-byte Sui account id at the
//! type level (atom #33/#34/#35/#36 precedent). No parallel address
//! shape is introduced here.
//!
//! Test coverage (verbatim from ATOM_PLAN line 1196):
//! [`tests::f0_1_capability_granted_for_owner`],
//! [`tests::f0_1_denied_for_wrong_kind`],
//! [`tests::f0_1_denied_for_wrong_actor`].

use mnemos_d_move::SuiAddress;

/// Capability discriminant. Phase 0 carries exactly the three kinds
/// listed in ATOM_PLAN §4.F (line 692): `ReadMemory = 1`,
/// `WriteMemory = 2`, `AnchorChunk = 3`. The `#[repr(u8)]` pin makes
/// the in-memory width byte-exact (1 byte) and stable across edits,
/// so future BCS / wire-form serialisation (Phase 1) can encode a
/// `CapabilityKind` as a single byte without ambiguity. Explicit
/// discriminant values are written out so reordering variants is a
/// compile-time-visible byte-VALUE change, not an implicit one
/// (cross-language schema lock discipline, codification #1).
///
/// `#[non_exhaustive]` keeps the variant set forward-compatible: Phase
/// 1's real Seal threshold path may add `DecryptShare` or similar
/// without that being a breaking match-arm change for downstream
/// crates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum CapabilityKind {
    /// Read access to a memory chunk (decryption / fetch path).
    ReadMemory = 1,
    /// Write access to a memory chunk (append / mutate path).
    WriteMemory = 2,
    /// Authority to anchor a chunk envelope to the chain (Move
    /// `add_chunk` entry — paired with atom #38 `assert_add_chunk_owner`).
    AnchorChunk = 3,
}

/// A capability token: the binding of a [`CapabilityKind`] to a Sui
/// owner [`SuiAddress`]. Phase 0 is a *checking* surface only — the
/// token is constructed by trusted code (the policy layer) and
/// presented to [`check_capability`] together with an `actor`
/// address; equality on both fields gates access.
///
/// Fields are private: a `Capability` cannot be silently mutated to
/// change either its kind or its owner after construction. The
/// `kind()` / `owner()` accessors expose copies (both fields are
/// `Copy`), so a caller cannot reach a `&mut` to the interior.
/// Future Phase 1 capability material (key share, expiry, nonce)
/// will be added behind the same `new` constructor to keep the
/// "no setter" property byte-stable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Capability {
    kind: CapabilityKind,
    owner: SuiAddress,
}

impl Capability {
    /// Construct a capability token binding the given kind to the
    /// given Sui owner address. The constructor takes both fields by
    /// value (both are `Copy`) so no borrow is held back. This is
    /// the only path to a `Capability`; no `Default` is provided
    /// because there is no defensible default owner.
    #[inline]
    pub const fn new(kind: CapabilityKind, owner: SuiAddress) -> Self {
        Self { kind, owner }
    }

    /// Borrow-free accessor for the bound capability kind.
    #[inline]
    pub const fn kind(&self) -> CapabilityKind {
        self.kind
    }

    /// Borrow-free accessor for the bound owner address.
    #[inline]
    pub const fn owner(&self) -> SuiAddress {
        self.owner
    }
}

/// Failure variant returned by [`check_capability`]. Phase 0 carries
/// exactly one variant — `Denied { kind }` — matching ATOM_PLAN §4.F
/// line 694. The carried `kind` is the *required* capability kind,
/// not the kind stored on the token: a future audit log entry then
/// reads as "actor X was denied a `<required>` capability" regardless
/// of whether the denial was for kind mismatch or for actor mismatch.
///
/// `#[non_exhaustive]` keeps the error surface forward-compatible
/// for Phase 1 (e.g. `Expired`, `Revoked`, `ThresholdShortfall`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum CapabilityError {
    /// The capability check failed: either the presented kind did
    /// not match the required kind, or the actor address did not
    /// match the bound owner. The carried `kind` is the *required*
    /// kind from the call site.
    Denied {
        /// The required capability kind at the call site (not the
        /// kind stored on the rejected token).
        kind: CapabilityKind,
    },
}

/// Check whether `cap` authorises `actor` to perform an action
/// requiring `required`. Returns `Ok(())` iff both
/// `cap.kind() == required` *and* `cap.owner() == actor`; otherwise
/// returns `Err(CapabilityError::Denied { kind: required })`.
///
/// Phase 0 semantics — equality on a `#[repr(u8)]` discriminant and
/// equality on a 32-byte address. No timing-side-channel claims are
/// made here: the check fails fast on the first mismatch and the
/// failure carries no information about whether kind or actor was
/// the cause. That carve-out is acceptable for Phase 0 because the
/// surface is not yet exposed across an untrusted boundary; Phase 1
/// (real Seal threshold) re-derives the discipline with constant-time
/// comparisons where they matter.
#[inline]
pub fn check_capability(
    cap: &Capability,
    required: CapabilityKind,
    actor: SuiAddress,
) -> Result<(), CapabilityError> {
    if cap.kind != required {
        return Err(CapabilityError::Denied { kind: required });
    }
    if cap.owner != actor {
        return Err(CapabilityError::Denied { kind: required });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32-byte test address `[0x11; 32]`. The first concrete owner
    /// used across the f-seal test surface; mirrors the d-move
    /// `tests::memory_root_args_owner_round_trip` fixture
    /// (`SuiAddress::new([0x11u8; 32])`).
    const OWNER_BYTES_ALPHA: [u8; 32] = [0x11u8; 32];
    /// 32-byte test address `[0x22; 32]` — distinct from
    /// [`OWNER_BYTES_ALPHA`] so an actor-mismatch denial fires.
    const OWNER_BYTES_BETA: [u8; 32] = [0x22u8; 32];

    /// ATOM_PLAN line 1196 test #1 — the happy path: a `WriteMemory`
    /// token bound to ALPHA, asserted with required = `WriteMemory`
    /// and actor = ALPHA, returns `Ok(())`.
    #[test]
    fn f0_1_capability_granted_for_owner() {
        let owner = SuiAddress::new(OWNER_BYTES_ALPHA);
        let cap = Capability::new(CapabilityKind::WriteMemory, owner);
        let outcome = check_capability(&cap, CapabilityKind::WriteMemory, owner);
        assert_eq!(outcome, Ok(()));
    }

    /// ATOM_PLAN line 1196 test #2 — kind-mismatch denial: a
    /// `ReadMemory` token bound to ALPHA, asserted with required =
    /// `WriteMemory` and actor = ALPHA, returns
    /// `Err(Denied { kind: WriteMemory })`. The carried kind is the
    /// *required* one (`WriteMemory`), not the token's stored
    /// `ReadMemory`.
    #[test]
    fn f0_1_denied_for_wrong_kind() {
        let owner = SuiAddress::new(OWNER_BYTES_ALPHA);
        let cap = Capability::new(CapabilityKind::ReadMemory, owner);
        let outcome = check_capability(&cap, CapabilityKind::WriteMemory, owner);
        assert_eq!(
            outcome,
            Err(CapabilityError::Denied {
                kind: CapabilityKind::WriteMemory,
            })
        );
    }

    /// ATOM_PLAN line 1196 test #3 — actor-mismatch denial: a
    /// `WriteMemory` token bound to ALPHA, asserted with required =
    /// `WriteMemory` and actor = BETA, returns
    /// `Err(Denied { kind: WriteMemory })`. Kind matches but actor
    /// does not, so the denial still fires.
    #[test]
    fn f0_1_denied_for_wrong_actor() {
        let owner_alpha = SuiAddress::new(OWNER_BYTES_ALPHA);
        let actor_beta = SuiAddress::new(OWNER_BYTES_BETA);
        let cap = Capability::new(CapabilityKind::WriteMemory, owner_alpha);
        let outcome = check_capability(&cap, CapabilityKind::WriteMemory, actor_beta);
        assert_eq!(
            outcome,
            Err(CapabilityError::Denied {
                kind: CapabilityKind::WriteMemory,
            })
        );
    }

    /// Width pin: the `#[repr(u8)]` on `CapabilityKind` is the
    /// canonical byte-width contract from ATOM_PLAN §4.F line 692.
    /// This structural assertion catches any future variant
    /// reordering / repr drift at test time without depending on the
    /// `static_assertions` dev-dep.
    #[test]
    fn capability_kind_is_one_byte() {
        assert_eq!(core::mem::size_of::<CapabilityKind>(), 1);
    }

    /// Discriminant pin: the three Phase 0 variants carry the exact
    /// integer discriminants written in ATOM_PLAN §4.F line 692
    /// (`ReadMemory = 1`, `WriteMemory = 2`, `AnchorChunk = 3`). A
    /// `#[repr(u8)]` enum can be cast to `u8` with `as`, so this is
    /// a literal byte-VALUE pin — reordering variants in source
    /// would flip a discriminant and fail this test before any
    /// downstream BCS / wire-form code observes the drift.
    #[test]
    fn capability_kind_discriminants_pinned() {
        assert_eq!(CapabilityKind::ReadMemory as u8, 1);
        assert_eq!(CapabilityKind::WriteMemory as u8, 2);
        assert_eq!(CapabilityKind::AnchorChunk as u8, 3);
    }
}
