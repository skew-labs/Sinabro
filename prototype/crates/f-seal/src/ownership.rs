//! atom #38 · F.0.2 — `add_chunk` owner-only gate (off-chain mirror).
//!
//! ATOM_PLAN §4.F (line 697) canonical OUT —
//! `assert_add_chunk_owner(root_owner, actor) -> Result<(), CapabilityError>`.
//! Phase 0 keeps the f-seal surface to an *ownership gate only* (no Seal
//! AEAD / key server / threshold cryptography — Phase 1, custody-adjacent,
//! deferred per §3.4 master and atom #37 module docs line 5-11). The 광기
//! line is direct: this is the Rust-side *짝* of the Move `add_chunk`
//! owner-only entry function (atom #16 · D.0.2 · `prototype/move/sources/`
//! `memory_root.move` line 76-77) so the security perimeter rejects a
//! non-owner *off-chain first* (cheap, no gas) before the on-chain abort
//! (`E_NOT_OWNER = 1`) fires (§10.6 "사용자 메모리 오남용 불가" access
//! control layer, ATOM_PLAN line 1205).
//!
//! Canonical IN — three reuse edges, all byte-for-byte (no parallel
//! shape introduced this atom):
//! - [`SuiAddress`](mnemos_d_move::SuiAddress) from atom #15 · D.0.1
//!   (32-byte Sui account address, `Copy + Eq`).
//! - [`CapabilityError`](crate::CapabilityError) from atom #37 · F.0.1
//!   (`Denied { kind }` variant; `#[non_exhaustive]`).
//! - [`CapabilityKind`](crate::CapabilityKind) from atom #37 · F.0.1
//!   (`AnchorChunk = 3` semantically matches the Move `add_chunk`
//!   entry — per atom #37 lib doc line 18 + capability.rs line 51-53).
//!
//! Move-side invariant (atom #16 · D.0.2 · spec line 75-105):
//! `forall f in {add_chunk, transfer_root}. ctx.sender() != root.owner
//! => f aborts with E_NOT_OWNER`. The Rust-side mirror is the same
//! by-construction equality check: `actor != root_owner` returns
//! `Err(Denied { kind: AnchorChunk })`. The `Result::Ok` branch encodes
//! the *negation* of the Move abort predicate — verified by
//! [`tests::f0_2_matches_move_invariant`].
//!
//! Test coverage (verbatim from ATOM_PLAN line 1206):
//! [`tests::f0_2_owner_can_add`],
//! [`tests::f0_2_non_owner_rejected`],
//! [`tests::f0_2_matches_move_invariant`].

use mnemos_d_move::SuiAddress;

use crate::capability::{CapabilityError, CapabilityKind};

/// Assert that `actor` is the current owner of a memory root, gating an
/// off-chain `add_chunk` call before it reaches the Move entry function.
/// Returns `Ok(())` iff `root_owner == actor`; otherwise returns
/// `Err(CapabilityError::Denied { kind: CapabilityKind::AnchorChunk })`.
///
/// The denial variant carries `AnchorChunk` (not `WriteMemory` or
/// `ReadMemory`) because that is the §4.F line 692 capability kind that
/// semantically matches the Move `add_chunk` entry — atom #37
/// `capability.rs` line 51-53 already pins this naming. A future audit
/// log entry then reads as "actor X was denied an `AnchorChunk`
/// capability" regardless of whether the rejection is enforced off-chain
/// (here) or on-chain (Move `E_NOT_OWNER`).
///
/// Phase 0 semantics — equality on a 32-byte Sui address. No
/// timing-side-channel claims are made: the check fails fast on
/// mismatch and the failure carries no extra information about *which*
/// owner is expected. Atom #37 `check_capability` makes the same
/// carve-out (capability.rs line 127-134); both will be revisited in
/// Phase 1 when the surface crosses an untrusted boundary.
///
/// Both parameters are passed by value because `SuiAddress` is `Copy`
/// (atom #15 · D.0.1 — `#[derive(Clone, Copy)]` + `pub struct
/// SuiAddress([u8; SUI_ADDRESS_BYTES])`). No allocation, no borrow.
///
/// # Boundary
///
/// This is an **off-chain reject** layer. The authoritative gate is the
/// Move `add_chunk` `E_NOT_OWNER` abort (atom #16 · D.0.2 ·
/// `memory_root.move` line 76-77 + spec line 84). Off-chain failure
/// short-circuits the transaction *before* it is signed and submitted,
/// saving gas and the round-trip — but a malicious caller who skips
/// this gate is still rejected on-chain. The double-gate is the
/// "경계에서 이중 검증 (오프체인 거부 → 온체인 거부)" of ATOM_PLAN
/// line 1205.
#[inline]
pub fn assert_add_chunk_owner(
    root_owner: SuiAddress,
    actor: SuiAddress,
) -> Result<(), CapabilityError> {
    if root_owner != actor {
        return Err(CapabilityError::Denied {
            kind: CapabilityKind::AnchorChunk,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 32-byte test address `[0x11; 32]` — mirrors the f-seal atom #37
    /// `capability.rs` `OWNER_BYTES_ALPHA` fixture (line 158) and the
    /// d-move `tests::memory_root_args_owner_round_trip` ALPHA fixture.
    const OWNER_BYTES_ALPHA: [u8; 32] = [0x11u8; 32];
    /// 32-byte test address `[0x22; 32]` — mirrors the f-seal atom #37
    /// `OWNER_BYTES_BETA` (line 161); distinct from ALPHA so a
    /// non-owner denial fires.
    const OWNER_BYTES_BETA: [u8; 32] = [0x22u8; 32];

    /// ATOM_PLAN line 1206 test #1 — happy path: a memory root owned
    /// by ALPHA, asserted with actor = ALPHA, returns `Ok(())`. This
    /// is the off-chain analogue of the Move
    /// `add_chunk_by_owner_succeeds` test (atom #16 · D.0.2 · spec
    /// line 166-168).
    #[test]
    fn f0_2_owner_can_add() {
        let owner = SuiAddress::new(OWNER_BYTES_ALPHA);
        let actor = SuiAddress::new(OWNER_BYTES_ALPHA);
        let outcome = assert_add_chunk_owner(owner, actor);
        assert_eq!(outcome, Ok(()));
    }

    /// ATOM_PLAN line 1206 test #2 — non-owner denial: a memory root
    /// owned by ALPHA, asserted with actor = BETA, returns
    /// `Err(Denied { kind: AnchorChunk })`. This is the off-chain
    /// analogue of the Move `add_chunk_by_non_owner_aborts` test
    /// (atom #16 · D.0.2 · spec line 90-93), which on-chain aborts
    /// with `E_NOT_OWNER`. The carried kind is `AnchorChunk` to mirror
    /// the §4.F line 692 / atom #37 capability discriminant naming.
    #[test]
    fn f0_2_non_owner_rejected() {
        let owner = SuiAddress::new(OWNER_BYTES_ALPHA);
        let actor = SuiAddress::new(OWNER_BYTES_BETA);
        let outcome = assert_add_chunk_owner(owner, actor);
        assert_eq!(
            outcome,
            Err(CapabilityError::Denied {
                kind: CapabilityKind::AnchorChunk,
            })
        );
    }

    /// ATOM_PLAN line 1206 test #3 — pairs the Rust-side gate with
    /// the Move-side invariant from atom #16 · D.0.4 (spec line 75-93,
    /// `(I-1) owner-only mutate`): "ctx.sender() != root.owner =>
    /// add_chunk aborts with E_NOT_OWNER". Off-chain mirror predicate:
    /// `actor != root_owner` <=> `assert_add_chunk_owner` returns
    /// `Err(Denied { kind: AnchorChunk })`. This test enumerates all
    /// four (owner, actor) combinations over the two test addresses
    /// and confirms the biconditional holds for every input, so any
    /// future drift between the Rust gate and the Move invariant is
    /// caught at `cargo test` time (G-PROVER on the Move side runs in
    /// atom #18; this is the G-CORE companion).
    #[test]
    fn f0_2_matches_move_invariant() {
        let alpha = SuiAddress::new(OWNER_BYTES_ALPHA);
        let beta = SuiAddress::new(OWNER_BYTES_BETA);

        let cases: [(SuiAddress, SuiAddress); 4] =
            [(alpha, alpha), (alpha, beta), (beta, alpha), (beta, beta)];

        for (owner, actor) in cases {
            let outcome = assert_add_chunk_owner(owner, actor);
            let move_would_abort = owner != actor;
            let rust_denied = matches!(
                outcome,
                Err(CapabilityError::Denied {
                    kind: CapabilityKind::AnchorChunk,
                })
            );
            assert_eq!(
                rust_denied, move_would_abort,
                "Rust gate must mirror Move E_NOT_OWNER abort for (owner={:?}, actor={:?})",
                owner, actor,
            );
            if !move_would_abort {
                assert_eq!(outcome, Ok(()));
            }
        }
    }
}
