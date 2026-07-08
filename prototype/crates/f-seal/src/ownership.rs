//! `add_chunk` owner-only gate (off-chain mirror).
//!
//! Canonical surface —
//! `assert_add_chunk_owner(root_owner, actor) -> Result<(), CapabilityError>`.
//! Phase 0 keeps the f-seal surface to an *ownership gate only* (no Seal
//! AEAD / key server / threshold cryptography — those are Phase 1,
//! custody-adjacent, deferred). This is the Rust-side counterpart of the
//! Move `add_chunk` owner-only entry function (`memory_root.move`) so
//! the security perimeter rejects a non-owner *off-chain first* (cheap,
//! no gas) before the on-chain abort (`E_NOT_OWNER = 1`) fires — the
//! access control layer that keeps user memory from being misused.
//!
//! Three reuse edges, all byte-for-byte (no parallel shape introduced
//! here):
//! - [`SuiAddress`](mnemos_d_move::SuiAddress) (32-byte Sui account
//!   address, `Copy + Eq`).
//! - [`CapabilityError`](crate::CapabilityError) (`Denied { kind }`
//!   variant; `#[non_exhaustive]`).
//! - [`CapabilityKind`](crate::CapabilityKind) (`AnchorChunk = 3`
//!   semantically matches the Move `add_chunk` entry).
//!
//! Move-side invariant: `forall f in {add_chunk, transfer_root}.
//! ctx.sender() != root.owner => f aborts with E_NOT_OWNER`. The
//! Rust-side mirror is the same by-construction equality check:
//! `actor != root_owner` returns `Err(Denied { kind: AnchorChunk })`.
//! The `Result::Ok` branch encodes the *negation* of the Move abort
//! predicate — verified by [`tests::f0_2_matches_move_invariant`].
//!
//! Test coverage: [`tests::f0_2_owner_can_add`],
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
/// `ReadMemory`) because that is the capability kind that semantically
/// matches the Move `add_chunk` entry — `capability.rs` already pins
/// this naming. A future audit log entry then reads as "actor X was
/// denied an `AnchorChunk` capability" regardless of whether the
/// rejection is enforced off-chain (here) or on-chain (Move
/// `E_NOT_OWNER`).
///
/// Phase 0 semantics — equality on a 32-byte Sui address. No
/// timing-side-channel claims are made: the check fails fast on
/// mismatch and the failure carries no extra information about *which*
/// owner is expected. `check_capability` makes the same carve-out; both
/// will be revisited in Phase 1 when the surface crosses an untrusted
/// boundary.
///
/// Both parameters are passed by value because `SuiAddress` is `Copy`
/// (`#[derive(Clone, Copy)]` + `pub struct
/// SuiAddress([u8; SUI_ADDRESS_BYTES])`). No allocation, no borrow.
///
/// # Boundary
///
/// This is an **off-chain reject** layer. The authoritative gate is the
/// Move `add_chunk` `E_NOT_OWNER` abort (`memory_root.move`). Off-chain
/// failure short-circuits the transaction *before* it is signed and
/// submitted, saving gas and the round-trip — but a malicious caller
/// who skips this gate is still rejected on-chain. This is the
/// double-gate: off-chain reject followed by on-chain reject.
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

    /// 32-byte test address `[0x11; 32]` — mirrors the f-seal
    /// `capability.rs` `OWNER_BYTES_ALPHA` fixture and the d-move
    /// `tests::memory_root_args_owner_round_trip` ALPHA fixture.
    const OWNER_BYTES_ALPHA: [u8; 32] = [0x11u8; 32];
    /// 32-byte test address `[0x22; 32]` — mirrors the f-seal
    /// `OWNER_BYTES_BETA`; distinct from ALPHA so a non-owner denial
    /// fires.
    const OWNER_BYTES_BETA: [u8; 32] = [0x22u8; 32];

    /// Happy path: a memory root owned by ALPHA, asserted with
    /// actor = ALPHA, returns `Ok(())`. This is the off-chain analogue
    /// of the Move `add_chunk_by_owner_succeeds` test.
    #[test]
    fn f0_2_owner_can_add() {
        let owner = SuiAddress::new(OWNER_BYTES_ALPHA);
        let actor = SuiAddress::new(OWNER_BYTES_ALPHA);
        let outcome = assert_add_chunk_owner(owner, actor);
        assert_eq!(outcome, Ok(()));
    }

    /// Non-owner denial: a memory root owned by ALPHA, asserted with
    /// actor = BETA, returns `Err(Denied { kind: AnchorChunk })`. This
    /// is the off-chain analogue of the Move
    /// `add_chunk_by_non_owner_aborts` test, which on-chain aborts with
    /// `E_NOT_OWNER`. The carried kind is `AnchorChunk` to mirror the
    /// capability discriminant naming.
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

    /// Pairs the Rust-side gate with the Move-side invariant
    /// (`(I-1) owner-only mutate`): "ctx.sender() != root.owner =>
    /// add_chunk aborts with E_NOT_OWNER". Off-chain mirror predicate:
    /// `actor != root_owner` <=> `assert_add_chunk_owner` returns
    /// `Err(Denied { kind: AnchorChunk })`. This test enumerates all
    /// four (owner, actor) combinations over the two test addresses
    /// and confirms the biconditional holds for every input, so any
    /// future drift between the Rust gate and the Move invariant is
    /// caught at `cargo test` time (the Move-side formal check is a
    /// separate gate; this is its unit-test companion).
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
