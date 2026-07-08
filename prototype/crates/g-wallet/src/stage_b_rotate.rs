//! Stage B testnet key rotation.
//!
//! Canonical shape: a testnet key rotation
//! report. The spec: "rotation changes owner key, zeroizes old scoped
//! secret, and records audit trace." Built on
//! [`rotate_key`](crate::rotate::rotate_key) (#36), wrapped under Stage B
//! testnet policy.
//!
//! # Invariants
//!
//! * **Rotation changes the owner key.** The returned keystore is sealed
//!   around a fresh OS-CSPRNG seed; the report's new address differs from the
//!   old by construction (the Stage A `rotate_key` structural canary refuses
//!   the cryptographically-impossible collision).
//! * **The old scoped secret is zeroized.** Stage A `rotate_key` unseals the
//!   old key for exactly one authentication step and drops the transient
//!   [`ScopedSecretKey`](crate::keystore::ScopedSecretKey), whose `Drop`
//!   zeroizes the 32-byte buffer (#33 invariant). No copy of the old seed
//!   escapes this surface.
//! * **The report carries no secret (redaction proof).** [`StageBWalletRotationReport`]
//!   holds only the (old, new) public [`SuiAddress`] pair and a redacted
//!   [`StageBWalletTrace`] (#152) — address-suffix / gas / trace only. There
//!   is no field that could carry a key, so the rotation audit record cannot
//!   leak secret material.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #147** — [`StageBTestnetKeystore`] (the sealed keystore rotated).
//! * **reuse: #152** — [`StageBWalletTrace`] (the redacted audit stamp).
//! * Reuses [`rotate_key`] / [`RotationReport`] (#36), and the #148
//!   scoped-secret zeroize invariant.

use crate::keystore::SealedKeypair;
use crate::rotate::rotate_key;
use crate::stage_b_config::StageBWalletError;
use crate::stage_b_keystore::StageBTestnetKeystore;
use crate::stage_b_trace::StageBWalletTrace;
use mnemos_b_memory::stage_b_handoff::StageBTraceLink;
use mnemos_d_move::types::{GasBudgetMist, SuiAddress};

/// A redacted testnet key-rotation report (canonical shape).
///
/// Carries only public information — the (old, new) Sui address pair and a
/// redacted [`StageBWalletTrace`]. No secret field exists, so the report is a
/// safe audit-trail record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StageBWalletRotationReport {
    old_address: SuiAddress,
    new_address: SuiAddress,
    trace: StageBWalletTrace,
}

impl StageBWalletRotationReport {
    /// The pre-rotation owner address.
    #[inline]
    #[must_use]
    pub fn old_address(&self) -> SuiAddress {
        self.old_address
    }

    /// The post-rotation owner address (differs from [`Self::old_address`]).
    #[inline]
    #[must_use]
    pub fn new_address(&self) -> SuiAddress {
        self.new_address
    }

    /// The redacted audit trace for the rotation action.
    #[inline]
    #[must_use]
    pub fn trace(&self) -> StageBWalletTrace {
        self.trace
    }
}

/// Rotate a Stage B testnet keystore: produce a fresh sealed keypair under
/// `new_pass` (bound to the same testnet policy) and a redacted
/// [`StageBWalletRotationReport`].
///
/// The `trace` stamp links this rotation into the trace chain; the
/// report's trace records the NEW owner address suffix, the configured gas
/// ceiling, and the trace link (no secret).
///
/// # Errors
///
/// - [`StageBWalletError::Decrypt`] — wrong `old_pass` or tampered old
///   ciphertext (uniform privacy posture).
/// - [`StageBWalletError::PlaintextRefused`] — empty `new_pass`.
/// - [`StageBWalletError::RotationFailed`] — `new_pass == old_pass`, or the
///   cryptographically-impossible address-collision canary.
pub fn rotate_testnet(
    old: &StageBTestnetKeystore,
    old_pass: &str,
    new_pass: &str,
    trace: StageBTraceLink,
) -> Result<(StageBTestnetKeystore, StageBWalletRotationReport), StageBWalletError> {
    let config = old.config();
    // Stage A rotation: unseals old (one auth step, then zeroizes the
    // transient scoped secret), refuses same-pass, seals a fresh seed under
    // new_pass, and reports the (old, new) address pair.
    let (new_sealed, report): (SealedKeypair, crate::rotate::RotationReport) =
        rotate_key(old.sealed(), old_pass, new_pass)?;

    let new_address = *report.new_address();
    let old_address = *report.old_address();

    let new_keystore = StageBTestnetKeystore::from_sealed(new_sealed, config);
    let wallet_trace = StageBWalletTrace::new(
        new_address,
        GasBudgetMist::new(config.max_gas_mist().get()),
        None,
        trace,
    );

    Ok((
        new_keystore,
        StageBWalletRotationReport {
            old_address,
            new_address,
            trace: wallet_trace,
        },
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::stage_b_address::owner_binding;
    use crate::stage_b_config::StageBTestnetWalletConfig;
    use crate::stage_b_sign_message::sign_chunk_digest;
    use ed25519_dalek::SigningKey;
    use mnemos_b_memory::chunk_digest::{ChunkDigest32, stage_b_chunk_digest};
    use mnemos_b_memory::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1, StageBChunkView};
    use mnemos_b_memory::chunk_signature::verify_stage_b_chunk;
    use mnemos_b_memory::network::StageBNetwork;
    use mnemos_b_memory::owner::SigningPublicKey;
    use mnemos_c_walrus::PublishPayloadClass;
    use mnemos_c_walrus::codec::{ChunkEnvelopeV1, ChunkKind, MemoryRole};

    fn cfg() -> StageBTestnetWalletConfig {
        StageBTestnetWalletConfig::new(StageBNetwork::Testnet, GasBudgetMist::new(800_000))
    }

    fn digest_of(content: &[u8]) -> ChunkDigest32 {
        let envelope = ChunkEnvelopeV1 {
            kind: ChunkKind::UserMessage,
            role: MemoryRole::User,
            parent: None,
            content: content.to_vec(),
            embedding: None,
            signature: None,
            provenance: None,
        };
        let header = StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            content.len() as u32,
            SuiAddress::new([0x55; 32]),
            None,
            StageBTraceLink::new(153, 153, 0),
        )
        .expect("header valid");
        let view = StageBChunkView::new(header, &envelope).expect("within cap");
        stage_b_chunk_digest(&view).expect("digest ok")
    }

    /// `b4_7_rotation_changes_address` — after rotation the report's old/new
    /// addresses differ and match the two keystores, and the audit trace
    /// records the new address suffix (no secret).
    #[test]
    fn b4_7_rotation_changes_address() {
        let old = StageBTestnetKeystore::seal(cfg(), "old-pass").expect("seal old");
        let old_addr = old.public_address();

        let (new_ks, report) = rotate_testnet(
            &old,
            "old-pass",
            "new-pass",
            StageBTraceLink::new(153, 153, 1),
        )
        .expect("rotation must succeed");

        assert_ne!(
            report.old_address().as_bytes(),
            report.new_address().as_bytes(),
            "rotation must change the owner address",
        );
        assert_eq!(report.old_address().as_bytes(), old_addr.as_bytes());
        assert_eq!(
            report.new_address().as_bytes(),
            new_ks.public_address().as_bytes(),
        );
        // Audit trace carries the NEW address suffix (last 4 bytes), no secret.
        assert_eq!(
            report.trace().address_suffix(),
            &new_ks.public_address().as_bytes()[28..],
        );
    }

    /// `b4_7_same_pass_refused` — rotating to the same passphrase is refused
    /// fail-closed (mapped onto `RotationFailed`).
    #[test]
    fn b4_7_same_pass_refused() {
        let old = StageBTestnetKeystore::seal(cfg(), "same").expect("seal");
        assert_eq!(
            rotate_testnet(&old, "same", "same", StageBTraceLink::new(153, 153, 2))
                .err()
                .expect("same-pass rotation refused"),
            StageBWalletError::RotationFailed,
        );
    }

    /// `b4_7_new_key_signs_chunk` — the rotated keystore's new key signs a
    /// chunk digest that verifies under the new key's owner binding (the new
    /// key is fully usable; the old transient secret was zeroized inside
    /// `rotate_key`).
    #[test]
    fn b4_7_new_key_signs_chunk() {
        let old = StageBTestnetKeystore::seal(cfg(), "old-pass").expect("seal old");
        let (new_ks, _report) = rotate_testnet(
            &old,
            "old-pass",
            "new-pass",
            StageBTraceLink::new(153, 153, 3),
        )
        .expect("rotation");

        let scoped = new_ks.unseal("new-pass").expect("unseal new");
        let digest = digest_of(b"post-rotation chunk");
        let sig = sign_chunk_digest(&scoped, digest);

        // Derive the new key's owner binding from its seed and verify.
        let signing = SigningKey::from_bytes(scoped.as_bytes());
        let pubkey = signing.verifying_key().to_bytes();
        let binding = owner_binding(&SigningPublicKey::from_bytes(&pubkey).expect("32 bytes"));
        verify_stage_b_chunk(&sig, digest, &binding)
            .expect("new key's chunk signature must verify");
    }
}
