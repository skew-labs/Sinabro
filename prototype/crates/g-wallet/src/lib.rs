//! `mnemos-g-wallet` — sealed keystore, transaction/message signing and key rotation.
//!
//! Atom #33 · G.0.1 lands the first canonical surface here: an
//! at-rest-encrypted Sui ed25519 keypair gated behind a passphrase, with
//! the in-memory secret confined to a `Drop`-zeroizing
//! `ScopedSecretKey` that structurally cannot be logged or cloned
//! (§10.3 광기 — `Debug` / `Display` / `Clone` / serde absent ⇒ those
//! code paths fail to compile).
//!
//! Atom #34 · G.0.2 layers the second canonical surface on top: the
//! [`sign_tx::sign_move_tx`] entry point that prepends the canonical
//! 3-byte Sui intent prefix `[TransactionData=0, V0=0, Sui=0]` to a
//! caller-supplied `intent_tx_bytes` slice and returns the 64-byte
//! ed25519 signature as the c-walrus [`SignatureBytes`](mnemos_c_walrus::SignatureBytes)
//! type (reused, not redeclared — atom #7 owns the canonical 64-byte
//! signature shape so storage path C and signing path G agree
//! byte-for-byte). The signature-scheme flag for ed25519
//! ([`sign_tx::SignatureFlag::ED25519`] = `0x00`) is exposed as a
//! typed constant for future wire-form serialisation.
//!
//! Atom #35 · G.0.3 layers the third canonical surface: the
//! [`sign_msg::sign_message`] entry point that prepends the **distinct**
//! 3-byte Sui personal-message intent prefix
//! `[IntentScope::PersonalMessage=3, V0=0, Sui=0]`
//! ([`sign_msg::SUI_INTENT_PREFIX_PERSONAL_MESSAGE`]) to a caller-
//! supplied `message` slice and returns the same 64-byte
//! [`SignatureBytes`] type — so a personal-message signature cannot
//! be replayed under the transaction-data scope (atom #34's prefix
//! `[0,0,0]`), and vice versa. The placeholder → real signing path
//! (ATOM_PLAN line 1171) is witnessed by the
//! `g0_3_signs_message_vector` test: the returned `SignatureBytes`
//! substitutes byte-for-byte for the `signature` field of a c-walrus
//! [`SignaturePlaceholderV1`](mnemos_c_walrus::SignaturePlaceholderV1).
//!
//! Atom #36 · G.0.4 closes Stage G with the [`rotate::rotate_key`]
//! entry point: given a caller-supplied `&SealedKeypair` + the old
//! passphrase + a NEW passphrase, returns the freshly-generated
//! `(SealedKeypair, RotationReport)` pair — a brand-new ed25519 seed
//! drawn from the OS CSPRNG, sealed under the new passphrase via the
//! atom #33 [`SealedKeypair::create_encrypted`] path; the transient
//! [`ScopedSecretKey`] unsealed from the OLD keypair is borrowed for
//! exactly one verification step and then dropped (its 32-byte buffer
//! is zeroized by `Drop`, atom #33 invariant). The returned
//! [`rotate::RotationReport`] carries **only** the (old, new) Sui
//! address pair — no secret material crosses the rotation surface.
//! The first emission site for [`WalletError::KeyRotation`] (declared
//! by atom #33's canonical OUT, reserved through atoms #34 / #35)
//! lands here: rotation refuses when `new_pass == old_pass` (silent
//! same-pass rotation defeats the purpose) and is also surfaced as a
//! structural canary on the cryptographically-impossible address-
//! collision branch. The "no signing gap during rotation"
//! requirement (ATOM_PLAN line 1181) is satisfied by construction —
//! `rotate_key` takes `&SealedKeypair` (NOT `&mut`), so the OLD
//! sealed file remains usable for [`sign_move_tx`] / [`sign_message`]
//! until the caller decides to overwrite it on disk; the
//! [`rotate::tests::g0_4_e2e_sign_after_rotation`] test witnesses
//! both signing paths under both old and new keys end-to-end.
#![deny(missing_docs)]
#![forbid(unsafe_code)]

pub mod keystore;
pub mod rotate;
pub mod sign_msg;
pub mod sign_tx;

// Stage B WorkPackage B-WP-03 (atoms #146–#155): testnet wallet core. Each
// module is a thin Stage-B testnet-policy surface over the Stage A §4.G
// crypto above — no parallel crypto is minted. Network selection reuses the
// one-variant `StageBNetwork` (atom #82) so a production network is
// unrepresentable across the whole package.
pub mod stage_b_address;
pub mod stage_b_balance;
pub mod stage_b_config;
pub mod stage_b_keystore;
pub mod stage_b_rotate;
pub mod stage_b_secret;
pub mod stage_b_sign_message;
pub mod stage_b_sign_tx;
pub mod stage_b_submit;
pub mod stage_b_trace;

// Stage C WorkPackage C-WP-05 (atoms #211–#218): mainnet multisig / timelock /
// signing envelope + deny-by-default Gas Station policy. These are typed
// approval-machinery surfaces — multisig roster, proposal envelope, timelock
// policy, exact signer envelope, no-single-key guard, Gas Station policy schema
// and dry-run/effect-shape checker. No live egress, no wallet signing, no gas
// spend: every surface produces `Locked` / `ApprovalPending` state, never
// `Executed`. Reuses the §4.D `SuiAddress`/`ObjectId`/`GasBudgetMist`/
// `SuiCallBuilder`/`EffectDelta` (d-move) and the §4.0 `StageCTraceLink` /
// §4.1 `MainnetExecutionState` (a-core) — no parallel type is minted.
pub mod stage_c_gas_effect;
pub mod stage_c_gas_policy;
pub mod stage_c_multisig;
pub mod stage_c_multisig_proposal;
pub mod stage_c_no_single_key;
pub mod stage_c_signer_boundary;
pub mod stage_c_signer_envelope;
pub mod stage_c_timelock;
// Stage C WorkPackage C-WP-06B (atoms #227–#228): signer isolation boundary +
// cold-treasury / hot-sponsor topology. Prepare-only datatypes — the API
// process holds a zero-sized key-less handle, the cold treasury is bound to a
// `threshold >= 2` multisig roster, and auto-refill is disabled by default.
// No live egress, no wallet signing, no gas spend; `MainnetExecutionState`
// stays `Locked`. Reuses §4.G `SealedKeypair`/`ScopedSecretKey`, §4.D
// `SuiAddress`/`GasBudgetMist`, #214 `MainnetSignerEnvelope`, and #211
// `MultisigRoster` — no parallel type is minted.
pub mod stage_c_wallet_topology;
// Stage C WorkPackage C-WP-07 (atoms #229–#231): sponsor hot-wallet cap policy,
// sponsor signer request/response boundary, and gas-coin lease pool. Pure typed
// policy / boundary / bookkeeping — no key material, no signer, no tx submitter.
// Reuses §4.D `SuiAddress`/`ObjectId`/`GasBudgetMist` (d-move) and #214
// `MainnetSignerEnvelope`; no parallel type is minted. `MainnetExecutionState`
// stays `Locked`.
pub mod stage_c_gas_coin_lease;
pub mod stage_c_hot_wallet;
pub mod stage_c_sponsor_signer;

pub use keystore::{
    KDF_SALT_BYTES, PUBLIC_KEY_BYTES, SECRET_KEY_BYTES, STORED_NONCE_BYTES, ScopedSecretKey,
    SealedKeypair, WalletError,
};
pub use rotate::{RotationReport, rotate_key};
pub use sign_msg::{
    SUI_INTENT_PREFIX_PERSONAL_MESSAGE, SUI_INTENT_SCOPE_PERSONAL_MESSAGE, sign_message,
};
pub use sign_tx::{
    SIGNATURE_BYTES, SUI_INTENT_PREFIX_BYTES, SUI_INTENT_PREFIX_TRANSACTION_DATA,
    SUI_SIGNATURE_FLAG_ED25519, SignatureFlag, sign_move_tx,
};

// ----- Stage B WorkPackage B-WP-03 canonical re-exports --------------------
pub use stage_b_address::{
    STAGE_B_SUI_ED25519_FLAG, address_from_placeholder, derive_testnet_address,
    derive_testnet_address_from_bytes, owner_binding,
};
pub use stage_b_balance::{StageBBalancePreflight, StageBBalanceVerdict};
pub use stage_b_config::{StageBTestnetWalletConfig, StageBWalletError};
pub use stage_b_keystore::StageBTestnetKeystore;
pub use stage_b_rotate::{StageBWalletRotationReport, rotate_testnet};
pub use stage_b_secret::StageBScopedSecretKey;
pub use stage_b_sign_message::sign_chunk_digest;
pub use stage_b_sign_tx::sign_testnet_call;
pub use stage_b_submit::{
    STAGE_B_TX_DIGEST_BYTES, StageBSubmitOutcome, StageBSubmitter, StageBTxDigest,
};
pub use stage_b_trace::{STAGE_B_WALLET_TRACE_ADDR_SUFFIX_BYTES, StageBWalletTrace};

// ----- Stage C WorkPackage C-WP-05 canonical re-exports --------------------
pub use stage_c_gas_effect::{
    GasIntent, GasStationDecision, SponsorshipRequest, evaluate_sponsorship,
};
pub use stage_c_gas_policy::{
    GasSponsorMode, GasStationPolicy, GasStationRejectReason, OfficialTrustDecision,
    SafetyKernelAttestation, SafetyKernelBuildRef, SponsoredFunction,
};
pub use stage_c_multisig::{
    MULTISIG_MAX_SIGNERS, MULTISIG_MIN_SIGNERS, MULTISIG_MIN_THRESHOLD, MULTISIG_ROSTER_BYTES,
    MultisigError, MultisigRoster, signer_set_hash,
};
pub use stage_c_multisig_proposal::{
    MultisigProposalEnvelope, PROPOSAL_PREIMAGE_BYTES, ProposalError,
};
pub use stage_c_no_single_key::{MainnetSigningAuthority, NoSingleKeyError};
pub use stage_c_signer_envelope::{
    MainnetSignerEnvelope, SIGNER_PREIMAGE_BYTES, SignerDisplayFields, SignerEnvelopeError,
};
pub use stage_c_timelock::{
    MIN_TIMELOCK_DELAY_SECS, TIMELOCK_POLICY_BYTES, TimelockError, TimelockPolicy,
};

// ----- Stage C WorkPackage C-WP-06B canonical re-exports -------------------
pub use stage_c_signer_boundary::{
    ApiProcessSignerHandle, SignerBackendBinding, SignerBackendKind, SignerBoundaryError,
    SignerIsolationBoundary, SigningAdmission, SigningRequest, envelope_binding_hash,
};
pub use stage_c_wallet_topology::{ColdHotTopology, WalletTopologyError};

// ----- Stage C WorkPackage C-WP-07 canonical re-exports --------------------
pub use stage_c_gas_coin_lease::{GasCoinLease, GasCoinLeaseError, GasCoinLeasePool};
pub use stage_c_hot_wallet::{
    HotWalletPolicyError, SponsorHotWalletPolicy, UNBOUNDED_DAILY_BURN_MIST,
    UNBOUNDED_MAX_COIN_LEASES,
};
pub use stage_c_sponsor_signer::{SponsorSignerError, SponsorSignerGrant, SponsorSignerRequest};
