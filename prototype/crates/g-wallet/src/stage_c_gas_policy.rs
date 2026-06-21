//! Stage C Gas Station policy schema (C-WP-05 · atom #217 · C.1.16).
//!
//! Canonical OUT (§4.3): [`GasStationPolicy`], [`GasSponsorMode`],
//! [`SponsoredFunction`], [`GasStationRejectReason`], [`SafetyKernelAttestation`],
//! [`OfficialTrustDecision`].
//!
//! # Madness invariants (atom #217)
//!
//! * **Deny-by-default.** The only sponsorable functions initially are
//!   `memory::add_chunk` (which also carries the compatibility-update
//!   semantics) and `audit_log::append`. The allowlist is a `u16` bitmask whose
//!   only valid bits are the three [`SponsoredFunction`] bits; any
//!   reserved/wildcard bit makes [`GasStationPolicy::reject_if_wildcard`]
//!   return [`GasStationRejectReason::Wildcard`].
//! * **Hosted sponsorship requires an intact official safety-kernel
//!   attestation.** [`GasStationPolicy::evaluate_trust`] returns
//!   [`OfficialTrustDecision::OfficialTrusted`] only for a `Hosted` policy that
//!   requires the official kernel **and** presents a non-expired attestation. A
//!   missing attestation is [`Quarantined`](OfficialTrustDecision::Quarantined);
//!   an expired one is [`Revoked`](OfficialTrustDecision::Revoked). An unknown
//!   fork (self-hosted / none) is local/self-host only — never officially
//!   trusted.
//! * **Caps are typed.** Per-tx gas is a [`GasBudgetMist`]; per-epoch tx count
//!   and storage bytes are `u32`. Over-cap is [`GasStationRejectReason::Budget`].
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: A [`ObjectId`](mnemos_d_move::types::ObjectId),
//!   [`GasBudgetMist`](mnemos_d_move::types::GasBudgetMist)** — the package id
//!   and gas-budget unit are the d-move §4.D types, not re-minted.
//! * **reuse: #216** — the threat model this policy enforces.

use blake2::{Blake2b, Digest, digest::consts::U32};
use mnemos_d_move::types::{GasBudgetMist, ObjectId};

/// Domain separator for the policy hash (bound by the atom #214 signer
/// envelope's `policy_hash_32`).
const POLICY_HASH_DOMAIN: &[u8] = b"mnemos.stage_c.gas_station_policy.v1";

/// Whether/how a sponsor pays for a transaction (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasSponsorMode {
    /// Hosted official sponsor (requires safety-kernel attestation).
    Hosted = 1,
    /// Operator self-hosts the sponsor.
    SelfHosted = 2,
    /// No sponsorship.
    None = 3,
}

impl GasSponsorMode {
    /// The raw discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Hosted),
            2 => Some(Self::SelfHosted),
            3 => Some(Self::None),
            _ => None,
        }
    }
}

/// A function the Gas Station may sponsor (§4.3). Deny-by-default: only these
/// three are representable, and only two are allowed initially.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SponsoredFunction {
    /// `memory::add_chunk` (anchor/update semantics).
    MemoryAddChunk = 1,
    /// Compatibility update — performed via `add_chunk`, not a separate call.
    MemoryUpdateCompat = 2,
    /// `audit_log::append`.
    AuditAppend = 3,
}

impl SponsoredFunction {
    /// The raw discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
    /// Parse from the discriminant byte, rejecting unknown values.
    #[inline]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::MemoryAddChunk),
            2 => Some(Self::MemoryUpdateCompat),
            3 => Some(Self::AuditAppend),
            _ => None,
        }
    }
    /// The single allowlist bit this function owns: `1 << (discriminant - 1)`.
    #[inline]
    pub const fn bit(self) -> u16 {
        1u16 << (self as u16 - 1)
    }
}

/// Why a Gas Station sponsorship request was rejected (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum GasStationRejectReason {
    /// Caller identity check failed.
    Identity = 1,
    /// Intent decode failed.
    Decode = 2,
    /// Package or function not on the allowlist.
    PackageFunction = 3,
    /// The dry-run effect shape did not match the claimed function.
    EffectShape = 4,
    /// Over a budget cap.
    Budget = 5,
    /// Replay / nonce reuse.
    ReplayNonce = 6,
    /// Per-identity quota risk.
    QuotaRisk = 7,
    /// Gas-coin lease contention or expiry.
    GasCoinLease = 8,
    /// Opaque byte payload offered for signing.
    OpaqueBytes = 9,
    /// Pre-baked raw `GasData` offered for signing.
    RawGasData = 10,
    /// Wildcard / reserved-bit allowlist.
    Wildcard = 11,
    /// Missing/expired/revoked safety-kernel attestation for a hosted sponsor.
    SafetyKernelAttestation = 12,
}

impl GasStationRejectReason {
    /// The raw discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// The official-trust verdict for a sponsor (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum OfficialTrustDecision {
    /// Hosted, attested, non-expired official sponsor.
    OfficialTrusted = 1,
    /// Local-only (unknown fork / no sponsorship).
    LocalOnly = 2,
    /// Self-hosted only.
    SelfHostedOnly = 3,
    /// Quarantined — attestation missing.
    Quarantined = 4,
    /// Revoked — attestation expired or explicitly revoked.
    Revoked = 5,
}

impl OfficialTrustDecision {
    /// The raw discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
    /// Whether this decision grants official hosted trust.
    #[inline]
    pub const fn is_trusted(self) -> bool {
        matches!(self, Self::OfficialTrusted)
    }
}

/// Reference to the reproducible build a safety-kernel attestation covers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SafetyKernelBuildRef {
    /// Build identifier.
    pub build_id_u64: u64,
    /// 32-byte release hash.
    pub release_hash_32: [u8; 32],
}

/// A safety-kernel attestation binding a reproducible build, SBOM, sandbox
/// policy and evidence schema, with an expiry epoch (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SafetyKernelAttestation {
    /// The reproducible build this attestation covers.
    pub build: SafetyKernelBuildRef,
    /// SBOM hash.
    pub sbom_hash_32: [u8; 32],
    /// Reproducible-build hash.
    pub reproducible_build_hash_32: [u8; 32],
    /// Sandbox-policy hash.
    pub sandbox_policy_hash_32: [u8; 32],
    /// Evidence-schema hash.
    pub evidence_schema_hash_32: [u8; 32],
    /// Epoch after which this attestation is no longer valid.
    pub expires_epoch_u64: u64,
}

impl SafetyKernelAttestation {
    /// Whether the attestation is still valid at `now_epoch_u64` (expiry is
    /// exclusive: an attestation expiring at epoch `E` is invalid at `E`).
    #[inline]
    pub const fn is_valid_at(&self, now_epoch_u64: u64) -> bool {
        now_epoch_u64 < self.expires_epoch_u64
    }
}

/// The deny-by-default Gas Station policy (§4.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct GasStationPolicy {
    /// Whether/how the sponsor pays.
    pub mode: GasSponsorMode,
    /// The single package this policy sponsors.
    pub package: ObjectId,
    /// Per-tx gas cap.
    pub max_gas_per_tx: GasBudgetMist,
    /// Per-epoch transaction cap.
    pub max_txs_per_epoch_u32: u32,
    /// Per-epoch storage-byte cap.
    pub max_storage_bytes_u32: u32,
    /// Allowlist bitmask over [`SponsoredFunction`] bits.
    pub allowed_mask_u16: u16,
    /// Whether compatibility update is performed via `add_chunk`.
    pub update_semantics_via_add_chunk: bool,
    /// Whether a hosted sponsor must present an official safety-kernel
    /// attestation.
    pub require_official_safety_kernel: bool,
}

impl GasStationPolicy {
    /// The only valid allowlist bits — the three [`SponsoredFunction`] bits.
    pub const FUNCTION_BITS_MASK: u16 = 0b0000_0000_0000_0111;

    /// The initial deny-by-default allowlist: `add_chunk` + `audit_log::append`
    /// (compatibility update is via `add_chunk`, not a separate allowed bit).
    pub const INITIAL_ALLOWED_MASK: u16 =
        SponsoredFunction::MemoryAddChunk.bit() | SponsoredFunction::AuditAppend.bit();

    /// Reject an allowlist mask that sets any reserved/wildcard bit.
    ///
    /// # Errors
    ///
    /// [`GasStationRejectReason::Wildcard`] when a bit outside
    /// [`FUNCTION_BITS_MASK`](Self::FUNCTION_BITS_MASK) is set.
    pub const fn reject_if_wildcard(&self) -> Result<(), GasStationRejectReason> {
        if self.allowed_mask_u16 & !Self::FUNCTION_BITS_MASK != 0 {
            Err(GasStationRejectReason::Wildcard)
        } else {
            Ok(())
        }
    }

    /// Whether a function is on this policy's allowlist.
    #[inline]
    pub const fn is_function_allowed(&self, f: SponsoredFunction) -> bool {
        self.allowed_mask_u16 & f.bit() != 0
    }

    /// Verify a presented package matches this policy's package.
    ///
    /// # Errors
    ///
    /// [`GasStationRejectReason::PackageFunction`] on mismatch.
    pub fn check_package(&self, presented: ObjectId) -> Result<(), GasStationRejectReason> {
        if self.package == presented {
            Ok(())
        } else {
            Err(GasStationRejectReason::PackageFunction)
        }
    }

    /// Verify a function is allowed.
    ///
    /// # Errors
    ///
    /// [`GasStationRejectReason::PackageFunction`] when not on the allowlist.
    pub const fn check_function(&self, f: SponsoredFunction) -> Result<(), GasStationRejectReason> {
        if self.is_function_allowed(f) {
            Ok(())
        } else {
            Err(GasStationRejectReason::PackageFunction)
        }
    }

    /// Verify a requested gas budget is within the per-tx cap.
    ///
    /// # Errors
    ///
    /// [`GasStationRejectReason::Budget`] when over cap.
    pub const fn check_gas_budget(
        &self,
        requested: GasBudgetMist,
    ) -> Result<(), GasStationRejectReason> {
        if requested.get() <= self.max_gas_per_tx.get() {
            Ok(())
        } else {
            Err(GasStationRejectReason::Budget)
        }
    }

    /// Evaluate the official-trust decision for this policy and an optional
    /// attestation at `now_epoch_u64`.
    pub const fn evaluate_trust(
        &self,
        attestation: Option<&SafetyKernelAttestation>,
        now_epoch_u64: u64,
    ) -> OfficialTrustDecision {
        match self.mode {
            GasSponsorMode::None => OfficialTrustDecision::LocalOnly,
            GasSponsorMode::SelfHosted => OfficialTrustDecision::SelfHostedOnly,
            GasSponsorMode::Hosted => {
                if !self.require_official_safety_kernel {
                    // Hosted but not requiring the official kernel = untrusted fork.
                    return OfficialTrustDecision::LocalOnly;
                }
                match attestation {
                    None => OfficialTrustDecision::Quarantined,
                    Some(att) => {
                        if att.is_valid_at(now_epoch_u64) {
                            OfficialTrustDecision::OfficialTrusted
                        } else {
                            OfficialTrustDecision::Revoked
                        }
                    }
                }
            }
        }
    }

    /// The canonical byte form used to derive the policy hash.
    pub fn to_canonical_bytes(&self) -> [u8; 1 + 32 + 8 + 4 + 4 + 2 + 1 + 1] {
        let mut out = [0u8; 1 + 32 + 8 + 4 + 4 + 2 + 1 + 1];
        out[0] = self.mode.as_u8();
        out[1..33].copy_from_slice(self.package.as_bytes());
        out[33..41].copy_from_slice(&self.max_gas_per_tx.get().to_le_bytes());
        out[41..45].copy_from_slice(&self.max_txs_per_epoch_u32.to_le_bytes());
        out[45..49].copy_from_slice(&self.max_storage_bytes_u32.to_le_bytes());
        out[49..51].copy_from_slice(&self.allowed_mask_u16.to_le_bytes());
        out[51] = u8::from(self.update_semantics_via_add_chunk);
        out[52] = u8::from(self.require_official_safety_kernel);
        out
    }

    /// `Blake2b-256` over the canonical byte form — the value an atom #214
    /// signer envelope binds as `policy_hash_32`.
    pub fn policy_hash(&self) -> [u8; 32] {
        let mut hasher = Blake2b::<U32>::new();
        hasher.update(POLICY_HASH_DOMAIN);
        hasher.update(self.to_canonical_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn base_policy() -> GasStationPolicy {
        GasStationPolicy {
            mode: GasSponsorMode::Hosted,
            package: ObjectId::new([0x22; 32]),
            max_gas_per_tx: GasBudgetMist::new(800_000),
            max_txs_per_epoch_u32: 1_000,
            max_storage_bytes_u32: 1_000_000,
            allowed_mask_u16: GasStationPolicy::INITIAL_ALLOWED_MASK,
            update_semantics_via_add_chunk: true,
            require_official_safety_kernel: true,
        }
    }

    fn att(expires: u64) -> SafetyKernelAttestation {
        SafetyKernelAttestation {
            build: SafetyKernelBuildRef {
                build_id_u64: 1,
                release_hash_32: [0x11; 32],
            },
            sbom_hash_32: [0x22; 32],
            reproducible_build_hash_32: [0x33; 32],
            sandbox_policy_hash_32: [0x44; 32],
            evidence_schema_hash_32: [0x55; 32],
            expires_epoch_u64: expires,
        }
    }

    /// `c1_16_wildcard_reject` — a reserved/wildcard mask bit is rejected; the
    /// initial allowlist passes.
    #[test]
    fn c1_16_wildcard_reject() {
        let mut p = base_policy();
        assert_eq!(p.reject_if_wildcard(), Ok(()));
        // add_chunk + audit_append allowed; update-compat not separately allowed.
        assert!(p.is_function_allowed(SponsoredFunction::MemoryAddChunk));
        assert!(p.is_function_allowed(SponsoredFunction::AuditAppend));
        assert!(!p.is_function_allowed(SponsoredFunction::MemoryUpdateCompat));

        p.allowed_mask_u16 = 0xFFFF;
        assert_eq!(
            p.reject_if_wildcard(),
            Err(GasStationRejectReason::Wildcard)
        );
        p.allowed_mask_u16 = 0b0000_1000; // a single reserved bit
        assert_eq!(
            p.reject_if_wildcard(),
            Err(GasStationRejectReason::Wildcard)
        );
    }

    /// `c1_16_package_function_mismatch_and_cap` — package mismatch, function
    /// mismatch, and over-cap are rejected; in-bounds requests pass (cap parse).
    #[test]
    fn c1_16_package_function_mismatch_and_cap() {
        let p = base_policy();
        assert_eq!(p.check_package(ObjectId::new([0x22; 32])), Ok(()));
        assert_eq!(
            p.check_package(ObjectId::new([0x99; 32])),
            Err(GasStationRejectReason::PackageFunction),
        );
        assert_eq!(p.check_function(SponsoredFunction::MemoryAddChunk), Ok(()));
        assert_eq!(
            p.check_function(SponsoredFunction::MemoryUpdateCompat),
            Err(GasStationRejectReason::PackageFunction),
        );
        // Cap parse: at-cap accepted, over-cap rejected.
        assert_eq!(p.check_gas_budget(GasBudgetMist::new(800_000)), Ok(()));
        assert_eq!(
            p.check_gas_budget(GasBudgetMist::new(800_001)),
            Err(GasStationRejectReason::Budget),
        );
        assert_eq!(p.max_txs_per_epoch_u32, 1_000);
        assert_eq!(p.max_storage_bytes_u32, 1_000_000);
    }

    /// `c1_16_attestation_trust` — missing attestation quarantines, expired
    /// revokes, valid is officially trusted; self-hosted/none are never
    /// officially trusted.
    #[test]
    fn c1_16_attestation_trust() {
        let p = base_policy();
        // Missing attestation -> Quarantined (reject).
        assert_eq!(
            p.evaluate_trust(None, 10),
            OfficialTrustDecision::Quarantined
        );
        assert!(!p.evaluate_trust(None, 10).is_trusted());
        // Expired -> Revoked.
        let expired = att(10);
        assert_eq!(
            p.evaluate_trust(Some(&expired), 10),
            OfficialTrustDecision::Revoked
        );
        assert_eq!(
            p.evaluate_trust(Some(&expired), 11),
            OfficialTrustDecision::Revoked
        );
        // Valid -> OfficialTrusted.
        let valid = att(100);
        assert_eq!(
            p.evaluate_trust(Some(&valid), 10),
            OfficialTrustDecision::OfficialTrusted
        );
        assert!(p.evaluate_trust(Some(&valid), 10).is_trusted());

        // Self-hosted / none are never officially trusted.
        let mut sh = base_policy();
        sh.mode = GasSponsorMode::SelfHosted;
        assert_eq!(
            sh.evaluate_trust(Some(&valid), 10),
            OfficialTrustDecision::SelfHostedOnly
        );
        let mut none = base_policy();
        none.mode = GasSponsorMode::None;
        assert_eq!(
            none.evaluate_trust(Some(&valid), 10),
            OfficialTrustDecision::LocalOnly
        );
        // Hosted but not requiring the official kernel = untrusted fork.
        let mut hosted_lax = base_policy();
        hosted_lax.require_official_safety_kernel = false;
        assert_eq!(
            hosted_lax.evaluate_trust(Some(&valid), 10),
            OfficialTrustDecision::LocalOnly
        );
    }

    /// `c1_16_policy_hash_deterministic` — the policy hash is stable and
    /// changes when any field changes (binds the #214 signer envelope).
    #[test]
    fn c1_16_policy_hash_deterministic() {
        let p = base_policy();
        let h1 = p.policy_hash();
        let h2 = p.policy_hash();
        assert_eq!(h1, h2);
        let mut p2 = base_policy();
        p2.max_gas_per_tx = GasBudgetMist::new(1);
        assert_ne!(h1, p2.policy_hash());
        // Enum round-trips.
        assert_eq!(GasSponsorMode::from_u8(2), Some(GasSponsorMode::SelfHosted));
        assert_eq!(GasSponsorMode::from_u8(0), None);
        assert_eq!(
            SponsoredFunction::from_u8(3),
            Some(SponsoredFunction::AuditAppend)
        );
    }
}
