//! Stage C mainnet package lock (C-WP-06B · atom #225 · C.2.6).
//!
//! Canonical OUT (§4.4): [`MainnetPackageLock`].
//!
//! # Madness invariants (atom #225)
//!
//! * **The package bytecode hash binds the prover hash and the gas baseline
//!   hash.** A [`MainnetPackageLock`] freezes a single tuple `(package,
//!   bytecode_hash, prover_hash, gas_baseline_hash)`. The lock is the one place
//!   that asserts: *this* compiled package (`bytecode_hash_32`) is the package
//!   the standalone `sui-prover` proved (`prover_hash_32`, atom #188) and the
//!   package the gas baseline was measured against (`gas_baseline_hash_32`,
//!   atom #200). [`MainnetPackageLock::verify`] rejects a presented bytecode,
//!   prover, or gas-baseline hash that drifts from the locked value, in a fixed
//!   branch order so each rejection is audit-targetable.
//! * **Hashes are mandatory.** A lock cannot be constructed with an all-zero
//!   bytecode, prover, or gas-baseline hash — an absent proof or absent gas
//!   baseline is fail-closed, never silently green.
//! * **Inert datatype, no execution.** This type performs no I/O, no network,
//!   no `sui` invocation, and no submit. It is the data a mainnet gate receipt
//!   binds; `MainnetExecutionState` stays `Locked` and a real publish requires
//!   the later operator-approval ceremony (atoms #226 / #234), never this lock.
//! * **Data-free errors.** [`PackageLockError`] variants carry no caller bytes,
//!   so a malformed hash string never leaks into the error channel.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: §4.D `ObjectId`** — [`crate::types::ObjectId`]
//!   (`d-move/src/types.rs:156`). No second 32-byte object-id type is minted.
//! * **reuse: #188 / #200** — the prover/gas coupling lives in
//!   `scripts/stage_c_prover_gas_gate.sh` (G-C-PROVER-GAS) and
//!   `scripts/stage_c_gas_trace_gate.sh` (G-C-GAS-TRACE); this lock is their
//!   Rust-side binding record. The G-C-CHECKLIST coupling is by-hash at the
//!   gate/evidence level (`ops/evidence/stage_c/checklist_step_2_proof_gas.md`)
//!   so no `d-move -> k-devex` cargo edge is created (cycle-avoidance precedent
//!   atom #222).

use crate::types::ObjectId;

/// Fixed serialized byte width of a [`MainnetPackageLock`]: `32` (package
/// object id) + `32` (bytecode hash) + `32` (prover hash) + `32` (gas baseline
/// hash).
pub const MAINNET_PACKAGE_LOCK_BYTES: usize = 32 * 4;

/// A mainnet package lock (§4.4 canonical OUT).
///
/// Binds the on-chain `package` object id to the three 32-byte hashes that must
/// agree before a mainnet publish ceremony is trustworthy: the compiled
/// bytecode digest, the `sui-prover` proved digest, and the gas baseline
/// digest.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MainnetPackageLock {
    /// The on-chain package object id. In the prepare-only state this is the
    /// all-zero placeholder; the real id is assigned at publish.
    pub package: ObjectId,
    /// `shasum -a 256` content digest of the compiled Move package bytecode.
    pub bytecode_hash_32: [u8; 32],
    /// The package digest the standalone `sui-prover` proved (atom #188).
    pub prover_hash_32: [u8; 32],
    /// The digest of the gas baseline the package was measured against
    /// (atom #200).
    pub gas_baseline_hash_32: [u8; 32],
}

/// Package-lock construction / verification error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum PackageLockError {
    /// The bytecode hash was all-zero.
    BytecodeHashRequired = 1,
    /// The prover hash was all-zero.
    ProverHashRequired = 2,
    /// The gas baseline hash was all-zero.
    GasBaselineHashRequired = 3,
    /// A presented bytecode hash did not match the locked one.
    BytecodeHashMismatch = 4,
    /// A presented prover hash did not match the locked one.
    ProverHashMismatch = 5,
    /// A presented gas baseline hash did not match the locked one.
    GasBaselineHashMismatch = 6,
    /// A hash / object-id string was not exactly 64 hex characters (optionally
    /// `0x`-prefixed) or carried a non-hex byte.
    HashFormat = 7,
}

impl PackageLockError {
    /// Stable class label of this failure mode, namespaced under
    /// `stage_c_package_lock.*`.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::BytecodeHashRequired => "stage_c_package_lock.bytecode_hash_required",
            Self::ProverHashRequired => "stage_c_package_lock.prover_hash_required",
            Self::GasBaselineHashRequired => "stage_c_package_lock.gas_baseline_hash_required",
            Self::BytecodeHashMismatch => "stage_c_package_lock.bytecode_hash_mismatch",
            Self::ProverHashMismatch => "stage_c_package_lock.prover_hash_mismatch",
            Self::GasBaselineHashMismatch => "stage_c_package_lock.gas_baseline_hash_mismatch",
            Self::HashFormat => "stage_c_package_lock.hash_format",
        }
    }
}

/// Map a single ASCII hex digit to its nibble value, fail-closed.
const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode a 32-byte hash from a 64-char hex string (optional `0x` prefix).
/// Fail-closed: any non-hex byte or wrong length is rejected with
/// [`PackageLockError::HashFormat`].
///
/// # Errors
///
/// [`PackageLockError::HashFormat`] when the string is not exactly 64 hex
/// characters.
pub fn parse_hash_32(raw: &str) -> Result<[u8; 32], PackageLockError> {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() != 64 {
        return Err(PackageLockError::HashFormat);
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2]).ok_or(PackageLockError::HashFormat)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(PackageLockError::HashFormat)?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(out)
}

const fn is_zero_32(h: &[u8; 32]) -> bool {
    let mut i = 0;
    while i < 32 {
        if h[i] != 0 {
            return false;
        }
        i += 1;
    }
    true
}

impl MainnetPackageLock {
    /// Build a lock from a package id and the three 32-byte hashes.
    ///
    /// # Errors
    ///
    /// [`PackageLockError::BytecodeHashRequired`] /
    /// [`PackageLockError::ProverHashRequired`] /
    /// [`PackageLockError::GasBaselineHashRequired`] when the corresponding hash
    /// is all-zero.
    pub fn new(
        package: ObjectId,
        bytecode_hash_32: [u8; 32],
        prover_hash_32: [u8; 32],
        gas_baseline_hash_32: [u8; 32],
    ) -> Result<Self, PackageLockError> {
        if is_zero_32(&bytecode_hash_32) {
            return Err(PackageLockError::BytecodeHashRequired);
        }
        if is_zero_32(&prover_hash_32) {
            return Err(PackageLockError::ProverHashRequired);
        }
        if is_zero_32(&gas_baseline_hash_32) {
            return Err(PackageLockError::GasBaselineHashRequired);
        }
        Ok(Self {
            package,
            bytecode_hash_32,
            prover_hash_32,
            gas_baseline_hash_32,
        })
    }

    /// Build a lock from hex strings (the `package_lock.toml` field shapes):
    /// 64-hex package object id and three 64-hex hashes.
    ///
    /// # Errors
    ///
    /// [`PackageLockError::HashFormat`] on any malformed hex field, then any
    /// [`new`](Self::new) error on the decoded hashes.
    pub fn from_hex(
        package_hex: &str,
        bytecode_hex: &str,
        prover_hex: &str,
        gas_baseline_hex: &str,
    ) -> Result<Self, PackageLockError> {
        let package = ObjectId::new(parse_hash_32(package_hex)?);
        let bytecode_hash_32 = parse_hash_32(bytecode_hex)?;
        let prover_hash_32 = parse_hash_32(prover_hex)?;
        let gas_baseline_hash_32 = parse_hash_32(gas_baseline_hex)?;
        Self::new(
            package,
            bytecode_hash_32,
            prover_hash_32,
            gas_baseline_hash_32,
        )
    }

    /// Verify a presented `(bytecode, prover, gas_baseline)` hash triple against
    /// the locked values, in a fixed branch order (bytecode → prover → gas
    /// baseline) so each rejection is audit-targetable.
    ///
    /// # Errors
    ///
    /// [`PackageLockError::BytecodeHashMismatch`] /
    /// [`PackageLockError::ProverHashMismatch`] /
    /// [`PackageLockError::GasBaselineHashMismatch`] on the first hash that
    /// drifts from the lock.
    pub fn verify(
        &self,
        presented_bytecode_32: &[u8; 32],
        presented_prover_32: &[u8; 32],
        presented_gas_baseline_32: &[u8; 32],
    ) -> Result<(), PackageLockError> {
        if &self.bytecode_hash_32 != presented_bytecode_32 {
            return Err(PackageLockError::BytecodeHashMismatch);
        }
        if &self.prover_hash_32 != presented_prover_32 {
            return Err(PackageLockError::ProverHashMismatch);
        }
        if &self.gas_baseline_hash_32 != presented_gas_baseline_32 {
            return Err(PackageLockError::GasBaselineHashMismatch);
        }
        Ok(())
    }

    /// The fixed-width 128-byte serialization: `package(32) ‖ bytecode(32) ‖
    /// prover(32) ‖ gas_baseline(32)`.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MAINNET_PACKAGE_LOCK_BYTES] {
        let mut out = [0u8; MAINNET_PACKAGE_LOCK_BYTES];
        out[..32].copy_from_slice(self.package.as_bytes());
        out[32..64].copy_from_slice(&self.bytecode_hash_32);
        out[64..96].copy_from_slice(&self.prover_hash_32);
        out[96..128].copy_from_slice(&self.gas_baseline_hash_32);
        out
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    // The real production Move package content digest (atom #188 / #200; the
    // sorted per-`.mv` `shasum -a 256`, recomputed read-only, no `sui move
    // build`). Used here as both the bytecode and the proved digest — the
    // prover proved exactly this compiled package.
    const REAL_DIGEST_HEX: &str =
        "d364f93e37cad118f94b33c24ecdd6d9ba5ec65b751ad61bdb344c75a560ab8d";
    // SHA-256 of the canonical gas-baseline preimage
    // `mnemos.stage_c.gas_baseline.v1|add_chunk_hard_cap_mist=800000`.
    const GAS_BASELINE_HEX: &str =
        "685982ceda3f0901330828f1412ceed3620ac37c713c26343287d06c13c820ef";
    const ZERO_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    /// `c2_6_hash_parse` — a 64-hex string (with and without `0x`) parses to the
    /// expected bytes; a wrong length or non-hex byte is rejected; a full lock
    /// parses from hex and serializes to the fixed 128-byte width.
    #[test]
    fn c2_6_hash_parse() {
        // Round-trip a known digest.
        let parsed = parse_hash_32(REAL_DIGEST_HEX).unwrap();
        assert_eq!(parsed[0], 0xd3);
        assert_eq!(parsed[31], 0x8d);
        // `0x` prefix accepted, same bytes.
        let with_prefix = format!("0x{REAL_DIGEST_HEX}");
        assert_eq!(parse_hash_32(&with_prefix).unwrap(), parsed);
        // Wrong length → HashFormat.
        assert_eq!(parse_hash_32("dead"), Err(PackageLockError::HashFormat));
        // Non-hex byte → HashFormat (64 chars, one `g`).
        let bad = format!("g{}", &REAL_DIGEST_HEX[1..]);
        assert_eq!(parse_hash_32(&bad), Err(PackageLockError::HashFormat));

        // Full lock from the prepare-only placeholder package + real hashes.
        let lock = MainnetPackageLock::from_hex(
            ZERO_HEX,
            REAL_DIGEST_HEX,
            REAL_DIGEST_HEX,
            GAS_BASELINE_HEX,
        )
        .unwrap();
        assert_eq!(lock.to_bytes().len(), MAINNET_PACKAGE_LOCK_BYTES);
        assert_eq!(&lock.to_bytes()[..32], &[0u8; 32]); // placeholder package
        assert_eq!(&lock.to_bytes()[32..64], &parsed[..]); // bytecode hash
    }

    /// `c2_6_zero_hash_reject` — an all-zero bytecode / prover / gas-baseline
    /// hash is fail-closed at construction.
    #[test]
    fn c2_6_zero_hash_reject() {
        let real = parse_hash_32(REAL_DIGEST_HEX).unwrap();
        let gas = parse_hash_32(GAS_BASELINE_HEX).unwrap();
        let pkg = ObjectId::new([0u8; 32]);
        assert_eq!(
            MainnetPackageLock::new(pkg, [0u8; 32], real, gas),
            Err(PackageLockError::BytecodeHashRequired),
        );
        assert_eq!(
            MainnetPackageLock::new(pkg, real, [0u8; 32], gas),
            Err(PackageLockError::ProverHashRequired),
        );
        assert_eq!(
            MainnetPackageLock::new(pkg, real, real, [0u8; 32]),
            Err(PackageLockError::GasBaselineHashRequired),
        );
    }

    /// `c2_6_prover_mismatch_reject` — a presented prover hash that differs from
    /// the locked one is rejected; the matching triple passes.
    #[test]
    fn c2_6_prover_mismatch_reject() {
        let real = parse_hash_32(REAL_DIGEST_HEX).unwrap();
        let gas = parse_hash_32(GAS_BASELINE_HEX).unwrap();
        let lock = MainnetPackageLock::new(ObjectId::new([0u8; 32]), real, real, gas).unwrap();
        // Matching triple → Ok.
        assert_eq!(lock.verify(&real, &real, &gas), Ok(()));
        // Drifted prover hash → ProverHashMismatch.
        let other = [0x11u8; 32];
        assert_eq!(
            lock.verify(&real, &other, &gas),
            Err(PackageLockError::ProverHashMismatch),
        );
    }

    /// `c2_6_gas_mismatch_reject` — a presented gas-baseline hash that differs
    /// from the locked one is rejected; a drifted bytecode hash is caught first
    /// (fixed branch order).
    #[test]
    fn c2_6_gas_mismatch_reject() {
        let real = parse_hash_32(REAL_DIGEST_HEX).unwrap();
        let gas = parse_hash_32(GAS_BASELINE_HEX).unwrap();
        let lock = MainnetPackageLock::new(ObjectId::new([0u8; 32]), real, real, gas).unwrap();
        let other = [0x22u8; 32];
        // Drifted gas baseline → GasBaselineHashMismatch.
        assert_eq!(
            lock.verify(&real, &real, &other),
            Err(PackageLockError::GasBaselineHashMismatch),
        );
        // Bytecode mismatch dominates (checked first).
        assert_eq!(
            lock.verify(&other, &real, &gas),
            Err(PackageLockError::BytecodeHashMismatch),
        );
    }

    /// Each error class label is namespaced and distinct.
    #[test]
    fn c2_6_class_labels_distinct() {
        let labels = [
            PackageLockError::BytecodeHashRequired.class_label(),
            PackageLockError::ProverHashRequired.class_label(),
            PackageLockError::GasBaselineHashRequired.class_label(),
            PackageLockError::BytecodeHashMismatch.class_label(),
            PackageLockError::ProverHashMismatch.class_label(),
            PackageLockError::GasBaselineHashMismatch.class_label(),
            PackageLockError::HashFormat.class_label(),
        ];
        for l in labels {
            assert!(l.starts_with("stage_c_package_lock."));
        }
        // All distinct.
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j]);
            }
        }
    }
}
