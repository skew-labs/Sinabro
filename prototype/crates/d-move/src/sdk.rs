//! `mnemos-d-move::sdk` — atom #20 · D.0.6 — Sui Rust SDK call builder.
//!
//! Canonical OUT (§4.D — see ATOM_PLAN line 562-567 + atom #20 line 993-1001):
//! - [`SuiCallBuilder`] — Move-call routing record carrying `(package,
//!   module, function, gas_budget)` per the canonical signature. Two
//!   implementation-private fields beyond the canonical four (`root` and
//!   `encoded_args`) are required to make [`SuiCallBuilder::to_dry_run_bytes`]
//!   `(&self)` self-contained; the §4.D struct text only enumerates the
//!   four routing fields. The disparity is the same family as atom #2
//!   (17 vs 13 enum variants), atom #3 (12 vs 11 enum variants), atom #7
//!   (manual BCS encoder), atom #11 (close sentinel) — recorded for
//!   Session 2 ACCEPT/RAISE via the BUILD_STATE disparity carry-forward
//!   protocol.
//! - [`SuiCallBuilder::add_chunk`] — sole constructor at atom #20.
//!   Targets the `mnemos::memory_root::add_chunk` Move entry function
//!   (atom #16 · D.0.2). Rejects `gas == 0` with
//!   [`CallBuildError::GasBudgetZero`] before any byte work is done.
//! - [`SuiCallBuilder::to_dry_run_bytes`] — emits a byte-stable
//!   representation of the planned Move call (`package ‖ uleb128(len(module))
//!   ‖ module ‖ uleb128(len(function)) ‖ function ‖ root ‖ encoded_args ‖
//!   gas_le`) for dry-run size measurement under the G-SUI gate. This is
//!   NOT a real Sui intent transaction — the intent-message prefix,
//!   gas-object refs, expiration, type args, and PTB command list are
//!   owned by future atoms in domain G (signing) and operator-side PTB
//!   synthesis. The 166-byte known vector is pinned by
//!   `d0_6_dry_run_bytes_are_bcs` in `tests/sdk.rs` and reproduced
//!   independently by the Python oracle at
//!   `ops/evidence/phase_0/atom_020/oracle_sui_call_builder_v0.py`.
//! - [`CallBuildError`] — fixed two-variant `Copy` failure channel
//!   (`GasBudgetZero` / `ArgEncode`) with the namespaced `class_label`
//!   discipline mirroring atom #7..#11 + atom #15
//!   [`crate::types::MoveBindError`].
//!
//! `GasBudgetMist` is the typed-unit newtype from atom #15 (`mnemos_d_move::types`)
//! and is re-exported through the canonical surface so callers see it on
//! a single crate-level path.
//!
//! ## Reuse anchor
//!
//! - atom #15 (D.0.1): [`crate::types::ObjectId`],
//!   [`crate::types::MemoryRootArgs`], [`crate::types::GasBudgetMist`],
//!   [`crate::types::encode_memory_root_args_bcs`],
//!   [`crate::types::MEMORY_ROOT_ARGS_BCS_LEN`] (= 72),
//!   [`crate::types::SUI_OBJECT_ID_BYTES`] (= 32).
//! - atom #7 (C.0.1): transitive via atom #15 — the `MoveAnchorArgsV1`
//!   anchor chain terminates at atom #15's `MemoryRootArgs`; atom #20
//!   does not touch Walrus surfaces directly.
//!
//! ## Carve-outs (Session 2 ACCEPT/RAISE)
//!
//! 1. **Package id placeholder.** The `mnemos::memory_root` package id
//!    is not known until atom #19 `D.0.5` testnet deploy completes
//!    (DEPLOY_TESTNET.md leaves `mnemos = "0x0"` until the operator
//!    fills `published-at` post-publish). Atom #20 pins the on-builder
//!    `package` field to [`MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER`] =
//!    32 zero bytes so the dry-run byte size is stable for measurement.
//!    The setter that swaps in a real published-at id is the
//!    user-lane "D-1 / D-2" decision carried forward from atom #19
//!    (per `[[ai-advisory-user-decides]]`).
//! 2. **No live RPC.** `to_dry_run_bytes` produces a byte string the
//!    caller can hand to `sui client dry-run-bytes --json --tx-bytes`
//!    *iff* the operator has independently constructed a proper PTB
//!    around it. Atom #20 itself does not call any RPC, does not
//!    consult `sui` CLI, and does not load a wallet — keeping the
//!    G-SUI gate satisfiable in `--offline` mode.
//! 3. **D-1 factory-absence carry-forward.** The `mnemos::memory_root`
//!    Move module exposes no `init_memory_root` factory (atom #19
//!    BUILD_STATE §2 ⚠ D-1). Atom #20 SDK builder still produces the
//!    byte string for the `add_chunk(root, blob_id, kind, parent)`
//!    Move entry, but a live `add_chunk` against a real on-chain root
//!    cannot execute until the user picks A/B/C of the D-1 resolution
//!    path. Atom #20 dry-run measurement is decoupled from D-1.
//! 4. **No intent prefix.** A real Sui intent message starts with
//!    `[scope, version, app_id]` (3 bytes) before the BCS-encoded
//!    `TransactionData`. Atom #20's `to_dry_run_bytes` emits ONLY the
//!    routing + args portion — adding the intent prefix + `TransactionData`
//!    wrapper is the domain of atoms G.0.x (signing) where wallet
//!    keypairs first appear. The current output is therefore a
//!    measurement-only carrier, not a signable transaction blob.
//! 5. **uleb128 helper kept local.** Atom #11 (C.0.5) precedent kept
//!    `uleb128_encoded_len_u32` in `c-walrus::stream` rather than
//!    promoting it to the private `c-walrus::wire` module; for atom
//!    #20 we follow the same pattern and ship a local `append_uleb128_u32`.
//!    The two-byte-cap module / function strings (≤ 127 chars each)
//!    always serialise as a single-byte uleb128, so the wire-byte
//!    width is fixed at compile time and pinned by
//!    [`SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN`] = 166.

use crate::types::{
    GasBudgetMist, MEMORY_ROOT_ARGS_BCS_LEN, MemoryRootArgs, ObjectId, SUI_OBJECT_ID_BYTES,
    encode_memory_root_args_bcs,
};

// ===========================================================================
// 1. Canonical constants
// ===========================================================================

/// Move-side module name for the `mnemos` memory-root package. The
/// 11-byte ASCII string `b"memory_root"` is the source of truth — atom
/// #16 (`D.0.2`) anchors the entry-function definition in the file
/// `prototype/move/sources/memory_root.move` under
/// `module mnemos::memory_root`.
pub const MNEMOS_MOVE_MODULE_NAME: &str = "memory_root";

/// Move-side function name for the owner-only chunk anchoring entry
/// point. The 9-byte ASCII string `b"add_chunk"` matches the canonical
/// Move signature emitted by atom #16 (`D.0.2`,
/// `public entry fun add_chunk(...)`).
pub const MNEMOS_MOVE_FUNCTION_ADD_CHUNK: &str = "add_chunk";

/// Placeholder 32-byte package id used in [`SuiCallBuilder::add_chunk`]
/// until the operator-side testnet-deploy step (atom #19 `D.0.5`,
/// `DEPLOY_TESTNET.md`) fills in the real `published-at` value. Mirrors
/// the `mnemos = "0x0"` placeholder line atom #19 leaves in
/// `prototype/move/Move.toml` for the same operator step. Pinned to 32
/// zero bytes so the dry-run byte size is stable across rebuilds.
pub const MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER: ObjectId = ObjectId::new([0u8; 32]);

/// Total byte length of the [`SuiCallBuilder::to_dry_run_bytes`] output
/// for the `add_chunk` call. Derived as:
/// `32 (package) + 1 (uleb128 module-len) + 11 (module) + 1 (uleb128
/// function-len) + 9 (function) + 32 (root ObjectId) + 72 (encoded args
/// BCS) + 8 (gas budget LE) = 166`. Pinned by
/// `_DRY_RUN_BYTES_ADD_CHUNK_LEN_IS_166` and asserted at runtime by
/// `d0_6_dry_run_bytes_are_bcs` and the Python oracle.
pub const SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN: usize = SUI_OBJECT_ID_BYTES
    + 1
    + MNEMOS_MOVE_MODULE_NAME.len()
    + 1
    + MNEMOS_MOVE_FUNCTION_ADD_CHUNK.len()
    + SUI_OBJECT_ID_BYTES
    + MEMORY_ROOT_ARGS_BCS_LEN
    + 8;

// ===========================================================================
// 2. Compile-time reuse / drift markers (atom #10 / #15 precedent)
// ===========================================================================

/// Pins [`SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN`] at 166 bytes. Any drift in
/// the module / function string length, the `MemoryRootArgs` BCS width,
/// or the `ObjectId` byte width breaks the build before any test runs.
const _DRY_RUN_BYTES_ADD_CHUNK_LEN_IS_166: [(); 0 - !(SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN == 166)
    as usize] = [];

/// Pins the Move module name at 11 bytes. Atom #16 anchors the Move
/// source at `module mnemos::memory_root`; if the module is ever
/// renamed, the build fails here before the dry-run oracle even runs.
const _MNEMOS_MOVE_MODULE_NAME_LEN_IS_11: [(); 0 - !(MNEMOS_MOVE_MODULE_NAME.len() == 11)
    as usize] = [];

/// Pins the Move function name at 9 bytes. Atom #16's
/// `public entry fun add_chunk(...)` defines this; rename = build fail
/// here.
const _MNEMOS_MOVE_FUNCTION_ADD_CHUNK_LEN_IS_9: [(); 0 - !(MNEMOS_MOVE_FUNCTION_ADD_CHUNK.len()
    == 9) as usize] = [];

// ===========================================================================
// 3. Failure channel
// ===========================================================================

/// Failure modes raised by the SDK call builder. `Copy`,
/// `#[non_exhaustive]`, no owned bytes — the channel cannot leak any
/// raw input through `Debug`. Class labels are namespaced under
/// `sui_call_build.*` (atom #7 / #8 / #9 / #10 / #11 / #15 precedent).
///
/// - `GasBudgetZero` — emitted by [`SuiCallBuilder::add_chunk`] when
///   the caller passes a [`GasBudgetMist`] of zero. Sui rejects
///   zero-budget transactions at validator-side; we fail-closed
///   early to avoid building a byte string the operator could never
///   submit.
/// - `ArgEncode` — reserved for future fallible arg encodes. At atom
///   #20 the only encode step is [`encode_memory_root_args_bcs`]
///   (infallible, total over `&MemoryRootArgs`) and the local
///   uleb128 length cast, where module / function names are
///   compile-time constants and the cast is statically guaranteed to
///   fit in `u32`. The variant is preserved verbatim from the §4.D
///   canonical signature so future atoms can layer fallible arg
///   builders (type-tag tables, vector inputs, owned-arg variants)
///   without an API break.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CallBuildError {
    /// Gas budget of zero. Sui validators reject zero-budget txs.
    GasBudgetZero,
    /// An argument failed to encode. Reserved for fallible future
    /// argument shapes; never emitted by atom #20 itself.
    ArgEncode,
}

impl CallBuildError {
    /// Stable class label of this failure mode. Namespaced under
    /// `sui_call_build.*` so audit pipelines can fan out on a single
    /// prefix (mirrors atom #15 `move_bind.*`).
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::GasBudgetZero => "sui_call_build.gas_budget_zero",
            Self::ArgEncode => "sui_call_build.arg_encode",
        }
    }
}

// ===========================================================================
// 4. Sui call builder
// ===========================================================================

/// Move-call routing record produced by [`SuiCallBuilder::add_chunk`].
///
/// The four `package` / `module` / `function` / `gas_budget` fields
/// match the §4.D canonical signature byte-for-byte (struct text at
/// ATOM_PLAN line 562). Two implementation-private fields (`root` and
/// `encoded_args`) are required to make [`SuiCallBuilder::to_dry_run_bytes`]
/// `(&self)` self-contained — without them, the dry-run output would
/// have to take additional parameters and break the canonical
/// `Result<Vec<u8>, CallBuildError>` signature.
///
/// The fields are private; access goes through the four `pub const fn`
/// accessors (`package`, `module`, `function`, `gas_budget`) plus the
/// two diagnostic accessors (`root`, `encoded_args`) for verifier-side
/// audits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SuiCallBuilder {
    package: ObjectId,
    module: &'static str,
    function: &'static str,
    gas_budget: GasBudgetMist,
    // ------------- implementation-private (beyond §4.D canonical) -----------
    root: ObjectId,
    encoded_args: [u8; MEMORY_ROOT_ARGS_BCS_LEN],
}

impl SuiCallBuilder {
    /// Build the routing record for an `add_chunk` Move call against
    /// the `mnemos::memory_root` module. Rejects a zero gas budget
    /// before any byte work is done.
    ///
    /// `root` is the on-chain [`ObjectId`] of the `MemoryRoot` object
    /// the caller intends to mutate; `args` is the Rust-side
    /// projection of the call args from atom #15 (`D.0.1`); `gas` is
    /// the typed gas budget. The package id is pinned to
    /// [`MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER`] (32 zero bytes) until
    /// atom #19's testnet-deploy operator step (`DEPLOY_TESTNET.md`)
    /// hands off the real `published-at` value through the user-lane
    /// D-1 / D-2 resolution path.
    #[inline]
    pub fn add_chunk(
        root: ObjectId,
        args: &MemoryRootArgs,
        gas: GasBudgetMist,
    ) -> Result<Self, CallBuildError> {
        if gas.get() == 0 {
            return Err(CallBuildError::GasBudgetZero);
        }
        let encoded_args = encode_memory_root_args_bcs(args);
        Ok(Self {
            package: MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER,
            module: MNEMOS_MOVE_MODULE_NAME,
            function: MNEMOS_MOVE_FUNCTION_ADD_CHUNK,
            gas_budget: gas,
            root,
            encoded_args,
        })
    }

    /// Emit the byte-stable dry-run representation of this call.
    ///
    /// Layout (166 bytes total, pinned by [`SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN`]):
    /// ```text
    /// [ 0..32 ]  package          (ObjectId, 32 raw bytes)
    /// [ 32    ]  uleb128(11)      (module name length = 11)
    /// [ 33..44]  "memory_root"    (11 ASCII bytes)
    /// [ 44    ]  uleb128(9)       (function name length = 9)
    /// [ 45..54]  "add_chunk"      (9 ASCII bytes)
    /// [ 54..86]  root             (ObjectId, 32 raw bytes)
    /// [ 86..158] encoded_args     (MemoryRootArgs BCS, 72 bytes)
    /// [158..166] gas_budget_le    (u64 little-endian, 8 bytes)
    /// ```
    ///
    /// This is a self-contained measurement carrier — NOT a Sui
    /// intent message. The intent prefix, gas-object refs,
    /// expiration, type args, and PTB command list are owned by
    /// future atoms in domain G (signing).
    pub fn to_dry_run_bytes(&self) -> Result<Vec<u8>, CallBuildError> {
        let mut out: Vec<u8> = Vec::with_capacity(SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN);
        out.extend_from_slice(self.package.as_bytes());
        append_uleb128_str(&mut out, self.module)?;
        append_uleb128_str(&mut out, self.function)?;
        out.extend_from_slice(self.root.as_bytes());
        out.extend_from_slice(&self.encoded_args);
        out.extend_from_slice(&self.gas_budget.get().to_le_bytes());
        Ok(out)
    }

    // ---- §4.D canonical accessors -----------------------------------------

    /// Borrow the on-builder package [`ObjectId`].
    #[inline]
    pub const fn package(&self) -> &ObjectId {
        &self.package
    }

    /// The Move module name. At atom #20 this is always
    /// [`MNEMOS_MOVE_MODULE_NAME`] (`"memory_root"`).
    #[inline]
    pub const fn module(&self) -> &'static str {
        self.module
    }

    /// The Move function name. At atom #20 this is always
    /// [`MNEMOS_MOVE_FUNCTION_ADD_CHUNK`] (`"add_chunk"`).
    #[inline]
    pub const fn function(&self) -> &'static str {
        self.function
    }

    /// The typed gas budget the caller supplied.
    #[inline]
    pub const fn gas_budget(&self) -> GasBudgetMist {
        self.gas_budget
    }

    // ---- implementation-private accessors (Session 2 audit) ----------------

    /// Borrow the on-builder `MemoryRoot` object id.
    #[inline]
    pub const fn root(&self) -> &ObjectId {
        &self.root
    }

    /// Borrow the pre-encoded 72-byte [`MemoryRootArgs`] BCS payload.
    #[inline]
    pub const fn encoded_args(&self) -> &[u8; MEMORY_ROOT_ARGS_BCS_LEN] {
        &self.encoded_args
    }
}

// ===========================================================================
// 5. Local uleb128 helper (atom #11 sibling-layer precedent)
// ===========================================================================

/// Append a uleb128-prefixed UTF-8 byte string to `out`. The length
/// must fit in `u32` (statically true for the compile-time module /
/// function constants used at atom #20; the cast is bounded by
/// `u32::try_from` for future fallible-arg shapes — never panics).
#[inline]
fn append_uleb128_str(out: &mut Vec<u8>, s: &str) -> Result<(), CallBuildError> {
    let bytes = s.as_bytes();
    let len_u32 = u32::try_from(bytes.len()).map_err(|_| CallBuildError::ArgEncode)?;
    append_uleb128_u32(out, len_u32);
    out.extend_from_slice(bytes);
    Ok(())
}

/// Append a uleb128-encoded `u32` to `out`. Mirrors the
/// `c-walrus::wire::append_uleb128_u32` semantics (atom #7); kept local
/// per the atom #11 sibling-layer-reuse-check precedent
/// (`uleb128_encoded_len_u32` stayed in `c-walrus::stream` instead of
/// being promoted to `c-walrus::wire`). Promote only if a third
/// consumer appears.
#[inline]
fn append_uleb128_u32(out: &mut Vec<u8>, mut value: u32) {
    loop {
        let byte = (value & 0x7F) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

// ===========================================================================
// 6. Inline unit tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::types::{SuiAddress, encode_memory_root_args_bcs};

    fn sample_args() -> MemoryRootArgs {
        MemoryRootArgs {
            owner: SuiAddress::new([0xAAu8; 32]),
            root_hash: [0xBBu8; 32],
            epoch_u64: 0x0102_0304_0506_0708,
        }
    }

    fn sample_root() -> ObjectId {
        ObjectId::new([0xCCu8; 32])
    }

    fn sample_gas() -> GasBudgetMist {
        GasBudgetMist::new(800_000)
    }

    #[test]
    fn canonical_constants_pin_known_widths() {
        assert_eq!(MNEMOS_MOVE_MODULE_NAME, "memory_root");
        assert_eq!(MNEMOS_MOVE_MODULE_NAME.len(), 11);
        assert_eq!(MNEMOS_MOVE_FUNCTION_ADD_CHUNK, "add_chunk");
        assert_eq!(MNEMOS_MOVE_FUNCTION_ADD_CHUNK.len(), 9);
        assert_eq!(
            MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER.as_bytes(),
            &[0u8; 32]
        );
        assert_eq!(SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN, 166);
    }

    #[test]
    fn call_build_error_class_labels_are_namespaced_and_unique() {
        let zero = CallBuildError::GasBudgetZero.class_label();
        let arg = CallBuildError::ArgEncode.class_label();
        assert!(zero.starts_with("sui_call_build."));
        assert!(arg.starts_with("sui_call_build."));
        assert_ne!(zero, arg);
        assert_eq!(zero, "sui_call_build.gas_budget_zero");
        assert_eq!(arg, "sui_call_build.arg_encode");
    }

    #[test]
    fn add_chunk_rejects_zero_gas_before_byte_work() {
        let zero_gas = GasBudgetMist::new(0);
        let result = SuiCallBuilder::add_chunk(sample_root(), &sample_args(), zero_gas);
        assert_eq!(result, Err(CallBuildError::GasBudgetZero));
    }

    #[test]
    fn add_chunk_happy_path_builds_routing_and_args() {
        let builder =
            SuiCallBuilder::add_chunk(sample_root(), &sample_args(), sample_gas()).unwrap();
        assert_eq!(builder.module(), MNEMOS_MOVE_MODULE_NAME);
        assert_eq!(builder.function(), MNEMOS_MOVE_FUNCTION_ADD_CHUNK);
        assert_eq!(
            builder.package().as_bytes(),
            MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER.as_bytes()
        );
        assert_eq!(builder.gas_budget().get(), 800_000);
        assert_eq!(builder.root().as_bytes(), &[0xCCu8; 32]);
        let expected_args = encode_memory_root_args_bcs(&sample_args());
        assert_eq!(builder.encoded_args(), &expected_args);
    }

    #[test]
    fn append_uleb128_u32_short_values_emit_one_byte() {
        // Module / function name lengths are both < 128 → 1-byte uleb128.
        let mut out: Vec<u8> = Vec::new();
        append_uleb128_u32(&mut out, 0);
        append_uleb128_u32(&mut out, 11);
        append_uleb128_u32(&mut out, 9);
        append_uleb128_u32(&mut out, 127);
        assert_eq!(out, vec![0, 11, 9, 127]);
    }

    #[test]
    fn append_uleb128_u32_boundary_at_128_emits_two_bytes() {
        // 128 = 0x80 → uleb128 = [0x80, 0x01]. Drift detector.
        let mut out: Vec<u8> = Vec::new();
        append_uleb128_u32(&mut out, 128);
        assert_eq!(out, vec![0x80, 0x01]);
    }

    #[test]
    fn to_dry_run_bytes_total_length_is_166() {
        let builder =
            SuiCallBuilder::add_chunk(sample_root(), &sample_args(), sample_gas()).unwrap();
        let bytes = builder.to_dry_run_bytes().unwrap();
        assert_eq!(bytes.len(), SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN);
        assert_eq!(bytes.len(), 166);
    }

    #[test]
    fn to_dry_run_bytes_layout_segments_pin_known_offsets() {
        let builder =
            SuiCallBuilder::add_chunk(sample_root(), &sample_args(), sample_gas()).unwrap();
        let bytes = builder.to_dry_run_bytes().unwrap();
        // [0..32] package (placeholder = 32× 0x00)
        assert_eq!(&bytes[0..32], &[0u8; 32]);
        // [32] uleb128(11)
        assert_eq!(bytes[32], 11);
        // [33..44] "memory_root"
        assert_eq!(&bytes[33..44], b"memory_root");
        // [44] uleb128(9)
        assert_eq!(bytes[44], 9);
        // [45..54] "add_chunk"
        assert_eq!(&bytes[45..54], b"add_chunk");
        // [54..86] root (= 32× 0xCC)
        assert_eq!(&bytes[54..86], &[0xCCu8; 32]);
        // [86..158] encoded_args (matches direct encode)
        let expected_args = encode_memory_root_args_bcs(&sample_args());
        assert_eq!(&bytes[86..158], &expected_args);
        // [158..166] gas LE = 800_000 = 0x0C_3500 → 35 0C 00 00 00 00 00 00
        let expected_gas_le: [u8; 8] = 800_000u64.to_le_bytes();
        assert_eq!(&bytes[158..166], &expected_gas_le);
    }

    #[test]
    fn to_dry_run_bytes_gas_position_changes_with_gas_budget() {
        let small = SuiCallBuilder::add_chunk(sample_root(), &sample_args(), GasBudgetMist::new(1))
            .unwrap();
        let large =
            SuiCallBuilder::add_chunk(sample_root(), &sample_args(), GasBudgetMist::new(800_000))
                .unwrap();
        let small_bytes = small.to_dry_run_bytes().unwrap();
        let large_bytes = large.to_dry_run_bytes().unwrap();
        // First 158 bytes are byte-identical (gas slot 158..166 is the
        // only thing that varies for fixed root + args).
        assert_eq!(&small_bytes[..158], &large_bytes[..158]);
        // Gas slot differs.
        assert_ne!(&small_bytes[158..166], &large_bytes[158..166]);
        assert_eq!(&small_bytes[158..166], &1u64.to_le_bytes());
        assert_eq!(&large_bytes[158..166], &800_000u64.to_le_bytes());
    }

    #[test]
    fn sui_call_builder_is_copy_and_pod_friendly() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<SuiCallBuilder>();
        assert_copy::<CallBuildError>();
        assert_copy::<GasBudgetMist>();
        assert_copy::<ObjectId>();
    }

    #[test]
    fn to_dry_run_bytes_is_deterministic_for_same_input() {
        let b1 = SuiCallBuilder::add_chunk(sample_root(), &sample_args(), sample_gas()).unwrap();
        let b2 = SuiCallBuilder::add_chunk(sample_root(), &sample_args(), sample_gas()).unwrap();
        let bytes1 = b1.to_dry_run_bytes().unwrap();
        let bytes2 = b2.to_dry_run_bytes().unwrap();
        assert_eq!(bytes1, bytes2);
    }
}
