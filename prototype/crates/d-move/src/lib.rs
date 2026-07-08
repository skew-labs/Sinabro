//! `mnemos-d-move` — Sui Move memory-root types and Rust SDK call bindings.
//!
//! Critical-path crate. Each module keeps `cargo build --workspace` green.
//!
//! Filled so far:
//! - [`types`][]: typed-unit newtypes (`GasBudgetMist`,
//!   `SuiAddress`, `ObjectId`), the `MemoryRootArgs` call-args projection,
//!   the `MoveBindError` failure channel, the `memory_root_args_from_anchor`
//!   conversion entrypoint, and a fixed-width 72-byte BCS encoder for
//!   cross-language schema lock against the Move-side `mnemos::memory_root`
//!   module (`prototype/move/sources/memory_root.move`). The Walrus-side
//!   reuse surface (`BlobId`, `BLOB_ID_BYTES`, `MoveAnchorArgsV1`) comes
//!   from the `mnemos-c-walrus` crate dependency.
//! - [`sdk`][]: `SuiCallBuilder` Move-call routing
//!   record with the canonical four `(package, module, function,
//!   gas_budget)` fields, the `add_chunk` constructor (rejects
//!   `gas == 0`), and the `to_dry_run_bytes` byte-stable measurement
//!   carrier. The `CallBuildError` failure channel mirrors the
//!   crate-wide class-label discipline. This is dry-run
//!   /gas-measurement only — real signing is owned by the future
//!   wallet/signing layer.
//! - [`stage_b_types`][]: Stage B Rust↔Move call-arg
//!   bindings — `MemoryRootAnchorArgs` (anchor a chunk), `AuditAppendArgs`
//!   (append an audit entry), and the full five-variant
//!   `StageBMoveBindError` channel. Reuses
//!   [`types::ObjectId`] and `MoveAnchorArgsV1`; the Move-boundary
//!   `vector<u8>` `len == 32` invariant is checked by the `try_from_move_*`
//!   adapters. The `digest` field is a raw `[u8; 32]` (not
//!   `b-memory::ChunkDigest32`) to avoid a `b-memory -> d-move` cargo
//!   cycle — see the module-level note.
//! - [`stage_b_call_builder`][]: testnet-only,
//!   unsigned Stage B PTB/call-builder dry-run. `StageBCallBuilder` builds
//!   `create_root` / `add_chunk` / `audit_log::append` calls, refusing a
//!   non-testnet network (`StageBMoveBindError::NetworkNotTestnet`) and a
//!   zero gas budget (`StageBMoveBindError::GasBudgetZero`), and emits
//!   byte-stable `to_dry_run_bytes` (65 / 130 / 162 / 123 bytes) without
//!   signing. The pure call args are the REAL Move entry ABI — `add_chunk`
//!   carries `(blob_id, kind, parent)` and `append` carries `(entry_hash)`,
//!   with each `&mut <Object>` (`root` / `log`) as a SEPARATE object input
//!   and NO serialized `digest`. Reuses the
//!   `stage_b_types` args + error channel and the `sdk` package placeholder;
//!   the BCS struct-parity wire is kept only as replay evidence in
//!   `encode_anchor_args_bcs` / `encode_audit_append_args_bcs`. The testnet
//!   allowlist is a local mirror of `b-memory::StageBNetwork` (unreachable —
//!   same cargo cycle; see the module-level note).
//! - [`stage_b_gas`][]: Stage B gas budget cap policy over
//!   the REUSED [`types::GasBudgetMist`] typed unit. `StageBGasBudgetPolicy`
//!   checks a requested (or checked-summed) budget against a configured
//!   ceiling BEFORE the call builder emits dry-run bytes — rejecting zero,
//!   over-cap, and `u64` addition-overflow through a dedicated `StageBGasError`
//!   channel. `StageBMoveBindError` is left byte-stable at five variants (the
//!   cap/overflow rejects have no home in that frozen schema — see the
//!   module-level note); the `STAGE_B_DEFAULT_MAX_GAS_MIST` = 1 SUI
//!   ceiling is a Stage-B policy default, not a Sui protocol constant.
#![deny(unsafe_code)]
#![deny(missing_docs)]

pub mod sdk;
pub mod stage_b_call_builder;
pub mod stage_b_gas;
pub mod stage_b_types;
pub mod stage_c_add_chunk_gas;
pub mod stage_c_audit_gas;
pub mod stage_c_effect_delta;
pub mod stage_c_event_budget;
pub mod stage_c_gas_baseline;
pub mod stage_c_gas_compare;
pub mod stage_c_gas_trace;
pub mod stage_c_idempotency;
pub mod stage_c_package_lock;
pub mod stage_c_ptb_size;
pub mod types;

#[doc(no_inline)]
pub use sdk::{
    CallBuildError, MNEMOS_MEMORY_ROOT_PACKAGE_PLACEHOLDER, MNEMOS_MOVE_FUNCTION_ADD_CHUNK,
    MNEMOS_MOVE_MODULE_NAME, SUI_DRY_RUN_BYTES_ADD_CHUNK_LEN, SuiCallBuilder,
};

#[doc(no_inline)]
pub use stage_b_call_builder::{
    MNEMOS_MOVE_FUNCTION_APPEND, MNEMOS_MOVE_FUNCTION_CREATE_ROOT, MNEMOS_MOVE_MODULE_AUDIT_LOG,
    STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_NONE, STAGE_B_ADD_CHUNK_DRY_RUN_LEN_PARENT_SOME,
    STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_NONE, STAGE_B_ADD_CHUNK_PURE_ARGS_LEN_PARENT_SOME,
    STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_NONE, STAGE_B_ANCHOR_ARGS_BCS_LEN_PARENT_SOME,
    STAGE_B_APPEND_PURE_ARGS_LEN, STAGE_B_AUDIT_APPEND_ARGS_BCS_LEN,
    STAGE_B_AUDIT_APPEND_DRY_RUN_LEN, STAGE_B_CALL_TESTNET_LABEL, STAGE_B_CREATE_ROOT_DRY_RUN_LEN,
    StageBCallBuilder, StageBCallKind, encode_add_chunk_pure_args, encode_anchor_args_bcs,
    encode_append_pure_args, encode_audit_append_args_bcs,
};

#[doc(no_inline)]
pub use stage_b_gas::{STAGE_B_DEFAULT_MAX_GAS_MIST, StageBGasBudgetPolicy, StageBGasError};

#[doc(no_inline)]
pub use stage_b_types::{
    AuditAppendArgs, MemoryRootAnchorArgs, STAGE_B_MOVE_VEC_LEN, StageBMoveBindError,
};

#[doc(no_inline)]
pub use types::{
    GasBudgetMist, MEMORY_ROOT_ARGS_BCS_LEN, MemoryRootArgs, MoveBindError, ObjectId,
    SUI_ADDRESS_BYTES, SUI_OBJECT_ID_BYTES, SuiAddress, encode_memory_root_args_bcs,
    memory_root_args_from_anchor,
};
