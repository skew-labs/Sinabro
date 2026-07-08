//! `mnemos-m-agent::tool_schema` — lazy tool schema + compact tool
//! registry.
//!
//! Public surface:
//!
//! - [`ToolId`] — `#[repr(transparent)]` newtype over `u16`, moved
//!   from the `m-agent::llm` forward-declaration placeholder (the same
//!   move pattern used for [`crate::sse::SseDelta`] and
//!   [`crate::turn::TurnUsage`]). 16-bit width — up to 65 536 tools
//!   per agent instance (against the Hermes 96-flat-prompt baseline).
//!   Inner `pub u16` preserved verbatim for surface compatibility
//!   (like `TurnUsage`: no invariant beyond "name newtype over
//!   `u16`").
//! - [`ToolRegistry`] — compact fixed-slot registry mapping
//!   [`ToolId`] → declared schema byte width. [`TOOL_REGISTRY_CAPACITY`]
//!   slots (16 in Phase 0: the builtin whitelist is 5 — read / write /
//!   exec / chat / memory — so 16 leaves headroom for the e-skill
//!   manifest without dynamic growth). Private slots + private
//!   `len_u8` with `pub const fn` accessors so the "no duplicate
//!   id" / "len ≤ capacity" / "slots[len..] unused" invariants are
//!   protected at the type boundary (like
//!   [`crate::turn::TurnState`] / [`crate::turn::DeltaAccumulator`]).
//! - [`ToolRegistrySlot`] — one registry slot: `(ToolId,
//!   schema_bytes_u32: u32)`. `#[repr(C)]` carrier with public
//!   fields (no invariant beyond "two independent values"; the same
//!   [`crate::turn::TurnUsage`] rationale for public fields without an
//!   invariant). Pre-measured byte width — the actual JSON encoder
//!   lives in the e-skill layer (manifest TOML → canonical JSON
//!   schema).
//! - [`LazyToolSchema<'a>`] — moved from the `crate::llm`
//!   forward-declaration placeholder. Borrows two slices: the
//!   declared [`ToolId`] slice AND the registry reference. Private
//!   fields + `pub const fn` constructor + accessors (the same
//!   [`crate::turn::TurnState`] invariant-protection approach —
//!   "declared tools must reference the registry passed at
//!   construction" is enforced by signature, not a runtime check).
//!   The "only declared tools enter the prompt" rule is encoded
//!   structurally: only the `declared` slice contributes to
//!   [`serialized_tool_bytes`]; tools registered in the registry but
//!   absent from `declared` contribute 0 bytes.
//! - [`serialized_tool_bytes`] — free function: `&LazyToolSchema<'_>
//!   → u32`. Sums the declared, registered tool schemas' byte
//!   widths (saturating at `u32::MAX`). Declared `ToolId`s not
//!   present in the registry silently contribute 0 — the explicit
//!   rejection surface lives in [`validate_declared`] (returns
//!   `Result`). Signature pin: free function (not method), `u32`
//!   return (not `Result`).
//! - [`validate_declared`] — companion validator returning
//!   `Result<(), ToolSchemaError>`. Surfaces the "unknown tool id"
//!   rejection that [`serialized_tool_bytes`] silently absorbs;
//!   production code paths can call validate-then-measure to
//!   fail fast or measure-only to compress on unknowns.
//! - [`ToolRegistryError`] — `#[non_exhaustive]` 2-variant `Copy`
//!   failure channel for [`ToolRegistry::register`]: capacity
//!   exceeded or duplicate id. Namespaced class labels under
//!   `tool_registry.*`.
//! - [`ToolSchemaError`] — `#[non_exhaustive]` 1-variant `Copy`
//!   failure channel for [`validate_declared`]. Carries the
//!   offending [`ToolId`] for diagnostic plumbing. Namespaced
//!   class label `tool_schema.unknown_tool_id`.
//! - [`EMPTY_TOOL_REGISTRY`] — `pub static ToolRegistry` whose
//!   `new()`-initialised state is a zero-tool registry. The
//!   static-lifetime reference (`&EMPTY_TOOL_REGISTRY`) is the
//!   fixture used by the `m-agent::llm` tests after the surface
//!   change closed the public `declared` field;
//!   production callers who genuinely need an empty registry can
//!   also point at it (zero-allocation, zero per-call cost).
//! - [`TOOL_REGISTRY_CAPACITY`] — `pub const usize = 16`. The
//!   slot count; pinned by the [`_REGISTRY_SIZE_IS_132`] width
//!   assertion below.
//!
//! ## Disabled tool = 0 bytes (structural encoding)
//!
//! Hermes's 96-call flat-prompt baseline pays the JSON schema byte
//! cost for every registered tool regardless of whether the agent
//! will use it on this turn. The token-saving spine inverts that: the
//! `declared` slice on each request is the per-turn subset; tools
//! absent from `declared` contribute 0 bytes to the serialized schema.
//! [`serialized_tool_bytes`] proves this measurably — the
//! `m0_4_disabled_tool_absent_from_bytes` test demonstrates that
//! removing a tool from `declared` reduces the byte count exactly by
//! that tool's slot width.
//!
//! ## Move pattern
//!
//! `LazyToolSchema<'a>` and `ToolId` were originally forward-declared
//! in `m-agent::llm`; their canonical homes are now this module.
//! [`crate::llm`] re-imports them via
//! `use crate::tool_schema::{LazyToolSchema, ToolId};` so the public
//! re-export path (`mnemos_m_agent::{LazyToolSchema, ToolId}` via the
//! crate `lib.rs`) stays bit-for-bit stable.
//!
//! ## Design notes
//!
//! 1. **`LazyToolSchema` fields are private.** The canonical
//!    signature has private fields; the earlier forward-declaration
//!    ran with `pub declared` for the placeholder surface. The
//!    private surface enforces the "declared tools reference the
//!    registry at construction" invariant via [`LazyToolSchema::new`].
//!    The inline tests in [`crate::llm`] use the constructor; the
//!    breaking change is scoped to the in-crate test surface — no
//!    external Phase 0 consumer of `mnemos-m-agent` exists.
//! 2. **`ToolId` keeps its `pub u16` inner field.** The
//!    [`crate::turn::TurnUsage`] rationale ("no invariant beyond
//!    inner value") applies: `ToolId(u16)` is a name newtype with no
//!    constraint, so a public inner is correct. The 16-bit width pin
//!    lives in the [`_TOOL_ID_SIZE_IS_2`] const block.
//! 3. **`ToolRegistry` capacity = 16 slots in Phase 0.** The constant
//!    is exported as [`TOOL_REGISTRY_CAPACITY`] and pinned by
//!    [`_REGISTRY_SIZE_IS_132`]. Future work can grow it with a new
//!    compile-time width pin.
//! 4. **`serialized_tool_bytes` is total-with-saturating, not
//!    fail-on-unknown.** The signature is pinned as `-> u32` (no
//!    `Result`). Unknown declared ids contribute 0 bytes — equivalent
//!    to "rejected from prompt". The explicit rejection surface is
//!    [`validate_declared`] (returns `Result<(), ToolSchemaError>`).
//!    The `m0_4_unknown_tool_id_rejected` test exercises
//!    [`validate_declared`]; production code paths can call
//!    validate-then-measure to fail fast or measure-only to compress
//!    on unknowns.
//! 5. **Per-slot byte width is provider-pre-measured.** This module
//!    does NOT include a live JSON serializer — the registry stores
//!    pre-measured byte widths per [`ToolId`]. The actual encoder is
//!    e-skill territory (manifest TOML → canonical JSON schema bytes).
//!    The "schema bytes measured" test pins the structural carrier,
//!    not a JSON encode.
//! 6. **`Default` impl on [`ToolRegistry`] forwards to `new()`.**
//!    Provided for ergonomic fixtures; the empty-registry shape is
//!    intentional (matches [`EMPTY_TOOL_REGISTRY`]). The same
//!    accidental-zero risk applies whether a caller writes
//!    `ToolRegistry::new()` or `ToolRegistry::default()`, so `Default`
//!    does not add a new failure mode.
//! 7. **Numerical regression bench deferred.** The "schema bytes are
//!    measured (4× compression target)" measurement axis is
//!    structurally encoded via the `m0_4_schema_bytes_measured` test
//!    (a `cargo test` assertion on a known-fixture sum). A
//!    criterion-based bench would additionally regress the cumulative
//!    bytes across the full builtin whitelist; that bench
//!    (`benches/tool_schema.rs`) is deferred to the e-skill layer
//!    where the actual JSON encoder lands and the 4× compression
//!    target becomes measurable against a Hermes-shaped baseline.

#![deny(missing_docs)]

// ===========================================================================
// 1. Compile-time width pins
// ===========================================================================

/// `ToolId` width pin. `#[repr(transparent)]` over `u16` ⇒ exactly
/// 2 bytes. Any future widening (e.g. `u32` for "more than 65 536
/// tools per agent") would diverge from the committed width — the
/// build fails here first.
const _TOOL_ID_SIZE_IS_2: [(); 0 - !(core::mem::size_of::<ToolId>() == 2) as usize] = [];

/// `ToolRegistrySlot` width pin. `#[repr(C)]` `{ id: ToolId,
/// schema_bytes_u32: u32 }` ⇒ 2 (id) + 2 (padding) + 4 (bytes)
/// = 8 bytes, alignment 4. Pins the slot layout so the registry
/// total below remains stable.
const _SLOT_SIZE_IS_8: [(); 0 - !(core::mem::size_of::<ToolRegistrySlot>() == 8) as usize] = [];

/// `ToolRegistry` width pin. `#[repr(C)]` `[slot; CAP]` (16 × 8 =
/// 128) + `len_u8` (1) + 3 trailing padding for slot alignment
/// (`align_of::<u32>() == 4`) ⇒ 132 bytes. Pinned so a future
/// capacity change is forced through this constant rather than
/// silently expanding the registry footprint.
const _REGISTRY_SIZE_IS_132: [(); 0 - !(core::mem::size_of::<ToolRegistry>() == 132) as usize] = [];

/// `LazyToolSchema` width pin. Two borrowed references: `&'a
/// [ToolId]` (fat pointer = 2 × `usize`) + `&'a ToolRegistry`
/// (thin pointer = 1 × `usize`) ⇒ 3 × `usize`. On macOS arm64
/// (the Phase 0 build host) `usize == 8` ⇒ 24 bytes; the pin is
/// target-width-agnostic so a hypothetical 32-bit cross compile
/// would also lock in 12 bytes.
const _LAZY_SCHEMA_SIZE_IS_3X_USIZE: [(); 0 - !(core::mem::size_of::<LazyToolSchema<'static>>()
    == 3 * core::mem::size_of::<usize>()) as usize] = [];

// ===========================================================================
// 2. Public constants
// ===========================================================================

/// Compact fixed-slot capacity for [`ToolRegistry`]. The Phase 0
/// builtin whitelist is 5 tools — read / write / exec / chat /
/// memory; 16 slots leave headroom for the e-skill manifest without
/// dynamic allocation.
pub const TOOL_REGISTRY_CAPACITY: usize = 16;

// ===========================================================================
// 3. ToolId — compact 16-bit tool identifier (moved from m-agent::llm)
// ===========================================================================

/// Compact tool identifier. `#[repr(transparent)]` over `u16` —
/// the unit-confusion barrier between "tool id" and any other
/// `u16`-shaped index that flows through the m-agent crate.
/// Moved from the [`crate::llm`] forward-declaration placeholder
/// (the same move pattern as `SseDelta` / `TurnUsage`). 16-bit
/// width — up to 65 536 tools per agent instance.
///
/// Inner `pub u16` preserved verbatim (the same `TurnUsage`
/// rationale: "no invariant beyond inner value, so public inner is
/// correct").
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
#[repr(transparent)]
pub struct ToolId(pub u16);

// ===========================================================================
// 4. ToolRegistrySlot — one fixed-capacity registry slot
// ===========================================================================

/// One slot of [`ToolRegistry`]. Holds the [`ToolId`] and the
/// pre-measured serialized schema byte width for that tool.
/// `#[repr(C)]` layout pinned at 8 bytes (see [`_SLOT_SIZE_IS_8`]).
///
/// No invariant beyond "two independent values" (the same
/// [`crate::turn::TurnUsage`] rationale), so fields are `pub`. The
/// owning [`ToolRegistry`] is responsible for the uniqueness and
/// in-bounds invariants — slots outside `len()` are unused and
/// hold the zero-initialised default value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
#[repr(C)]
pub struct ToolRegistrySlot {
    /// Tool identifier registered in this slot.
    pub id: ToolId,
    /// Pre-measured serialized schema byte width for this tool.
    pub schema_bytes_u32: u32,
}

// ===========================================================================
// 5. ToolRegistry — compact fixed-slot id → byte-width map
// ===========================================================================

/// Compact fixed-slot tool registry. Maps [`ToolId`] →
/// pre-measured schema byte width. [`TOOL_REGISTRY_CAPACITY`]
/// slots, insertion order (linear scan on lookup; 16 slots ⇒
/// 16 compares worst-case, well below any cache pressure).
///
/// Private fields + `pub const fn` accessors (the same
/// invariant-protection approach as `TurnState`). The owning
/// invariants are:
///
/// - `len_u8 ≤ TOOL_REGISTRY_CAPACITY` — enforced by
///   [`ToolRegistry::register`] returning [`ToolRegistryError::CapacityExceeded`].
/// - `slots[i].id` is pairwise distinct for `i in 0..len_u8` —
///   enforced by [`ToolRegistry::register`] returning
///   [`ToolRegistryError::DuplicateToolId`].
/// - `slots[i] == ToolRegistrySlot::default()` for `i in
///   len_u8..CAPACITY` — preserved by construction; the registry
///   never exposes a mutable handle to the unused tail.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(C)]
pub struct ToolRegistry {
    /// Backing slot array. Slots `0..len_u8` are live; the tail is
    /// the zero-initialised default.
    slots: [ToolRegistrySlot; TOOL_REGISTRY_CAPACITY],
    /// Number of live slots. Always ≤ [`TOOL_REGISTRY_CAPACITY`].
    len_u8: u8,
}

impl Default for ToolRegistry {
    /// Default registry is the empty registry (`new()`).
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    /// Construct an empty registry. `const fn` so the empty
    /// [`EMPTY_TOOL_REGISTRY`] static can be initialised at
    /// compile time.
    #[inline]
    pub const fn new() -> Self {
        Self {
            slots: [ToolRegistrySlot {
                id: ToolId(0),
                schema_bytes_u32: 0,
            }; TOOL_REGISTRY_CAPACITY],
            len_u8: 0,
        }
    }

    /// Number of registered tools.
    #[inline]
    pub const fn len(&self) -> u8 {
        self.len_u8
    }

    /// `true` when no tools are registered.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len_u8 == 0
    }

    /// Maximum capacity (compile-time constant; equals
    /// [`TOOL_REGISTRY_CAPACITY`]).
    #[inline]
    pub const fn capacity(&self) -> usize {
        TOOL_REGISTRY_CAPACITY
    }

    /// Register one tool with its pre-measured serialized schema
    /// byte width. Returns
    /// [`ToolRegistryError::DuplicateToolId`] when a slot with
    /// the same [`ToolId`] is already live, and
    /// [`ToolRegistryError::CapacityExceeded`] when the registry
    /// is full.
    ///
    /// `&mut self` (not interior mutability) so a registry
    /// construction phase has explicit ownership and a finalised
    /// registry can be passed by `&` afterwards.
    pub fn register(&mut self, id: ToolId, schema_bytes_u32: u32) -> Result<(), ToolRegistryError> {
        let len = self.len_u8 as usize;
        let mut i = 0usize;
        while i < len {
            if self.slots[i].id.0 == id.0 {
                return Err(ToolRegistryError::DuplicateToolId);
            }
            i += 1;
        }
        if len >= TOOL_REGISTRY_CAPACITY {
            return Err(ToolRegistryError::CapacityExceeded);
        }
        self.slots[len] = ToolRegistrySlot {
            id,
            schema_bytes_u32,
        };
        self.len_u8 = self.len_u8.saturating_add(1);
        Ok(())
    }

    /// Look up the pre-measured schema byte width for a
    /// [`ToolId`]. Returns `None` if the id is not registered.
    /// Linear scan over `0..len()`; the unused tail is never
    /// consulted.
    #[inline]
    pub fn lookup_bytes(&self, id: ToolId) -> Option<u32> {
        let len = self.len_u8 as usize;
        let mut i = 0usize;
        while i < len {
            if self.slots[i].id.0 == id.0 {
                return Some(self.slots[i].schema_bytes_u32);
            }
            i += 1;
        }
        None
    }

    /// `true` when [`Self::lookup_bytes`] would return `Some`.
    /// Convenience wrapper.
    #[inline]
    pub fn contains(&self, id: ToolId) -> bool {
        self.lookup_bytes(id).is_some()
    }
}

// ===========================================================================
// 6. EMPTY_TOOL_REGISTRY — static empty fixture
// ===========================================================================

/// Static empty [`ToolRegistry`]. The `'static` reference
/// (`&EMPTY_TOOL_REGISTRY`) is the fixture used by the
/// [`crate::llm`] tests after the surface change closed
/// the public `declared` field. Production callers who genuinely
/// need an empty-registry [`LazyToolSchema`] can also point at
/// it — zero-allocation, zero per-call cost.
pub static EMPTY_TOOL_REGISTRY: ToolRegistry = ToolRegistry::new();

// ===========================================================================
// 7. ToolRegistryError — register-time failure channel
// ===========================================================================

/// Failure modes for [`ToolRegistry::register`]. `Copy`,
/// `#[non_exhaustive]`, no owned bytes — the channel cannot leak
/// the offending registration through `Debug`. Class labels
/// namespaced under `tool_registry.*`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ToolRegistryError {
    /// Registry has reached [`TOOL_REGISTRY_CAPACITY`] slots.
    CapacityExceeded,
    /// A slot with the same [`ToolId`] is already registered.
    DuplicateToolId,
}

impl ToolRegistryError {
    /// Stable class label of this failure mode. Namespaced
    /// under `tool_registry.*` so audit pipelines can fan out
    /// on a single prefix.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::CapacityExceeded => "tool_registry.capacity_exceeded",
            Self::DuplicateToolId => "tool_registry.duplicate_tool_id",
        }
    }
}

// ===========================================================================
// 8. ToolSchemaError — validate-time failure channel
// ===========================================================================

/// Failure modes for [`validate_declared`]. `Copy`,
/// `#[non_exhaustive]`. Carries the offending [`ToolId`] for
/// diagnostic plumbing; the carrier is itself `Copy` so the
/// error never owns heap state. Class label namespaced under
/// `tool_schema.*`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ToolSchemaError {
    /// A [`ToolId`] in `declared` is not registered in the
    /// backing [`ToolRegistry`]. Production code paths should
    /// either re-register the tool or remove it from the
    /// declared slice before re-attempting serialisation.
    UnknownToolId(ToolId),
}

impl ToolSchemaError {
    /// Stable class label of this failure mode.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::UnknownToolId(_) => "tool_schema.unknown_tool_id",
        }
    }
}

// ===========================================================================
// 9. LazyToolSchema — borrowed declared-slice + registry view
// ===========================================================================

/// Lazy tool schema view. Moved from the forward-declaration
/// placeholder in [`crate::llm`]. Borrows two slices: the
/// declared [`ToolId`] slice AND the backing [`ToolRegistry`]
/// reference. Private fields + `pub const fn` constructor +
/// accessors (following the [`crate::turn::TurnState`]
/// invariant-protection precedent).
///
/// Only declared tools enter the prompt: this is encoded
/// structurally — only the `declared` slice contributes
/// to [`serialized_tool_bytes`]; tools registered in the
/// registry but absent from `declared` contribute 0 bytes.
///
/// Lifetime `'a` is the common borrow of the declared slice and
/// the registry reference; both must outlive any
/// [`LazyToolSchema`] view that points at them.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct LazyToolSchema<'a> {
    /// Declared tool ids that should enter the prompt.
    declared: &'a [ToolId],
    /// Backing registry. Looked up by [`serialized_tool_bytes`]
    /// to recover the per-tool schema byte width.
    registry: &'a ToolRegistry,
}

impl<'a> LazyToolSchema<'a> {
    /// Construct a [`LazyToolSchema`] from a declared-id slice
    /// and a backing registry reference. `const fn` so fixture
    /// schemas can be folded at compile time.
    #[inline]
    pub const fn new(declared: &'a [ToolId], registry: &'a ToolRegistry) -> Self {
        Self { declared, registry }
    }

    /// The declared tool id slice. Borrows for the schema's
    /// lifetime; no owned bytes.
    #[inline]
    pub const fn declared(&self) -> &'a [ToolId] {
        self.declared
    }

    /// The backing tool registry. Borrows for the schema's
    /// lifetime; no owned bytes.
    #[inline]
    pub const fn registry(&self) -> &'a ToolRegistry {
        self.registry
    }
}

// ===========================================================================
// 10. serialized_tool_bytes — sum declared, registered schema widths
// ===========================================================================

/// Sum of the pre-measured serialized schema byte widths for
/// every declared, registered tool in `schema`. Declared
/// [`ToolId`]s absent from the backing registry silently
/// contribute 0 — the explicit rejection surface lives in
/// [`validate_declared`]. Saturates at `u32::MAX` (16 slots ×
/// `u32::MAX` bytes per slot exceeds `u32::MAX` total; the
/// saturating add prevents silent wrap).
///
/// Signature pin: free function (not method), `u32` return
/// (not `Result`). The compression measurement axis reads this
/// value directly.
pub fn serialized_tool_bytes(schema: &LazyToolSchema<'_>) -> u32 {
    let mut total: u32 = 0;
    for id in schema.declared {
        if let Some(bytes) = schema.registry.lookup_bytes(*id) {
            total = total.saturating_add(bytes);
        }
    }
    total
}

// ===========================================================================
// 11. validate_declared — explicit unknown-id rejection
// ===========================================================================

/// Validate that every declared [`ToolId`] in `schema` is
/// registered in the backing [`ToolRegistry`]. Returns
/// `Err(ToolSchemaError::UnknownToolId(first_unknown))` on the
/// first declared id whose registry lookup misses, otherwise
/// `Ok(())`. Companion to [`serialized_tool_bytes`]: production
/// code paths can call validate-then-measure to fail fast or
/// measure-only to compress on unknowns.
pub fn validate_declared(schema: &LazyToolSchema<'_>) -> Result<(), ToolSchemaError> {
    for id in schema.declared {
        if !schema.registry.contains(*id) {
            return Err(ToolSchemaError::UnknownToolId(*id));
        }
    }
    Ok(())
}

// ===========================================================================
// 12. Inline unit tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ---- Test helpers ------------------------------------------------------

    /// Build a 5-tool registry with deterministic, distinct byte
    /// widths so test assertions are byte-precise. Ids are
    /// 1..=5 (avoiding the zero-initialised placeholder for the
    /// unused tail), widths are 10, 20, 30, 40, 50 — pairwise
    /// distinct + summable to 150.
    fn five_tool_registry() -> ToolRegistry {
        let mut reg = ToolRegistry::new();
        reg.register(ToolId(1), 10).unwrap();
        reg.register(ToolId(2), 20).unwrap();
        reg.register(ToolId(3), 30).unwrap();
        reg.register(ToolId(4), 40).unwrap();
        reg.register(ToolId(5), 50).unwrap();
        reg
    }

    // ---- Declared-schema serialization tests ------------------------------

    /// `m0_4_only_declared_tools_serialized` — verifies that
    /// [`serialized_tool_bytes`] sums ONLY the declared tools'
    /// widths, even when the backing registry holds additional
    /// tools that were not declared on this turn. The Hermes
    /// 96-flat-prompt baseline would pay for every registered
    /// tool; the token-saving spine pays only for the
    /// per-turn `declared` subset.
    #[test]
    fn m0_4_only_declared_tools_serialized() {
        let registry = five_tool_registry();
        // Declare tools 2 and 4 only (widths 20 + 40 = 60).
        let declared = [ToolId(2), ToolId(4)];
        let schema = LazyToolSchema::new(&declared, &registry);
        assert_eq!(serialized_tool_bytes(&schema), 60);

        // Registry still holds five tools (tools 1, 3, 5 are
        // present-but-not-declared).
        assert_eq!(registry.len(), 5);
        assert_eq!(registry.lookup_bytes(ToolId(1)), Some(10));
        assert_eq!(registry.lookup_bytes(ToolId(3)), Some(30));
        assert_eq!(registry.lookup_bytes(ToolId(5)), Some(50));

        // Declaring the full registry sums to 150.
        let all_declared = [ToolId(1), ToolId(2), ToolId(3), ToolId(4), ToolId(5)];
        let full_schema = LazyToolSchema::new(&all_declared, &registry);
        assert_eq!(serialized_tool_bytes(&full_schema), 150);

        // Declaring nothing sums to 0 (the empty-declared
        // canonical zero — disabled-prompt extremum).
        let empty_declared: [ToolId; 0] = [];
        let empty_schema = LazyToolSchema::new(&empty_declared, &registry);
        assert_eq!(serialized_tool_bytes(&empty_schema), 0);
    }

    /// `m0_4_disabled_tool_absent_from_bytes` — verifies the
    /// "disabled tool = 0 bytes" structural property: removing
    /// a tool from `declared` reduces the byte count EXACTLY
    /// by that tool's slot width. The pre/post delta isolates
    /// the tool's contribution to zero.
    #[test]
    fn m0_4_disabled_tool_absent_from_bytes() {
        let registry = five_tool_registry();

        // Baseline: declare {1, 2, 3} — widths 10 + 20 + 30 = 60.
        let with_tool3 = [ToolId(1), ToolId(2), ToolId(3)];
        let schema_with = LazyToolSchema::new(&with_tool3, &registry);
        let baseline = serialized_tool_bytes(&schema_with);
        assert_eq!(baseline, 60);

        // Disable tool 3: declare {1, 2} only — widths 10 + 20 = 30.
        let without_tool3 = [ToolId(1), ToolId(2)];
        let schema_without = LazyToolSchema::new(&without_tool3, &registry);
        let disabled = serialized_tool_bytes(&schema_without);
        assert_eq!(disabled, 30);

        // The delta is exactly tool 3's slot width (30). Disabled
        // tool contributes 0 bytes — Hermes-baseline saving.
        assert_eq!(baseline - disabled, 30);
        assert_eq!(
            baseline - disabled,
            registry.lookup_bytes(ToolId(3)).unwrap()
        );

        // Disabling every tool by declaring an empty slice yields 0.
        let no_declared: [ToolId; 0] = [];
        let schema_none = LazyToolSchema::new(&no_declared, &registry);
        assert_eq!(serialized_tool_bytes(&schema_none), 0);

        // The unused-tail invariant: registry slots beyond `len()`
        // are zero-initialised and never consulted. Declaring a
        // ToolId(0) on an empty-tail registry that does not own a
        // zero-id slot returns 0 bytes (silently absorbed by
        // serialized_tool_bytes; validate_declared rejects).
        let zero_declared = [ToolId(0)];
        let schema_zero = LazyToolSchema::new(&zero_declared, &registry);
        assert_eq!(serialized_tool_bytes(&schema_zero), 0);
    }

    /// `m0_4_schema_bytes_measured` — verifies that
    /// [`serialized_tool_bytes`] returns a measurable `u32`
    /// reflecting the actual cumulative byte width across a
    /// known fixture. This is the structural carrier for the
    /// 4× compression target measurement axis — the
    /// criterion bench will compare this value
    /// against a Hermes-shaped flat baseline.
    #[test]
    fn m0_4_schema_bytes_measured() {
        let registry = five_tool_registry();

        // Sum over the full registry: 10 + 20 + 30 + 40 + 50 = 150.
        let all_declared = [ToolId(1), ToolId(2), ToolId(3), ToolId(4), ToolId(5)];
        let schema = LazyToolSchema::new(&all_declared, &registry);
        let total = serialized_tool_bytes(&schema);
        assert_eq!(total, 150);

        // The value is a u32 (typed unit; pinned by the
        // signature and the `_TOOL_ID_SIZE_IS_2` width
        // assertion above).
        let _: u32 = total;

        // Single-tool sums are byte-precise — measurement is
        // additive across declarations.
        for (tool, expected) in [
            (ToolId(1), 10u32),
            (ToolId(2), 20u32),
            (ToolId(3), 30u32),
            (ToolId(4), 40u32),
            (ToolId(5), 50u32),
        ] {
            let one = [tool];
            let s = LazyToolSchema::new(&one, &registry);
            assert_eq!(serialized_tool_bytes(&s), expected);
        }

        // Empty registry × declared anything = 0 bytes (the
        // "registry is the source of truth, declared is just
        // a hint" structural invariant).
        let empty_reg = ToolRegistry::new();
        let schema_empty_reg = LazyToolSchema::new(&all_declared, &empty_reg);
        assert_eq!(serialized_tool_bytes(&schema_empty_reg), 0);
    }

    /// `m0_4_unknown_tool_id_rejected` — verifies
    /// [`validate_declared`] rejects a declared [`ToolId`] that
    /// is NOT registered, surfacing
    /// [`ToolSchemaError::UnknownToolId`] with the offending id
    /// for diagnostic plumbing. The companion
    /// [`serialized_tool_bytes`] silently absorbs (returns 0
    /// for unknowns); the explicit rejection lives on the
    /// validator surface per the canonical signature pin.
    #[test]
    fn m0_4_unknown_tool_id_rejected() {
        let registry = five_tool_registry();

        // ToolId(99) is not registered. validate_declared
        // returns Err(UnknownToolId(ToolId(99))).
        let declared_bad = [ToolId(99)];
        let schema_bad = LazyToolSchema::new(&declared_bad, &registry);
        match validate_declared(&schema_bad) {
            Err(ToolSchemaError::UnknownToolId(id)) => assert_eq!(id, ToolId(99)),
            other => panic!("expected UnknownToolId(99), got {:?}", other),
        }
        assert_eq!(
            ToolSchemaError::UnknownToolId(ToolId(99)).class_label(),
            "tool_schema.unknown_tool_id"
        );

        // Mixed valid + invalid: validator returns on the FIRST
        // unknown encountered (declared scan order).
        let declared_mixed = [ToolId(1), ToolId(99), ToolId(2)];
        let schema_mixed = LazyToolSchema::new(&declared_mixed, &registry);
        match validate_declared(&schema_mixed) {
            Err(ToolSchemaError::UnknownToolId(id)) => assert_eq!(id, ToolId(99)),
            other => panic!(
                "expected UnknownToolId(99) on mixed declared, got {:?}",
                other
            ),
        }

        // The serialized_tool_bytes companion silently absorbs:
        // tools 1 and 2 sum to 30; tool 99 contributes 0.
        assert_eq!(serialized_tool_bytes(&schema_mixed), 30);

        // All-valid declared: validator returns Ok(()).
        let declared_good = [ToolId(1), ToolId(3), ToolId(5)];
        let schema_good = LazyToolSchema::new(&declared_good, &registry);
        assert_eq!(validate_declared(&schema_good), Ok(()));

        // Empty declared: validator returns Ok(()) trivially.
        let declared_empty: [ToolId; 0] = [];
        let schema_empty = LazyToolSchema::new(&declared_empty, &registry);
        assert_eq!(validate_declared(&schema_empty), Ok(()));
    }

    // ---- Scaffolding tests ------------------------------------------------

    #[test]
    fn public_types_are_copy_and_fixed_width() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ToolId>();
        assert_copy::<ToolRegistrySlot>();
        assert_copy::<ToolRegistry>();
        assert_copy::<LazyToolSchema<'static>>();
        assert_copy::<ToolRegistryError>();
        assert_copy::<ToolSchemaError>();

        // Width pins (also enforced at compile time by the
        // const _SIZE_IS_… blocks; tested here so the verifier
        // can spot drift via cargo test output alone).
        assert_eq!(core::mem::size_of::<ToolId>(), 2);
        assert_eq!(core::mem::size_of::<ToolRegistrySlot>(), 8);
        assert_eq!(core::mem::size_of::<ToolRegistry>(), 132);
        assert_eq!(
            core::mem::size_of::<LazyToolSchema<'static>>(),
            3 * core::mem::size_of::<usize>()
        );
    }

    #[test]
    fn empty_registry_static_is_empty() {
        assert!(EMPTY_TOOL_REGISTRY.is_empty());
        assert_eq!(EMPTY_TOOL_REGISTRY.len(), 0);
        assert_eq!(EMPTY_TOOL_REGISTRY.capacity(), TOOL_REGISTRY_CAPACITY);
        assert_eq!(EMPTY_TOOL_REGISTRY.lookup_bytes(ToolId(0)), None);
        assert_eq!(EMPTY_TOOL_REGISTRY.lookup_bytes(ToolId(1)), None);
        assert!(!EMPTY_TOOL_REGISTRY.contains(ToolId(0)));

        // Pairs identically with ToolRegistry::default() and
        // ToolRegistry::new() — three names, one shape.
        assert_eq!(EMPTY_TOOL_REGISTRY, ToolRegistry::new());
        assert_eq!(EMPTY_TOOL_REGISTRY, ToolRegistry::default());

        // Declared-anything against EMPTY_TOOL_REGISTRY yields 0.
        let any = [ToolId(1), ToolId(2), ToolId(3)];
        let schema = LazyToolSchema::new(&any, &EMPTY_TOOL_REGISTRY);
        assert_eq!(serialized_tool_bytes(&schema), 0);
        assert!(matches!(
            validate_declared(&schema),
            Err(ToolSchemaError::UnknownToolId(_))
        ));
    }

    #[test]
    fn register_rejects_duplicate_and_capacity_exceeded() {
        let mut reg = ToolRegistry::new();
        assert_eq!(reg.register(ToolId(7), 100), Ok(()));
        assert_eq!(reg.len(), 1);

        // Duplicate id rejected.
        assert_eq!(
            reg.register(ToolId(7), 200),
            Err(ToolRegistryError::DuplicateToolId)
        );
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.lookup_bytes(ToolId(7)), Some(100));

        // Fill to capacity (15 more registrations after the first).
        for i in 1u16..(TOOL_REGISTRY_CAPACITY as u16) {
            // Use distinct ids: 100 + i so we don't collide with 7.
            reg.register(ToolId(100 + i), u32::from(i)).unwrap();
        }
        assert_eq!(reg.len(), TOOL_REGISTRY_CAPACITY as u8);

        // Next registration rejected — capacity exceeded.
        assert_eq!(
            reg.register(ToolId(999), 7),
            Err(ToolRegistryError::CapacityExceeded)
        );
        assert_eq!(reg.len(), TOOL_REGISTRY_CAPACITY as u8);

        // Class labels for both error variants.
        assert_eq!(
            ToolRegistryError::CapacityExceeded.class_label(),
            "tool_registry.capacity_exceeded"
        );
        assert_eq!(
            ToolRegistryError::DuplicateToolId.class_label(),
            "tool_registry.duplicate_tool_id"
        );
    }

    #[test]
    fn serialized_tool_bytes_saturates_at_u32_max() {
        // Drive total to u32::MAX with three near-half-max slot
        // widths and prove saturation.
        let mut reg = ToolRegistry::new();
        let half = u32::MAX / 2;
        reg.register(ToolId(1), half).unwrap();
        reg.register(ToolId(2), half).unwrap();
        reg.register(ToolId(3), half).unwrap();
        let declared = [ToolId(1), ToolId(2), ToolId(3)];
        let schema = LazyToolSchema::new(&declared, &reg);
        // half + half + half overflows; saturating pins to u32::MAX.
        assert_eq!(serialized_tool_bytes(&schema), u32::MAX);

        // Saturating semantics directly (std), referenced as
        // documentation-of-invariant.
        assert_eq!(u32::MAX.saturating_add(1), u32::MAX);
        assert_eq!(half.saturating_add(half).saturating_add(half), u32::MAX);
    }

    #[test]
    fn lazy_schema_constructor_and_accessors() {
        let registry = five_tool_registry();
        let declared = [ToolId(2), ToolId(4)];
        let schema = LazyToolSchema::new(&declared, &registry);

        // Accessors return the originally-borrowed slice / ref —
        // pointer identity proves zero-copy.
        assert_eq!(schema.declared().len(), 2);
        assert_eq!(
            schema.declared().as_ptr() as usize,
            declared.as_ptr() as usize,
            "declared slice must be borrowed, not copied"
        );
        assert!(core::ptr::eq(schema.registry(), &registry));

        // Equality propagates through the fields.
        let schema2 = LazyToolSchema::new(&declared, &registry);
        assert_eq!(schema, schema2);
    }
}
