//! `mnemos-e-skill::manifest` — atom #39 · E.0.1 — skill manifest
//! TOML parse + validate.
//!
//! Canonical OUT (§4.E — see ATOM_PLAN line 705-709 + atom #39 line
//! 1216-1224):
//!
//! - [`SkillId`] — `#[repr(transparent)]` newtype over `u16`. Public
//!   inner field per atom #24 `ToolId` rationale: no invariant beyond
//!   "name newtype over u16", so the inner exposure is correct (atom
//!   #23 `TurnUsage` precedent). 16-bit width pinned by
//!   [`_SKILL_ID_SIZE_IS_2`] below.
//! - [`SkillManifest`] — fixed-shape carrier with private fields +
//!   `pub const fn` accessors (atom #3 `TurnState` / atom #24
//!   `LazyToolSchema` invariant-protection precedent). The name string
//!   itself is NEVER retained — only its byte length collapses into
//!   `name_len_u8: u8` at the parser boundary (atom #5
//!   `RuntimeConfig` `_lenN` collapse precedent). `tool_ids` is the
//!   only owned heap allocation: a `Vec<ToolId>` whose every element
//!   has been cross-validated against [`KNOWN_TOOL_IDS`] before the
//!   manifest is returned.
//! - [`ManifestError`] — `#[non_exhaustive]` 4-variant `Copy` enum.
//!   Every variant is payload-less: the raw TOML cause behind
//!   [`ManifestError::Toml`] is DROPPED immediately on parse failure
//!   (the source-redaction spine from atom #2 `MnemosError` applied to
//!   the atom-local error channel) so a canary embedded in a manifest
//!   body cannot reach `Debug`, `Display`, or `source()` via this
//!   surface. Class labels are namespaced under `manifest.*` (atom
//!   #24 `tool_schema.*` precedent).
//! - [`load_manifest`] — the only public function. Signature pinned by
//!   §4.E line 709: `(toml_text: &str) -> Result<SkillManifest,
//!   ManifestError>`. No registry argument; no filesystem read; no
//!   `MnemosError` surface. Parses the TOML into a private
//!   [`RawManifest`] DTO, then validates length / version / tool ids
//!   in order. Returns on the first failure (fail-fast).
//! - [`KNOWN_TOOL_IDS`] — `pub const &[u16] = &[1, 2, 3]`. The
//!   canonical allow-set for the Phase 0 manifest. Pinned to §4.E
//!   line 711 forward-commitment `Builtin{ReadFile=1, WriteFile=2,
//!   RunCommand=3}`. Atom #40 (E.0.2) will promote this set to the
//!   `Builtin` `#[repr(u8)]` enum and SHOULD re-export this const so
//!   the discriminants stay one source-of-truth. Until atom #40
//!   lands, the const is the authoritative whitelist.
//!
//! ## Why name is collapsed to a length-only u8
//!
//! `name_len_u8: u8` (not `name: String`) is intentional. The §9.5
//! token-saving spine forbids the runtime from carrying redacted-able
//! bytes that never re-enter a prompt. A skill name is operator-tied
//! metadata: useful at registration time, but the runtime only needs
//! the *byte width* (for size pins) and the *id* (for dispatch). The
//! parser drops the name string immediately after measuring; the
//! u8 width bounds the maximum legal name length at 255 bytes —
//! larger names are rejected with [`ManifestError::NameTooLong`].
//!
//! ## Why an atom-local error channel (not `MnemosError`)
//!
//! §4.E line 708 pins [`ManifestError`] as a 4-variant local enum.
//! The atom #2 `MnemosError` carries source-redacted plumbing that is
//! correct for *runtime* failures (boot / agent / tool); the manifest
//! is a *configuration boundary* (atom #5 `RuntimeConfig` precedent)
//! that fails fast at load time with a fixed-shape verdict. Folding
//! into `MnemosError` here would create an asymmetric surface —
//! callers would handle 4 manifest failure modes via a 6-class
//! `ErrorCode` envelope, paying the dispatch cost without gaining
//! redaction (the manifest body is operator-controlled, not a network
//! response). Atom #40 dispatch errors fold into `MnemosError` per
//! §4.E line 713 `tool_denied`; atom #39 validation errors stay
//! local. The boundary is the load-time / run-time split.
//!
//! ## Carve-outs (Session 2 ACCEPT/RAISE)
//!
//! 1. **`SkillManifest` fields private.** §4.E line 707 shows the
//!    canonical signature with public fields (the prose-form
//!    declaration is `{ id: SkillId, name_len_u8: u8, ... }` without
//!    a `pub` modifier on each field). Atom #39 makes them private +
//!    `pub const fn` accessors per atom #3 `TurnState` precedent —
//!    the "name string dropped, only length retained" invariant
//!    requires construction-time validation, which a public field
//!    would let callers bypass. The const accessors preserve
//!    zero-cost read for downstream consumers.
//! 2. **`SkillId` keeps `pub u16` inner field.** Mirrors atom #24
//!    `ToolId(pub u16)` rationale ("no invariant beyond inner value,
//!    so public inner is correct"). The 16-bit width pin lives in
//!    [`_SKILL_ID_SIZE_IS_2`].
//! 3. **`KNOWN_TOOL_IDS` is a const `&[u16]`, not a runtime
//!    registry.** The §4.E line 709 signature
//!    `load_manifest(toml_text: &str) → Result<...>` admits NO
//!    registry parameter — UnknownTool validation must use a
//!    compile-time set. The const is pinned to the §4.E line 711
//!    `Builtin{1, 2, 3}` forward-commitment; atom #40 takes this
//!    over (either by re-using the const or by adding a compile-time
//!    assertion that the `Builtin` discriminants match). This atom
//!    deliberately does NOT depend on atom #40 — the const is
//!    self-contained and references §4.E line 711 only via this
//!    doc comment.
//! 4. **`ManifestError` is payload-less.** §4.E line 708 lists the
//!    4 variants without payloads. Atom #2 `MnemosError`'s pattern
//!    of carrying redaction-class metadata is intentionally NOT
//!    replicated here — the failure shape is structurally narrow
//!    (parse / length / version / tool), so a `class_label()` const
//!    accessor suffices for diagnostic plumbing. The TOML parse
//!    error variant is `ManifestError::Toml` with no inner; the
//!    `toml::de::Error` is dropped at the conversion boundary so a
//!    canary in the input cannot escape via the error channel.
//! 5. **`load_manifest` is fail-fast.** Returns on the first
//!    rejection encountered — length first, then version, then tool
//!    ids in declared order. The tests exercise each rejection in
//!    isolation; the validation order is documented but not
//!    invariant (a future atom that needs collected diagnostics
//!    would add a separate validator surface).
//! 6. **`#[serde(deny_unknown_fields)]` on `RawManifest`.** Mirrors
//!    atom #5 `RuntimeConfig` precedent — an attempt to declare an
//!    unrecognised top-level key collapses to
//!    [`ManifestError::Toml`] at parse time, before any validation
//!    runs. Future atoms that add fields (e.g. a `description_len`)
//!    must update both `RawManifest` and the test fixtures.
//! 7. **No `Default` impl on `SkillManifest`.** The empty-manifest
//!    shape is operator-meaningful only as a parse failure; a
//!    `Default` impl would invite accidental construction of an
//!    unregistered skill at runtime. The empty-tool-ids case is
//!    legal (tests cover) but requires explicit `load_manifest`
//!    invocation against a `tool_ids = []` TOML.
//! 8. **Token-cost is `u32`, declared not measured.** §4.E line 707
//!    pins the field as `token_cost_estimate_u32: u32`. The 광기
//!    note says "manifest 가 *선언* (측정 가능)" — the manifest
//!    DECLARES an estimate; the actual measurement lives in atom
//!    #28 `m-agent::token_bench` (per-call envelope) and atom #26
//!    `DailyTokenBudget`. The estimate has no enforced ceiling at
//!    this atom — Phase 0 trust boundary is operator-controlled.

#![deny(missing_docs)]
#![deny(unsafe_code)]

extern crate alloc;

use alloc::vec::Vec;

use serde::Deserialize;

use mnemos_m_agent::tool_schema::ToolId;

// ===========================================================================
// 1. Compile-time width pins (atom #21 / #23 / #24 precedent)
// ===========================================================================

/// `SkillId` width pin. `#[repr(transparent)]` over `u16` ⇒ exactly
/// 2 bytes. Any future widening (e.g. `u32` for "more than 65 536
/// skills per agent") would diverge from §4.E line 706 — the build
/// fails here first.
const _SKILL_ID_SIZE_IS_2: [(); 0 - !(core::mem::size_of::<SkillId>() == 2) as usize] = [];

// ===========================================================================
// 2. KNOWN_TOOL_IDS — Phase 0 allow-set (cross-pin with §4.E line 711)
// ===========================================================================

/// Canonical allow-set of tool ids accepted by [`load_manifest`].
/// Pinned to §4.E line 711 forward-commitment
/// `Builtin{ReadFile=1, WriteFile=2, RunCommand=3}`. A declared
/// `tool_ids` entry whose `ToolId.0` is not in this slice causes
/// [`load_manifest`] to return [`ManifestError::UnknownTool`].
///
/// Atom #40 (E.0.2) promotes these discriminants to the `Builtin`
/// `#[repr(u8)]` enum; this const is the one source-of-truth until
/// then. Future atoms that grow the whitelist MUST update this slice
/// AND the §4.E line 711 prose simultaneously.
pub const KNOWN_TOOL_IDS: &[u16] = &[1, 2, 3];

// ===========================================================================
// 3. SkillId — compact 16-bit skill identifier
// ===========================================================================

/// Compact skill identifier. `#[repr(transparent)]` over `u16` —
/// the unit-confusion barrier between "skill id" and any other
/// `u16`-shaped index (atom #24 `ToolId` precedent). 16-bit width
/// per §4.E line 706 commitment — up to 65 536 skills per agent
/// instance.
///
/// Inner `pub u16` per atom #24 `ToolId(pub u16)` rationale: "no
/// invariant beyond inner value, so public inner is correct" (atom
/// #23 `TurnUsage` precedent).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Default)]
#[repr(transparent)]
pub struct SkillId(pub u16);

// ===========================================================================
// 4. SkillManifest — validated manifest carrier
// ===========================================================================

/// Validated skill manifest. Built only via [`load_manifest`]; the
/// private fields + `pub const fn` accessors ensure every public
/// instance has been length-validated (`name_len_u8 ≤ 255`),
/// version-validated (`version_u32 ≠ 0`), and tool-validated (every
/// `tool_ids[i].0 ∈ KNOWN_TOOL_IDS`).
///
/// The name string itself is NOT retained — only its byte length
/// (`name_len_u8`). This matches the atom #5 `RuntimeConfig` `_lenN`
/// collapse precedent and the §9.5 token-saving spine.
///
/// `tool_ids` is the only owned heap allocation; it carries one
/// [`ToolId`] per declared tool, in declaration order, post-validation.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct SkillManifest {
    /// Stable id of this skill (operator-assigned at manifest time).
    id: SkillId,
    /// Byte length of the original `name` field. The string itself is
    /// dropped at the parser boundary.
    name_len_u8: u8,
    /// Manifest schema version. Must be non-zero (zero is reserved
    /// for the "uninitialised" sentinel).
    version_u32: u32,
    /// Declared tool ids. Every entry has been cross-validated against
    /// [`KNOWN_TOOL_IDS`] at construction time.
    tool_ids: Vec<ToolId>,
    /// Operator-declared token cost estimate for this skill (Phase 0
    /// trust-boundary — no enforced ceiling at this atom).
    token_cost_estimate_u32: u32,
}

impl SkillManifest {
    /// Stable id of this skill.
    #[inline]
    pub const fn id(&self) -> SkillId {
        self.id
    }

    /// Byte length of the original `name` field (the string itself is
    /// not retained).
    #[inline]
    pub const fn name_len_u8(&self) -> u8 {
        self.name_len_u8
    }

    /// Manifest schema version (always non-zero post-validation).
    #[inline]
    pub const fn version_u32(&self) -> u32 {
        self.version_u32
    }

    /// Borrowed view of the declared tool ids (post-validation).
    #[inline]
    pub fn tool_ids(&self) -> &[ToolId] {
        &self.tool_ids
    }

    /// Operator-declared token cost estimate.
    #[inline]
    pub const fn token_cost_estimate_u32(&self) -> u32 {
        self.token_cost_estimate_u32
    }
}

// ===========================================================================
// 5. ManifestError — load-time failure channel
// ===========================================================================

/// Failure modes for [`load_manifest`]. `Copy`, `#[non_exhaustive]`,
/// payload-less — the raw TOML cause behind [`Self::Toml`] is dropped
/// at the conversion boundary so a canary in a manifest body cannot
/// reach `Debug`, `Display`, or `source()` via this surface.
///
/// Class labels namespaced under `manifest.*` (atom #24
/// `tool_schema.*` precedent).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ManifestError {
    /// TOML parse failure OR unknown top-level field (the
    /// `RawManifest` DTO uses `#[serde(deny_unknown_fields)]`). The
    /// raw `toml::de::Error` is dropped at the boundary — no payload.
    Toml,
    /// Manifest `name` field exceeds 255 bytes (the `name_len_u8`
    /// carrier's representable range).
    NameTooLong,
    /// A declared `tool_ids` entry is not present in
    /// [`KNOWN_TOOL_IDS`]. Returned on the first unknown id
    /// encountered (declaration order).
    UnknownTool,
    /// Manifest `version` field is zero (zero is reserved for the
    /// "uninitialised" sentinel).
    VersionZero,
}

impl ManifestError {
    /// Stable class label of this failure mode. Namespaced under
    /// `manifest.*` so audit pipelines can fan out on a single
    /// prefix.
    #[inline]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::Toml => "manifest.toml",
            Self::NameTooLong => "manifest.name_too_long",
            Self::UnknownTool => "manifest.unknown_tool",
            Self::VersionZero => "manifest.version_zero",
        }
    }
}

// ===========================================================================
// 6. RawManifest — private TOML deserialization DTO
// ===========================================================================

/// Private deserialization DTO for the manifest TOML schema. Mirrors
/// the §4.E line 707 field names verbatim. `#[serde(deny_unknown_fields)]`
/// rejects unknown top-level keys at parse time (atom #5
/// `RuntimeConfig` precedent).
///
/// `name: String` is the only retained heap allocation in the DTO —
/// it is measured into `name_len_u8` and then dropped at the boundary
/// inside [`load_manifest`].
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    /// Stable id of this skill.
    id: u16,
    /// Operator-readable name; measured into `name_len_u8` and dropped.
    name: String,
    /// Manifest schema version.
    version: u32,
    /// Declared tool ids (cross-validated against [`KNOWN_TOOL_IDS`]).
    tool_ids: Vec<u16>,
    /// Operator-declared token cost estimate.
    token_cost_estimate: u32,
}

// ===========================================================================
// 7. load_manifest — the only public function (§4.E line 709)
// ===========================================================================

/// Parse and validate a skill manifest from a TOML text. Returns the
/// validated [`SkillManifest`] on success, or the first
/// [`ManifestError`] encountered on failure.
///
/// Validation order (fail-fast):
/// 1. TOML parse + unknown-field check → [`ManifestError::Toml`].
/// 2. `name.len() ≤ 255` → [`ManifestError::NameTooLong`].
/// 3. `version != 0` → [`ManifestError::VersionZero`].
/// 4. Every `tool_ids[i] ∈ KNOWN_TOOL_IDS` →
///    [`ManifestError::UnknownTool`] on the first unknown id.
///
/// The signature is pinned by §4.E line 709 — no registry parameter,
/// no filesystem read, no `MnemosError` surface. The name string is
/// dropped after step 2 succeeds; the returned manifest never owns
/// the original bytes.
pub fn load_manifest(toml_text: &str) -> Result<SkillManifest, ManifestError> {
    // Step 1: parse + unknown-field check. The raw `toml::de::Error`
    // is dropped at the `map_err` boundary so a canary in the input
    // cannot escape via the error channel.
    let raw: RawManifest = toml::from_str(toml_text).map_err(|_| ManifestError::Toml)?;

    // Step 2: name length collapse. The string survives only until
    // this line; after the measure, only `name_len_u8` is retained.
    let name_bytes = raw.name.len();
    if name_bytes > u8::MAX as usize {
        return Err(ManifestError::NameTooLong);
    }
    let name_len_u8 = name_bytes as u8;

    // Step 3: version sentinel rejection.
    if raw.version == 0 {
        return Err(ManifestError::VersionZero);
    }

    // Step 4: tool id whitelist. Fail-fast on the first unknown id;
    // the offending id is NOT carried in the error (the channel is
    // payload-less per carve-out 4).
    let mut tool_ids: Vec<ToolId> = Vec::with_capacity(raw.tool_ids.len());
    for raw_id in &raw.tool_ids {
        if !known_tool_id(*raw_id) {
            return Err(ManifestError::UnknownTool);
        }
        tool_ids.push(ToolId(*raw_id));
    }

    Ok(SkillManifest {
        id: SkillId(raw.id),
        name_len_u8,
        version_u32: raw.version,
        tool_ids,
        token_cost_estimate_u32: raw.token_cost_estimate,
    })
}

/// Linear scan over [`KNOWN_TOOL_IDS`]. 3 entries in Phase 0 — well
/// below any cache pressure; const fn so the check can fold at
/// compile time for static fixtures.
const fn known_tool_id(id: u16) -> bool {
    let mut i = 0usize;
    while i < KNOWN_TOOL_IDS.len() {
        if KNOWN_TOOL_IDS[i] == id {
            return true;
        }
        i += 1;
    }
    false
}

// ===========================================================================
// 8. Inline unit tests — ATOM_PLAN line 1220 verbatim names
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // ---- Width pin sanity (also enforced at compile time) ----------------

    #[test]
    fn skill_id_size_is_2() {
        assert_eq!(core::mem::size_of::<SkillId>(), 2);
    }

    #[test]
    fn known_tool_ids_match_section_4e_line_711_commitment() {
        // §4.E line 711: `Builtin { ReadFile=1, WriteFile=2, RunCommand=3 }`.
        // Cross-pin: this const + the §4.E prose must move together.
        assert_eq!(KNOWN_TOOL_IDS, &[1u16, 2, 3]);
    }

    #[test]
    fn manifest_error_class_labels_namespaced_under_manifest() {
        assert_eq!(ManifestError::Toml.class_label(), "manifest.toml");
        assert_eq!(
            ManifestError::NameTooLong.class_label(),
            "manifest.name_too_long"
        );
        assert_eq!(
            ManifestError::UnknownTool.class_label(),
            "manifest.unknown_tool"
        );
        assert_eq!(
            ManifestError::VersionZero.class_label(),
            "manifest.version_zero"
        );
    }

    // ---- ATOM_PLAN line 1220 verbatim tests ------------------------------

    /// `e0_1_parses_valid_manifest` — verifies that a well-formed
    /// manifest with all four §4.E fields parses successfully and
    /// the returned [`SkillManifest`] carries the validated values.
    /// All declared tool ids are inside [`KNOWN_TOOL_IDS`].
    #[test]
    fn e0_1_parses_valid_manifest() {
        let toml_text = r#"
            id = 42
            name = "echo"
            version = 1
            tool_ids = [1, 2, 3]
            token_cost_estimate = 250
        "#;
        let manifest = load_manifest(toml_text).expect("valid manifest must parse");

        assert_eq!(manifest.id(), SkillId(42));
        // "echo" is 4 bytes; collapsed into u8.
        assert_eq!(manifest.name_len_u8(), 4);
        assert_eq!(manifest.version_u32(), 1);
        assert_eq!(
            manifest.tool_ids(),
            &[ToolId(1), ToolId(2), ToolId(3)],
            "tool_ids must round-trip post-validation"
        );
        assert_eq!(manifest.token_cost_estimate_u32(), 250);

        // Empty tool list is also legal — operator-declared zero-tool skill.
        let empty_tools = r#"
            id = 7
            name = "passthrough"
            version = 1
            tool_ids = []
            token_cost_estimate = 0
        "#;
        let m_empty = load_manifest(empty_tools).expect("empty tool list is legal");
        assert!(m_empty.tool_ids().is_empty());
        assert_eq!(m_empty.id(), SkillId(7));
        assert_eq!(m_empty.name_len_u8(), 11);
    }

    /// `e0_1_unknown_tool_rejected` — verifies that a manifest
    /// declaring a `tool_id` outside [`KNOWN_TOOL_IDS`] is rejected
    /// with [`ManifestError::UnknownTool`]. Fail-fast on the first
    /// unknown id encountered (declaration order).
    #[test]
    fn e0_1_unknown_tool_rejected() {
        // ToolId 99 is not in {1, 2, 3}.
        let toml_text = r#"
            id = 1
            name = "bad"
            version = 1
            tool_ids = [99]
            token_cost_estimate = 0
        "#;
        let err = load_manifest(toml_text).expect_err("unknown tool must reject");
        assert_eq!(err, ManifestError::UnknownTool);
        assert_eq!(err.class_label(), "manifest.unknown_tool");

        // Mixed valid + invalid: still rejects (the validator does
        // NOT silently drop unknowns — the canonical path is to fail).
        let toml_mixed = r#"
            id = 1
            name = "mixed"
            version = 1
            tool_ids = [1, 99, 2]
            token_cost_estimate = 0
        "#;
        let err_mixed = load_manifest(toml_mixed).expect_err("mixed unknown must reject");
        assert_eq!(err_mixed, ManifestError::UnknownTool);

        // Boundary: ToolId 0 is also not in {1, 2, 3} — rejected.
        let toml_zero = r#"
            id = 1
            name = "zeroid"
            version = 1
            tool_ids = [0]
            token_cost_estimate = 0
        "#;
        let err_zero = load_manifest(toml_zero).expect_err("tool id 0 must reject");
        assert_eq!(err_zero, ManifestError::UnknownTool);

        // Boundary: every entry in KNOWN_TOOL_IDS individually is accepted.
        for &id in KNOWN_TOOL_IDS {
            let toml_ok = format!(
                "id = 1\nname = \"k\"\nversion = 1\ntool_ids = [{id}]\ntoken_cost_estimate = 0\n"
            );
            let manifest = load_manifest(&toml_ok).expect("known tool id must parse");
            assert_eq!(manifest.tool_ids(), &[ToolId(id)]);
        }
    }

    /// `e0_1_name_too_long_rejected` — verifies that a manifest
    /// whose `name` field exceeds 255 bytes (the `name_len_u8`
    /// carrier's representable range) is rejected with
    /// [`ManifestError::NameTooLong`]. The 256-byte boundary is the
    /// minimal length that must fail.
    #[test]
    fn e0_1_name_too_long_rejected() {
        // 256 bytes of 'a' — exactly one byte over the u8 limit.
        let long_name = "a".repeat(256);
        let toml_text = format!(
            "id = 1\nname = \"{long_name}\"\nversion = 1\ntool_ids = []\ntoken_cost_estimate = 0\n"
        );
        let err = load_manifest(&toml_text).expect_err("256-byte name must reject");
        assert_eq!(err, ManifestError::NameTooLong);
        assert_eq!(err.class_label(), "manifest.name_too_long");

        // Boundary: 255 bytes is exactly at the u8 limit — accepted.
        let max_name = "a".repeat(255);
        let toml_max = format!(
            "id = 1\nname = \"{max_name}\"\nversion = 1\ntool_ids = []\ntoken_cost_estimate = 0\n"
        );
        let m_max = load_manifest(&toml_max).expect("255-byte name must parse");
        assert_eq!(m_max.name_len_u8(), 255);

        // Boundary: 0-byte name is legal (operator-declared
        // anonymous skill — name_len_u8 = 0).
        let toml_empty = r#"
            id = 1
            name = ""
            version = 1
            tool_ids = []
            token_cost_estimate = 0
        "#;
        let m_empty = load_manifest(toml_empty).expect("empty name is legal");
        assert_eq!(m_empty.name_len_u8(), 0);

        // Boundary: 1024-byte name still rejects (well above the limit).
        let huge_name = "a".repeat(1024);
        let toml_huge = format!(
            "id = 1\nname = \"{huge_name}\"\nversion = 1\ntool_ids = []\ntoken_cost_estimate = 0\n"
        );
        assert_eq!(
            load_manifest(&toml_huge),
            Err(ManifestError::NameTooLong),
            "1024-byte name must also reject"
        );
    }

    /// `e0_1_version_zero_rejected` — verifies that a manifest with
    /// `version = 0` is rejected with [`ManifestError::VersionZero`].
    /// Zero is reserved for the "uninitialised" sentinel.
    #[test]
    fn e0_1_version_zero_rejected() {
        let toml_text = r#"
            id = 1
            name = "v0"
            version = 0
            tool_ids = []
            token_cost_estimate = 0
        "#;
        let err = load_manifest(toml_text).expect_err("version = 0 must reject");
        assert_eq!(err, ManifestError::VersionZero);
        assert_eq!(err.class_label(), "manifest.version_zero");

        // Boundary: version = 1 is the minimum legal value.
        let toml_min = r#"
            id = 1
            name = "v1"
            version = 1
            tool_ids = []
            token_cost_estimate = 0
        "#;
        let m_min = load_manifest(toml_min).expect("version = 1 must parse");
        assert_eq!(m_min.version_u32(), 1);

        // Boundary: u32::MAX is also accepted (no upper limit at
        // this atom — operator-declared trust boundary).
        let toml_max = format!(
            "id = 1\nname = \"vmax\"\nversion = {}\ntool_ids = []\ntoken_cost_estimate = 0\n",
            u32::MAX
        );
        let m_max = load_manifest(&toml_max).expect("version = u32::MAX must parse");
        assert_eq!(m_max.version_u32(), u32::MAX);
    }

    // ---- Scaffolding tests (atom #2 / #5 / #24 precedent) ----------------

    #[test]
    fn toml_parse_failure_yields_toml_variant() {
        // Garbage TOML: not even valid syntax.
        let garbage = "this is not toml at all }{][";
        assert_eq!(load_manifest(garbage), Err(ManifestError::Toml));

        // Missing required field.
        let missing = r#"
            id = 1
            version = 1
            tool_ids = []
            token_cost_estimate = 0
        "#;
        assert_eq!(load_manifest(missing), Err(ManifestError::Toml));

        // Unknown top-level field rejected by deny_unknown_fields.
        let unknown_field = r#"
            id = 1
            name = "x"
            version = 1
            tool_ids = []
            token_cost_estimate = 0
            evil_field = "smuggled"
        "#;
        assert_eq!(load_manifest(unknown_field), Err(ManifestError::Toml));

        // Wrong field type (id as string instead of int).
        let wrong_type = r#"
            id = "string-not-int"
            name = "x"
            version = 1
            tool_ids = []
            token_cost_estimate = 0
        "#;
        assert_eq!(load_manifest(wrong_type), Err(ManifestError::Toml));
    }

    #[test]
    fn manifest_error_is_copy_and_payload_less() {
        fn assert_copy<T: Copy>() {}
        assert_copy::<ManifestError>();
        assert_copy::<SkillId>();

        // The error round-trips by value; no heap allocation.
        let e1 = ManifestError::UnknownTool;
        let e2 = e1; // copy
        assert_eq!(e1, e2);
    }

    #[test]
    fn skill_manifest_accessors_round_trip() {
        let toml_text = r#"
            id = 1234
            name = "round-trip-skill"
            version = 7
            tool_ids = [1, 3]
            token_cost_estimate = 999
        "#;
        let m = load_manifest(toml_text).expect("must parse");

        // Every accessor reads through to the canonical field.
        assert_eq!(m.id(), SkillId(1234));
        assert_eq!(m.name_len_u8(), 16); // "round-trip-skill" = 16 bytes
        assert_eq!(m.version_u32(), 7);
        assert_eq!(m.tool_ids(), &[ToolId(1), ToolId(3)]);
        assert_eq!(m.token_cost_estimate_u32(), 999);
    }
}
