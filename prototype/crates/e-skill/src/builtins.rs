//! `mnemos-e-skill::builtins` — atom #40 · E.0.2 — Phase 0 builtin
//! whitelist (read-file / write-file / run-command).
//!
//! Canonical OUT (§4.E — ATOM_PLAN line 710-714 + atom #40 line
//! 1226-1234):
//!
//! - [`Builtin`] — `#[repr(u8)]` 3-variant enum `{ReadFile=1,
//!   WriteFile=2, RunCommand=3}`. Discriminants are cross-pinned to
//!   the atom #39 [`crate::manifest::KNOWN_TOOL_IDS`] allow-set via
//!   [`_BUILTIN_DISCRIMINANTS_MATCH_KNOWN_TOOL_IDS`]; widening either
//!   surface without the other will fail the build here first. Width
//!   is pinned by [`_BUILTIN_SIZE_IS_1`].
//! - [`CommandAllowlist`] — `&'static [&'static str]` carrier. The
//!   `&'static` choice (per §4.E line 712) makes runtime injection of
//!   new programs impossible — the only way to extend the whitelist is
//!   a source edit that re-builds the agent (`[[no-disabled-path-workaround]]`
//!   answer to the obvious "just take a `Vec<&str>`" sycophancy).
//!   Private field + `pub const fn` constructor / accessor + `pub fn
//!   contains` follow the atom #3 `TurnState` / atom #24
//!   `LazyToolSchema` invariant-protection precedent.
//! - [`PHASE0_COMMAND_ALLOWLIST`] — the §4.E line 712 canonical Phase 0
//!   set `["cargo", "git", "sui", "walrus"]`. Listed in the same order
//!   as [`mnemos_a_core::ToolProgram`] variants `Cargo=1, Git=2, Sui=3,
//!   Walrus=4` so a future cross-pin lint can verify them by index.
//! - [`BuiltinOutcome`] — fixed-width length-only carrier
//!   `(i32, u32, u32)` = 12 bytes pinned by
//!   [`_BUILTIN_OUTCOME_SIZE_IS_12`]. The §4.E line 714 prose says
//!   "출력은 길이만 반환(본문 미보관, redaction)" — this struct has NO
//!   field that can carry stdout / stderr bytes, so the "content
//!   never reaches the agent" guarantee holds by-construction. Private
//!   fields + `pub const fn` accessors + `pub const fn accepted_zero`
//!   constructor.
//! - [`dispatch_builtin`] — pure validator. §4.E line 713 admits NO IO
//!   path argument and the atom #40 광기 line says `run_command`
//!   pairs with `§2.7 T0~T2 격리 라우팅` — that routing layer is NOT
//!   wired in Phase 0, so dispatching with `std::fs::read` /
//!   `std::process::Command::spawn` here would skip the future
//!   sandbox boundary and silently degrade the policy
//!   (`[[no-disabled-path-workaround]]`). The validator-only shape
//!   returns [`BuiltinOutcome::accepted_zero`] on policy pass and
//!   folds every rejection through [`mnemos_a_core::MnemosError::tool_denied`]
//!   per atom #2 reuse.
//!
//! ## Why validator-only (and not raw spawn)
//!
//! The atom #40 광기 spec ("run_command는 §2.7 T0~T2 격리 라우팅과
//! 짝(Phase0)") forward-commits to a sandboxed routing layer that does
//! not yet exist in the Phase 0 tree. A raw `std::process::Command`
//! spawn would (a) compile a code path that bypasses the future
//! sandbox by construction, (b) introduce a `std::fs` / `std::process`
//! dependency that the §4.E line 713 signature does not need, and (c)
//! produce a `BuiltinOutcome` whose `stdout_len_u32` is "what the
//! unsandboxed process printed" — not "what the agent is allowed to
//! observe" (these diverge once T0~T2 routing lands). Validator-only
//! keeps the surface honest: the verdict is "this call would have
//! been admitted to the sandbox"; the actual execution is the job of
//! the later atom that wires §2.7. Atom #40 is the policy boundary,
//! not the IO boundary.
//!
//! ## Reuse map
//!
//! | atom | symbol                  | how |
//! |------|-------------------------|-----|
//! | #2   | [`mnemos_a_core::MnemosError::tool_denied`] | every rejection path folds through this constructor — no atom-local `MnemosError` variant added |
//! | #2   | [`mnemos_a_core::ToolProgram`]              | denial telemetry; `Cargo/Git/Sui/Walrus` map by name, anything else → `Other` |
//! | #2   | [`mnemos_a_core::ToolDenyReason`]           | `Program` for non-allowlisted, `ArgumentShape` for empty / missing args |
//! | #39  | [`crate::manifest::KNOWN_TOOL_IDS`]         | cross-pinned to `Builtin` discriminants by compile-time const |
//!
//! ## Carve-outs (Session 2 ACCEPT/RAISE)
//!
//! 1. **`request_id_u64` is hard-coded to `0`.** §4.E line 713
//!    `dispatch_builtin(b, args, allow)` admits NO `request_id`
//!    parameter; the atom #2 [`mnemos_a_core::MnemosError::tool_denied`]
//!    constructor requires one. The `0` sentinel is documented here
//!    so a later wiring atom (the one that calls `dispatch_builtin`
//!    from the agent loop) can wrap the call with the actual
//!    `RuntimeTaskId`. Atom #40 itself never reads the request id, so
//!    folding it through `0` neither leaks information nor masks a
//!    real id — it is a placeholder by signature.
//! 2. **`Builtin` is closed (no `#[non_exhaustive]`).** Atom #2
//!    [`mnemos_a_core::ToolProgram`] precedent: a `#[repr(u8)]` enum
//!    whose discriminants are part of the wire contract is closed —
//!    `#[non_exhaustive]` would let downstream crates pattern-match
//!    incompletely on a contract they read from `KNOWN_TOOL_IDS`. The
//!    cross-pin in [`_BUILTIN_DISCRIMINANTS_MATCH_KNOWN_TOOL_IDS`]
//!    enforces this — adding a 4th variant would break the build
//!    until the atom #39 allow-set grows simultaneously, per
//!    [`crate::manifest::KNOWN_TOOL_IDS`] doc comment.
//! 3. **`PHASE0_COMMAND_ALLOWLIST` is a `pub const`, not a function.**
//!    The §4.E line 712 prose declares the contents
//!    (`cargo/git/sui/walrus`) directly; exporting the canonical
//!    [`CommandAllowlist`] as a const lets external crates (and tests
//!    in this crate) reference the canonical Phase 0 whitelist by
//!    name. The `&'static` requirement of [`CommandAllowlist::new`]
//!    is preserved — the const is itself `&'static`.
//! 4. **`CommandAllowlist::contains` is non-`const`.** It accepts a
//!    `&str` (the program name to test) and walks the slice. A
//!    `const fn` variant exists in private form ([`bytes_eq`] +
//!    [`slice_contains`]) so [`PHASE0_COMMAND_ALLOWLIST`] can be
//!    const-validated at compile time if a future atom needs it; the
//!    public surface is the runtime `fn` because the typical caller
//!    holds the program name as a `&str` produced at request time.

use mnemos_a_core::{MnemosError, ToolDenyReason, ToolProgram};

use crate::manifest::KNOWN_TOOL_IDS;

// ===========================================================================
// 1. Builtin — the closed 3-variant enum
// ===========================================================================

/// Phase 0 builtin discriminants. `#[repr(u8)]` — every variant is a
/// single byte with an explicit value pinned to the §4.E line 711
/// canonical declaration `{ReadFile=1, WriteFile=2, RunCommand=3}`.
/// Cross-pinned to atom #39 [`KNOWN_TOOL_IDS`] by
/// [`_BUILTIN_DISCRIMINANTS_MATCH_KNOWN_TOOL_IDS`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Builtin {
    /// Read a file from a path supplied as `args[0]`. The actual
    /// `std::fs::read` is NOT performed by [`dispatch_builtin`] — see
    /// the module-level "Why validator-only" comment.
    ReadFile = 1,
    /// Write the byte payload represented by `args[1..]` to the path
    /// in `args[0]`. The actual `std::fs::write` is NOT performed here.
    WriteFile = 2,
    /// Spawn `args[0]` (a program name) with the remaining `args[1..]`
    /// as positional arguments. The actual `std::process::Command::spawn`
    /// is NOT performed here.
    RunCommand = 3,
}

// `#[repr(u8)]` width pin — `Builtin` MUST stay 1 byte.
const _BUILTIN_SIZE_IS_1: [(); 0 - !(core::mem::size_of::<Builtin>() == 1) as usize] = [];

// Cross-pin: every `KNOWN_TOOL_IDS` entry must equal the `Builtin`
// discriminant at the same index. Adding a 4th `Builtin` variant
// without growing [`KNOWN_TOOL_IDS`] (or vice-versa) fails the build
// here first.
const _BUILTIN_DISCRIMINANTS_MATCH_KNOWN_TOOL_IDS: () = {
    assert!(KNOWN_TOOL_IDS.len() == 3);
    assert!(KNOWN_TOOL_IDS[0] == Builtin::ReadFile as u16);
    assert!(KNOWN_TOOL_IDS[1] == Builtin::WriteFile as u16);
    assert!(KNOWN_TOOL_IDS[2] == Builtin::RunCommand as u16);
};

// ===========================================================================
// 2. CommandAllowlist — `&'static` whitelist of run-command programs
// ===========================================================================

/// Whitelist of programs accepted by the [`Builtin::RunCommand`]
/// dispatch. Backed by a `&'static [&'static str]` — runtime
/// injection of new programs is impossible by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CommandAllowlist {
    programs: &'static [&'static str],
}

impl CommandAllowlist {
    /// Build a new allowlist from a `&'static` slice of program names.
    /// `const fn` — the canonical [`PHASE0_COMMAND_ALLOWLIST`] is built
    /// from this in const context.
    pub const fn new(programs: &'static [&'static str]) -> Self {
        Self { programs }
    }

    /// Return the backing slice. `const fn` so callers can iterate the
    /// whitelist in const context (e.g. compile-time assertions).
    pub const fn programs(&self) -> &'static [&'static str] {
        self.programs
    }

    /// Return `true` if `program` (byte-equal) is on the whitelist.
    pub fn contains(&self, program: &str) -> bool {
        slice_contains(self.programs, program.as_bytes())
    }
}

/// Canonical Phase 0 allowlist — `cargo`, `git`, `sui`, `walrus`
/// per §4.E line 712. Order matches [`mnemos_a_core::ToolProgram`]
/// variants `Cargo=1, Git=2, Sui=3, Walrus=4`.
pub const PHASE0_COMMAND_ALLOWLIST: CommandAllowlist =
    CommandAllowlist::new(&["cargo", "git", "sui", "walrus"]);

// ===========================================================================
// 3. BuiltinOutcome — length-only carrier
// ===========================================================================

/// Result of a successful [`dispatch_builtin`]. Contains ONLY the
/// exit code and the byte lengths of `stdout` / `stderr`. There is no
/// field that can carry the actual bytes — the "출력은 길이만 반환
/// (본문 미보관)" guarantee from §4.E line 714 holds by-construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuiltinOutcome {
    exit_code_i32: i32,
    stdout_len_u32: u32,
    stderr_len_u32: u32,
}

impl BuiltinOutcome {
    /// "Validation passed" outcome for Phase 0 dispatch. Real IO is
    /// the job of the later atom that wires §2.7 T0~T2 routing;
    /// until then a successful [`dispatch_builtin`] returns this
    /// zero-result, signalling "the call would have been admitted to
    /// the sandbox" — see the module-level "Why validator-only" doc.
    pub const fn accepted_zero() -> Self {
        Self {
            exit_code_i32: 0,
            stdout_len_u32: 0,
            stderr_len_u32: 0,
        }
    }

    /// `i32` exit code of the underlying process (0 in the
    /// validator-only path).
    pub const fn exit_code_i32(&self) -> i32 {
        self.exit_code_i32
    }

    /// `u32` length in bytes of the captured stdout (0 in the
    /// validator-only path; content is never retained).
    pub const fn stdout_len_u32(&self) -> u32 {
        self.stdout_len_u32
    }

    /// `u32` length in bytes of the captured stderr (0 in the
    /// validator-only path; content is never retained).
    pub const fn stderr_len_u32(&self) -> u32 {
        self.stderr_len_u32
    }
}

// Width pin — `BuiltinOutcome` MUST stay 12 bytes
// (i32 + u32 + u32 = 4 + 4 + 4 with no padding on 4-byte alignment).
const _BUILTIN_OUTCOME_SIZE_IS_12: [(); 0 - !(core::mem::size_of::<BuiltinOutcome>() == 12)
    as usize] = [];

// ===========================================================================
// 4. dispatch_builtin — validator-only policy boundary
// ===========================================================================

/// Validate a [`Builtin`] call against the supplied [`CommandAllowlist`]
/// and the per-variant arg-shape rules. Real IO is intentionally not
/// performed — see the module-level "Why validator-only" doc.
///
/// Rules:
///
/// - [`Builtin::ReadFile`] / [`Builtin::WriteFile`]: `args.len() >= 1`
///   and `args[0]` non-empty (path-shape). Otherwise
///   [`MnemosError::tool_denied`] with [`ToolProgram::Other`] +
///   [`ToolDenyReason::ArgumentShape`].
/// - [`Builtin::RunCommand`]: `args.len() >= 1` and `args[0]` non-empty
///   AND [`CommandAllowlist::contains(args[0])`]. Empty / missing args
///   → [`ToolDenyReason::ArgumentShape`]; non-allowlisted program →
///   [`ToolDenyReason::Program`] with the mapped [`ToolProgram`] for
///   telemetry (`cargo/git/sui/walrus` → typed variant, anything else
///   → [`ToolProgram::Other`]).
///
/// `request_id_u64` is hard-coded to `0` per carve-out #1 — the §4.E
/// signature does not admit a request id and the surrounding wiring
/// atom is the right place to thread one through.
pub fn dispatch_builtin(
    b: Builtin,
    args: &[&str],
    allow: &CommandAllowlist,
) -> Result<BuiltinOutcome, MnemosError> {
    let arg_count_u16 = clamp_to_u16(args.len());
    match b {
        Builtin::ReadFile | Builtin::WriteFile => {
            if first_arg_is_empty(args) {
                return Err(MnemosError::tool_denied(
                    ToolProgram::Other,
                    arg_count_u16,
                    ToolDenyReason::ArgumentShape,
                    0,
                ));
            }
            Ok(BuiltinOutcome::accepted_zero())
        }
        Builtin::RunCommand => {
            if first_arg_is_empty(args) {
                return Err(MnemosError::tool_denied(
                    ToolProgram::Other,
                    arg_count_u16,
                    ToolDenyReason::ArgumentShape,
                    0,
                ));
            }
            let program = args[0];
            if !allow.contains(program) {
                return Err(MnemosError::tool_denied(
                    program_label(program),
                    arg_count_u16,
                    ToolDenyReason::Program,
                    0,
                ));
            }
            Ok(BuiltinOutcome::accepted_zero())
        }
    }
}

// ===========================================================================
// 5. Internal helpers (no public surface)
// ===========================================================================

/// `args.is_empty() || args[0].is_empty()` collapsed into a single
/// shape check. Used by both ReadFile/WriteFile and RunCommand paths.
fn first_arg_is_empty(args: &[&str]) -> bool {
    match args.first() {
        None => true,
        Some(first) => first.is_empty(),
    }
}

/// Saturating cast `usize → u16` — `arg_count_u16` in the §4.A line
/// 288 `tool_denied` signature is 16-bit; `args.len()` is `usize`.
/// Saturate at `u16::MAX` rather than truncate so the telemetry stays
/// honest under absurd call shapes.
fn clamp_to_u16(n: usize) -> u16 {
    if n > u16::MAX as usize {
        u16::MAX
    } else {
        n as u16
    }
}

/// Map a program name to its [`ToolProgram`] discriminant. Reused
/// from atom #2's enum — the order here matches the order in
/// [`PHASE0_COMMAND_ALLOWLIST`].
fn program_label(name: &str) -> ToolProgram {
    let bytes = name.as_bytes();
    if bytes_eq(bytes, b"cargo") {
        ToolProgram::Cargo
    } else if bytes_eq(bytes, b"git") {
        ToolProgram::Git
    } else if bytes_eq(bytes, b"sui") {
        ToolProgram::Sui
    } else if bytes_eq(bytes, b"walrus") {
        ToolProgram::Walrus
    } else {
        ToolProgram::Other
    }
}

/// `const fn` byte-slice equality. Stable on Rust 2024 / 1.94 — used
/// by [`slice_contains`] so the canonical [`PHASE0_COMMAND_ALLOWLIST`]
/// can be const-validated if a future caller wants to.
const fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `const fn` linear search for [`bytes_eq`] over a `&[&str]`.
const fn slice_contains(haystack: &[&str], needle: &[u8]) -> bool {
    let mut i = 0;
    while i < haystack.len() {
        if bytes_eq(haystack[i].as_bytes(), needle) {
            return true;
        }
        i += 1;
    }
    false
}

// ===========================================================================
// 6. Tests — verbatim names from MNEMOS_ATOM_PLAN.md atom #40 (line 1230)
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use mnemos_a_core::ErrorCode;

    /// §4.E line 711 builtins ReadFile / WriteFile dispatch through
    /// the validator with a valid path-shape argument and return the
    /// accepted-zero outcome. "Within whitelist" = the [`Builtin`]
    /// enum itself is the closed set of allowed actions; the
    /// per-call shape check is the arg-shape gate.
    #[test]
    fn e0_2_read_write_within_whitelist() {
        let read = dispatch_builtin(
            Builtin::ReadFile,
            &["/tmp/mnemos-e02-read"],
            &PHASE0_COMMAND_ALLOWLIST,
        )
        .expect("ReadFile with non-empty path-shape arg must be accepted");
        assert_eq!(read, BuiltinOutcome::accepted_zero());

        let write = dispatch_builtin(
            Builtin::WriteFile,
            &["/tmp/mnemos-e02-write", "payload-placeholder"],
            &PHASE0_COMMAND_ALLOWLIST,
        )
        .expect("WriteFile with non-empty path-shape arg must be accepted");
        assert_eq!(write, BuiltinOutcome::accepted_zero());
    }

    /// §4.E line 712 RunCommand admits every program in
    /// [`PHASE0_COMMAND_ALLOWLIST`] (`cargo / git / sui / walrus`)
    /// and rejects everything else with [`ToolDenyReason::Program`].
    #[test]
    fn e0_2_run_command_allowlist_enforced() {
        for program in PHASE0_COMMAND_ALLOWLIST.programs() {
            let out = dispatch_builtin(
                Builtin::RunCommand,
                &[program, "--help"],
                &PHASE0_COMMAND_ALLOWLIST,
            )
            .expect("allowlisted program must be accepted");
            assert_eq!(out, BuiltinOutcome::accepted_zero());
        }

        let denied = dispatch_builtin(
            Builtin::RunCommand,
            &["docker", "run", "--rm", "alpine"],
            &PHASE0_COMMAND_ALLOWLIST,
        )
        .expect_err("non-allowlisted program must be denied");
        assert_eq!(denied.code(), ErrorCode::ToolDenied);
    }

    /// Every non-allowlisted / ill-shaped call goes through
    /// [`MnemosError::tool_denied`] and surfaces as
    /// [`ErrorCode::ToolDenied`] — the atom #2 reuse contract.
    #[test]
    fn e0_2_non_allowlisted_denied() {
        // RunCommand with a non-allowlisted program.
        let p1 = dispatch_builtin(
            Builtin::RunCommand,
            &["python3", "-c", "print(1)"],
            &PHASE0_COMMAND_ALLOWLIST,
        )
        .expect_err("python3 not in allowlist");
        assert_eq!(p1.code(), ErrorCode::ToolDenied);

        // RunCommand with empty args slice → arg-shape rejection.
        let p2 = dispatch_builtin(Builtin::RunCommand, &[], &PHASE0_COMMAND_ALLOWLIST)
            .expect_err("empty args slice must be denied");
        assert_eq!(p2.code(), ErrorCode::ToolDenied);

        // RunCommand with empty program name → arg-shape rejection.
        let p3 = dispatch_builtin(Builtin::RunCommand, &[""], &PHASE0_COMMAND_ALLOWLIST)
            .expect_err("empty program name must be denied");
        assert_eq!(p3.code(), ErrorCode::ToolDenied);

        // ReadFile / WriteFile with empty path → arg-shape rejection.
        let p4 = dispatch_builtin(Builtin::ReadFile, &[""], &PHASE0_COMMAND_ALLOWLIST)
            .expect_err("empty path must be denied");
        assert_eq!(p4.code(), ErrorCode::ToolDenied);

        let p5 = dispatch_builtin(Builtin::WriteFile, &[], &PHASE0_COMMAND_ALLOWLIST)
            .expect_err("missing path must be denied");
        assert_eq!(p5.code(), ErrorCode::ToolDenied);
    }

    /// By-construction proof that [`BuiltinOutcome`] cannot carry
    /// stdout / stderr content. The struct has exactly three fields
    /// (i32 + u32 + u32 = 12 bytes), all length / exit_code typed —
    /// any future addition of a `Vec<u8>` / `String` payload field
    /// would change the struct size and fail this assertion.
    #[test]
    fn e0_2_output_is_length_only() {
        // Width pin — also enforced at compile time by
        // `_BUILTIN_OUTCOME_SIZE_IS_12`, asserted here at runtime so
        // the test name surfaces the invariant in the test report.
        assert_eq!(core::mem::size_of::<BuiltinOutcome>(), 12);

        // The constructed zero outcome has no payload.
        let z = BuiltinOutcome::accepted_zero();
        assert_eq!(z.exit_code_i32(), 0);
        assert_eq!(z.stdout_len_u32(), 0);
        assert_eq!(z.stderr_len_u32(), 0);

        // Builtin enum width pin — surfaced as a runtime assertion
        // for the same reason as above.
        assert_eq!(core::mem::size_of::<Builtin>(), 1);
    }

    /// Cross-pin between [`Builtin`] discriminants and atom #39
    /// [`KNOWN_TOOL_IDS`]. Not in the atom #40 named test list, but
    /// kept as an internal guard so a Session 2 verifier sees the
    /// invariant explicitly rather than relying solely on the
    /// compile-time [`_BUILTIN_DISCRIMINANTS_MATCH_KNOWN_TOOL_IDS`].
    #[test]
    fn e0_2_internal_builtin_cross_pin_with_known_tool_ids() {
        assert_eq!(KNOWN_TOOL_IDS, &[1u16, 2u16, 3u16]);
        assert_eq!(Builtin::ReadFile as u16, KNOWN_TOOL_IDS[0]);
        assert_eq!(Builtin::WriteFile as u16, KNOWN_TOOL_IDS[1]);
        assert_eq!(Builtin::RunCommand as u16, KNOWN_TOOL_IDS[2]);
    }

    /// The canonical [`PHASE0_COMMAND_ALLOWLIST`] matches the §4.E
    /// line 712 declaration verbatim and in the
    /// [`mnemos_a_core::ToolProgram`] variant order. Internal guard.
    #[test]
    fn e0_2_internal_phase0_allowlist_matches_canonical_spec() {
        assert_eq!(
            PHASE0_COMMAND_ALLOWLIST.programs(),
            &["cargo", "git", "sui", "walrus"]
        );
        assert!(PHASE0_COMMAND_ALLOWLIST.contains("cargo"));
        assert!(PHASE0_COMMAND_ALLOWLIST.contains("git"));
        assert!(PHASE0_COMMAND_ALLOWLIST.contains("sui"));
        assert!(PHASE0_COMMAND_ALLOWLIST.contains("walrus"));
        assert!(!PHASE0_COMMAND_ALLOWLIST.contains(""));
        assert!(!PHASE0_COMMAND_ALLOWLIST.contains("cargo "));
        assert!(!PHASE0_COMMAND_ALLOWLIST.contains("CARGO"));
    }
}
