//! `slash.rs` — Control command grammar.
//!
//! # Design rationale
//!
//! Phase 0 ships zero live control-rail wiring. This module defines only
//! the *grammar* surface: a fixed [`SlashCommand`] enum and a pure
//! [`parse_slash`] function. The four control commands `/budget`,
//! `/clear`, `/skill <id>`, `/kill` map to fixed enum variants — any
//! other input collapses to `None`, so an "arbitrary command execution"
//! path is syntactically unreachable through this surface.
//!
//! The grammar deliberately stops short of the side-effect wiring:
//!
//! - `/kill` is the emergency-stop trigger, which a later stage
//!   routes to [`mnemos_a_core::runtime::RuntimeSupervisor::request_shutdown`]
//!   (reuse concept only — this module imports zero a-core
//!   types and performs zero supervisor side effects).
//! - `/budget` is a cost-ledger query, which a later
//!   integration routes to [`mnemos_m_agent`] — again, concept-reuse only.
//! - `/skill <id>` carries the integer payload as a
//!   [`mnemos_e_skill::manifest::SkillId`], the only
//!   cross-crate import on this surface.
//!
//! A later stage promotes `/kill` and `/budget cap` from the normal /
//! background queue onto an express control rail; this
//! module carries no routing field. The decision shape is byte- and
//! state-pure (no I/O, no allocations on the success paths beyond the
//! payload integer parse, no `unsafe`).
//!
//! Reuse:
//! - `SkillId`: `#[repr(transparent)] pub struct SkillId(pub u16)`
//!   (`prototype/crates/e-skill/src/manifest.rs:182`) — re-used verbatim
//!   for the `/skill <id>` payload. Adding `mnemos-e-skill` as a
//!   path-dep is the only Cargo.toml delta this introduces.
//! - Cost telemetry and supervisor shutdown:
//!   concept-reuse only. No code path here calls into either crate;
//!   a later stage performs that wiring per the express control rail
//!   schedule above.
//!
//! Canonical signature:
//!
//! ```text
//! pub enum SlashCommand { Budget, Clear, Skill(SkillId), Kill }
//! pub fn parse_slash(input: &str) -> Option<SlashCommand>;
//! ```

use mnemos_e_skill::manifest::SkillId;

// ===========================================================================
// 1. SlashCommand — fixed 4-variant control-command enum
// ===========================================================================

/// A parsed control command. The four variants enumerate the entire
/// Phase 0 control surface — there is no `Other(String)` variant, so
/// the grammar cannot widen to "arbitrary command execution" via this
/// type. Variant order is
/// the order in which the commands appear in the canonical
/// signature (`/budget`, `/clear`, `/skill <id>`, `/kill`).
///
/// The enum is `Copy` because every payload it carries is itself
/// `Copy` — [`SkillId`] is `#[repr(transparent)]` over `u16`
/// (`prototype/crates/e-skill/src/manifest.rs:182`).
/// Snapshotting a parse result before dispatch therefore never moves
/// the value out of any surrounding borrow.
///
/// `#[non_exhaustive]` reserves the right for a later stage
/// to add additional control-class commands without breaking
/// downstream `match` exhaustiveness — but this module locks the four
/// canonical variants in place; no other variant exists today.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum SlashCommand {
    /// `/budget` — query the daily/period cost ledger. This
    /// module only emits the variant; the cost-ledger read
    /// is wired by a later integration.
    Budget,
    /// `/clear` — reset the current turn / progressive-edit state. The
    /// concrete reset action is wired by a later integration (the m-agent
    /// turn engine and the j-ux progressive editor are the eventual
    /// consumers).
    Clear,
    /// `/skill <id>` — switch the active skill manifest. The payload
    /// is a [`SkillId`]; the actual manifest re-bind is
    /// wired by a later integration.
    Skill(SkillId),
    /// `/kill` — emergency-stop trigger. A later stage routes this
    /// to the supervisor's `request_shutdown` on the express control
    /// rail. This module emits only the variant.
    Kill,
}

// ===========================================================================
// 2. parse_slash — pure grammar predicate (no I/O, no side effects)
// ===========================================================================

/// Parse a single control-command line into a [`SlashCommand`].
///
/// The function is byte-pure: no I/O, no allocations beyond the
/// payload integer parse for `/skill`, no `unsafe`. Returns `None`
/// for any input that does not match one of the four canonical
/// commands; the variant set cannot widen through this surface.
///
/// # Grammar
///
/// After trimming leading and trailing whitespace, the input MUST
/// start with a single ASCII `/` byte. The substring after `/` is
/// split at the first whitespace into a command word and a payload
/// remainder (the remainder may itself be empty). The command word
/// is matched case-sensitively against the canonical four:
///
/// | command  | payload                          | maps to                     |
/// |----------|----------------------------------|-----------------------------|
/// | `budget` | MUST be empty                    | [`SlashCommand::Budget`]    |
/// | `clear`  | MUST be empty                    | [`SlashCommand::Clear`]     |
/// | `kill`   | MUST be empty                    | [`SlashCommand::Kill`]      |
/// | `skill`  | non-empty `u16` decimal literal  | [`SlashCommand::Skill(..)`] |
///
/// The trailing-payload restriction on `/budget`, `/clear`, and
/// `/kill` prevents
/// a smuggled argument from riding on top of a recognised control
/// command. The `/skill` payload is restricted to a single decimal
/// `u16` literal (no leading sign, no whitespace, no extra tokens) —
/// values outside the `0..=u16::MAX` range collapse to `None`.
///
/// All non-matching inputs return `None`:
///
/// - leading text that is not `/` (e.g. `budget`, `hello /budget`)
/// - unknown commands (e.g. `/help`, `/Budget` — case-sensitive)
/// - trailing arguments on unary commands (e.g. `/clear now`)
/// - missing payload on `/skill`
/// - non-decimal or out-of-range payload on `/skill`
/// - multiple whitespace-separated tokens after `/skill`
pub fn parse_slash(input: &str) -> Option<SlashCommand> {
    // Trim the entire input first. Telegram and the local CLI both
    // tolerate trailing newlines and incidental whitespace; we drop
    // them here so a `"/kill\n"` reading parses identically to
    // `"/kill"`. `str::trim` strips Unicode whitespace from both
    // ends (well-defined for arbitrary &str input).
    let trimmed = input.trim();

    // The leading `/` is mandatory. `strip_prefix` returns `None`
    // (which we propagate via `?`) when the prefix does not match,
    // so any non-slash input — including a bare empty string —
    // collapses to `None` here without further work.
    let body = trimmed.strip_prefix('/')?;

    // Split into the command word and the (possibly-empty) payload at
    // the first whitespace byte. `splitn(2, ..)` always returns at
    // least one element (the empty string if `body` is empty), so
    // `cmd` is well-defined for any input that passed the strip
    // above. The payload is trimmed of its leading whitespace so
    // `"/skill   42"` and `"/skill 42"` parse identically.
    let mut parts = body.splitn(2, char::is_whitespace);
    let cmd = parts.next().unwrap_or("");
    let payload = parts.next().map(str::trim_start).unwrap_or("");

    match cmd {
        // Unary commands: any non-empty payload collapses to `None`,
        // preventing arbitrary command execution via a smuggled
        // argument.
        "budget" if payload.is_empty() => Some(SlashCommand::Budget),
        "clear" if payload.is_empty() => Some(SlashCommand::Clear),
        "kill" if payload.is_empty() => Some(SlashCommand::Kill),

        // `/skill <id>`: payload MUST be a single non-empty,
        // ASCII-digit-only u16 decimal literal. The byte-level
        // `is_ascii_digit` filter rejects:
        //
        // - empty payload (`bytes().all` over an empty slice is
        //   `true`, so the `!is_empty()` guard runs first),
        // - leading `+` / `-` sign (Rust's stdlib
        //   `<u16 as FromStr>::from_str` accepts `"+1"` as `1`,
        //   which would otherwise smuggle past a naive parse-only
        //   path),
        // - embedded whitespace (e.g. `"42 extra"`) — so a smuggled
        //   trailing argument cannot ride on the back of `/skill`,
        // - non-ASCII digit code points (Unicode-digit confusion
        //   barrier — only `b'0'..=b'9'` is accepted).
        //
        // After the filter, `parse::<u16>()` rejects out-of-range
        // values (e.g. `"65536"`).
        "skill" if !payload.is_empty() && payload.bytes().all(|b| b.is_ascii_digit()) => {
            let id_u16 = payload.parse::<u16>().ok()?;
            Some(SlashCommand::Skill(SkillId(id_u16)))
        }

        // Every other shape — unknown command, mistyped command, a
        // unary command with trailing payload, `/skill` with a
        // non-numeric or out-of-range payload, `/skill` with
        // embedded whitespace — collapses to `None`. The variant set
        // therefore cannot widen through this surface.
        _ => None,
    }
}

// ===========================================================================
// 3. Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// All four canonical control commands parse to the matching
    /// [`SlashCommand`] variant. Trailing whitespace and a leading
    /// whitespace prefix are tolerated by the `str::trim` front
    /// gate; case-sensitivity is enforced (no `/Budget`, no
    /// `/CLEAR`).
    #[test]
    fn j0_3_parses_budget_clear_skill_kill() {
        // Four canonical forms — pure command words.
        assert_eq!(parse_slash("/budget"), Some(SlashCommand::Budget));
        assert_eq!(parse_slash("/clear"), Some(SlashCommand::Clear));
        assert_eq!(parse_slash("/kill"), Some(SlashCommand::Kill));
        assert_eq!(
            parse_slash("/skill 1"),
            Some(SlashCommand::Skill(SkillId(1)))
        );

        // Surrounding whitespace is tolerated (Telegram and CLI both
        // routinely deliver trailing newlines and stray spaces).
        assert_eq!(parse_slash("  /budget"), Some(SlashCommand::Budget));
        assert_eq!(parse_slash("/clear  "), Some(SlashCommand::Clear));
        assert_eq!(parse_slash("\t/kill\n"), Some(SlashCommand::Kill));
        assert_eq!(
            parse_slash(" /skill 42 "),
            Some(SlashCommand::Skill(SkillId(42)))
        );

        // Multiple internal spaces between `/skill` and the payload
        // are tolerated (the splitn-then-trim_start shape).
        assert_eq!(
            parse_slash("/skill   7"),
            Some(SlashCommand::Skill(SkillId(7)))
        );

        // Case sensitivity: an upper-case command word is unknown.
        assert!(parse_slash("/Budget").is_none());
        assert!(parse_slash("/CLEAR").is_none());
        assert!(parse_slash("/Kill").is_none());
        assert!(parse_slash("/Skill 1").is_none());

        // Unary commands with trailing payload are rejected —
        // preventing arbitrary command execution via a smuggled argument.
        assert!(parse_slash("/budget cap").is_none());
        assert!(parse_slash("/clear now").is_none());
        assert!(parse_slash("/kill --force").is_none());

        // SlashCommand is Copy (zero-cost snapshot before dispatch).
        let cmd = parse_slash("/skill 100").unwrap();
        let copy = cmd;
        assert_eq!(cmd, copy);
        assert_eq!(copy, SlashCommand::Skill(SkillId(100)));
    }

    /// Any non-canonical input — including the empty string, a
    /// missing leading slash, an unknown command word, `/skill`
    /// without a payload, `/skill` with a non-decimal or
    /// out-of-range payload, and `/skill` with embedded whitespace
    /// after the id — collapses to `None`.
    #[test]
    fn j0_3_unknown_slash_is_none() {
        // Bare-empty inputs.
        assert!(parse_slash("").is_none());
        assert!(parse_slash("   ").is_none());
        assert!(parse_slash("\n").is_none());

        // Leading non-slash inputs.
        assert!(parse_slash("budget").is_none());
        assert!(parse_slash("hello").is_none());
        assert!(parse_slash("hello /budget").is_none());

        // Double-slash prefix → the first slash strips, leaving
        // `"/budget"` as the command word (which does not match
        // `"budget"`).
        assert!(parse_slash("//budget").is_none());

        // Unknown commands.
        assert!(parse_slash("/").is_none());
        assert!(parse_slash("/help").is_none());
        assert!(parse_slash("/status").is_none());
        assert!(parse_slash("/exec rm -rf /").is_none());

        // `/skill` without a payload.
        assert!(parse_slash("/skill").is_none());
        assert!(parse_slash("/skill ").is_none());
        assert!(parse_slash("/skill\t").is_none());

        // `/skill` with a non-decimal payload.
        assert!(parse_slash("/skill abc").is_none());
        assert!(parse_slash("/skill 0x10").is_none());
        assert!(parse_slash("/skill -1").is_none());
        assert!(parse_slash("/skill +1").is_none());

        // `/skill` with an out-of-range u16 payload.
        // 65_535 is u16::MAX — must parse. 65_536 is one past — must
        // collapse to `None` (value is out of u16 range).
        assert_eq!(
            parse_slash("/skill 65535"),
            Some(SlashCommand::Skill(SkillId(u16::MAX)))
        );
        assert!(parse_slash("/skill 65536").is_none());
        assert!(parse_slash("/skill 4294967295").is_none());

        // `/skill` with multiple tokens — a smuggled trailing
        // argument cannot ride on top of `/skill <id>`.
        assert!(parse_slash("/skill 1 2").is_none());
        assert!(parse_slash("/skill 42 extra").is_none());
    }

    /// `/skill <id>` parses the payload as a `u16` decimal literal
    /// and wraps it in [`SkillId`]. Round-trips boundary values
    /// (0, 1, u16::MAX) and the reuse-precision (the inner `u16`
    /// payload reaches the [`SkillId`] without loss).
    #[test]
    fn j0_3_skill_id_parsed() {
        // Boundary 0.
        assert_eq!(
            parse_slash("/skill 0"),
            Some(SlashCommand::Skill(SkillId(0)))
        );
        // A small id (matches the `/skill <id>` template comment).
        assert_eq!(
            parse_slash("/skill 1"),
            Some(SlashCommand::Skill(SkillId(1)))
        );
        // A mid-range id.
        assert_eq!(
            parse_slash("/skill 1234"),
            Some(SlashCommand::Skill(SkillId(1234)))
        );
        // Boundary u16::MAX (= 65_535) — parses.
        assert_eq!(
            parse_slash("/skill 65535"),
            Some(SlashCommand::Skill(SkillId(u16::MAX)))
        );

        // Round-trip pin: the parsed `SkillId(u16)` carries the same
        // numeric value the input declared. Destructure to read the
        // inner u16 — `SkillId` exposes the inner field as `pub u16`.
        if let Some(SlashCommand::Skill(SkillId(inner))) = parse_slash("/skill 9999") {
            assert_eq!(inner, 9999_u16);
        } else {
            panic!("/skill 9999 must parse to SlashCommand::Skill(SkillId(9999))");
        }

        // Surface-stability pin: SlashCommand size stays bounded. A
        // future accidental large payload (e.g. a `String` argument
        // smuggled in) would change the byte size and surface the
        // creep at the gate, not at runtime. SkillId is
        // #[repr(transparent)] over u16, so SlashCommand fits inside
        // a small fixed envelope.
        assert!(core::mem::size_of::<SlashCommand>() <= 8);
    }
}
