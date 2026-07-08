//! `telegram.rs` — Telegram gateway authorization spine.
//!
//! # Design rationale
//!
//! Phase 0 ships zero live Telegram transport. This module defines only the
//! gateway's *authorization* surface: a compile-time-locked allowlist over
//! [`TelegramUserId`]. The allowlist is a `&'static` slice — there is no
//! runtime mutation API, so a future code path cannot side-load an extra
//! operator id (allowlist bypass and plaintext secret transmission are
//! both blocked by construction).
//!
//! The gateway carries no token field. The Bot API token is owned by a
//! separate secret-gated boundary (a later wiring integration); this struct
//! decides yes/no on the user identity only. Authorization failure returns
//! the unit variant [`GatewayError::NotAllowlisted`], which carries no user
//! id — neither the derived `Debug` nor a future `Display` impl can describe
//! *who* was rejected (authorization failure is a silent denial with zero
//! information disclosure).
//!
//! Reuse: `mnemos-a-core` boot wiring — this module imports no
//! a-core types but compiles inside the same workspace boot graph and stays
//! `--offline`-clean (zero new dependency on the j-ux Cargo.toml).
//!
//! Canonical signature:
//!
//! ```text
//! pub struct TelegramUserId(i64);
//! pub struct Allowlist { ids: &'static [TelegramUserId] }
//! pub enum GatewayError { NotAllowlisted, SendFailed, EditFailed }
//! pub struct TelegramGateway { allow: Allowlist }
//! impl TelegramGateway {
//!     pub fn authorize(&self, user: TelegramUserId) -> Result<(), GatewayError>;
//! }
//! ```

// ===========================================================================
// 1. TelegramUserId — newtype over i64 (Telegram Bot API user id)
// ===========================================================================

/// Telegram user identifier. `#[repr(transparent)]` over `i64` — Telegram's
/// Bot API encodes user ids as signed 64-bit integers.
///
/// The inner `i64` field is `pub`, following the same pattern as
/// `ToolId(pub u16)` / `SkillId(pub u16)`: there is no invariant beyond
/// the inner value, so the public inner field is correct.
/// The unit-confusion barrier (a stray `u16` skill id cannot be passed
/// where a `TelegramUserId` is required) lives at the type level, not at
/// the field-visibility level.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct TelegramUserId(pub i64);

// ===========================================================================
// 2. Allowlist — compile-time `&'static` slice of authorized operators
// ===========================================================================

/// Compile-time allowlist over [`TelegramUserId`]. The internal `ids`
/// slice is `&'static` — the only way to extend the allowlist is to
/// recompile the binary. No `&mut self` method exists on this type, and
/// the `ids` field is private, so a future caller cannot side-load an
/// extra operator id at runtime (runtime addition is impossible,
/// closing off that bypass).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allowlist {
    /// Allowlisted Telegram user ids. The `'static` lifetime is the
    /// key invariant: runtime additions are syntactically impossible.
    ids: &'static [TelegramUserId],
}

impl Allowlist {
    /// Construct an [`Allowlist`] from a compile-time slice of allowed
    /// ids. The `const fn` together with the `&'static` parameter
    /// ensures the caller's slice lives at least as long as the binary;
    /// runtime-allocated slices cannot be passed here.
    #[inline]
    pub const fn from_static(ids: &'static [TelegramUserId]) -> Self {
        Self { ids }
    }

    /// Returns the number of allowlisted ids. This is intentionally the
    /// only observable size property of the slice — the exact identity
    /// list is not re-exported through any read accessor, so a log call
    /// site cannot inadvertently dump the operator set.
    #[inline]
    pub const fn len(&self) -> usize {
        self.ids.len()
    }

    /// `true` iff the allowlist is empty (i.e. no user is authorized).
    /// An empty allowlist is a legal but useless posture: every
    /// `authorize` call returns [`GatewayError::NotAllowlisted`].
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Linear membership scan over the static slice. `n` is the
    /// operator-set cardinality (small by construction — Phase 0
    /// expects a single-digit operator allowlist), so a linear scan
    /// avoids any sort invariant we would otherwise need to const-verify
    /// at the [`from_static`](Self::from_static) boundary.
    #[inline]
    fn contains(&self, candidate: TelegramUserId) -> bool {
        let mut i = 0;
        while i < self.ids.len() {
            // Compare by inner `i64` — `TelegramUserId` is
            // `#[repr(transparent)]` so this is byte-identical to
            // the derived `PartialEq`, expressed in a const-fn-
            // friendly shape for future const-context callers.
            if self.ids[i].0 == candidate.0 {
                return true;
            }
            i += 1;
        }
        false
    }
}

// ===========================================================================
// 3. GatewayError — payload-less authorization / transport failure
// ===========================================================================

/// Gateway authorization or transport failure.
///
/// Every variant is unit-only — no rejected identity, no provider body,
/// no transport reason is carried in the value. This is a
/// silent-denial, zero-information-disclosure design: neither the
/// derived `Debug` nor any future `Display` impl on this enum can
/// describe *who* was rejected or *why* the transport failed. The
/// variant labels themselves are intentionally coarse class tags,
/// following the `MnemosError` `RedactionClass` lineage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum GatewayError {
    /// Authorization failed: the candidate user id did not appear in
    /// the gateway's allowlist. No identity is carried in the value.
    NotAllowlisted,
    /// A `sendMessage`-class transport call failed. The transport-
    /// level reason is intentionally elided so a bot-token-bearing
    /// transport cannot leak a server response through this error
    /// channel. Realised by a later wiring integration.
    SendFailed,
    /// An `editMessageText`-class transport call failed. Same
    /// payload-less rationale as [`GatewayError::SendFailed`].
    EditFailed,
}

// ===========================================================================
// 4. TelegramGateway — allowlist carrier + `authorize` decision
// ===========================================================================

/// Telegram gateway. Carries only an [`Allowlist`]; the Bot API token is
/// owned by a separate secret-gated boundary (a later wiring integration)
/// and never enters this struct. The gateway therefore has no plaintext
/// secret surface — `Debug` on a `TelegramGateway` reveals only the
/// allowlist's identity-set (which is operator metadata, not a secret).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelegramGateway {
    /// Compile-time allowlist of authorized Telegram user ids.
    allow: Allowlist,
}

impl TelegramGateway {
    /// Construct a gateway from a compile-time [`Allowlist`].
    #[inline]
    pub const fn new(allow: Allowlist) -> Self {
        Self { allow }
    }

    /// Borrow the gateway's allowlist (read-only). No mutation accessor
    /// is provided — the `'static` lifetime on the inner slice is the
    /// final word.
    #[inline]
    pub const fn allowlist(&self) -> &Allowlist {
        &self.allow
    }

    /// Authorize `user`.
    ///
    /// Returns [`Ok`] iff `user` appears in the gateway's allowlist;
    /// otherwise returns the payload-less
    /// [`GatewayError::NotAllowlisted`]. The rejected `user` id is
    /// *not* echoed in the returned value, so a downstream caller
    /// cannot accidentally serialise it through this error channel
    /// into a log record or a transport reply.
    #[inline]
    pub fn authorize(&self, user: TelegramUserId) -> Result<(), GatewayError> {
        if self.allow.contains(user) {
            Ok(())
        } else {
            Err(GatewayError::NotAllowlisted)
        }
    }
}

// ===========================================================================
// 5. Tests
// ===========================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Compile-time static allowlist (two distinct operator ids). The
    // `&[TelegramUserId]` literal has `'static` lifetime because it is
    // declared at module scope, so it satisfies the lifetime bound on
    // `Allowlist::from_static`.
    const TEST_OPERATORS: &[TelegramUserId] = &[TelegramUserId(1001), TelegramUserId(2002)];

    /// Happy path: an id in the allowlist authorizes.
    #[test]
    fn j0_1_allowlisted_user_authorized() {
        let gw = TelegramGateway::new(Allowlist::from_static(TEST_OPERATORS));
        assert_eq!(gw.authorize(TelegramUserId(1001)), Ok(()));
        assert_eq!(gw.authorize(TelegramUserId(2002)), Ok(()));
        // The gateway is Copy — authorizing does not consume the
        // gateway and does not mutate the allowlist.
        let gw2 = gw;
        assert_eq!(gw2.authorize(TelegramUserId(1001)), Ok(()));
    }

    /// Negative path: an id outside the allowlist is rejected silently
    /// — the `Err` value carries no identity, and `Debug` of the
    /// rejection does not mention the candidate id.
    #[test]
    fn j0_1_unknown_user_rejected() {
        let gw = TelegramGateway::new(Allowlist::from_static(TEST_OPERATORS));

        // Unknown positive id rejected.
        assert_eq!(
            gw.authorize(TelegramUserId(9999)),
            Err(GatewayError::NotAllowlisted)
        );
        // Negative id (e.g. a Telegram channel-style negative
        // `chat_id` accidentally passed as a user id) also rejected.
        assert_eq!(
            gw.authorize(TelegramUserId(-1)),
            Err(GatewayError::NotAllowlisted)
        );
        // Zero (a non-allocated Telegram id) also rejected.
        assert_eq!(
            gw.authorize(TelegramUserId(0)),
            Err(GatewayError::NotAllowlisted)
        );

        // Empty allowlist: even a previously-allowlisted id is
        // rejected. Demonstrates fail-closed default posture.
        let empty: &[TelegramUserId] = &[];
        let closed = TelegramGateway::new(Allowlist::from_static(empty));
        assert_eq!(
            closed.authorize(TelegramUserId(1001)),
            Err(GatewayError::NotAllowlisted)
        );

        // Payload-less rejection — the Debug rendering of the error
        // variant must not contain any candidate id (no `9999`,
        // `-1`, or `0` substring). This enforces zero information disclosure.
        let s = format!("{:?}", GatewayError::NotAllowlisted);
        assert!(!s.contains("9999"));
        assert!(!s.contains("-1"));
        assert!(
            !s.contains("0"),
            "GatewayError Debug must not embed numeric ids"
        );
        // The error class label itself is fine — it is operator-
        // visible class metadata, not a leaked identity.
        assert_eq!(s, "NotAllowlisted");
    }

    /// Compile-time proof: the allowlist is `&'static`. The proof has
    /// three parts:
    ///
    /// 1. `Allowlist::from_static` is a `const fn` that accepts a
    ///    `&'static [TelegramUserId]`. If the inner slice were not
    ///    `'static`, the `const ALLOW: Allowlist = …` construction
    ///    below would fail to compile.
    /// 2. The `Allowlist::ids` field is private (no `pub ids:` declared
    ///    above), so no external caller can construct an `Allowlist`
    ///    with a non-`'static` slice via struct-literal syntax.
    /// 3. The public surface of `Allowlist` contains no `&mut self`
    ///    method — neither `add`, nor `extend`, nor `replace` — so
    ///    runtime mutation is impossible.
    #[test]
    fn j0_1_allowlist_is_static() {
        // Part 1: const construction succeeds only if `TEST_OPERATORS`
        // really has the `'static` lifetime that `from_static`
        // demands. If a future refactor passes a non-`'static` slice
        // here, the build fails (the gate, not the runtime, catches
        // it).
        const ALLOW: Allowlist = Allowlist::from_static(TEST_OPERATORS);
        const GW: TelegramGateway = TelegramGateway::new(ALLOW);
        assert_eq!(GW.allowlist().len(), 2);
        assert!(!GW.allowlist().is_empty());

        // Part 2: rebinding the static slice through a `'static`
        // type ascription confirms the lifetime statically. If
        // `TEST_OPERATORS` ever loses its `'static` lifetime (e.g.
        // becomes a non-const local), this line stops compiling.
        let _static_view: &'static [TelegramUserId] = TEST_OPERATORS;

        // Part 3: const-context authorize works because every call
        // along the chain is `const`-compatible up to `authorize`
        // itself (which performs a runtime decision but takes only
        // `&self`, so it never mutates the allowlist).
        let allow_runtime = Allowlist::from_static(TEST_OPERATORS);
        assert_eq!(allow_runtime.len(), GW.allowlist().len());

        // The Allowlist value itself is `Copy` — passing it by value
        // never moves or mutates the underlying static slice.
        let copied: Allowlist = ALLOW;
        assert_eq!(copied.len(), 2);

        // Size invariant: the public types are bounded. On a 64-bit
        // target, `Allowlist` carries one `(ptr, len)` fat pointer
        // (16 bytes); `TelegramGateway` wraps it 1:1 (`#[repr(Rust)]`
        // single field). The exact byte count is asserted only as
        // upper bounds to stay portable; failure here would mean a
        // field accidentally grew (e.g. a token field was added),
        // which would also break the secret-gated invariant.
        assert!(core::mem::size_of::<TelegramUserId>() == 8);
        assert!(core::mem::size_of::<Allowlist>() <= 16);
        assert!(core::mem::size_of::<TelegramGateway>() <= 16);
    }
}
