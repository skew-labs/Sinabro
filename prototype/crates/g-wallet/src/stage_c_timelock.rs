//! Stage C timelock policy (C-WP-05 · atom #213 · C.1.12).
//!
//! Canonical OUT (§4.2): [`TimelockPolicy`].
//!
//! # Madness invariants (atom #213)
//!
//! * **Mainnet publish/upgrade always has a delay and a cancel window.** A
//!   policy cannot be constructed with `min_delay_secs` below
//!   [`MIN_TIMELOCK_DELAY_SECS`]; a too-short delay is rejected fail-closed
//!   with [`TimelockError::DelayTooShort`], so there is no "execute now"
//!   bypass representable as a value of this type.
//! * **Emergency pause is explicit.** `emergency_pause_enabled` is a stored
//!   `bool`, never inferred. The policy records whether the incident-pause
//!   path is armed; it does not itself execute a pause (that is the
//!   incident-pause surface in a later package).
//! * **Data-free errors.** [`TimelockError`] carries no caller bytes.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: #212** — this policy is referenced by the multisig proposal /
//!   signer-envelope flow; it mints no new mainnet-state or address type.

use serde::Deserialize;

/// Serialized byte width of a [`TimelockPolicy`]: `4` (min delay) + `4`
/// (cancel window) + `1` (emergency-pause flag).
pub const TIMELOCK_POLICY_BYTES: usize = 4 + 4 + 1;

/// Minimum mainnet timelock delay, in seconds (`86_400` = 24h). A publish or
/// upgrade must wait at least this long before it can be executed, leaving a
/// real cancel window for incident response.
pub const MIN_TIMELOCK_DELAY_SECS: u32 = 86_400;

/// A mainnet timelock policy (§4.2 canonical OUT).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct TimelockPolicy {
    /// Minimum delay (seconds) between queueing and executing a mainnet
    /// publish/upgrade. `>= MIN_TIMELOCK_DELAY_SECS` by construction.
    pub min_delay_secs_u32: u32,
    /// Window (seconds) during which a queued action may be cancelled.
    pub cancel_window_secs_u32: u32,
    /// Whether the explicit emergency-pause path is armed for this policy.
    pub emergency_pause_enabled: bool,
}

/// Timelock policy construction / parse error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum TimelockError {
    /// `min_delay_secs` below [`MIN_TIMELOCK_DELAY_SECS`].
    DelayTooShort = 1,
    /// The cancel window is zero — there must be a real window to cancel in.
    CancelWindowZero = 2,
    /// The policy TOML failed to parse or carried unknown fields.
    TomlParse = 3,
}

impl core::fmt::Display for TimelockError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::DelayTooShort => "stage_c timelock: min delay below the 24h floor",
            Self::CancelWindowZero => "stage_c timelock: cancel window must be non-zero",
            Self::TomlParse => "stage_c timelock: policy toml parse failed",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for TimelockError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlTimelock {
    min_delay_secs: u32,
    cancel_window_secs: u32,
    emergency_pause_enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlTimelockTop {
    timelock: TomlTimelock,
}

impl TimelockPolicy {
    /// Build a timelock policy from its parts.
    ///
    /// # Errors
    ///
    /// - [`TimelockError::DelayTooShort`] when `min_delay_secs <
    ///   MIN_TIMELOCK_DELAY_SECS`.
    /// - [`TimelockError::CancelWindowZero`] when the cancel window is `0`.
    pub fn from_parts(
        min_delay_secs_u32: u32,
        cancel_window_secs_u32: u32,
        emergency_pause_enabled: bool,
    ) -> Result<Self, TimelockError> {
        if min_delay_secs_u32 < MIN_TIMELOCK_DELAY_SECS {
            return Err(TimelockError::DelayTooShort);
        }
        if cancel_window_secs_u32 == 0 {
            return Err(TimelockError::CancelWindowZero);
        }
        Ok(Self {
            min_delay_secs_u32,
            cancel_window_secs_u32,
            emergency_pause_enabled,
        })
    }

    /// Build a timelock policy from a `[timelock]` TOML document.
    ///
    /// # Errors
    ///
    /// [`TimelockError::TomlParse`] on malformed / unknown-field TOML, and any
    /// [`from_parts`](Self::from_parts) error on the parsed values.
    pub fn from_toml_str(toml_text: &str) -> Result<Self, TimelockError> {
        let parsed: TimelockTopParse = TimelockTopParse::parse(toml_text)?;
        Self::from_parts(
            parsed.min_delay_secs,
            parsed.cancel_window_secs,
            parsed.emergency_pause_enabled,
        )
    }

    /// Serialize to the fixed [`TIMELOCK_POLICY_BYTES`] byte form (little-endian
    /// counters, then the pause flag as `1`/`0`).
    pub fn to_bytes(&self) -> [u8; TIMELOCK_POLICY_BYTES] {
        let mut out = [0u8; TIMELOCK_POLICY_BYTES];
        out[0..4].copy_from_slice(&self.min_delay_secs_u32.to_le_bytes());
        out[4..8].copy_from_slice(&self.cancel_window_secs_u32.to_le_bytes());
        out[8] = u8::from(self.emergency_pause_enabled);
        out
    }
}

/// Intermediate parse projection so `from_toml_str` folds the TOML error before
/// the value validation runs.
struct TimelockTopParse {
    min_delay_secs: u32,
    cancel_window_secs: u32,
    emergency_pause_enabled: bool,
}

impl TimelockTopParse {
    fn parse(toml_text: &str) -> Result<Self, TimelockError> {
        let parsed: TomlTimelockTop =
            toml::from_str(toml_text).map_err(|_| TimelockError::TomlParse)?;
        Ok(Self {
            min_delay_secs: parsed.timelock.min_delay_secs,
            cancel_window_secs: parsed.timelock.cancel_window_secs,
            emergency_pause_enabled: parsed.timelock.emergency_pause_enabled,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    /// `c1_12_too_short_delay_reject` — a delay below the 24h floor (and `0`)
    /// is rejected fail-closed.
    #[test]
    fn c1_12_too_short_delay_reject() {
        assert_eq!(
            TimelockPolicy::from_parts(0, 3_600, true),
            Err(TimelockError::DelayTooShort),
        );
        assert_eq!(
            TimelockPolicy::from_parts(MIN_TIMELOCK_DELAY_SECS - 1, 3_600, true),
            Err(TimelockError::DelayTooShort),
        );
        // Exactly the floor is accepted.
        assert!(TimelockPolicy::from_parts(MIN_TIMELOCK_DELAY_SECS, 3_600, false).is_ok());
    }

    /// `c1_12_cancel_window_parse` — a `[timelock]` document parses, the cancel
    /// window round-trips, and a zero window is rejected.
    #[test]
    fn c1_12_cancel_window_parse() {
        let doc = "[timelock]\nmin_delay_secs = 172800\ncancel_window_secs = 86400\nemergency_pause_enabled = true\n";
        let policy = TimelockPolicy::from_toml_str(doc).expect("timelock toml parses");
        assert_eq!(policy.min_delay_secs_u32, 172_800);
        assert_eq!(policy.cancel_window_secs_u32, 86_400);
        assert_eq!(policy.to_bytes().len(), TIMELOCK_POLICY_BYTES);

        assert_eq!(
            TimelockPolicy::from_parts(MIN_TIMELOCK_DELAY_SECS, 0, true),
            Err(TimelockError::CancelWindowZero),
        );

        // Unknown field rejected.
        let bad = "[timelock]\nmin_delay_secs = 172800\ncancel_window_secs = 1\nemergency_pause_enabled = true\nextra = 1\n";
        assert_eq!(
            TimelockPolicy::from_toml_str(bad),
            Err(TimelockError::TomlParse),
        );
    }

    /// `c1_12_emergency_pause_flag` — the explicit pause flag is carried
    /// verbatim in both directions and is reflected in the byte form.
    #[test]
    fn c1_12_emergency_pause_flag() {
        let armed = TimelockPolicy::from_parts(MIN_TIMELOCK_DELAY_SECS, 3_600, true).unwrap();
        assert!(armed.emergency_pause_enabled);
        assert_eq!(armed.to_bytes()[8], 1);

        let disarmed = TimelockPolicy::from_parts(MIN_TIMELOCK_DELAY_SECS, 3_600, false).unwrap();
        assert!(!disarmed.emergency_pause_enabled);
        assert_eq!(disarmed.to_bytes()[8], 0);
    }
}
