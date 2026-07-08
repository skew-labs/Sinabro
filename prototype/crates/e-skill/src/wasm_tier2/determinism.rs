//! Deterministic time / random policy.
//!
//! The sandbox provides a **replayable logical clock** and a **seed derived
//! solely from the run id**; the ambient system clock and OS RNG are never read
//! (this module imports no `std::time` / `getrandom`). Two runs with identical
//! declared inputs therefore produce an identical [`DeterministicContext::replay_digest`]
//! regardless of real wall-clock drift — the basis for replay-portability.

#![deny(missing_docs)]

use crate::package::blake2b_256;

/// Domain tag for the run seed.
pub(crate) const DOMAIN_SEED: &[u8] = b"mnemos.d.wasm_seed.v1";
/// Domain tag for the replay digest.
pub(crate) const DOMAIN_REPLAY: &[u8] = b"mnemos.d.wasm_replay.v1";

/// The only time / random source a sandboxed run may observe: a replayable
/// logical clock and a run-id-derived seed. Ambient system time and OS
/// randomness are inaccessible by construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DeterministicContext {
    /// The run identifier — the sole entropy source for [`Self::seed`].
    pub run_id_u64: u64,
    /// The replayable logical clock value (milliseconds), fixed at run start.
    pub logical_time_ms_u64: u64,
}

impl DeterministicContext {
    /// Construct a deterministic context from a run id and a logical clock.
    #[inline]
    #[must_use]
    pub const fn new(run_id_u64: u64, logical_time_ms_u64: u64) -> Self {
        Self {
            run_id_u64,
            logical_time_ms_u64,
        }
    }

    /// Deterministic 32-byte seed derived **solely from the run id** — never
    /// from an ambient RNG. The same run id always yields the same seed; the
    /// logical clock does not affect it, so a seed "changes only when declared"
    /// (i.e. only when the run id changes).
    #[must_use]
    pub fn seed(&self) -> [u8; 32] {
        blake2b_256(&[DOMAIN_SEED, &self.run_id_u64.to_le_bytes()])
    }

    /// The replayable logical time. The ambient system clock is never consulted,
    /// so this value — not wall-clock drift — drives any time-dependent output.
    #[inline]
    #[must_use]
    pub const fn logical_time_ms(&self) -> u64 {
        self.logical_time_ms_u64
    }

    /// Stable replay digest over `(run_id, logical_time, declared_input_hash)`.
    /// Two runs with identical inputs produce an identical digest regardless of
    /// real wall-clock drift, because no ambient time is consulted.
    #[must_use]
    pub fn replay_digest(&self, declared_input_hash_32: &[u8; 32]) -> [u8; 32] {
        blake2b_256(&[
            DOMAIN_REPLAY,
            &self.run_id_u64.to_le_bytes(),
            &self.logical_time_ms_u64.to_le_bytes(),
            declared_input_hash_32,
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_run_same_output() {
        let a = DeterministicContext::new(0xD263_0001, 1_000);
        let b = DeterministicContext::new(0xD263_0001, 1_000);
        let input = [3u8; 32];
        assert_eq!(a.seed(), b.seed());
        assert_eq!(a.replay_digest(&input), b.replay_digest(&input));
    }

    #[test]
    fn seed_changes_only_when_run_id_changes() {
        let base = DeterministicContext::new(7, 1_000);
        // Different logical time, same run id ⇒ same seed.
        let later = DeterministicContext::new(7, 9_999);
        assert_eq!(base.seed(), later.seed());
        // Different run id ⇒ different seed.
        let other = DeterministicContext::new(8, 1_000);
        assert_ne!(base.seed(), other.seed());
    }

    #[test]
    fn system_clock_drift_ignored() {
        // Two contexts built with identical declared parameters are byte-for-byte
        // identical no matter how much real time elapsed between them: no ambient
        // clock is read.
        let input = [9u8; 32];
        let first = DeterministicContext::new(42, 500).replay_digest(&input);
        let second = DeterministicContext::new(42, 500).replay_digest(&input);
        assert_eq!(first, second);
        // But the declared logical time DOES move the digest (it is the clock).
        let drifted = DeterministicContext::new(42, 501).replay_digest(&input);
        assert_ne!(first, drifted);
    }
}
