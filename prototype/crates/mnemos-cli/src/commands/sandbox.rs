//! Sandbox inspect / warmup / deny (atom #437 F.4.2).
//!
//! `sinabro sandbox inspect|warmup`. A 5-tier sandbox bounds what a tool / skill
//! may do. Warmup is **performance-only**: it moves the runtime from cold to
//! warm so the next call is fast, but it never widens the capability ceiling
//! (`G-F-CAPABILITY`). The deny matrix — the capabilities a tier forbids — is
//! always inspectable.
//!
//! Reuse (no reinvention): mirrors Stage A's 5-tier sandbox and the Stage D WASM
//! runtime, expressed over the local [`CapabilityKind`] / [`CapabilitySet`]
//! ladder from [`crate::commands::capability`].

use crate::commands::capability::{CapabilityKind, CapabilitySet};

/// A 5-tier sandbox. A higher tier permits a strictly larger capability ceiling.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SandboxTier {
    /// Tier 1 — strict: pure computation only.
    Strict = 1,
    /// Tier 2 — read-only local filesystem.
    ReadOnly = 2,
    /// Tier 3 — local read + write.
    LocalWrite = 3,
    /// Tier 4 — local + network egress.
    Networked = 4,
    /// Tier 5 — privileged (process spawn / system).
    Privileged = 5,
}

impl SandboxTier {
    /// The tier ordinal (1..=5).
    #[must_use]
    pub const fn ordinal(self) -> u8 {
        self as u8
    }

    /// The capability ceiling a tier permits — the cumulative ladder up to and
    /// including the tier's own level.
    #[must_use]
    pub const fn capability_ceiling(self) -> CapabilitySet {
        let base = CapabilitySet::with(CapabilityKind::PureCompute);
        match self {
            Self::Strict => base,
            Self::ReadOnly => base.insert(CapabilityKind::ReadLocal),
            Self::LocalWrite => base
                .insert(CapabilityKind::ReadLocal)
                .insert(CapabilityKind::WriteLocal),
            Self::Networked => base
                .insert(CapabilityKind::ReadLocal)
                .insert(CapabilityKind::WriteLocal)
                .insert(CapabilityKind::Network),
            Self::Privileged => CapabilitySet::all(),
        }
    }

    /// The deny matrix — every capability the tier forbids.
    #[must_use]
    pub const fn deny_matrix(self) -> CapabilitySet {
        CapabilitySet::all().difference(self.capability_ceiling())
    }
}

/// The warmup phase of a sandbox runtime. Performance state only — it carries no
/// capability meaning.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxWarmupState {
    /// Not yet warmed; the next call pays the cold-start cost.
    Cold = 1,
    /// Warmup in progress.
    Warming = 2,
    /// Warm; the next call is fast.
    Warm = 3,
}

/// The `sandbox inspect` projection — tier, warmup state, the allowed capability
/// ceiling, and the deny matrix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SandboxInspectView {
    /// The sandbox tier.
    pub tier: SandboxTier,
    /// The warmup phase.
    pub warmup_state: SandboxWarmupState,
    /// The capability ceiling this tier allows.
    pub allowed: CapabilitySet,
    /// The capabilities this tier denies (the deny matrix).
    pub denied: CapabilitySet,
}

/// A sandbox: a fixed tier plus a mutable warmup phase. The tier (and therefore
/// the capability ceiling) is immutable once created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sandbox {
    tier: SandboxTier,
    warmup: SandboxWarmupState,
}

impl Sandbox {
    /// A new cold sandbox at `tier`.
    #[must_use]
    pub const fn new(tier: SandboxTier) -> Self {
        Self {
            tier,
            warmup: SandboxWarmupState::Cold,
        }
    }

    /// The sandbox tier.
    #[must_use]
    pub const fn tier(self) -> SandboxTier {
        self.tier
    }

    /// The current warmup phase.
    #[must_use]
    pub const fn warmup_state(self) -> SandboxWarmupState {
        self.warmup
    }

    /// The capability ceiling this sandbox allows — a function of the tier only.
    #[must_use]
    pub const fn allowed_capabilities(self) -> CapabilitySet {
        self.tier.capability_ceiling()
    }

    /// Warm the sandbox up (`Cold`/`Warming` → `Warm`). Performance-only: it
    /// never changes the tier or the capability ceiling. Returns the inspect
    /// view after warming.
    pub const fn warmup(&mut self) -> SandboxInspectView {
        self.warmup = SandboxWarmupState::Warm;
        self.inspect()
    }

    /// The `sandbox inspect` projection.
    #[must_use]
    pub const fn inspect(self) -> SandboxInspectView {
        SandboxInspectView {
            tier: self.tier,
            warmup_state: self.warmup,
            allowed: self.tier.capability_ceiling(),
            denied: self.tier.deny_matrix(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    #[test]
    fn inspect_reports_tier_allowed_and_denied() {
        let s = Sandbox::new(SandboxTier::ReadOnly);
        let v = s.inspect();
        assert_eq!(v.tier, SandboxTier::ReadOnly);
        assert_eq!(v.warmup_state, SandboxWarmupState::Cold);
        assert!(v.allowed.contains(CapabilityKind::ReadLocal));
        assert!(v.allowed.contains(CapabilityKind::PureCompute));
        assert!(v.denied.contains(CapabilityKind::WriteLocal));
        assert!(v.denied.contains(CapabilityKind::Network));
        assert!(v.denied.contains(CapabilityKind::Privileged));
    }

    #[test]
    fn warmup_moves_cold_to_warm() {
        let mut s = Sandbox::new(SandboxTier::LocalWrite);
        assert_eq!(s.warmup_state(), SandboxWarmupState::Cold);
        let v = s.warmup();
        assert_eq!(v.warmup_state, SandboxWarmupState::Warm);
        assert_eq!(s.warmup_state(), SandboxWarmupState::Warm);
    }

    #[test]
    fn deny_matrix_is_complement_of_ceiling() {
        // Strict tier allows only PureCompute; everything else is denied.
        let strict = SandboxTier::Strict;
        assert!(
            strict
                .capability_ceiling()
                .contains(CapabilityKind::PureCompute)
        );
        for denied in [
            CapabilityKind::ReadLocal,
            CapabilityKind::WriteLocal,
            CapabilityKind::Network,
            CapabilityKind::Privileged,
        ] {
            assert!(
                strict.deny_matrix().contains(denied),
                "{denied:?} must be denied at Strict"
            );
            assert!(!strict.capability_ceiling().contains(denied));
        }
        // Privileged tier denies nothing.
        assert!(SandboxTier::Privileged.deny_matrix().is_empty());
    }

    #[test]
    fn warmup_never_widens_permissions() {
        for tier in [
            SandboxTier::Strict,
            SandboxTier::ReadOnly,
            SandboxTier::LocalWrite,
            SandboxTier::Networked,
            SandboxTier::Privileged,
        ] {
            let mut s = Sandbox::new(tier);
            let before = s.allowed_capabilities();
            let denied_before = s.inspect().denied;
            s.warmup();
            let after = s.allowed_capabilities();
            assert_eq!(before, after, "{tier:?} warmup must not widen the ceiling");
            assert_eq!(
                denied_before,
                s.inspect().denied,
                "{tier:?} deny matrix must be unchanged"
            );
        }
    }

    #[test]
    fn warmup_status_p95_within_100ms() {
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let mut s = Sandbox::new(SandboxTier::Networked);
            let t = std::time::Instant::now();
            let v = s.warmup();
            std::hint::black_box(&v);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(
            p95 <= 100,
            "sandbox warmup status p95 {p95}ms exceeds 100ms budget"
        );
    }
}
