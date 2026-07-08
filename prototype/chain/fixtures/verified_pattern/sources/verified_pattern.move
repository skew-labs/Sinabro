module verified_pattern::pattern {
    /// Minimal oracle-verified pattern artifact — sinabro W2-D / 0G Buildathon.
    ///
    /// Passing `sui move build` IS sinabro's `code_oracle`: a deterministic,
    /// generator-independent compiler oracle, run in the E6 network-DENIED sandbox
    /// (`crates/mnemos-cli/src/code_oracle.rs::sui_build_oracle`). That un-fakeable
    /// PASS is exactly what makes this source an "oracle-verified pattern" in the
    /// sense of the master plan's certifying-generation theory (master_plan §6: the
    /// compiler is the one free deterministic oracle).
    ///
    /// Its sha256 is anchored on 0G Galileo testnet (chain 16602) as the first
    /// verified-pattern PROVENANCE (W2-D). The chain proves the owner anchored this
    /// exact compiler-verified artifact at an L1 slot — NOT that any downstream
    /// inference is per-user-correct. That aggregate/provenance scope is the honest
    /// boundary; per-user correctness is the later self-evolution work (W5/W7).
    public fun pattern_kind(): u8 {
        0u8
    }
}
