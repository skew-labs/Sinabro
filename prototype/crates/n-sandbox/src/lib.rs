//! `mnemos-n-sandbox` — 5-tier capability sandbox (T0..T2 in Phase 0).
//!
//! Phase 0 workspace skeleton (atom #1 · A.0.1). Intentional empty stub: the
//! canonical types for this crate are specified in `MNEMOS_ATOM_PLAN.md` §4 and
//! are filled in by later atoms on the critical path. Keeping it as a buildable
//! stub holds `cargo build --workspace` green from the first atom — the
//! "canonical state of emptiness" (ATOM_PLAN atom #0 OUT).
//!
//! ## ENDGAME E6 — where the REAL OS-enforced sandbox lives (disk-truth note)
//!
//! Owner-ratified 2026-06-12 (AskUserQuestion): the real OS-enforced skill
//! sandbox is **B+Seatbelt** — a kernel-confined bounded child process — and it
//! is co-located with the proven `exec_local` spawn discipline in
//! `crates/mnemos-cli` (`sinabro`): see `sinabro::sandbox_exec`
//! (`seatbelt_profile_for` + `run_in_sandbox`, tier → macOS `sandbox-exec`
//! Seatbelt profile, network kernel-DENIED for non-Networked tiers) and the
//! threat model `ops/evidence/stage_g/agent_loop/SKILL_SANDBOX_THREAT_MODEL.md`
//! (⑫ IV-S). The SECURITY finding "the sandbox tier enforces nothing at the OS
//! level" is CLOSED there (kernel-enforced ceiling + a real `skill eval`
//! executor, gated tests). This crate stays an intentional stub: a later
//! in-process **WASM VM** (the deferred wasm go-live gate — there is currently
//! NO executable skill payload in the data model, so no module to run) would
//! land here under its own explicit approval + security review; until then it
//! holds NO live action by design, and the executable surface is honestly the
//! kernel-confined `skill eval` path, not this crate.
#![deny(missing_docs)]
