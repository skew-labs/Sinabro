//! `mnemos-n-sandbox` — 5-tier capability sandbox (T0..T2 in Phase 0).
//!
//! Intentional empty stub: the canonical types for this crate are filled in by
//! later work on the critical path. Keeping it as a buildable stub holds
//! `cargo build --workspace` green from the start.
//!
//! ## Where the real OS-enforced sandbox lives
//!
//! The real OS-enforced skill sandbox is a kernel-confined bounded child
//! process, co-located with the proven `exec_local` spawn discipline in
//! `crates/mnemos-cli` (`sinabro`): see `sinabro::sandbox_exec`
//! (`seatbelt_profile_for` + `run_in_sandbox`, tier → macOS `sandbox-exec`
//! Seatbelt profile, network kernel-DENIED for non-Networked tiers). The
//! concern that "the sandbox tier enforces nothing at the OS level" is closed
//! there (kernel-enforced ceiling + a real `skill eval` executor, gated tests).
//! This crate stays an intentional stub: a later in-process **WASM VM** (the
//! deferred wasm go-live gate — there is currently NO executable skill payload
//! in the data model, so no module to run) would land here under its own
//! explicit approval + security review; until then it holds NO live action by
//! design, and the executable surface is the kernel-confined `skill eval` path,
//! not this crate.
#![deny(missing_docs)]
