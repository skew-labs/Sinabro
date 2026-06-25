//! `code_oracle` — the CODE-class verification oracle (P1-3-full(a); plan
//! `ops/evidence/stage_g/agent_loop/P1_ORCHESTRATOR_PLAN.md`).
//!
//! The [`crate::verification`] ladder is PURE (it cannot do IO). This module is its
//! one impure companion: the deterministic EXTERNAL check that a `Code` sub-task's
//! Move implementation actually COMPILES. It extracts the Move source from the local
//! brain's answer, materializes a minimal Sui package under a temp dir, and runs
//! `sui move build --path <pkg>` INSIDE the E6 kernel sandbox at the `LocalWrite`
//! tier — whose Seatbelt profile is `(allow default)(deny network*)`, so the build
//! writes its `build/` dir but the kernel BLOCKS every socket (build-only; NO chain
//! action, NO `sui client publish` — that is chain-write and is refused; custody /
//! funds stay HARD-LOCKED). The build's exit code is the oracle bit fed to
//! `verify(Code, CodeOracle(Some(exit==0)))`.
//!
//! token-min + drift-0 (META-LAW): the oracle is 100% LOCAL (0 external LLM tokens),
//! deterministic, and FAIL-CLOSED — no Move to compile / no `sui` toolchain / no
//! kernel sandbox ⇒ `CodeOracle(None)` (NotApplicable, an honest absence, NEVER a
//! false Verified); a build that ran and failed/timed-out ⇒ `CodeOracle(Some(false))`.
//! R5 reconcile (real probe 2026-06-14): `sui move build` runs offline in this sandbox
//! and genuinely discriminates (valid ⇒ exit 0, type-error ⇒ exit 1). Nuance found at
//! LIVE-smoke time and corrected: `sui` resolves the framework from `$HOME/.move` when
//! `HOME` is set (a COLD home with no cache ⇒ a network fetch ⇒ kernel-DENIED ⇒ fail),
//! but uses its BUNDLED framework when `HOME` is ABSENT. So the oracle withholds `HOME`
//! from the build child (see [`sui_build_oracle`]) — portable to any box, no warm cache
//! prerequisite.

use crate::agent_loop::AgentLoopOutcome;
use crate::exec_local::EXEC_STREAM_CAP_BYTES;
use crate::provider::executor_route::{ExecutorKind, SubTask};
use crate::sandbox_exec::{SandboxRunDeny, run_in_sandbox};
use crate::verification::VerificationEvidence;
use std::path::PathBuf;

use crate::commands::sandbox::SandboxTier;

/// Wall-clock cap for one Move build oracle (ms). R5 measured < 1s; this is a generous
/// paranoid ceiling so a cold compile never flakes, while a runaway build fail-closes.
pub const CODE_ORACLE_BUILD_TIMEOUT_MS: u64 = 90_000;

/// Resolve the `sui` binary absolute path: an explicit `SINABRO_SUI_BIN` override, then
/// the common install locations. `None` ⇒ no toolchain ⇒ the oracle is honestly absent
/// (`CodeOracle(None)`), never a false pass. An absolute path is required (the sandbox
/// child's env is scrubbed, so `$PATH` resolution of a bare `sui` is not relied on).
#[must_use]
pub fn resolve_sui_bin() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("SINABRO_SUI_BIN") {
        let pb = PathBuf::from(p);
        if pb.is_file() {
            return Some(pb);
        }
    }
    for c in [
        "/opt/homebrew/bin/sui",
        "/usr/local/bin/sui",
        "/usr/bin/sui",
    ] {
        let pb = PathBuf::from(c);
        if pb.is_file() {
            return Some(pb);
        }
    }
    None
}

/// Extract a compilable Move source from the model's answer: the first ```` ```move ````
/// fenced block, else the substring from the first `module ` to the last `}`. `None` ⇒
/// nothing to compile (the oracle is `NotApplicable`, never a false `Verified`).
#[must_use]
pub fn extract_move_source(answer: &str) -> Option<String> {
    // Prefer a fenced ```move block (the brain's idiomatic code block).
    if let Some(start) = answer.find("```move") {
        let after = &answer[start + "```move".len()..];
        if let Some(end) = after.find("```") {
            let body = after[..end].trim();
            if body.contains("module ") {
                return Some(body.to_string());
            }
        }
    }
    // Fall back to the module span (first `module ` .. last `}`).
    let mstart = answer.find("module ")?;
    let tail = &answer[mstart..];
    let lastbrace = tail.rfind('}')?;
    let body = tail[..=lastbrace].trim();
    if body.contains("module ") {
        Some(body.to_string())
    } else {
        None
    }
}

/// Is `a` a NAMED Move address (must be DECLARED in `[addresses]`), as opposed to a
/// numeric literal like `0x1` (needs no declaration)?
fn is_named_address(a: &str) -> bool {
    match a.chars().next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {
            a.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        }
        _ => false,
    }
}

/// The distinct NAMED addresses used by `module <addr>::` declarations (numeric / hex
/// addresses are skipped — they need no `[addresses]` entry). Sui / std are implicit
/// system deps and are NOT redeclared.
#[must_use]
fn module_named_addresses(src: &str) -> Vec<String> {
    let mut addrs: Vec<String> = Vec::new();
    for line in src.lines() {
        let t = line.trim_start();
        if let Some(rest) = t.strip_prefix("module ") {
            if let Some((addr, _)) = rest.split_once("::") {
                let a = addr.trim();
                if is_named_address(a) && a != "sui" && a != "std" && !addrs.iter().any(|x| x == a)
                {
                    addrs.push(a.to_string());
                }
            }
        }
    }
    addrs
}

/// Build a minimal Sui Move package (`Move.toml` + `sources/m.move`) for `src` under a
/// fresh temp dir; return the package dir. `None` on any fs error. The package name is a
/// fixed `oracle_pkg`; every NAMED module address is declared `= "0x0"` so the source
/// resolves (the Sui framework + std are implicit).
#[must_use]
pub fn materialize_package(src: &str) -> Option<PathBuf> {
    use std::fmt::Write as _;
    use std::sync::atomic::{AtomicU32, Ordering};
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!("sinabro_code_oracle_{}_{n}", std::process::id()));
    let sources = dir.join("sources");
    std::fs::create_dir_all(&sources).ok()?;
    let mut toml = String::from("[package]\nname = \"oracle_pkg\"\nedition = \"2024\"\n");
    let addrs = module_named_addresses(src);
    if !addrs.is_empty() {
        toml.push_str("\n[addresses]\n");
        for a in &addrs {
            let _ = writeln!(toml, "{a} = \"0x0\"");
        }
    }
    std::fs::write(dir.join("Move.toml"), &toml).ok()?;
    std::fs::write(sources.join("m.move"), src).ok()?;
    Some(dir)
}

/// Shared CODE-oracle core: extract Move from `answer`, materialize a temp package, run
/// `sui move <sub> --path <pkg>` in the E6 network-DENIED sandbox (HOME withheld), and
/// return the typed exit-code evidence. `sub` ∈ {`"build"` structural compile, `"test"`
/// compile + behavioral unit tests}. `CodeOracle(Some(true))` ONLY on a real exit-0 run;
/// `Some(false)` when it ran and failed / timed out; `None` on honest absence (no Move,
/// no `sui`, no kernel sandbox, a whitespace path) — NEVER a false `Verified`.
fn run_sui_move_oracle(answer: &str, sub: &str) -> VerificationEvidence {
    let Some(src) = extract_move_source(answer) else {
        return VerificationEvidence::CodeOracle(None); // nothing to compile
    };
    let Some(sui) = resolve_sui_bin() else {
        return VerificationEvidence::CodeOracle(None); // no toolchain
    };
    let Some(pkg) = materialize_package(&src) else {
        return VerificationEvidence::CodeOracle(None); // fs trouble
    };
    let pkg_str = pkg.to_string_lossy().to_string();
    let sui_str = sui.to_string_lossy().to_string();
    // argv-only (no shell): "<sui> move <sub> --path <pkg>". The sandbox splits on
    // whitespace, so a path containing whitespace cannot be safely carried — fail-closed
    // to an honest absence (macOS temp/install paths are whitespace-free).
    if sui_str.split_whitespace().count() != 1 || pkg_str.split_whitespace().count() != 1 {
        let _ = std::fs::remove_dir_all(&pkg);
        return VerificationEvidence::CodeOracle(None);
    }
    let line = format!("{sui_str} move {sub} --path {pkg_str}");
    // Withhold HOME from the build child: with no HOME, `sui` resolves its BUNDLED
    // framework (offline, fast, no `~/.move` cache needed) instead of probing
    // `$HOME/.move` — which, on a box without a warm cache, attempts a network fetch
    // (kernel-DENIED here) and fails. Reconcile 2026-06-14: HOME=cold-dir ⇒ exit 1
    // ("Read-only file system"); no HOME ⇒ exit 0. This makes the oracle portable to
    // ANY box (pristine or warm) under the net-DENIED sandbox.
    let evidence = match run_in_sandbox(
        SandboxTier::LocalWrite,
        &line,
        CODE_ORACLE_BUILD_TIMEOUT_MS,
        EXEC_STREAM_CAP_BYTES,
        &["HOME"],
    ) {
        Ok(outcome) => VerificationEvidence::CodeOracle(Some(
            outcome.exit_code == Some(0) && !outcome.timed_out,
        )),
        // No kernel sandbox on this host ⇒ honest absence (NEVER an unsandboxed run).
        Err(SandboxRunDeny::SandboxUnavailable) => VerificationEvidence::CodeOracle(None),
        // A pre-spawn wall (empty/over-long/spawn-failed) ⇒ the check did not pass.
        Err(_) => VerificationEvidence::CodeOracle(Some(false)),
    };
    let _ = std::fs::remove_dir_all(&pkg);
    evidence
}

/// The CODE oracle (structural compile): run `sui move build` in the net-DENIED sandbox.
/// `CodeOracle(Some(true))` ONLY on a real exit-0 build; `Some(false)` on a failed build;
/// `None` on honest absence — never a false `Verified`.
#[must_use]
pub fn sui_build_oracle(answer: &str) -> VerificationEvidence {
    run_sui_move_oracle(answer, "build")
}

/// The CODE oracle STRENGTHENED with behavioral unit tests (W4 ②; the architecture's L3
/// "compile + tests", EvalPlus 2305.01210-motivated): runs `sui move test` — which
/// COMPILES the package AND runs its `#[test]` functions. A failing test exits non-zero
/// ⇒ `CodeOracle(Some(false))`, a SOUND reject that catches behaviorally-broken code
/// which merely COMPILES (LIVE-probed 2026-06-25: a failing assert exits 1, a passing
/// test exits 0, a broken compile exits 1). `Some(true)` only on a clean compile AND all
/// tests passing (or no tests). Because `sui move test` includes the build, this is
/// STRICTLY STRONGER than [`sui_build_oracle`] — never weaker.
///
/// Honest scope: model-WRITTEN passing tests do NOT over-certify correctness (EvalPlus:
/// sparse/weak tests let broken code pass) — this is a sound REJECTOR (a failing test is
/// a real bug), not a strong acceptor. The genuinely-INDEPENDENT second derivation is the
/// cross-memory check (a different class), not this same-axis stronger compile.
#[must_use]
pub fn sui_test_oracle(answer: &str) -> VerificationEvidence {
    run_sui_move_oracle(answer, "test")
}

/// The orchestrate verb's per-sub-task verify oracle: the `sui_move` CODE rung gets the
/// real `sui move test` oracle (W4 ②: COMPILE + behavioral unit tests — strictly stronger
/// than build-only, a failing test is a sound reject); `solana_anchor` / `web3_frontend`
/// are Code class but their toolchain is an owner go-live (`Absent` ⇒ NotApplicable,
/// honest); the non-Code trust tiers (personal / external-fact / model-inference /
/// cross-memory) ride the P1-4 autonomous R-E-W loop, so here they are `Absent`. The
/// MODEL's answer text is fed only to the deterministic COMPILER/TEST-RUNNER, never to
/// `verify` (no self-certification — the hidden-oracle β boundary).
#[must_use]
pub fn orchestrate_verify_oracle(
    subtask: &SubTask,
    outcome: &AgentLoopOutcome,
) -> VerificationEvidence {
    if subtask.kind.label() != ExecutorKind::SUI_MOVE {
        return VerificationEvidence::Absent;
    }
    match outcome.answer.as_deref() {
        Some(answer) => sui_test_oracle(answer),
        None => VerificationEvidence::CodeOracle(None), // no answer to compile/test
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn extract_prefers_fenced_move_block() {
        let answer =
            "Here is the module:\n```move\nmodule demo::a { public fun f() {} }\n```\nDone.";
        let src = extract_move_source(answer).expect("extracts");
        assert!(src.contains("module demo::a"));
        assert!(!src.contains("```"), "the fence markers are stripped");
        assert!(!src.contains("Done."), "prose after the block is excluded");
    }

    #[test]
    fn extract_falls_back_to_module_span() {
        let answer = "module demo::b { public fun g(): u64 { 1 } } trailing prose";
        let src = extract_move_source(answer).expect("extracts");
        assert!(src.starts_with("module demo::b"));
        assert!(
            src.ends_with('}'),
            "trailing prose past the last brace is excluded"
        );
    }

    #[test]
    fn extract_none_when_no_module() {
        assert_eq!(extract_move_source("just prose, no code at all"), None);
        assert_eq!(extract_move_source(""), None);
    }

    #[test]
    fn named_addresses_distinct_and_skip_numeric_and_system() {
        let src = "module foo::a {}\nmodule foo::b {}\nmodule bar::c {}\nmodule 0x1::d {}\nmodule sui::e {}";
        let addrs = module_named_addresses(src);
        assert_eq!(addrs, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn materialize_writes_toml_and_source() {
        let src = "module mypkg::thing { public fun x(): u8 { 7 } }";
        let dir = materialize_package(src).expect("materializes");
        let toml = std::fs::read_to_string(dir.join("Move.toml")).expect("toml");
        assert!(toml.contains("name = \"oracle_pkg\""));
        assert!(toml.contains("edition = \"2024\""));
        assert!(toml.contains("mypkg = \"0x0\""), "named address declared");
        let body = std::fs::read_to_string(dir.join("sources/m.move")).expect("src");
        assert_eq!(body, src);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn oracle_absent_without_move_or_toolchain() {
        // No Move in the answer ⇒ CodeOracle(None) regardless of toolchain.
        assert_eq!(
            sui_build_oracle("no move here"),
            VerificationEvidence::CodeOracle(None)
        );
    }

    /// LIVE oracle discrimination (macOS + `sui` present): a valid module ⇒ Some(true),
    /// a type-error module ⇒ Some(false). The real `sui move build` in the net-DENIED
    /// sandbox is the oracle bit. Skipped (asserting the honest-absence contract instead)
    /// when `sui` or the kernel sandbox is unavailable.
    #[test]
    #[cfg(target_os = "macos")]
    fn live_oracle_discriminates_valid_from_broken() {
        if resolve_sui_bin().is_none() || !crate::sandbox_exec::seatbelt_available() {
            // Honest-absence contract on a host without the toolchain/sandbox.
            assert_eq!(
                sui_build_oracle("module x::y { public fun f() {} }"),
                VerificationEvidence::CodeOracle(None)
            );
            return;
        }
        let valid = "```move\nmodule okp::counter {\n    use sui::object::{Self, UID};\n    use sui::tx_context::TxContext;\n    public struct C has key { id: UID, v: u64 }\n    public fun new(ctx: &mut TxContext): C { C { id: object::new(ctx), v: 0 } }\n}\n```";
        assert_eq!(
            sui_build_oracle(valid),
            VerificationEvidence::CodeOracle(Some(true)),
            "a valid sui module compiles ⇒ Some(true)"
        );
        let broken = "```move\nmodule badp::counter {\n    public struct C has drop { v: u64 }\n    public fun new(): C { C { v: true } }\n}\n```";
        assert_eq!(
            sui_build_oracle(broken),
            VerificationEvidence::CodeOracle(Some(false)),
            "a type-error module ⇒ Some(false)"
        );
    }

    /// LIVE TEST oracle (macOS + `sui` present; W4 ②): a module with a PASSING `#[test]`
    /// ⇒ Some(true); a module that COMPILES but whose `#[test]` FAILS ⇒ Some(false) — the
    /// behavioral reject build-only would MISS. The real `sui move test` in the net-DENIED
    /// sandbox is the bit. Honest-absence contract when `sui` / the kernel sandbox is gone.
    #[test]
    #[cfg(target_os = "macos")]
    fn live_test_oracle_is_strictly_stronger_than_build() {
        if resolve_sui_bin().is_none() || !crate::sandbox_exec::seatbelt_available() {
            assert_eq!(
                sui_test_oracle("module x::y { public fun f() {} }"),
                VerificationEvidence::CodeOracle(None)
            );
            return;
        }
        let passing = "```move\nmodule okp::m {\n    public fun add(a: u64, b: u64): u64 { a + b }\n    #[test]\n    fun t_ok() { assert!(add(2, 3) == 5, 0); }\n}\n```";
        assert_eq!(
            sui_test_oracle(passing),
            VerificationEvidence::CodeOracle(Some(true)),
            "compiles + passing test ⇒ Some(true)"
        );
        // a module that COMPILES but whose test FAILS — the W4 ② behavioral reject.
        let failing = "```move\nmodule badp::m {\n    public fun add(a: u64, b: u64): u64 { a + b }\n    #[test]\n    fun t_bad() { assert!(add(2, 3) == 6, 0); }\n}\n```";
        assert_eq!(
            sui_test_oracle(failing),
            VerificationEvidence::CodeOracle(Some(false)),
            "compiles but a failing test ⇒ Some(false) (behavioral reject)"
        );
        // build-only PASSES that same module (it compiles) — proving the strengthening is
        // real, not vacuous: the test oracle is strictly stronger than the build oracle.
        assert_eq!(
            sui_build_oracle(failing),
            VerificationEvidence::CodeOracle(Some(true)),
            "build-only passes the compiling-but-test-failing module ⇒ test oracle is strictly stronger"
        );
    }
}
