//! Real source-tree audit scan (ENDGAME).
//!
//! `sinabro audit scan` previously projected over an EMPTY candidate slice
//! (`scan(&[])` ⇒ always 0). This walks a REAL source tree and emits REAL,
//! source-anchored [`AuditCandidate`]s for the honestly pattern-detectable set
//! (the `unsafe` / `unwrap` / `expect` / `panic!` / `todo!` / `unimplemented!` /
//! `dbg!` surface the project's own panic-gate already enforces). It is
//! deliberately NOT a reentrancy / oracle / auth vulnerability engine — that is a
//! separate security-research lane; a pattern hit here is a CANDIDATE (never a
//! finding: `local_repro_done = false`, `repro_plan_safe_local = false`), so the
//! Stage-F game-tree invariant (candidate ≠ finding) is preserved.
//!
//! Output is counts + `[u8; 32]` hashes ONLY — a candidate carries a hashed
//! source anchor (`SHA-256(relpath:line)`) and a hashed evidence line, never a raw
//! source byte (so a secret-shaped source line can never leak into a render). The
//! walk is bounded (file / candidate / depth caps) and reports when a cap clips it
//! (no silent truncation).
//!
//! Reuse (no reinvention): [`AuditCandidate`] / [`AuditProfile`] /
//! [`AuditScanView`] from [`crate::commands::eval_core`]; [`sha256_32`] for the
//! anchors. This module performs no network / chain / wallet I/O — pure local
//! read-only filesystem analysis.

use std::path::Path;

use crate::commands::eval_core::{AuditCandidate, AuditProfile};
use crate::sha256_32;

/// Max files visited before the walk stops (bounded work; logged when hit).
const MAX_FILES: u32 = 5_000;
/// Max candidates collected before the scan stops (bounded memory; logged).
const MAX_CANDIDATES: usize = 50_000;
/// Max directory depth (defensive against a deep / symlinked tree).
const MAX_DEPTH: u32 = 32;
/// Max file size read (a larger file is skipped — not a source unit of interest).
const MAX_FILE_BYTES: u64 = 2 * 1024 * 1024;

/// A pattern rule: the substring that flags it, a stable rule label, the affected
/// invariant label, and a candidate confidence (basis points). Pattern-only, so
/// confidence stays modest — these are leads, never findings.
struct PatternRule {
    needle: &'static str,
    rule: &'static str,
    invariant: &'static str,
    confidence_bps: u16,
}

/// The Rust pattern set — exactly the panic / unsafe surface the project's own
/// `G-GREP-PANIC` gate enforces, so a hit is a real, actionable lead.
const RUST_RULES: &[PatternRule] = &[
    PatternRule {
        needle: ".unwrap(",
        rule: "rust.unwrap",
        invariant: "no_unwrap_on_fallible_path",
        confidence_bps: 3000,
    },
    PatternRule {
        needle: ".expect(",
        rule: "rust.expect",
        invariant: "no_expect_on_fallible_path",
        confidence_bps: 3000,
    },
    PatternRule {
        needle: "panic!(",
        rule: "rust.panic",
        invariant: "no_panic_in_prod",
        confidence_bps: 5000,
    },
    PatternRule {
        needle: "todo!(",
        rule: "rust.todo",
        invariant: "no_todo_in_prod",
        confidence_bps: 6000,
    },
    PatternRule {
        needle: "unimplemented!(",
        rule: "rust.unimplemented",
        invariant: "no_unimplemented_in_prod",
        confidence_bps: 6000,
    },
    PatternRule {
        needle: "dbg!(",
        rule: "rust.dbg",
        invariant: "no_dbg_in_prod",
        confidence_bps: 4000,
    },
    PatternRule {
        needle: "unsafe ",
        rule: "rust.unsafe",
        invariant: "unsafe_block_review",
        confidence_bps: 4000,
    },
];

/// the static Rust pattern-rule labels paired with their `rule_id_hash_32`
/// (`sha256_32(rule.as_bytes())`) — the stable identity [`scan_tree`] stamps on each
/// candidate. Lets a consumer (`audit detect`) build a per-rule histogram from
/// candidate hashes WITHOUT a raw source byte (the labels are compile-time
/// constants). Pure; allocates a small fixed-size table.
#[must_use]
pub fn rust_rule_hashes() -> Vec<(&'static str, [u8; 32])> {
    RUST_RULES
        .iter()
        .map(|r| (r.rule, sha256_32(r.rule.as_bytes())))
        .collect()
}

/// The file extension a profile scans (Move/Sui/Solana reuse the same pattern
/// spine over their source extension; non-Rust profiles default to Rust rules
/// until a language-specific rule set lands — honest scope, not a fake engine).
const fn extension_for(profile: AuditProfile) -> &'static str {
    match profile {
        AuditProfile::Move | AuditProfile::SuiSource => "move",
        AuditProfile::SolanaSource => "rs",
        _ => "rs",
    }
}

/// The result of a real source-tree scan: the source-anchored candidates plus the
/// bounded-walk telemetry (so a cap is never silent).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceScanResult {
    /// Source-anchored, pattern-only candidates (never findings).
    pub candidates: Vec<AuditCandidate>,
    /// Number of source files actually read.
    pub files_scanned: u32,
    /// Whether the file cap clipped the walk.
    pub files_capped: bool,
    /// Whether the candidate cap clipped the walk.
    pub candidates_capped: bool,
}

impl SourceScanResult {
    /// The candidate count (saturating to `u32::MAX`).
    #[must_use]
    pub fn candidate_count_u32(&self) -> u32 {
        u32::try_from(self.candidates.len()).unwrap_or(u32::MAX)
    }
}

/// Walk `root` and flag pattern candidates over the profile's source files. Pure
/// read-only filesystem analysis; bounded; deterministic in its COUNTS over an
/// unchanged tree (candidate order is unspecified, only counts are rendered).
#[must_use]
pub fn scan_tree(root: &Path, profile: AuditProfile) -> SourceScanResult {
    let ext = extension_for(profile);
    let mut result = SourceScanResult::default();
    // Explicit stack (depth-bounded; never recurses) of (path, depth).
    let mut stack: Vec<(std::path::PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        if depth > MAX_DEPTH {
            continue;
        }
        let Ok(read) = std::fs::read_dir(&dir) else {
            continue;
        };
        for dirent in read.flatten() {
            if result.files_scanned >= MAX_FILES {
                result.files_capped = true;
                return result;
            }
            if result.candidates.len() >= MAX_CANDIDATES {
                result.candidates_capped = true;
                return result;
            }
            let path = dirent.path();
            // Never follow symlinks (cycle / escape safety); use file_type (no
            // extra stat that follows links).
            let Ok(ft) = dirent.file_type() else {
                continue;
            };
            if ft.is_symlink() {
                continue;
            }
            if ft.is_dir() {
                if is_skipped_dir(&path) {
                    continue;
                }
                stack.push((path, depth + 1));
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            if path.extension().and_then(|e| e.to_str()) != Some(ext) {
                continue;
            }
            // Skip a too-large file (not a source unit of interest).
            if std::fs::metadata(&path).map_or(u64::MAX, |m| m.len()) > MAX_FILE_BYTES {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            result.files_scanned += 1;
            let rel = path.strip_prefix(root).unwrap_or(path.as_path());
            let rel_str = rel.to_string_lossy();
            scan_text(rel_str.as_ref(), &text, &mut result.candidates);
        }
    }
    result
}

/// Whether a directory should be skipped (build output, VCS, deps, hidden, temp).
/// `pub(crate)` so the find-in-files walk ([`crate::search`]) reuses the SAME
/// build-output / VCS / deps skip set this audit scan walks (no drift between the
/// two read-only tree walks). Pure predicate; no logic change.
pub(crate) fn is_skipped_dir(path: &Path) -> bool {
    match path.file_name().and_then(|n| n.to_str()) {
        Some(name) => {
            name == "target"
                || name == ".git"
                || name == "node_modules"
                || name == ".cargo"
                || name.starts_with('.')
        }
        None => true,
    }
}

/// Flag pattern candidates over one file's text (counts + hashed anchors only).
fn scan_text(rel_path: &str, text: &str, out: &mut Vec<AuditCandidate>) {
    for (idx, line) in text.lines().enumerate() {
        if out.len() >= MAX_CANDIDATES {
            return;
        }
        for rule in RUST_RULES {
            if line.contains(rule.needle) {
                let line_no = idx + 1;
                out.push(AuditCandidate {
                    rule_id_hash_32: sha256_32(rule.rule.as_bytes()),
                    // The REAL source anchor: relpath:line (hashed, never raw).
                    location_hash_32: sha256_32(format!("{rel_path}:{line_no}").as_bytes()),
                    invariant_hash_32: sha256_32(rule.invariant.as_bytes()),
                    // Evidence is the matched line, hashed — never a raw byte.
                    evidence_hash_32: sha256_32(line.trim().as_bytes()),
                    confidence_bps_u16: rule.confidence_bps,
                    // Pattern-only: NEVER a finding without a local repro receipt.
                    repro_plan_safe_local: false,
                    local_repro_done: false,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use std::io::Write;

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sinabro_srcscan_{}_{tag}_{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_file(dir: &Path, name: &str, body: &str) {
        let path = dir.join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("mkdir");
        }
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(body.as_bytes()).expect("write");
    }

    #[test]
    fn scans_a_real_tree_and_flags_real_anchored_candidates() {
        let dir = unique_dir("flag");
        write_file(
            &dir,
            "src/a.rs",
            "fn f() {\n    let x = maybe().unwrap();\n    panic!(\"boom\");\n}\n",
        );
        write_file(&dir, "src/clean.rs", "fn g() -> i32 { 1 + 1 }\n");
        let r = scan_tree(&dir, AuditProfile::Rust);
        assert_eq!(r.files_scanned, 2);
        // one unwrap + one panic => 2 candidates, each anchored to a real line.
        assert_eq!(r.candidate_count_u32(), 2);
        let unwrap_anchor = sha256_32(b"src/a.rs:2");
        assert!(
            r.candidates
                .iter()
                .any(|c| c.location_hash_32 == unwrap_anchor),
            "the unwrap candidate is anchored to the real relpath:line"
        );
        // Every candidate is pattern-only (never a finding).
        assert!(r.candidates.iter().all(|c| !c.local_repro_done));
    }

    #[test]
    fn empty_tree_yields_zero_candidates_not_a_crash() {
        let dir = unique_dir("empty");
        let r = scan_tree(&dir, AuditProfile::Rust);
        assert_eq!(r.files_scanned, 0);
        assert_eq!(r.candidate_count_u32(), 0);
        assert!(!r.files_capped && !r.candidates_capped);
    }

    #[test]
    fn skips_build_and_vcs_dirs() {
        let dir = unique_dir("skip");
        write_file(&dir, "src/a.rs", "let y = z.unwrap();\n");
        write_file(&dir, "target/debug/gen.rs", "let q = w.unwrap();\n");
        write_file(&dir, ".git/hooks/x.rs", "let p = o.unwrap();\n");
        let r = scan_tree(&dir, AuditProfile::Rust);
        // only src/a.rs is scanned; target/ and .git/ are skipped.
        assert_eq!(r.files_scanned, 1);
        assert_eq!(r.candidate_count_u32(), 1);
    }

    #[test]
    fn count_is_deterministic_over_unchanged_tree() {
        let dir = unique_dir("det");
        write_file(
            &dir,
            "src/a.rs",
            "a.unwrap(); b.expect(\"x\"); unsafe { read() }\n",
        );
        let a = scan_tree(&dir, AuditProfile::Rust).candidate_count_u32();
        let b = scan_tree(&dir, AuditProfile::Rust).candidate_count_u32();
        assert_eq!(a, b);
        assert_eq!(a, 3); // unwrap + expect + unsafe
    }
}
