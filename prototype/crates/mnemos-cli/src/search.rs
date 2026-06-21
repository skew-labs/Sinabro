//! A④-rg find-in-files — a regex `search` across the workspace source as a
//! sandbox-free READ capability (CURSOR PARITY TIER-2; design:
//! `ops/evidence/stage_g/agent_loop/CURSOR_PARITY_REFRAME_DESIGN.md` §3 A④).
//!
//! ## Thesis (ripgrep-as-a-capability, the IDE substrate's find-in-files)
//!
//! Cursor's find-in-files is ripgrep over the project. sinabro re-expresses that
//! as a capability-typed READ: walk the workspace source, match a caller-supplied
//! REGEX per line, and surface `path:line: content` hits — so the agent (and the
//! GUI panel that this unlocks) can LOCATE code by pattern instead of guessing a
//! path. The match engine is the `regex` crate, whose matcher is LINEAR-TIME (no
//! catastrophic backtracking), so an agent/owner-supplied pattern cannot ReDoS.
//!
//! ## Security (the per-slice §7 invariants)
//!
//! * CAPABILITY = READ (free). Pure in-Rust filesystem analysis — NO subprocess,
//!   NO sandbox child, NO network, NO write (like `context index`). custody
//!   unreachable.
//! * FAIL-CLOSED: every candidate file is read through the PROVEN file-context wall
//!   stack ([`crate::file_context::FileReadPolicy::workspace_default`] →
//!   canonicalise → under-workspace-root → lane-A DENYLIST ([`denied_token`]) →
//!   256 KiB size cap → UTF-8 gate). A binary / oversized / denylisted / outside
//!   file is skipped, never matched. The walk is bounded (depth / file-count /
//!   match-count) so a huge tree can never block the loop.
//! * REDACTION (SI-2): every matching line passes the SAME per-line `redact()` wall
//!   the file-read tool uses — a secret-shaped line renders as a withheld marker,
//!   never its bytes; a key/cert (`-----BEGIN`) file is skipped wholesale.
//! * CUSTODY untouched (PD-6): no egress/mutate/custody capability, no chain RPC /
//!   socket; funds hard-locked.
//!
//! ## Reuse (no new walk security floor)
//!
//! The per-file read reuses [`FileReadPolicy`](crate::file_context::FileReadPolicy)
//! (the lane-A denylist + size cap + UTF-8 gate); the directory prune reuses
//! [`is_skipped_dir`](crate::commands::source_scan::is_skipped_dir) (the SAME
//! build-output / VCS / deps skip set the audit scan walks). Only the per-line
//! match (regex over text) is new. ALWAYS compiled (no feature) — `regex` is a
//! vendored crate already in the lockfile.

use std::path::{Path, PathBuf};

use regex::RegexBuilder;

use crate::file_context::FileReadPolicy;

/// Bound on the pattern argument (a regex is short; refuse, never truncate).
const SEARCH_MAX_PATTERN_BYTES: usize = 512;

/// Compiled-program memory cap for the regex (defense-in-depth on top of the
/// linear-time matcher: a pathological pattern fails to compile, never hangs).
const SEARCH_REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// Max rendered hits (a bounded result; the loop's per-result byte cap clips the
/// rendered string further). A cap is announced, never silent.
const SEARCH_MAX_MATCHES: usize = 200;

/// Max files actually read during a walk (a bounded walk; announced if hit).
const SEARCH_MAX_FILES: u32 = 5_000;

/// Max directory depth the walk descends (cycle / runaway guard).
const SEARCH_MAX_DEPTH: u32 = 32;

/// Per-matching-line render cap (a long line is char-safe-truncated, never the
/// whole result dropped).
const SEARCH_LINE_RENDER_CAP: usize = 240;

/// Typed, data-free denial reasons for a search.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SearchDeny {
    /// The pattern is empty.
    PatternEmpty,
    /// The pattern exceeds [`SEARCH_MAX_PATTERN_BYTES`] (refuse, never truncate).
    PatternTooLong,
    /// The pattern is not a valid regex (or exceeds the compiled-size limit).
    PatternInvalid,
    /// No workspace root resolves (cwd unknown + no `SINABRO_PROJECT_ROOT`) — the
    /// file policy is fail-closed, so a search cannot run.
    WorkspaceUnavailable,
}

impl SearchDeny {
    /// Stable, allow-listed `class_label` (namespaced `search.*`).
    #[must_use]
    pub const fn class_label(self) -> &'static str {
        match self {
            Self::PatternEmpty => "search.pattern.empty",
            Self::PatternTooLong => "search.pattern.too_long",
            Self::PatternInvalid => "search.pattern.invalid",
            Self::WorkspaceUnavailable => "search.workspace.unavailable",
        }
    }
}

/// The chokepoint's verdict (mirror of [`crate::test_run::TestRunRender`]): the
/// rendered hits (or the typed deny), whether it consumed a READ (a real walk that
/// produced a result, even zero hits), and a stable class label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchRender {
    /// The rendered `path:line: content` hits (success) or the typed deny.
    pub rendered: String,
    /// `true` only when a real walk ran (consumes the loop's K-read budget); every
    /// deny is `false`.
    pub consumed_read: bool,
    /// A stable ASCII class label (`search.*`).
    pub class_label: &'static str,
}

/// The ONE search chokepoint shared by BOTH consumers (the loop tool + the dispatch
/// verb). Gate order: validate the pattern (non-empty, bounded, a valid linear-time
/// regex) → resolve the workspace root (fail-closed via the file policy) → walk the
/// workspace source (bounded; build-output / VCS / deps pruned; symlinks never
/// followed) reading EACH file through the proven file-context wall (denylist + size
/// cap + UTF-8 gate) → match the regex per line → redact each matching line → render
/// the bounded `path:line: content` hits. A search is a free local READ (like
/// `context index` / `git status`), so it is NOT a high-significance audited action,
/// runs NO subprocess, and touches NO network. custody/funds untouched (PD-6).
#[must_use]
pub fn render_search(pattern: &str) -> SearchRender {
    if pattern.is_empty() {
        return search_deny(SearchDeny::PatternEmpty, pattern);
    }
    if pattern.len() > SEARCH_MAX_PATTERN_BYTES {
        return search_deny(SearchDeny::PatternTooLong, pattern);
    }
    // The `regex` crate's matcher is linear-time; the size limit additionally
    // refuses a pathological compiled program (it never hangs). An invalid regex
    // is an honest deny, never a fabricated result.
    let Ok(re) = RegexBuilder::new(pattern)
        .size_limit(SEARCH_REGEX_SIZE_LIMIT)
        .build()
    else {
        return search_deny(SearchDeny::PatternInvalid, pattern);
    };

    let policy = FileReadPolicy::workspace_default();
    // The walk root = the FIRST allowed root (the workspace root); fail-closed if
    // the policy admitted none (cwd unknown + no `SINABRO_PROJECT_ROOT`).
    let Some(root) = policy.roots().first().cloned() else {
        return search_deny(SearchDeny::WorkspaceUnavailable, pattern);
    };
    search_walk(&re, &policy, &root, pattern)
}

/// The bounded regex walk + render, split out so the chokepoint is unit-testable over
/// an arbitrary root/policy (the real path resolves `workspace_default`'s first root).
/// Walk = the audit-scan discipline (explicit stack, depth bound, symlink-skip,
/// `is_skipped_dir`); each file via `policy.read` (under-root + denylist + size cap +
/// UTF-8); each matching line redact-belted. `root` MUST be the policy's canonical
/// root so the `path:line` labels are workspace-relative.
fn search_walk(
    re: &regex::Regex,
    policy: &FileReadPolicy,
    root: &Path,
    pattern: &str,
) -> SearchRender {
    let mut hits: Vec<String> = Vec::new();
    let mut files_scanned: u32 = 0;
    let mut files_capped = false;
    let mut matches_capped = false;
    // Explicit stack (depth-bounded; never recurses) of (path, depth).
    let mut stack: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
    'walk: while let Some((dir, depth)) = stack.pop() {
        if depth > SEARCH_MAX_DEPTH {
            continue;
        }
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for dirent in read_dir.flatten() {
            if files_scanned >= SEARCH_MAX_FILES {
                files_capped = true;
                break 'walk;
            }
            if hits.len() >= SEARCH_MAX_MATCHES {
                matches_capped = true;
                break 'walk;
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
                if crate::commands::source_scan::is_skipped_dir(&path) {
                    continue;
                }
                stack.push((path, depth + 1));
                continue;
            }
            if !ft.is_file() {
                continue;
            }
            // Read EACH file through the PROVEN file-context wall: under-root +
            // lane-A denylist + 256 KiB size cap + UTF-8 gate. A binary / oversized
            // / denylisted file ⇒ Err / `text == None` ⇒ skipped (never matched).
            let Ok(result) = policy.read(&path) else {
                continue;
            };
            let Some(text) = result.text.as_deref() else {
                continue; // binary — never matched (IV-F5)
            };
            files_scanned = files_scanned.saturating_add(1);
            // A REAL multi-line key/cert block is skipped wholesale — its base64 body
            // lines do NOT match the single-line secret markers, so a per-line redact
            // could leak them. Detect it by a LINE that (trimmed) BEGINS with
            // `-----BEGIN` — NOT a mere prose mention of the marker (a source file may
            // document it, as THIS file does; whole-file-skipping on a substring would
            // silently drop every match in such a file — wrong for find-in-files).
            if text.lines().any(|l| {
                l.trim_start()
                    .to_ascii_lowercase()
                    .starts_with("-----begin")
            }) {
                continue;
            }
            let rel = path.strip_prefix(root).unwrap_or(path.as_path());
            let rel_str = rel.to_string_lossy();
            for (idx, line) in text.lines().enumerate() {
                if hits.len() >= SEARCH_MAX_MATCHES {
                    matches_capped = true;
                    break 'walk;
                }
                if !re.is_match(line) {
                    continue;
                }
                // SI-2: a secret-shaped matching line renders as a withheld marker
                // (its position is reported, never its bytes); a benign line is
                // char-safe-truncated.
                let shown = if line_is_secret(line) {
                    "[withheld: secret-shaped line]".to_string()
                } else {
                    truncate_line(line)
                };
                hits.push(format!("{rel_str}:{}: {shown}", idx.saturating_add(1)));
            }
        }
    }

    let mut rendered = if hits.is_empty() {
        format!(
            "search {pattern}: 0 matches (read-only regex walk over the workspace source; \
             bounded; denylisted/binary/oversized files skipped)"
        )
    } else {
        format!(
            "search {pattern}: {} match(es) in {files_scanned} file(s) scanned \
             (read-only regex walk; redacted; bounded):\n{}",
            hits.len(),
            hits.join("\n")
        )
    };
    if files_capped {
        rendered.push_str(&format!(
            "\n[walk capped at {SEARCH_MAX_FILES} files — narrow the search root]"
        ));
    }
    if matches_capped {
        rendered.push_str(&format!(
            "\n[hits capped at {SEARCH_MAX_MATCHES} — refine the pattern for fewer matches]"
        ));
    }
    SearchRender {
        rendered,
        consumed_read: true,
        class_label: if hits.is_empty() {
            "search.no_hits"
        } else {
            "search.hits"
        },
    }
}

/// SI-2 per-line redaction gate (the SAME canonical `redact()` wall the file-read /
/// test-run / git tools use): `true` ⇒ the line is secret-shaped ⇒ WITHHELD. Exposed
/// `pub(crate)` so the codebase index ([4] B⑨) redacts indexed chunks through the SAME
/// wall (the prune set never drifts).
#[must_use]
pub(crate) fn line_is_secret(line: &str) -> bool {
    use crate::provider::redaction::{RedactionRequest, redact};
    let fragment = [line];
    match redact(&RedactionRequest {
        fragments: &fragment,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) => receipt.secret_fragments_denied_u32() != 0,
        // fail-closed: a line we cannot classify is withheld, never shown.
        Err(_) => true,
    }
}

/// Char-boundary-safe truncation of a single matching line (a long line is clipped
/// with an ellipsis; the whole hit is never dropped).
#[must_use]
fn truncate_line(line: &str) -> String {
    if line.len() <= SEARCH_LINE_RENDER_CAP {
        return line.to_string();
    }
    let mut end = SEARCH_LINE_RENDER_CAP;
    while end > 0 && !line.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &line[..end])
}

/// Render a typed search deny (the pattern label only — never repo bytes).
#[must_use]
fn search_deny(deny: SearchDeny, pattern: &str) -> SearchRender {
    let hint = match deny {
        SearchDeny::PatternInvalid => " (use a valid regular expression, e.g. `fn \\w+`)",
        SearchDeny::WorkspaceUnavailable => {
            " (no workspace root — set SINABRO_PROJECT_ROOT or run inside a project)"
        }
        _ => "",
    };
    SearchRender {
        rendered: format!("search {pattern}: denied ({}){hint}", deny.class_label()),
        consumed_read: false,
        class_label: deny.class_label(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn empty_oversized_and_invalid_patterns_are_typed_denies() {
        // All fail the pre-walk wall BEFORE any filesystem read (deterministic).
        assert_eq!(render_search("").class_label, "search.pattern.empty");
        assert!(!render_search("").consumed_read);
        let big = "x".repeat(SEARCH_MAX_PATTERN_BYTES + 1);
        assert_eq!(render_search(&big).class_label, "search.pattern.too_long");
        // An unbalanced group is not a valid regex ⇒ honest deny, never a result.
        let bad = render_search("(unclosed");
        assert!(!bad.consumed_read);
        assert_eq!(bad.class_label, "search.pattern.invalid");
    }

    #[test]
    fn deny_labels_are_stable() {
        assert_eq!(
            SearchDeny::PatternEmpty.class_label(),
            "search.pattern.empty"
        );
        assert_eq!(
            SearchDeny::PatternTooLong.class_label(),
            "search.pattern.too_long"
        );
        assert_eq!(
            SearchDeny::PatternInvalid.class_label(),
            "search.pattern.invalid"
        );
        assert_eq!(
            SearchDeny::WorkspaceUnavailable.class_label(),
            "search.workspace.unavailable"
        );
    }

    #[test]
    fn long_line_is_char_safe_truncated_with_ellipsis() {
        let line = "λ".repeat(SEARCH_LINE_RENDER_CAP); // multi-byte chars
        let out = truncate_line(&line);
        assert!(out.len() <= line.len());
        // The truncation never splits a char (no panic on a char boundary).
        assert!(out.ends_with('…') || out.len() == line.len());
    }

    #[test]
    fn secret_shaped_line_is_classified_for_withholding() {
        // A `suiprivkey1`-shaped token is a build-independent secret marker.
        assert!(line_is_secret("let k = \"suiprivkey1abcdef\";"));
        // A benign source line is not.
        assert!(!line_is_secret("pub fn render_search(pattern: &str) {}"));
    }

    /// A policy rooted at THIS crate's own `src/` (small + fixed) so the walk result
    /// is deterministic regardless of the cwd-resolved workspace size (the real
    /// `render_search` resolves `workspace_default`, which over a giant tree could
    /// cap before any given file — a unit test must not depend on that).
    fn crate_src_policy() -> (FileReadPolicy, PathBuf) {
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let policy = FileReadPolicy::new(&[src], crate::file_context::MAX_FILE_BYTES);
        let root = policy
            .roots()
            .first()
            .cloned()
            .expect("the crate src root resolves");
        (policy, root)
    }

    #[test]
    fn search_walk_over_the_crate_src_finds_this_chokepoint_deterministically() {
        // A real regex walk over the crate's own src finds this module's chokepoint.
        // Non-vacuous: the wire reads files, matches per line, renders relative hits.
        let (policy, root) = crate_src_policy();
        let re = RegexBuilder::new("fn render_search")
            .build()
            .expect("valid regex");
        let r = search_walk(&re, &policy, &root, "fn render_search");
        assert!(
            r.consumed_read,
            "a real walk consumes a read: {}",
            r.rendered
        );
        assert_eq!(r.class_label, "search.hits", "rendered: {}", r.rendered);
        assert!(
            r.rendered.contains("search.rs:"),
            "expected a hit in search.rs: {}",
            r.rendered
        );
    }

    #[test]
    fn a_secret_shaped_matching_line_is_withheld_in_the_walk_output() {
        // Searching the crate src for the secret marker matches the `suiprivkey1`
        // fixtures in THIS file's own tests — but every matching line renders as the
        // withheld marker, never its raw bytes (SI-2 enforced inside the walk).
        let (policy, root) = crate_src_policy();
        let re = RegexBuilder::new("suiprivkey1")
            .build()
            .expect("valid regex");
        let r = search_walk(&re, &policy, &root, "suiprivkey1");
        assert!(r.consumed_read, "{}", r.rendered);
        assert!(
            r.rendered.contains("[withheld: secret-shaped line]"),
            "expected a withheld marker: {}",
            r.rendered
        );
        // The full secret token (the suffix beyond the searched prefix) never renders.
        assert!(
            !r.rendered.contains("suiprivkey1abcdef"),
            "the raw secret token must never render: {}",
            r.rendered
        );
    }
}
