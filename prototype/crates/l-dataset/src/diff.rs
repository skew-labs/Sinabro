//! `code_diff.patch` structural parser (atom #346 · E.0.15).
//!
//! Parsed structurally enough for changed-file count, language flags, and
//! insert/delete counts; the full patch is stored by `sha256` so a huge raw
//! patch never needs to be materialized downstream. A binary patch, a path
//! traversal, or a patch missing unified-diff headers rejects.
use crate::error::{DietError, DietResult};

/// Structural summary of a unified-diff patch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct DiffSummary {
    /// Number of changed files (`+++` headers).
    pub files_changed_u32: u32,
    /// Added lines.
    pub insertions_u32: u32,
    /// Removed lines.
    pub deletions_u32: u32,
    /// An added line introduced an `unsafe` block/fn.
    pub has_unsafe: bool,
    /// A changed file is Move source (`.move`).
    pub has_move: bool,
    /// `sha256` of the whole patch.
    pub patch_hash_32: [u8; 32],
}

fn header_path(line: &str) -> &str {
    line.split('\t').next().unwrap_or(line)
}

fn check_traversal(path: &str) -> DietResult<()> {
    if path.contains("../") || path.contains("..\\") {
        return Err(DietError::PathTraversal);
    }
    Ok(())
}

/// Parse a `code_diff.patch` document.
pub fn parse(text: &str) -> DietResult<DiffSummary> {
    if text.contains("Binary files ") || text.contains("GIT binary patch") {
        return Err(DietError::BinaryDiffRejected);
    }
    let mut files = 0u32;
    let mut ins = 0u32;
    let mut del = 0u32;
    let mut has_unsafe = false;
    let mut has_move = false;
    let mut saw_old = false;
    let mut saw_new = false;
    for line in text.lines() {
        if let Some(path) = line.strip_prefix("--- ") {
            saw_old = true;
            check_traversal(header_path(path))?;
        } else if let Some(path) = line.strip_prefix("+++ ") {
            saw_new = true;
            let p = header_path(path);
            check_traversal(p)?;
            files = files.saturating_add(1);
            if p.trim_end().ends_with(".move") {
                has_move = true;
            }
        } else if let Some(content) = line.strip_prefix('+') {
            if !content.starts_with("++") {
                ins = ins.saturating_add(1);
                if content.contains("unsafe ") || content.contains("unsafe{") {
                    has_unsafe = true;
                }
            }
        } else if let Some(content) = line.strip_prefix('-') {
            if !content.starts_with("--") {
                del = del.saturating_add(1);
            }
        }
    }
    if !saw_old || !saw_new {
        return Err(DietError::MalformedPatch);
    }
    Ok(DiffSummary {
        files_changed_u32: files,
        insertions_u32: ins,
        deletions_u32: del,
        has_unsafe,
        has_move,
        patch_hash_32: crate::sha256(text.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rust_diff_counts_lines() -> DietResult<()> {
        let patch = "--- a/x.rs\n+++ b/x.rs\n@@ -1,1 +1,1 @@\n-let y = 2;\n+let x = 1;\n";
        let d = parse(patch)?;
        assert_eq!(d.files_changed_u32, 1);
        assert_eq!(d.insertions_u32, 1);
        assert_eq!(d.deletions_u32, 1);
        assert!(!d.has_move);
        assert!(!d.has_unsafe);
        Ok(())
    }

    #[test]
    fn move_diff_sets_flag() -> DietResult<()> {
        let patch = "--- /dev/null\n+++ b/sources/m.move\n@@ -0,0 +1,1 @@\n+module mnemos::m {}\n";
        assert!(parse(patch)?.has_move);
        Ok(())
    }

    #[test]
    fn unsafe_marker_detected() -> DietResult<()> {
        let patch = "--- a/x.rs\n+++ b/x.rs\n@@ -0,0 +1,1 @@\n+    unsafe { *p }\n";
        assert!(parse(patch)?.has_unsafe);
        Ok(())
    }

    #[test]
    fn binary_diff_rejects() {
        let patch = "--- a/x.bin\n+++ b/x.bin\nBinary files a/x.bin and b/x.bin differ\n";
        assert!(matches!(parse(patch), Err(DietError::BinaryDiffRejected)));
    }

    #[test]
    fn path_traversal_rejects() {
        let patch = "--- a/ok\n+++ b/../../etc/passwd\n+x\n";
        assert!(matches!(parse(patch), Err(DietError::PathTraversal)));
    }

    #[test]
    fn missing_headers_reject() {
        assert!(matches!(
            parse("just some text\nno headers here\n"),
            Err(DietError::MalformedPatch)
        ));
    }

    #[test]
    fn patch_hash_is_content_addressed() -> DietResult<()> {
        let patch = "--- a/x\n+++ b/x\n+a\n";
        assert_eq!(parse(patch)?.patch_hash_32, crate::sha256(patch.as_bytes()));
        Ok(())
    }
}
