//! Bounded, deterministic, content-free project file index for multi-repo /
//! project context. Gives the operator an O(K) projection of a registered
//! project root's file tree — the discovery primitive for working across
//! multiple repos WITHOUT a whole-tree load.
//!
//! # New surface vs single-file reads
//! [`crate::file_context`] reads ONE file's bytes. This module adds recursive
//! ENUMERATION of an arbitrary (allowlisted) USER project directory tree
//! (`std::fs::read_dir` over a USER root — `read_dir` over the sinabro-owned
//! `~/.mnemos` stores pre-existed, but enumerating a user project tree is new).
//! It REUSES the [`FileReadPolicy`] allowlist + the [`denied_token`] denylist
//! verbatim and adds enumeration bounds.
//!
//! # The walls (each fail-closed)
//! - **CONFINED**: the indexed root canonicalises INSIDE an allowed root;
//!   the walk uses [`std::fs::DirEntry::file_type`], which NEVER follows
//!   symlinks, so descent can never escape the root and a symlink cycle can
//!   never loop. Every emitted path is physically under the canonical root.
//! - **BOUNDED**: global entry cap [`MAX_INDEX_ENTRIES`], depth cap
//!   [`MAX_INDEX_DEPTH`], per-directory deterministic keep-smallest cap; a cap
//!   hit sets an explicit `truncated` flag (never a silent cut). No whole-tree
//!   load.
//! - **DENYLIST-PRUNED**: [`denied_token`] prunes secret containers (`.git`,
//!   `.ssh`, `.env`, `id_rsa*`, …) BEFORE emit/descent — they never appear in
//!   the index and are never entered (defense in depth + a CU floor: pruned
//!   subtrees cost zero syscalls).
//! - **CONTENT-FREE + DETERMINISTIC**: an entry is
//!   `{rel_path, is_dir, is_symlink, size_bytes}` — NO file content is read.
//!   Entries are sorted by their UTF-8 path bytes ⇒ readdir order never leaks ⇒
//!   the same tree yields the same index and the same [`ProjectIndex::fingerprint_32`].
//!
//! The local/operator tier (`context index [<path>]`) renders the operator's
//! own project listing on their own screen. The agent loop has NO enumeration
//! tool — the loop grammar is byte-unchanged, so the model cannot enumerate a
//! tree (structural). A frontier discovery tool (the model searching the index,
//! with entry names passing redaction before any prompt) is deferred.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

use crate::file_context::{FileReadPolicy, MAX_FILE_RENDER_LINES, denied_token};
use crate::sha256_32;

/// Global cap on emitted index entries: the index is an O(K) projection, never
/// an O(tree) load. Also the per-directory keep cap — we never emit more than
/// this globally, so reading more of any one directory is waste.
pub const MAX_INDEX_ENTRIES: usize = 4096;

/// Recursion depth cap: bounds both work and stack. A tree deeper than this is
/// truncated (honest flag), never followed without bound.
pub const MAX_INDEX_DEPTH: usize = 32;

/// Render line cap for the local `context index` surface — reuses the 200-line
/// file-render bound for one consistent on-screen ceiling.
pub const MAX_INDEX_RENDER_LINES: usize = MAX_FILE_RENDER_LINES;

/// One entry in a project index: a path RELATIVE to the indexed root, its kind,
/// and its byte size (0 for directories / symlinks — content is never read).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectIndexEntry {
    /// Path relative to the indexed root, `/`-joined (platform-stable render).
    pub rel_path: String,
    /// Whether this entry is a real directory. A symlink is NEVER a dir here —
    /// symlinks are reported but never descended.
    pub is_dir: bool,
    /// Whether this entry is a symlink (reported, never followed).
    pub is_symlink: bool,
    /// File size in bytes (0 for directories and symlinks).
    pub size_bytes: u64,
}

/// A bounded, deterministic, content-free projection of a project root's tree.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProjectIndex {
    /// The canonical (symlink/`..`-resolved) root that was indexed.
    pub root: PathBuf,
    /// The entries, sorted by `rel_path` UTF-8 bytes, `len <= MAX_INDEX_ENTRIES`.
    pub entries: Vec<ProjectIndexEntry>,
    /// Whether ANY cap (entries / depth / per-dir) truncated the walk.
    pub truncated: bool,
    /// `sha256` over the sorted entries: same tree ⇒ same value.
    pub fingerprint_32: [u8; 32],
}

impl ProjectIndex {
    /// Number of entries in the index.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the index has no entries.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Why a project index was refused (typed, content-free). Fail-closed taxonomy,
/// mirroring [`crate::file_context::FileReadDeny`] for the enumeration surface.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProjectIndexDeny {
    /// No allowed roots configured — nothing is indexable (fail-closed).
    NoAllowedRoots,
    /// The path does not exist / did not canonicalise.
    NotFound,
    /// The canonical path is not under any allowed root.
    OutsideAllowedRoots,
    /// A path component / name matched the secret-container denylist.
    DeniedName(&'static str),
    /// The path exists but is not a directory (read a file via `context file`).
    NotADirectory,
}

impl ProjectIndexDeny {
    /// Stable, content-free diagnostic label (namespaced `project_index.*`).
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::NoAllowedRoots => "project_index.no_allowed_roots",
            Self::NotFound => "project_index.not_found",
            Self::OutsideAllowedRoots => "project_index.outside_allowed_roots",
            Self::DeniedName(_) => "project_index.denied_name",
            Self::NotADirectory => "project_index.not_a_directory",
        }
    }
}

/// Build a bounded, deterministic, content-free index of `root` with the default
/// caps (the canonical OUT). Delegates to [`index_project_with`].
pub fn index_project(
    policy: &FileReadPolicy,
    root: &Path,
) -> Result<ProjectIndex, ProjectIndexDeny> {
    index_project_with(policy, root, MAX_INDEX_ENTRIES, MAX_INDEX_DEPTH)
}

/// Build a bounded index of `root` with explicit caps (the cap-parameterised
/// form; [`index_project`] delegates with the const caps, and tests drive
/// truncation with small caps). `root` must canonicalise INSIDE one of
/// `policy`'s allowed roots and must not be a denylisted container. Every
/// failure is a typed [`ProjectIndexDeny`]; no path escapes the allowlist, no
/// symlink is followed, no file content is read, and the walk is bounded on
/// every axis.
pub fn index_project_with(
    policy: &FileReadPolicy,
    root: &Path,
    max_entries: usize,
    max_depth: usize,
) -> Result<ProjectIndex, ProjectIndexDeny> {
    if policy.roots().is_empty() {
        return Err(ProjectIndexDeny::NoAllowedRoots);
    }
    // canonicalise (resolves symlinks + `..`; NotFound if absent).
    let canonical = std::fs::canonicalize(root).map_err(|_| ProjectIndexDeny::NotFound)?;
    // allowlist prefix over the RESOLVED path.
    if !policy.roots().iter().any(|r| canonical.starts_with(r)) {
        return Err(ProjectIndexDeny::OutsideAllowedRoots);
    }
    // denylist over the resolved root: never index a secret container.
    if let Some(token) = denied_token(&canonical) {
        return Err(ProjectIndexDeny::DeniedName(token));
    }
    // must be a directory (a file is read via `context file`, not enumerated).
    let meta = std::fs::metadata(&canonical).map_err(|_| ProjectIndexDeny::NotFound)?;
    if !meta.is_dir() {
        return Err(ProjectIndexDeny::NotADirectory);
    }
    let mut entries: Vec<ProjectIndexEntry> = Vec::new();
    let mut truncated = false;
    walk(
        &canonical,
        &canonical,
        0,
        max_entries,
        max_depth,
        &mut entries,
        &mut truncated,
    );
    // Canonical order for fingerprint + render, independent of walk specifics:
    // sort by the UTF-8 path bytes (== Rust str Ord; matches the Python golden).
    entries.sort_by(|a, b| a.rel_path.as_bytes().cmp(b.rel_path.as_bytes()));
    let fingerprint_32 = fingerprint(&entries);
    Ok(ProjectIndex {
        root: canonical,
        entries,
        truncated,
        fingerprint_32,
    })
}

/// `sha256` over the sorted entries. Serialization (Rust ↔ Python golden lock):
/// for each entry in `rel_path`-byte order,
/// `rel_path_utf8 || 0x00 || (is_dir ? 0x01 : 0x00) || size_bytes.to_le_bytes()`.
/// `is_symlink` is NOT in the fingerprint — a symlink is a leaf with `is_dir =
/// false` and `size_bytes = 0`, already distinct from a real directory.
#[must_use]
fn fingerprint(entries: &[ProjectIndexEntry]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(entries.len() * 48);
    for e in entries {
        buf.extend_from_slice(e.rel_path.as_bytes());
        buf.push(0x00);
        buf.push(u8::from(e.is_dir));
        buf.extend_from_slice(&e.size_bytes.to_le_bytes());
    }
    sha256_32(&buf)
}

/// Depth-first, lexicographically-ordered, bounded, symlink-safe walk. Pushes
/// entries in pre-order; the caller re-sorts the flat result for the canonical
/// fingerprint. Sets `truncated` on any cap hit.
fn walk(
    root: &Path,
    dir: &Path,
    depth: usize,
    max_entries: usize,
    max_depth: usize,
    out: &mut Vec<ProjectIndexEntry>,
    truncated: &mut bool,
) {
    if out.len() >= max_entries {
        *truncated = true;
        return;
    }
    if depth >= max_depth {
        *truncated = true;
        return;
    }
    for child in bounded_sorted_children(dir, max_entries, truncated) {
        if out.len() >= max_entries {
            *truncated = true;
            return;
        }
        // Prune denylisted containers BEFORE emit/descent (their names never
        // appear and we never `read_dir` into them).
        if denied_token(&child.path).is_some() {
            continue;
        }
        let Some(rel) = relative_slash(root, &child.path) else {
            // A child not under `root` is impossible without a symlink (which we
            // never follow); skip fail-closed rather than emit an escaped path.
            continue;
        };
        out.push(ProjectIndexEntry {
            rel_path: rel,
            is_dir: child.is_dir,
            is_symlink: child.is_symlink,
            size_bytes: child.size_bytes,
        });
        // Descend ONLY into real directories, NEVER symlinks (escape + cycle
        // safety). `file_type()` already resolved this without following.
        if child.is_dir {
            walk(
                root,
                &child.path,
                depth + 1,
                max_entries,
                max_depth,
                out,
                truncated,
            );
        }
    }
}

/// A directory child captured WITHOUT following symlinks. Ordered by `name`
/// ONLY (names are unique within a directory) so a bounded max-heap can keep the
/// lexicographically-smallest N entries deterministically.
struct Child {
    name: OsString,
    path: PathBuf,
    is_dir: bool,
    is_symlink: bool,
    size_bytes: u64,
}

impl PartialEq for Child {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}
impl Eq for Child {}
impl PartialOrd for Child {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Child {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

/// Read `dir`'s immediate children, keeping at most `max_entries` of them in
/// deterministic lexicographic order (by file name). If the directory holds
/// more, the lexicographically-SMALLEST `max_entries` are kept (a deterministic
/// truncation — NEVER readdir-order-dependent) and `truncated` is set.
/// Symlinks are captured with `is_symlink = true` and are never followed.
/// Unreadable entries / directories are skipped fail-closed. Sizes are
/// lstat'd only for the kept real files (≤ `max_entries` stats; content-free).
fn bounded_sorted_children(dir: &Path, max_entries: usize, truncated: &mut bool) -> Vec<Child> {
    let Ok(read_dir) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    // Max-heap (by name) of size ≤ `max_entries`: when full, the lex-LARGEST
    // kept name is popped if a smaller one arrives ⇒ the lex-smallest survive.
    let mut heap: BinaryHeap<Child> = BinaryHeap::new();
    for entry in read_dir.flatten() {
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        let is_symlink = file_type.is_symlink();
        let child = Child {
            name: entry.file_name(),
            path: entry.path(),
            // `file_type()` does not follow symlinks, so a symlink-to-dir reports
            // `is_dir() == false`; the explicit `&& !is_symlink` is belt-and-braces.
            is_dir: file_type.is_dir() && !is_symlink,
            is_symlink,
            size_bytes: 0,
        };
        if heap.len() < max_entries {
            heap.push(child);
        } else {
            // The directory exceeds the per-dir cap: keep the lex-smallest
            // `max_entries` (deterministic, never readdir-order-dependent).
            *truncated = true;
            if let Some(largest_kept) = heap.peek() {
                if child < *largest_kept {
                    heap.pop();
                    heap.push(child);
                }
            }
        }
    }
    let mut children = heap.into_vec();
    children.sort();
    for child in &mut children {
        if !child.is_dir && !child.is_symlink {
            // lstat (never follows): the real file's own size, content untouched.
            if let Ok(meta) = std::fs::symlink_metadata(&child.path) {
                child.size_bytes = meta.len();
            }
        }
    }
    children
}

/// The `/`-joined path of `path` relative to `root` (platform-stable render;
/// content-free). `None` if `path` is not under `root` (fail-closed) or contains
/// a non-normal component (a stripped relative path under a canonical root never
/// holds `.`/`..`/prefix components).
fn relative_slash(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let mut parts: Vec<String> = Vec::new();
    for component in rel.components() {
        match component {
            Component::Normal(os) => parts.push(os.to_string_lossy().into_owned()),
            _ => return None,
        }
    }
    Some(parts.join("/"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use std::io::Write;
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    fn unique_dir(tag: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sinabro_projidx_{}_{tag}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(content).expect("write");
        path
    }

    fn policy_for(dir: &Path) -> FileReadPolicy {
        FileReadPolicy::new(
            std::slice::from_ref(&dir.to_path_buf()),
            crate::file_context::MAX_FILE_BYTES,
        )
    }

    /// The fingerprint serialization is byte-locked to an INDEPENDENT Python
    /// derivation, and is permutation-invariant after the canonical sort.
    #[test]
    fn golden_fingerprint_matches_python() {
        let entries = vec![
            ProjectIndexEntry {
                rel_path: "README.md".to_string(),
                is_dir: false,
                is_symlink: false,
                size_bytes: 5,
            },
            ProjectIndexEntry {
                rel_path: "src".to_string(),
                is_dir: true,
                is_symlink: false,
                size_bytes: 0,
            },
            ProjectIndexEntry {
                rel_path: "src/lib.rs".to_string(),
                is_dir: false,
                is_symlink: false,
                size_bytes: 200,
            },
            ProjectIndexEntry {
                rel_path: "src/main.rs".to_string(),
                is_dir: false,
                is_symlink: false,
                size_bytes: 100,
            },
        ];
        // The vec is already in canonical (UTF-8 byte) order.
        let fp = fingerprint(&entries);
        assert_eq!(
            crate::hex32(&fp),
            "d593eac7efc8480586fd8d7fc9ead91d7ff0db29d9e375b97a6fd8ad91c2362b",
            "Rust fingerprint must match the Python golden"
        );
        // Permutation-invariant AFTER the canonical sort the indexer applies.
        let mut shuffled = entries.clone();
        shuffled.reverse();
        shuffled.sort_by(|a, b| a.rel_path.as_bytes().cmp(b.rel_path.as_bytes()));
        assert_eq!(fingerprint(&shuffled), fp, "sort ⇒ order-invariant (L2)");
    }

    /// A real tree indexes with sorted content-free entries; the denylist prunes
    /// secret containers; a symlink is recorded but NEVER followed (no escaped
    /// path); re-indexing is byte-identical (determinism).
    #[test]
    fn indexes_real_tree_prunes_denylist_and_never_follows_symlinks() {
        let dir = unique_dir("tree");
        write_file(&dir, "README.md", b"readme");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        write_file(&dir.join("src"), "main.rs", b"fn main(){}");
        // denylisted containers MUST be pruned.
        std::fs::create_dir_all(dir.join(".git")).unwrap();
        write_file(&dir.join(".git"), "config", b"[core]");
        write_file(&dir, "service.env", b"API_KEY=x");
        // a symlink pointing OUTSIDE must be recorded but NEVER followed.
        let outside = unique_dir("tree_outside");
        write_file(&outside, "secret.txt", b"outside");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, dir.join("escape")).ok();

        let policy = policy_for(&dir);
        let index = index_project(&policy, &dir).expect("indexes");
        let rels: Vec<&str> = index.entries.iter().map(|e| e.rel_path.as_str()).collect();

        assert!(rels.contains(&"README.md"), "{rels:?}");
        assert!(rels.contains(&"src"), "{rels:?}");
        assert!(rels.contains(&"src/main.rs"), "{rels:?}");
        // denylist pruned: no `.git` subtree, no `.env`.
        assert!(!rels.iter().any(|r| r.contains(".git")), "{rels:?}");
        assert!(!rels.iter().any(|r| r.ends_with(".env")), "{rels:?}");
        // content-free: every entry has size for files, 0 for dirs.
        let src = index.entries.iter().find(|e| e.rel_path == "src").unwrap();
        assert!(src.is_dir && src.size_bytes == 0);

        #[cfg(unix)]
        {
            assert!(rels.contains(&"escape"), "symlink recorded: {rels:?}");
            assert!(
                !rels.iter().any(|r| r.contains("secret.txt")),
                "symlink NEVER followed: {rels:?}"
            );
            let escape = index
                .entries
                .iter()
                .find(|e| e.rel_path == "escape")
                .unwrap();
            assert!(escape.is_symlink && !escape.is_dir, "symlink is a leaf");
        }

        // deterministic: re-index ⇒ identical fingerprint (L1/L2).
        let again = index_project(&policy, &dir).expect("re-indexes");
        assert_eq!(again.fingerprint_32, index.fingerprint_32);
        // entries sorted by rel_path bytes.
        let mut sorted = rels.clone();
        sorted.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        assert_eq!(rels, sorted, "entries must be sorted");

        std::fs::remove_dir_all(&dir).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// Every enumeration denial is typed and fail-closed.
    #[test]
    fn enumeration_denies_are_typed_and_fail_closed() {
        let empty = FileReadPolicy::new(&[], crate::file_context::MAX_FILE_BYTES);
        let dir = unique_dir("deny");
        assert_eq!(
            index_project(&empty, &dir),
            Err(ProjectIndexDeny::NoAllowedRoots)
        );

        let root = unique_dir("deny_root");
        let outside = unique_dir("deny_outside");
        let policy = policy_for(&root);
        assert_eq!(
            index_project(&policy, &outside),
            Err(ProjectIndexDeny::OutsideAllowedRoots)
        );

        let file = write_file(&root, "note.md", b"x");
        assert_eq!(
            index_project(&policy, &file),
            Err(ProjectIndexDeny::NotADirectory)
        );

        let ssh = root.join(".ssh");
        std::fs::create_dir_all(&ssh).unwrap();
        match index_project(&policy, &ssh) {
            Err(ProjectIndexDeny::DeniedName(_)) => {}
            other => panic!("expected DeniedName, got {other:?}"),
        }

        assert_eq!(
            index_project(&policy, &root.join("nope")),
            Err(ProjectIndexDeny::NotFound)
        );
        assert_eq!(
            ProjectIndexDeny::OutsideAllowedRoots.class_label(),
            "project_index.outside_allowed_roots"
        );

        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// The entry cap and depth cap bound the walk and set `truncated`; the kept
    /// entries under an entry cap are the lexicographically smallest
    /// (deterministic, never readdir-order).
    #[test]
    fn caps_bound_the_walk_and_set_truncated() {
        let dir = unique_dir("caps");
        for i in 0..5 {
            write_file(&dir, &format!("f{i}.txt"), b"x");
        }
        let policy = policy_for(&dir);

        // entry cap of 2 over 5 files ⇒ exactly 2 entries, truncated, lex-smallest.
        let index = index_project_with(&policy, &dir, 2, MAX_INDEX_DEPTH).expect("indexes");
        assert_eq!(index.len(), 2, "entry cap bounds emission");
        assert!(index.truncated, "cap hit sets truncated");
        assert!(!index.is_empty());
        let rels: Vec<&str> = index.entries.iter().map(|e| e.rel_path.as_str()).collect();
        assert_eq!(
            rels,
            vec!["f0.txt", "f1.txt"],
            "lex-smallest kept: {rels:?}"
        );

        // depth cap of 1 ⇒ nested file not listed, subdir recorded, truncated.
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        write_file(&dir.join("sub"), "deep.rs", b"x");
        let shallow = index_project_with(&policy, &dir, MAX_INDEX_ENTRIES, 1).expect("indexes");
        let rels: Vec<&str> = shallow
            .entries
            .iter()
            .map(|e| e.rel_path.as_str())
            .collect();
        assert!(rels.contains(&"sub"), "subdir recorded: {rels:?}");
        assert!(
            !rels.iter().any(|r| r.contains("deep.rs")),
            "depth cap: nested not listed: {rels:?}"
        );
        assert!(shallow.truncated);

        std::fs::remove_dir_all(&dir).ok();
    }
}
