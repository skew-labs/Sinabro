//! Local file context — bounded, allowlist-confined, secret-denylisted
//! read-only file access (agent-core lane A).
//!
//! This is the FIRST arbitrary-path filesystem read in the sinabro core
//! (non-test `std::fs` was 0 before this module). Scope is **READ-ONLY**:
//! there is no write / delete / exec path here (those are separate surfaces
//! with their own threat models). The model can read a file; it can never
//! write or run one.
//!
//! # The wall stack (each a typed refusal — fail-closed)
//!
//! 1. **canonicalise** (`std::fs::canonicalize`, resolves symlinks + `..`) —
//!    a non-existent path is [`FileReadDeny::NotFound`].
//! 2. **allowlist** — the canonical path must be PREFIXED by a canonical
//!    allowed root, else [`FileReadDeny::OutsideAllowedRoots`]. Prefixing the
//!    RESOLVED path defeats both `./` traversal and symlink escape.
//! 3. **denylist** — known secret CONTAINERS (dotfiles, `*.pem`/`*.key`,
//!    `id_rsa*`, `.env*`, `.ssh`/`.git`/`.aws` components, …) are refused
//!    before being opened; defense-in-depth ON TOP of redaction.
//! 4. **size cap** — `> MAX_FILE_BYTES` ⇒ [`FileReadDeny::FileTooLarge`]
//!    (refused, never partially read).
//! 5. **read + hash** — `{bytes, sha256(bytes)}` (content-addressed).
//! 6. **UTF-8** — binary ⇒ metadata only, bytes never rendered.
//!
//! Frontier redaction is applied by the CALLER (the agent loop /
//! dispatch verb) over [`FileReadResult::text`], reusing the same
//! `redaction::redact` gate a frontier `memory read` passes — this module
//! owns the path-safety + bounded-read half; the trust-tier half is the
//! caller's, exactly as with the memory selectors.

use std::path::{Component, Path, PathBuf};

use crate::sha256_32;

/// Maximum readable file size in bytes. A larger file is refused,
/// never truncated — a partial read of a config/secret is worse than no read.
pub const MAX_FILE_BYTES: u64 = 256 * 1024;

/// Maximum rendered/injected content lines; overflow gets an
/// explicit truncation marker, never a silent cut.
pub const MAX_FILE_RENDER_LINES: usize = 200;

/// Environment variable that OWNER-WIDENS the allowlist (the
/// documented "owner explicitly widens" path). A `:`-separated list
/// of extra allowed root directories, added to the working directory. The
/// GUI registers the parent directory of each dragged file here (a drag IS an
/// explicit capability grant); a terminal owner can `export
/// SINABRO_FILE_ROOTS=/path/to/project`. The denylist + redaction + size cap
/// STILL apply inside every widened root — widening admits ordinary files,
/// never secret containers.
pub const FILE_ROOTS_ENV: &str = "SINABRO_FILE_ROOTS";

/// Environment variable that sets a SINGLE explicit workspace root, read by
/// [`workspace_default`](FileReadPolicy::workspace_default). When set + non-empty it
/// OVERRIDES the walk-up detection (the owner names the project root explicitly); the
/// lane-A denylist + size cap + frontier redaction STILL apply inside it.
pub const PROJECT_ROOT_ENV: &str = "SINABRO_PROJECT_ROOT";

/// Workspace-root markers: the nearest ancestor of cwd containing one of
/// these IS the project root the agent reads (like an IDE reading the opened repo), so
/// a coding agent launched from a subdir still sees the whole project. Existence is
/// checked by a stat (never a policy-read), so a dotfile marker is fine.
const WORKSPACE_MARKERS: &[&str] = &[".git", ".hg", ".svn", ".sinabro"];

/// Secret-container filename SUFFIXES (lowercased final component).
const DENY_SUFFIXES: &[&str] = &[
    ".pem",
    ".key",
    ".p12",
    ".pfx",
    ".crt",
    ".cer",
    ".der",
    ".ppk",
    ".keystore",
    ".jks",
    ".secret",
    ".env",
];

/// Secret-container filename PREFIXES (lowercased final component).
const DENY_PREFIXES: &[&str] = &[
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    "id_dsa",
    ".env",
    "secrets",
    "credentials",
    "secret",
];

/// Path COMPONENT names that deny the whole path: a file anywhere
/// under one of these directories is a refused container.
const DENY_COMPONENTS: &[&str] = &[
    ".git",
    ".ssh",
    ".gnupg",
    ".aws",
    ".config",
    "node_modules",
    ".secrets",
];

/// Why a file read was refused (typed, data-free except the path the caller
/// already supplied; `Clone` for rendering). Fail-closed taxonomy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FileReadDeny {
    /// The path does not exist (canonicalise failed).
    NotFound,
    /// The canonical path is not under any allowed root.
    OutsideAllowedRoots,
    /// A path component / filename matched the secret-container denylist
    /// ; carries the matched token for an honest, secret-free reason.
    DeniedName(&'static str),
    /// The file exceeds [`MAX_FILE_BYTES`].
    FileTooLarge,
    /// The file could not be read (permission / io); class label only.
    IoError,
    /// No allowed roots were configured — fail-closed (nothing is readable).
    NoAllowedRoots,
}

impl FileReadDeny {
    /// Stable, allow-listed `class_label` for diagnostic envelopes
    /// (namespaced under `file_context.*`). Carries no path or content.
    #[inline]
    #[must_use]
    pub const fn class_label(&self) -> &'static str {
        match self {
            Self::NotFound => "file_context.not_found",
            Self::OutsideAllowedRoots => "file_context.outside_allowed_roots",
            Self::DeniedName(_) => "file_context.denied_name",
            Self::FileTooLarge => "file_context.file_too_large",
            Self::IoError => "file_context.io_error",
            Self::NoAllowedRoots => "file_context.no_allowed_roots",
        }
    }
}

/// A successful bounded read: the canonical path, the bytes, their
/// content hash, and the UTF-8 view (or `None` for binary).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileReadResult {
    /// The canonical (symlink/`..`-resolved) path actually read.
    pub canonical_path: PathBuf,
    /// The raw bytes (≤ [`MAX_FILE_BYTES`]).
    pub bytes: Vec<u8>,
    /// `sha256(bytes)` — content-addressed, quotable like a memory chunk.
    pub sha256_32: [u8; 32],
    /// The UTF-8 view of `bytes`, or `None` if the content is binary
    /// ( binary is never rendered/injected, only its metadata).
    pub text: Option<String>,
}

impl FileReadResult {
    /// File size in bytes.
    #[inline]
    #[must_use]
    pub fn len_bytes(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the content is binary (non-UTF-8) — render metadata only.
    #[inline]
    #[must_use]
    pub const fn is_binary(&self) -> bool {
        self.text.is_none()
    }
}

/// The read policy: the closed set of allowed roots + the size cap. Roots
/// are stored canonicalised so the prefix check is over resolved
/// paths on both sides.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FileReadPolicy {
    canonical_roots: Vec<PathBuf>,
    max_bytes: u64,
}

impl FileReadPolicy {
    /// Build a policy from candidate roots (each canonicalised; a root that
    /// does not resolve is dropped — a non-existent root cannot confine
    /// anything). An EMPTY resulting set is fail-closed: every read refuses
    /// with [`FileReadDeny::NoAllowedRoots`].
    #[must_use]
    pub fn new(roots: &[PathBuf], max_bytes: u64) -> Self {
        let canonical_roots = roots
            .iter()
            .filter_map(|root| std::fs::canonicalize(root).ok())
            .collect();
        Self {
            canonical_roots,
            max_bytes,
        }
    }

    /// A policy rooted at the process working directory PLUS any owner-widened
    /// roots from [`FILE_ROOTS_ENV`] (TM R-F1) with the default size cap.
    /// Fail-closed: if cwd is unknown and the env is unset/empty, the
    /// allowlist is empty and every read refuses. The env is READ here only
    /// (`std::env::var`, no `set_var`), so this is `unsafe`-free; the GUI/
    /// owner sets the value out of band (a drag, or `export`).
    #[must_use]
    pub fn cwd_default() -> Self {
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Ok(cwd) = std::env::current_dir() {
            roots.push(cwd);
        }
        if let Ok(value) = std::env::var(FILE_ROOTS_ENV) {
            roots.extend(parse_extra_roots(&value));
        }
        Self::new(&roots, MAX_FILE_BYTES)
    }

    /// Like [`cwd_default`](Self::cwd_default), but rooted at the WORKSPACE root — the
    /// nearest ancestor of cwd holding a [`WORKSPACE_MARKERS`] entry (`.git`,
    /// `.sinabro`, …) — so a coding agent launched from a subdir reads the WHOLE
    /// project, not just the launch dir. `SINABRO_PROJECT_ROOT` (a single explicit
    /// root) overrides
    /// the detection; `SINABRO_FILE_ROOTS` extra roots are still added; the lane-A
    /// denylist + size cap + frontier redaction STILL apply inside every root, so
    /// widening admits ordinary project files, never secret containers. Env is read
    /// only (no `set_var`). Fail-closed: empty roots ⇒ every read refuses.
    #[must_use]
    pub fn workspace_default() -> Self {
        let mut roots: Vec<PathBuf> = Vec::new();
        match std::env::var(PROJECT_ROOT_ENV) {
            Ok(value) if !value.trim().is_empty() => roots.push(PathBuf::from(value.trim())),
            _ => {
                if let Ok(cwd) = std::env::current_dir() {
                    roots.push(workspace_root_of(&cwd));
                }
            }
        }
        if let Ok(value) = std::env::var(FILE_ROOTS_ENV) {
            roots.extend(parse_extra_roots(&value));
        }
        Self::new(&roots, MAX_FILE_BYTES)
    }

    /// The canonical allowed roots (for rendering the honest posture).
    #[inline]
    #[must_use]
    pub fn roots(&self) -> &[PathBuf] {
        &self.canonical_roots
    }

    /// Whether a CANONICAL path is confined to an allowed root.
    #[must_use]
    fn within_roots(&self, canonical: &Path) -> bool {
        self.canonical_roots
            .iter()
            .any(|root| canonical.starts_with(root))
    }

    /// Read a file through the full wall stack (the canonical OUT). Every
    /// failure is a typed [`FileReadDeny`]; no path escapes a gate, no
    /// over-cap file is partially read, no binary is rendered.
    pub fn read(&self, requested: &Path) -> Result<FileReadResult, FileReadDeny> {
        if self.canonical_roots.is_empty() {
            return Err(FileReadDeny::NoAllowedRoots);
        }
        // 1. canonicalise (resolves symlinks + `..`; NotFound if absent).
        let canonical = std::fs::canonicalize(requested).map_err(|_| FileReadDeny::NotFound)?;
        // 2. allowlist prefix over the RESOLVED path (defeats `..` + symlink).
        if !self.within_roots(&canonical) {
            return Err(FileReadDeny::OutsideAllowedRoots);
        }
        // 3. denylist over the resolved path's components + final name.
        if let Some(token) = denied_token(&canonical) {
            return Err(FileReadDeny::DeniedName(token));
        }
        // 4. size cap (refuse, never truncate).
        let meta = std::fs::metadata(&canonical).map_err(|_| FileReadDeny::IoError)?;
        if meta.len() > self.max_bytes {
            return Err(FileReadDeny::FileTooLarge);
        }
        // 5. read + hash. Re-bound by the actual read length (TOCTOU: the
        // bytes hashed are the bytes read).
        let bytes = std::fs::read(&canonical).map_err(|_| FileReadDeny::IoError)?;
        if bytes.len() as u64 > self.max_bytes {
            return Err(FileReadDeny::FileTooLarge);
        }
        let sha256_32 = sha256_32(&bytes);
        // 6. UTF-8 gate (binary ⇒ metadata only).
        let text = core::str::from_utf8(&bytes).ok().map(str::to_string);
        Ok(FileReadResult {
            canonical_path: canonical,
            bytes,
            sha256_32,
            text,
        })
    }

    /// Confine a NON-existent target for CREATION (the create-time analog of [`read`](Self::read)
    /// walls 1-3). The file itself may not exist, so we resolve + confine its PARENT:
    /// canonicalise the parent (`NotFound` if the parent is absent — we never create
    /// directories), require it WITHIN an allowed root (defeats `.` + symlink), then
    /// re-apply the secret-container denylist over the resolved path ( never CREATE a
    /// secret container). Returns the resolved canonical target (parent ⊕ file name). The
    /// caller still checks "still absent" at write time (the creation-staleness law).
    pub fn confine_new(&self, requested: &Path) -> Result<PathBuf, FileReadDeny> {
        if self.canonical_roots.is_empty() {
            return Err(FileReadDeny::NoAllowedRoots);
        }
        // The final component must be a plain file name (rejects "", "..", a trailing "/").
        let file_name = requested
            .file_name()
            .filter(|name| !name.is_empty())
            .ok_or(FileReadDeny::NotFound)?;
        // Resolve the PARENT (an empty parent is cwd-relative ".").
        let parent = match requested.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        // canonicalise the parent (resolves `..` + symlinks; NotFound if it is absent).
        let canonical_parent =
            std::fs::canonicalize(&parent).map_err(|_| FileReadDeny::NotFound)?;
        if !self.within_roots(&canonical_parent) {
            return Err(FileReadDeny::OutsideAllowedRoots);
        }
        let resolved = canonical_parent.join(file_name);
        if let Some(token) = denied_token(&resolved) {
            return Err(FileReadDeny::DeniedName(token));
        }
        Ok(resolved)
    }
}

/// Walk up from `start` to the nearest ancestor containing a [`WORKSPACE_MARKERS`]
/// entry (the project root); fall back to `start` if none is found. The
/// returned root is always `start` or an ancestor of it, so it can only WIDEN to a
/// project boundary, never to an unrelated tree. Bounded by filesystem depth.
#[must_use]
pub fn workspace_root_of(start: &Path) -> PathBuf {
    let mut cur = start;
    loop {
        if WORKSPACE_MARKERS.iter().any(|m| cur.join(m).exists()) {
            return cur.to_path_buf();
        }
        match cur.parent() {
            Some(parent) => cur = parent,
            None => return start.to_path_buf(),
        }
    }
}

/// The resolved workspace root the agent treats as the project root:
/// [`PROJECT_ROOT_ENV`] when set + non-empty, else the nearest ancestor of cwd
/// holding a [`WORKSPACE_MARKERS`] entry (via [`workspace_root_of`]). `None` only
/// when cwd is unavailable. Used to locate the optional per-project `.sinabrorules`
/// constitution file — a stat-only locate, never a policy read.
#[must_use]
pub fn workspace_root() -> Option<PathBuf> {
    match std::env::var(PROJECT_ROOT_ENV) {
        Ok(value) if !value.trim().is_empty() => Some(PathBuf::from(value.trim())),
        _ => std::env::current_dir()
            .ok()
            .map(|cwd| workspace_root_of(&cwd)),
    }
}

/// Parse the `:`-separated [`FILE_ROOTS_ENV`] value into candidate root
/// paths (PURE over the string — unit-testable without env mutation). Empty
/// segments are dropped; each survivor is canonicalised by
/// [`FileReadPolicy::new`] (a non-existent root cannot confine anything).
#[must_use]
pub fn parse_extra_roots(value: &str) -> Vec<PathBuf> {
    value
        .split(':')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(PathBuf::from)
        .collect()
}

/// Return the denylist token a path matches, or `None` if it is allowed by
/// the denylist. PURE over the path string — unit-testable without
/// touching the filesystem. Checks (a) any component name in
/// [`DENY_COMPONENTS`], (b) any non-root component that is a dotfile, and
/// (c) the final component vs the secret prefix/suffix lists.
#[must_use]
pub fn denied_token(path: &Path) -> Option<&'static str> {
    for component in path.components() {
        if let Component::Normal(os) = component {
            let name = os.to_string_lossy().to_ascii_lowercase();
            if let Some(token) = DENY_COMPONENTS.iter().find(|deny| name == **deny) {
                return Some(token);
            }
        }
    }
    let final_name = match path.file_name() {
        Some(os) => os.to_string_lossy().to_ascii_lowercase(),
        // No final component (e.g. `/`) — nothing to read; treat as denied.
        None => return Some("no_file_name"),
    };
    // Any dotfile final component is a secret-container by default
    // (classify-fail = deny). `.` / `.` cannot be a final component
    // of a canonical path, so this only catches real dot-prefixed names.
    if final_name.starts_with('.') {
        return Some("dotfile");
    }
    if let Some(token) = DENY_PREFIXES
        .iter()
        .find(|deny| final_name.starts_with(**deny))
    {
        return Some(token);
    }
    if let Some(token) = DENY_SUFFIXES
        .iter()
        .find(|deny| final_name.ends_with(**deny))
    {
        return Some(token);
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use std::io::Write;

    // ---- pure denylist (no fs) -------------------------------------------

    /// Every secret-container class denies, by suffix / prefix /
    /// dotfile / directory component; ordinary source files pass.
    #[test]
    fn denylist_refuses_secret_containers() {
        for denied in [
            "/proj/server.pem",
            "/proj/tls.key",
            "/proj/bundle.crt",
            "/proj/keystore.p12",
            "/home/u/id_rsa",
            "/home/u/id_ed25519.pub",
            "/proj/.env",
            "/proj/.env.local",
            "/proj/prod.env",
            "/proj/secrets.yaml",
            "/proj/credentials.json",
            "/home/u/.ssh/config",
            "/home/u/.aws/credentials",
            "/proj/.git/config",
            "/proj/node_modules/x/index.js",
            "/proj/.hidden",
        ] {
            assert!(
                denied_token(Path::new(denied)).is_some(),
                "expected denied: {denied}"
            );
        }
        for allowed in [
            "/proj/src/main.rs",
            "/proj/README.md",
            "/proj/Cargo.toml",
            "/proj/docs/design.md",
            "/proj/keymap.rs", // 'key' is a SUFFIX/exact match guard, not substring
        ] {
            assert_eq!(
                denied_token(Path::new(allowed)),
                None,
                "expected allowed: {allowed}"
            );
        }
    }

    /// TM R-F1 — owner-widened roots: an extra root admits a normal file (the
    /// drag-grant / `export` path); the denylist STILL refuses a secret
    /// container inside the widened root (widening never disables a wall).
    #[test]
    fn extra_root_widens_but_denylist_still_holds() {
        // Pure parse: `:`-split, trim, drop empties.
        assert_eq!(
            parse_extra_roots("/a/b: /c/d :"),
            vec![PathBuf::from("/a/b"), PathBuf::from("/c/d")]
        );
        assert!(parse_extra_roots("").is_empty());

        // A policy whose ONLY root is an explicitly-widened dir reads a normal
        // file there but still refuses a denylisted name (the .env container).
        let extra = unique_dir("widened");
        let policy =
            FileReadPolicy::new(&parse_extra_roots(&extra.to_string_lossy()), MAX_FILE_BYTES);
        let ok = write_file(&extra, "report.md", b"widened content");
        assert_eq!(
            policy.read(&ok).expect("reads").text.as_deref(),
            Some("widened content")
        );
        let env = write_file(&extra, "service.env", b"API_KEY=nope");
        match policy.read(&env) {
            Err(FileReadDeny::DeniedName(_)) => {}
            other => panic!("denylist must hold in a widened root, got {other:?}"),
        }
        std::fs::remove_dir_all(&extra).ok();
    }

    // ---- bounded read + walls (tempdir integration) ----------------------

    fn unique_dir(tag: &str) -> PathBuf {
        // Process- + tag-unique dir under the OS temp root (no tempfile dep;
        // Date/random are unavailable, so use pid + a tag + a static counter).
        use std::sync::atomic::{AtomicU32, Ordering};
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("sinabro_filectx_{}_{tag}_{n}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn write_file(dir: &Path, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).expect("create");
        f.write_all(content).expect("write");
        path
    }

    /// A normal file inside the root reads with a correct hash
    /// and UTF-8 text; a binary file returns metadata only (no text).
    #[test]
    fn reads_text_and_flags_binary() {
        let dir = unique_dir("read");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);

        let text_path = write_file(&dir, "note.md", "안녕 sinabro\nline two".as_bytes());
        let result = policy.read(&text_path).expect("reads");
        assert_eq!(
            result.sha256_32,
            sha256_32("안녕 sinabro\nline two".as_bytes())
        );
        assert_eq!(result.text.as_deref(), Some("안녕 sinabro\nline two"));
        assert!(!result.is_binary());

        let bin_path = write_file(&dir, "blob.bin", &[0xFF, 0xFE, 0x00, 0x01]);
        let bin = policy.read(&bin_path).expect("reads binary metadata");
        assert!(bin.is_binary());
        assert_eq!(bin.text, None);
        assert_eq!(bin.len_bytes(), 4);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// `.` traversal AND symlink escape both reject (the prefix
    /// check is over the canonicalised, symlink-resolved path).
    #[test]
    fn traversal_and_symlink_escape_rejected() {
        let root = unique_dir("root");
        let outside = unique_dir("outside");
        let secret_outside = write_file(&outside, "target.txt", b"outside secret");
        let policy = FileReadPolicy::new(std::slice::from_ref(&root), MAX_FILE_BYTES);

        // `..` traversal: a path that climbs out of the root resolves outside.
        let traversal = root.join("..").join(
            outside
                .file_name()
                .expect("name")
                .to_string_lossy()
                .to_string(),
        );
        let traversal = traversal.join("target.txt");
        assert_eq!(
            policy.read(&traversal),
            Err(FileReadDeny::OutsideAllowedRoots),
            "..-traversal must reject"
        );

        // symlink inside the root pointing OUTSIDE: canonicalise resolves the
        // target, which is outside ⇒ reject (not the link path).
        #[cfg(unix)]
        {
            let link = root.join("escape_link.txt");
            std::os::unix::fs::symlink(&secret_outside, &link).expect("symlink");
            assert_eq!(
                policy.read(&link),
                Err(FileReadDeny::OutsideAllowedRoots),
                "symlink escape must reject on the RESOLVED path"
            );
        }
        let _ = &secret_outside;

        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&outside).ok();
    }

    /// A denylisted file INSIDE the root is still refused (the
    /// denylist is independent of the allowlist).
    #[test]
    fn denylisted_file_inside_root_refused() {
        let dir = unique_dir("deny");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        let env_path = write_file(&dir, "service.env", b"API_KEY=should-never-read");
        match policy.read(&env_path) {
            Err(FileReadDeny::DeniedName(_)) => {}
            other => panic!("expected DeniedName, got {other:?}"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// An over-cap file is refused, not truncated.
    #[test]
    fn over_cap_file_refused() {
        let dir = unique_dir("cap");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), 16);
        let big = write_file(&dir, "big.txt", &[b'x'; 17]);
        assert_eq!(policy.read(&big), Err(FileReadDeny::FileTooLarge));
        let ok = write_file(&dir, "small.txt", &[b'x'; 16]);
        assert!(policy.read(&ok).is_ok());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Fail-closed: an empty allowlist refuses everything; a non-existent
    /// path is NotFound.
    #[test]
    fn fail_closed_paths() {
        let empty = FileReadPolicy::new(&[], MAX_FILE_BYTES);
        assert_eq!(
            empty.read(Path::new("/etc/hosts")),
            Err(FileReadDeny::NoAllowedRoots)
        );

        let dir = unique_dir("missing");
        let policy = FileReadPolicy::new(std::slice::from_ref(&dir), MAX_FILE_BYTES);
        assert_eq!(
            policy.read(&dir.join("does_not_exist.txt")),
            Err(FileReadDeny::NotFound)
        );
        std::fs::remove_dir_all(&dir).ok();

        assert_eq!(
            FileReadDeny::OutsideAllowedRoots.class_label(),
            "file_context.outside_allowed_roots"
        );
        assert_eq!(
            FileReadDeny::DeniedName("dotfile").class_label(),
            "file_context.denied_name"
        );
    }

    #[test]
    fn workspace_root_of_walks_up_to_a_marker_and_returns_an_ancestor() {
        // a nested dir under a base that has a `.git` marker resolves to base.
        let base = unique_dir("ws_root");
        let nested = base.join("a").join("b");
        std::fs::create_dir_all(&nested).expect("mk nested");
        std::fs::create_dir_all(base.join(".git")).expect("mk .git");
        let root = workspace_root_of(&nested);
        assert_eq!(
            std::fs::canonicalize(&root).ok(),
            std::fs::canonicalize(&base).ok(),
            "walks up to the .git ancestor"
        );
        // the detected root is always an ancestor (prefix) of the start — it can only
        // WIDEN to a project boundary, never reach an unrelated tree.
        assert!(nested.starts_with(&root));
        std::fs::remove_dir_all(&base).ok();
    }
}
