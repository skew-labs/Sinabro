//! The AGENT REGISTRY loop-tool glue (the agent-native GitHub, mid-think).
//!
//! The think-loop's `registry index` / `registry fetch <artifact-id>` executors read the
//! OWNER-PINNED repo — a local pointer file naming the main-index Walrus blob — never a
//! model-supplied blob-id (-1: content-hash proves *integrity*, not *authenticity*;
//! the trust anchor must stay out of the model's hands). The pointer is written ONLY by
//! the owner-armed `registry publish` ceremony and the owner-invoked `registry pin`
//! dispatch verb (-6); the loop is read-only on it.
//!
//! Every fetched artifact passes the supply-chain seatbelt
//! [`crate::dispatch::registry_content_verified`] (bytes must re-hash to the id, else
//! REJECTED-2), and the caller redact-belts + bounds + advisory-frames the render
//! (-5). Fetched bytes are DATA, never executed. NO funds; custody
//! / chain-write HARD-LOCKED.
//!
//! This module is PURE except the `put-fixture-net`-gated [`net`] glue (the
//! `memory_walrus` idiom): pointer file + blob-id shape + prefix resolution here; the
//! testnet GET lives behind the feature and honest-degrades off-build (-8).

use std::path::{Path, PathBuf};

/// The local pointer file (under the data dir) naming the main-index Walrus blob-id of
/// the repo the agent's loop tools read (base64url text). Written ONLY by the owner-armed
/// publish ceremony + the owner-invoked `registry pin` verb. NOT a secret (a blob-id is a
/// public content address).
pub const REGISTRY_POINTER_FILE: &str = "registry_repo.ref";

/// Byte cap for the artifact-content preview a loop fetch renders (bounded well under
/// [`crate::agent_loop::AGENT_LOOP_TOOL_RESULT_CAP_BYTES`]; char-safe truncation at the
/// call site). The preview is DATA — advisory, never instructions, never executed.
pub const REGISTRY_PREVIEW_CAP_BYTES: usize = 800;

/// A Walrus blob-id is base64url(32-byte digest), NO padding ⇒ EXACTLY 43 chars of
/// `[A-Za-z0-9_-]` (Python-verified against 6 real testnet ids, 2026-07-06). Anything
/// else is rejected by `registry pin` fail-closed (a 64-hex artifact id, a path, a URL
/// all fail the length pin).
pub const WALRUS_BLOB_ID_LEN: usize = 43;

/// Shape gate for `registry pin <main-index-blob-id>`: exactly
/// [`WALRUS_BLOB_ID_LEN`] base64url chars. A shape gate only — the REAL integrity gate
/// is the fetch-time content-hash seatbelt (-2).
#[must_use]
pub fn looks_like_walrus_blob_id(s: &str) -> bool {
    s.len() == WALRUS_BLOB_ID_LEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The pointer-file path under a data dir.
#[must_use]
pub fn registry_pointer_path(data_dir: &Path) -> PathBuf {
    data_dir.join(REGISTRY_POINTER_FILE)
}

/// Read the pinned repo's main-index blob-id (trimmed). `None` if absent / empty /
/// unreadable — an honest "nothing pinned yet", never a fabricated pointer.
#[must_use]
pub fn read_registry_pointer(data_dir: &Path) -> Option<String> {
    let text = std::fs::read_to_string(registry_pointer_path(data_dir)).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Write the pinned repo's main-index blob-id (a public content address). OWNER surfaces
/// only (`registry publish` / `registry pin`) — the loop path never calls this (-6).
pub fn write_registry_pointer(data_dir: &Path, blob_id: &str) -> std::io::Result<()> {
    std::fs::write(registry_pointer_path(data_dir), blob_id.as_bytes())
}

/// Minimum artifact-id prefix a loop fetch accepts (hex chars). The index render shows
/// 16-char prefixes (64 bits); 8 is the git-style floor — below it, resolution refuses
/// (deterministic, never a guess).
pub const ARTIFACT_ID_PREFIX_MIN: usize = 8;

/// Typed resolution failures for [`resolve_artifact`] (fail-closed; never a guess).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResolveError {
    /// The query was shorter than [`ARTIFACT_ID_PREFIX_MIN`].
    TooShort,
    /// No entry's id matched the query (exact or prefix).
    NotFound,
    /// More than one entry's id starts with the prefix — refuse to pick.
    Ambiguous,
}

impl ResolveError {
    /// A stable render label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ResolveError::TooShort => "id prefix too short (need >= 8 chars)",
            ResolveError::NotFound => "artifact id not in the pinned repo",
            ResolveError::Ambiguous => "ambiguous id prefix (matches several artifacts)",
        }
    }
}

/// Resolve an artifact by FULL id or a UNIQUE >=8-char prefix, inside the pinned
/// manifest ONLY (deterministic: exact match wins; a prefix must be unique or it is
/// refused — the git short-hash rule).
pub fn resolve_artifact<'a>(
    manifest: &'a crate::agent_registry::RegistryManifest,
    id_or_prefix: &str,
) -> Result<&'a crate::agent_registry::AgentArtifact, ResolveError> {
    let query = id_or_prefix.trim();
    if let Some(exact) = manifest.get(query) {
        return Ok(exact);
    }
    if query.len() < ARTIFACT_ID_PREFIX_MIN {
        return Err(ResolveError::TooShort);
    }
    let mut hit: Option<&crate::agent_registry::AgentArtifact> = None;
    for a in &manifest.entries {
        if a.id.starts_with(query) {
            if hit.is_some() {
                return Err(ResolveError::Ambiguous);
            }
            hit = Some(a);
        }
    }
    hit.ok_or(ResolveError::NotFound)
}

// ===========================================================================
// EXECUTE A FETCHED ARTIFACT (owner-armed, network-DENIED sandbox)
// ===========================================================================

/// The fixed prefix for a materialized artifact temp file (the
/// gated-download confinement idiom). A materialized artifact lands ONLY under
/// `temp_dir` with this prefix + a separator-free id-derived name (-4).
pub const ARTIFACT_TEMP_PREFIX: &str = "sinabro-registry-artifact-";

/// The placeholder the owner puts in the `registry exec` command where the
/// materialized artifact PATH is substituted (-6: the owner supplies the literal
/// command; D-6 only fills this in — the artifact never picks its own interpreter).
pub const ARTIFACT_PLACEHOLDER: &str = "{artifact}";

/// The temp path a verified artifact is materialized to (-4): a DIRECT child of
/// `std::env::temp_dir()` with a SEPARATOR-FREE name (`prefix` + only-hex-of-id +
/// `.bin`). The name is OURS and keeps ONLY hex from the id, so it can NEVER contain a
/// path separator nor be `..`/empty — the write cannot escape temp (not the workspace /
/// `.ssh` / `.git`). Mirrors `download_fetch::temp_path_for`.
#[must_use]
pub fn artifact_temp_path(id: &str) -> PathBuf {
    let safe_id: String = id
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(32)
        .collect();
    std::env::temp_dir().join(format!("{ARTIFACT_TEMP_PREFIX}{safe_id}.bin"))
}

/// Substitute the materialized artifact `path` for every [`ARTIFACT_PLACEHOLDER`] in the
/// owner's `command` (-6). Returns `None` if the command has no placeholder — the
/// whole point of `registry exec` is to run the fetched artifact, so a command that never
/// references it is a usage error (fail-closed, never a silent no-op).
#[must_use]
pub fn substitute_artifact_path(command: &str, path: &str) -> Option<String> {
    if !command.contains(ARTIFACT_PLACEHOLDER) {
        return None;
    }
    Some(command.replace(ARTIFACT_PLACEHOLDER, path))
}

/// The CLOSED extension → interpreter map (-1). **WE own this**, not the
/// artifact: an artifact declares only its `kind` + filename; the interpreter is derived
/// HERE from the extension, so a hostile artifact can never pick its own execution shape.
/// A deliberately minimal set: explicit interpreters that read a data
/// file — NO shell, NO binaries (an unmapped extension is REFUSED, -2). Each maps to
/// an ABSOLUTE interpreter path resolved from a small allowlist of standard locations at
/// call time (the sandbox env is scrubbed; a bare name would not resolve).
pub const AUTO_EXEC_INTERPRETERS: &[(&str, &str)] = &[
    ("py", "python3"),
    ("js", "node"),
    ("rb", "ruby"),
    ("pl", "perl"),
    ("lua", "lua"),
];

/// The lowercased extension of a filename-ish `summary` (the segment after the LAST `.`),
/// or `None` if there is no extension. PURE.
#[must_use]
pub fn artifact_extension(summary: &str) -> Option<String> {
    let name = summary.rsplit(['/', '\\']).next().unwrap_or(summary);
    let (stem, ext) = name.rsplit_once('.')?;
    if stem.is_empty() || ext.is_empty() {
        return None;
    }
    Some(ext.to_ascii_lowercase())
}

/// The interpreter NAME for a `summary`'s extension via the closed map, or `None`
/// (unmapped ⇒ auto-exec refused, -2). PURE.
#[must_use]
pub fn interpreter_for(summary: &str) -> Option<&'static str> {
    let ext = artifact_extension(summary)?;
    AUTO_EXEC_INTERPRETERS
        .iter()
        .find(|(e, _)| *e == ext)
        .map(|(_, interp)| *interp)
}

/// Standard absolute locations an auto-exec interpreter may live at (the sandbox env is
/// scrubbed to PATH/HOME/LANG/TERM, but we resolve to an absolute path so the run does not
/// depend on PATH resolution inside the sandbox). Checked in order; first existing wins.
const AUTO_EXEC_INTERP_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"];

/// Resolve an interpreter NAME to an absolute path that exists (or `None`). PURE-ish (only
/// filesystem existence checks; no exec). Keeps the derived command fully-qualified.
#[must_use]
pub fn resolve_interpreter_path(name: &str) -> Option<String> {
    for dir in AUTO_EXEC_INTERP_DIRS {
        let p = std::path::Path::new(dir).join(name);
        if p.is_file() {
            return Some(p.to_string_lossy().to_string());
        }
    }
    None
}

/// Derive the auto-exec command `<absolute-interpreter> <materialized-path>` for an
/// artifact whose `summary` maps to a known interpreter (-1/2). `Err(reason)` when the
/// extension is unmapped OR the interpreter binary is not installed (fail-closed; the owner
/// falls back to the owner-literal `registry exec` — D-6). The command shape is ALWAYS
/// `<interpreter> <path>` — never artifact-controlled.
pub fn derive_auto_command(summary: &str, materialized_path: &str) -> Result<String, String> {
    let name = interpreter_for(summary).ok_or_else(|| {
        "no auto-interpreter for this artifact (extension unmapped); use `registry exec … -- <command>` instead"
            .to_string()
    })?;
    let abs = resolve_interpreter_path(name)
        .ok_or_else(|| format!("interpreter `{name}` not installed on this machine"))?;
    Ok(format!("{abs} {materialized_path}"))
}

/// The feature-gated network navigation the AUTONOMOUS loop executors use
/// (the `memory_walrus::net` idiom). Off-build, the loop tools honest-degrade
/// (-8). Testnet aggregator only; the GET is a content-free public READ;
/// bytes are UNTRUSTED until try-AEAD-open-else-plaintext + the content-hash
/// seatbelt pass. NO funds.
#[cfg(feature = "put-fixture-net")]
mod net {
    use crate::agent_registry::RegistryManifest;
    use crate::memory_store::PersistedStore;

    const REGISTRY_GET_TIMEOUT_MS: u32 = 30_000;

    /// GET a blob by its cid, routing to the backend the cid's SHAPE implies
    /// (`classify_cid`): a 64-hex cid is a LocalCAS blob (no network, no crypto), a
    /// 43-base64url cid is a Walrus blob. Bytes are UNTRUSTED until the registry's
    /// content-hash seatbelt verifies them. This one primitive makes every fetch
    /// (loop / exec / publish round-trip) backend-independent.
    fn store_get(cid: &str) -> Option<Vec<u8>> {
        use crate::content_store::{CidBackend, ContentStore, classify_cid};
        match classify_cid(cid) {
            CidBackend::LocalCas => crate::content_store::LocalCasStore::open_local()?.get(cid),
            CidBackend::Walrus => walrus_get_testnet(cid),
            CidBackend::S3 => {
                #[cfg(feature = "s3")]
                {
                    crate::s3_store::S3Store::from_env()?.get(cid)
                }
                #[cfg(not(feature = "s3"))]
                {
                    None // honest: the S3 adapter is not compiled
                }
            }
            CidBackend::Unknown => None,
        }
    }

    /// GET a blob from the TESTNET aggregator by a STORED blob-id text (the
    /// `memory_walrus` idiom). Bytes are UNTRUSTED until verified.
    fn walrus_get_testnet(blob_text: &str) -> Option<Vec<u8>> {
        use mnemos_c_walrus::aggregator::{
            AggregatorEndpoint, AggregatorGetRequest, AggregatorResponseDecision,
            fetch_blob_with_transport,
        };
        use mnemos_c_walrus::blob_id_from_text;
        use mnemos_c_walrus::reqwest_transport::ReqwestAggregator;
        let blob_id = blob_id_from_text(blob_text)?;
        let request = AggregatorGetRequest::new(AggregatorEndpoint::testnet_public(), &blob_id);
        let mut agg = ReqwestAggregator::new(REGISTRY_GET_TIMEOUT_MS).ok()?;
        match fetch_blob_with_transport(&mut agg, &request, 0x6713_0007, 2).ok()? {
            AggregatorResponseDecision::Fetched { body, .. } => Some(body),
            _ => None,
        }
    }

    /// PRIVATE (AEAD ciphertext) vs PUBLIC (plaintext) is a per-repo publish choice the
    /// fetcher infers by *try-open-else-raw* (D-3: GCM-SIV open fails cleanly on
    /// non-ciphertext; a missing local key simply means only public repos open).
    fn open_or_raw(store: Option<&PersistedStore>, raw: Vec<u8>) -> Vec<u8> {
        store.and_then(|s| s.open_index(&raw).ok()).unwrap_or(raw)
    }

    /// Load the OWNER-PINNED repo's manifest: pointer → GET → try-open-else-raw →
    /// fail-closed AGRX decode. `Err(reason)` honest miss (no pointer / propagation /
    /// tamper). Returns `(pointer, manifest)`.
    pub fn load_pinned_manifest(
        store: Option<&PersistedStore>,
    ) -> Result<(String, RegistryManifest), &'static str> {
        let dir = crate::memory_store::data_dir().map_err(|_| "no data dir")?;
        let pointer = super::read_registry_pointer(&dir).ok_or(
            "no repo pinned (owner: `registry publish …` or `registry pin <blob-id>` first)",
        )?;
        let fetched = store_get(&pointer)
            .ok_or("pinned main index not fetched (local CAS miss / Walrus propagation)")?;
        let manifest = RegistryManifest::from_bytes(&open_or_raw(store, fetched)).map_err(
            |_| "pinned main index did not decode (not a registry / wrong key / tampered)",
        )?;
        Ok((pointer, manifest))
    }

    /// A loop fetch's VERIFIED result: the resolved artifact's identity + its
    /// seatbelt-passed content bytes. Constructed ONLY after
    /// [`crate::dispatch::registry_content_verified`] returns `true`.
    pub struct VerifiedArtifact {
        /// The FULL artifact id (hex content address).
        pub id: String,
        /// The artifact kind label.
        pub kind: &'static str,
        /// The bounded summary recorded at publish time.
        pub summary: String,
        /// The verified content bytes (DATA — never executed).
        pub content: Vec<u8>,
    }

    /// Fetch ONE artifact from the pinned repo by full id / unique >=8-char prefix,
    /// and VERIFY it through the D-3 seatbelt chokepoint. `Err(reason)` fail-closed —
    /// a verify failure NEVER returns bytes (-2).
    pub fn fetch_pinned_artifact(
        store: Option<&PersistedStore>,
        id_or_prefix: &str,
    ) -> Result<VerifiedArtifact, String> {
        let (_pointer, manifest) = load_pinned_manifest(store)?;
        let artifact =
            super::resolve_artifact(&manifest, id_or_prefix).map_err(|e| e.label().to_string())?;
        let blob_ref = artifact
            .blob_ref
            .as_deref()
            .ok_or_else(|| "artifact has no published blob (local-only entry)".to_string())?;
        let raw = store_get(blob_ref).ok_or_else(|| {
            "artifact blob not fetched (local CAS miss / testnet propagation)".to_string()
        })?;
        let content = open_or_raw(store, raw);
        // -2 — the SAME supply-chain seatbelt chokepoint: bytes must re-hash to
        // the recorded digest AND the id must re-derive, else REJECTED (never rendered).
        if !crate::dispatch::registry_content_verified(artifact, &content) {
            return Err(
                "REJECTED — fetched bytes do NOT re-hash to the artifact id (tamper / substitution / wrong key); withheld"
                    .to_string(),
            );
        }
        Ok(VerifiedArtifact {
            id: artifact.id.clone(),
            kind: artifact.kind.label(),
            summary: artifact.summary.clone(),
            content,
        })
    }

    /// A materialized artifact ready for an owner-approved `registry exec`: the
    /// confined temp path its VERIFIED bytes were written to + its identity.
    pub struct MaterializedArtifact {
        /// The FULL artifact id.
        pub id: String,
        /// The artifact kind label.
        pub kind: &'static str,
        /// The bounded summary (the filename — D-7 derives the extension from it).
        pub summary: String,
        /// The confined temp path (a direct child of `temp_dir()`, separator-free).
        pub path: std::path::PathBuf,
        /// The verified byte length.
        pub bytes: usize,
    }

    /// Fetch + content-hash-VERIFY an artifact (the seatbelt path) and MATERIALIZE
    /// its bytes to a CONFINED temp file (-2/4). Materializes ONLY the verified
    /// `fetch_pinned_artifact` return — a REJECTED tamper never reaches disk. The write is a
    /// direct child of `temp_dir()` with a separator-free id-derived name, so it cannot escape
    /// temp. `Err(reason)` fail-closed (no bytes written on any failure). The caller runs the
    /// owner-supplied command over this path through the network-DENIED exec chokepoint.
    pub fn materialize_verified_artifact(
        store: Option<&PersistedStore>,
        id_or_prefix: &str,
    ) -> Result<MaterializedArtifact, String> {
        let verified = fetch_pinned_artifact(store, id_or_prefix)?;
        let path = super::artifact_temp_path(&verified.id);
        std::fs::write(&path, &verified.content)
            .map_err(|e| format!("could not materialize the verified artifact to temp: {e}"))?;
        Ok(MaterializedArtifact {
            id: verified.id,
            kind: verified.kind,
            summary: verified.summary,
            path,
            bytes: verified.content.len(),
        })
    }
}

#[cfg(feature = "put-fixture-net")]
pub use net::{
    MaterializedArtifact, VerifiedArtifact, fetch_pinned_artifact, load_pinned_manifest,
    materialize_verified_artifact,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_registry::{AgentArtifact, ArtifactKind, RegistryManifest};

    fn manifest_of(digests: &[[u8; 32]]) -> RegistryManifest {
        let mut m = RegistryManifest::default();
        for (i, d) in digests.iter().enumerate() {
            m.upsert(AgentArtifact::new(
                ArtifactKind::Code,
                *d,
                "agent://local".to_string(),
                &format!("artifact-{i}"),
                None,
            ));
        }
        m
    }

    #[test]
    fn pointer_round_trips_and_absent_is_none() {
        let dir = std::env::temp_dir().join(format!("sinabro_reg_ptr_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        assert_eq!(read_registry_pointer(&dir), None, "absent ⇒ honest None");
        let blob = "e9gNh5jlTZIKFzKtIHBjby8f07H3xJbkqAf6hT-HDAQ";
        write_registry_pointer(&dir, blob).expect("write");
        assert_eq!(read_registry_pointer(&dir).as_deref(), Some(blob));
        // whitespace-only ⇒ honest None (never an empty pointer)
        std::fs::write(registry_pointer_path(&dir), b"  \n").expect("write ws");
        assert_eq!(read_registry_pointer(&dir), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn blob_id_shape_gate_is_exact() {
        // 6 real testnet ids are 43 base64url chars (Python-verified) — one suffices here.
        assert!(looks_like_walrus_blob_id(
            "P9H_vtuehM2Tgqcio5DD24e34ICo8nTQt51WvGVjaBg"
        ));
        assert!(!looks_like_walrus_blob_id("abc"), "too short");
        assert!(
            !looks_like_walrus_blob_id(&"a".repeat(64)),
            "a 64-hex artifact id is NOT a blob-id (length pin)"
        );
        assert!(
            !looks_like_walrus_blob_id("P9H_vtuehM2Tgqcio5DD24e34ICo8nTQt51WvGVjaB/"),
            "raw base64 '/' is not base64url"
        );
        assert!(
            !looks_like_walrus_blob_id("https://example.com/e9gNh5jlTZIKFzKtIHBjby8"),
            "a URL is rejected"
        );
    }

    #[test]
    fn resolve_is_exact_then_unique_prefix_fail_closed() {
        // Two digests sharing NO prefix + the resolution rules.
        let m = manifest_of(&[[0xaa; 32], [0xbb; 32]]);
        let full_a = m.entries[0].id.clone();
        let full_b = m.entries[1].id.clone();
        assert_ne!(full_a, full_b);
        // exact
        assert_eq!(resolve_artifact(&m, &full_a).expect("exact").id, full_a);
        // unique 16-char prefix (what the index render shows)
        assert_eq!(
            resolve_artifact(&m, &full_b[..16]).expect("prefix").id,
            full_b
        );
        // too short
        assert_eq!(
            resolve_artifact(&m, &full_a[..4]),
            Err(ResolveError::TooShort)
        );
        // not found
        assert_eq!(
            resolve_artifact(&m, "0000000000000000"),
            Err(ResolveError::NotFound)
        );
    }

    #[test]
    fn resolve_refuses_an_ambiguous_prefix() {
        // Hand-built entries whose ids share an 8-char prefix (fields are pub; a real
        // hash collision is not constructible through the codec, but a HOSTILE or
        // hand-edited manifest is exactly what the fail-closed rule must survive).
        let a = AgentArtifact {
            id: format!("deadbeef{:056}", 1),
            kind: ArtifactKind::Code,
            content_digest: [0u8; 32],
            author: "agent://local".to_string(),
            summary: "a".to_string(),
            blob_ref: None,
        };
        let b = AgentArtifact {
            id: format!("deadbeef{:056}", 2),
            kind: ArtifactKind::Code,
            content_digest: [1u8; 32],
            author: "agent://local".to_string(),
            summary: "b".to_string(),
            blob_ref: None,
        };
        let m = RegistryManifest {
            entries: vec![a.clone(), b],
        };
        assert_eq!(
            resolve_artifact(&m, "deadbeef"),
            Err(ResolveError::Ambiguous),
            "a shared prefix is REFUSED, never a guess"
        );
        // …while the FULL id still resolves exactly.
        assert_eq!(resolve_artifact(&m, &a.id).expect("exact").id, a.id);
    }

    // The artifact temp path is CONFINED (-4): a direct child of temp_dir
    // with a separator-free name, even for a hostile id trying path traversal.
    #[test]
    fn artifact_temp_path_is_confined_separator_free() {
        let td = std::env::temp_dir();
        // A benign hex id → a direct child, name = prefix + hex + .bin.
        let p = artifact_temp_path("a62d8f451f16abcd");
        assert_eq!(p.parent(), Some(td.as_path()), "a DIRECT child of temp_dir");
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(name.starts_with(ARTIFACT_TEMP_PREFIX) && name.ends_with(".bin"));
        assert!(!name.contains('/') && !name.contains(std::path::MAIN_SEPARATOR));
        // A HOSTILE id (traversal / separators / absolute) keeps ONLY hex ⇒ cannot escape.
        let hostile = artifact_temp_path("../../etc/passwd\0/root");
        assert_eq!(
            hostile.parent(),
            Some(td.as_path()),
            "traversal cannot escape temp"
        );
        let hname = hostile.file_name().unwrap().to_string_lossy();
        assert!(!hname.contains("..") && !hname.contains('/') && !hname.contains("passwd"));
    }

    // The {artifact} substitution is mandatory (-6): a command that never
    // references the artifact is a fail-closed usage error (None), never a silent no-op.
    #[test]
    fn substitute_requires_the_placeholder() {
        assert_eq!(
            substitute_artifact_path("python3 {artifact} --check", "/tmp/x.bin").as_deref(),
            Some("python3 /tmp/x.bin --check")
        );
        // multiple placeholders all fill
        assert_eq!(
            substitute_artifact_path("cat {artifact} && wc -l {artifact}", "/tmp/x.bin").as_deref(),
            Some("cat /tmp/x.bin && wc -l /tmp/x.bin")
        );
        // no placeholder ⇒ None (fail-closed usage error)
        assert_eq!(substitute_artifact_path("echo hello", "/tmp/x.bin"), None);
    }

    // The interpreter comes from OUR closed map keyed on extension (-1); an
    // unmapped extension is refused (-2); the artifact never picks the interpreter.
    #[test]
    fn interpreter_map_is_closed_and_ours() {
        assert_eq!(artifact_extension("strategy.py").as_deref(), Some("py"));
        assert_eq!(artifact_extension("dir/sub/tool.JS").as_deref(), Some("js"));
        assert_eq!(artifact_extension("no_extension"), None);
        assert_eq!(artifact_extension(".hidden"), None, "a dotfile has no stem");
        // mapped
        assert_eq!(interpreter_for("x.py"), Some("python3"));
        assert_eq!(interpreter_for("x.js"), Some("node"));
        assert_eq!(interpreter_for("x.rb"), Some("ruby"));
        // UNMAPPED (deliberately minimal set: no shell, no binaries) ⇒ refused
        assert_eq!(
            interpreter_for("x.sh"),
            None,
            "shell is NOT in the closed map"
        );
        assert_eq!(interpreter_for("x.exe"), None, "a binary is refused");
        assert_eq!(interpreter_for("readme.md"), None);
        assert_eq!(interpreter_for("opaque"), None);
    }

    // The derived command is ALWAYS `<absolute-interpreter> <path>` (never
    // artifact-controlled); an unmapped extension fails closed with a fallback hint.
    #[test]
    fn derive_auto_command_shape_and_fail_closed() {
        // Unmapped ⇒ Err (owner falls back to owner-literal `registry exec`).
        let unmapped = derive_auto_command("x.sh", "/tmp/a.bin");
        assert!(unmapped.is_err(), "shell is unmapped ⇒ refused");
        assert!(unmapped.unwrap_err().contains("registry exec"));
        // Mapped: if python3 is installed, the command is `<abs>/python3 /tmp/a.bin`.
        match derive_auto_command("x.py", "/tmp/a.bin") {
            Ok(cmd) => {
                assert!(
                    cmd.ends_with(" /tmp/a.bin"),
                    "path is the sole argument: {cmd}"
                );
                assert!(
                    cmd.contains("python3"),
                    "our interpreter, not the artifact's: {cmd}"
                );
                assert!(cmd.starts_with('/'), "absolute interpreter path: {cmd}");
            }
            // python3 absent on this machine ⇒ honest not-installed error (still fail-closed).
            Err(e) => assert!(e.contains("not installed"), "{e}"),
        }
    }
}
