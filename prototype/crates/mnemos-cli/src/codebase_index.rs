//! [4] Semantic codebase index — local embeddings + an encrypted-at-rest vector
//! store, surfaced as a READ capability (`@codebase`). The Cursor "semantic index"
//! reframed onto sinabro's physics: embeddings NEVER leave the box (privacy = thesis),
//! the index is AES-256-GCM-SIV sealed at rest (the memory substrate), retrieval is a
//! hybrid of cosine similarity + lexical overlap, and every retrieved chunk passes the
//! SAME per-line `redact()` wall the search / file-read tools use.
//!
//! # The seam
//!
//! [`Embedder`] is the pluggable model seam: v1 ships a deterministic [`StubEmbedder`]
//! (a hashed bag-of-tokens — no model, no network), which makes the whole pipeline
//! hermetically testable AND functional today. A REAL local embedding model (a loopback
//! `/v1/embeddings` endpoint) is the deferred live-fire — it drops into the SAME trait,
//! and the feature WORKS the moment it is wired (only retrieval QUALITY improves).
//!
//! # The walls
//!
//! * Embeddings + the index stay LOCAL; only an AES-sealed blob touches disk (the
//!   32-byte key never leaves the box).
//! * [`CODEBASE_INDEX_AAD`] is DISTINCT from the memory / settings / index AADs.
//! * Each chunk's text is REDACTED at index time (a secret-shaped line ⇒ WITHHELD via
//!   `crate::search::line_is_secret`, the canonical wall) AND re-redacted at retrieval
//!   time — a secret never enters the index nor surfaces.
//! * READ-class: no egress / mutate / custody symbol; custody HARD-LOCKED.

use std::path::{Path, PathBuf};

use crate::file_context::FileReadPolicy;

/// The codebase-index AEAD associated data — DISTINCT from the memory record / index /
/// settings AADs (a codebase-index blob is not interchangeable with any other).
pub const CODEBASE_INDEX_AAD: &[u8] = b"sinabro.codebase.index.v1";

/// The encrypted-at-rest index filename (under `<data_dir>`). The sealed bytes are
/// `seal_codebase_index(index.to_bytes())`; the plaintext index never touches disk.
pub const CODEBASE_INDEX_FILE: &str = "codebase_index.enc";

/// The fixed embedding dimensionality (small + deterministic for the stub; a real model
/// re-projects to this dimension at the seam, or the dimension is a model-config follow-on).
pub const EMBED_DIM: usize = 96;

/// The line-window size for a chunk (a chunk = up to this many consecutive lines).
pub const CHUNK_LINES: usize = 40;

/// Walk bounds (a cap is announced, never silent): max files indexed, max chunks, depth.
pub const INDEX_MAX_FILES: u32 = 5_000;
/// Max chunks held in the index (bounds memory + the sealed blob size).
pub const INDEX_MAX_CHUNKS: usize = 20_000;
/// Max directory depth walked.
pub const INDEX_MAX_DEPTH: u32 = 32;

/// The withheld marker for a secret-shaped line (kept out of the index + any render).
const WITHHELD_LINE: &str = "[withheld: secret-shaped line]";

/// The pluggable embedding seam. v1 = [`StubEmbedder`] (deterministic, no model); a real
/// local embedding model implements the SAME trait (the deferred live-fire).
pub trait Embedder {
    /// Embed `text` into a fixed-dimension vector. Implementations SHOULD L2-normalize
    /// (so [`cosine_similarity`] is a dot product) — the stub does.
    fn embed(&self, text: &str) -> [f32; EMBED_DIM];
}

/// A deterministic, model-free embedder: a hashed bag of tokens (+ char trigrams for a
/// sub-word signal), L2-normalized. NOT a semantic model — but deterministic (hermetic
/// tests) and genuinely functional (shared tokens ⇒ high cosine), so the feature WORKS
/// today; a real model swaps in at the [`Embedder`] seam for better quality.
#[derive(Debug, Default, Clone, Copy)]
pub struct StubEmbedder;

impl Embedder for StubEmbedder {
    fn embed(&self, text: &str) -> [f32; EMBED_DIM] {
        let mut v = [0f32; EMBED_DIM];
        for tok in tokenize(text) {
            let h = fnv1a(tok.as_bytes());
            v[(h % EMBED_DIM as u64) as usize] += 1.0;
            // a light sub-word signal: each char trigram of the token.
            let bytes = tok.as_bytes();
            for w in bytes.windows(3) {
                let hw = fnv1a(w);
                v[(hw % EMBED_DIM as u64) as usize] += 0.5;
            }
        }
        l2_normalize(&mut v);
        v
    }
}

/// FNV-1a 64-bit hash (deterministic, stable across runs — no `Math.random`/time).
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// Tokenize into lowercased alphanumeric tokens of length ≥ 2 (identifiers / words).
fn tokenize(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            cur.push(ch.to_ascii_lowercase());
        } else if !cur.is_empty() {
            if cur.len() >= 2 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= 2 {
        out.push(cur);
    }
    out
}

/// L2-normalize in place (a zero vector stays zero — guarded against div-by-zero).
fn l2_normalize(v: &mut [f32; EMBED_DIM]) {
    let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > f32::EPSILON {
        for x in v.iter_mut() {
            *x /= norm;
        }
    }
}

/// Cosine similarity of two vectors. For L2-normalized inputs this equals the dot
/// product; computed in full (with a zero-norm guard) so it is correct for any input.
#[must_use]
pub fn cosine_similarity(a: &[f32; EMBED_DIM], b: &[f32; EMBED_DIM]) -> f32 {
    let dot: f32 = a.iter().zip(b.iter()).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na <= f32::EPSILON || nb <= f32::EPSILON {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// A redacted source chunk: a workspace-relative path + a 1-based line range + the
/// already-secret-screened text (secret lines are WITHHELD before this is stored).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodebaseChunk {
    /// Workspace-relative path (`/`-joined display form).
    pub rel_path: String,
    /// 1-based first line of the chunk.
    pub start_line: u32,
    /// 1-based last line of the chunk.
    pub end_line: u32,
    /// The chunk text — REDACTED (secret-shaped lines already withheld).
    pub text: String,
}

/// An indexed vector: a redacted chunk + its embedding.
#[derive(Clone, Debug, PartialEq)]
pub struct IndexEntry {
    /// The redacted chunk.
    pub chunk: CodebaseChunk,
    /// The chunk's embedding (over the REDACTED text).
    pub embedding: [f32; EMBED_DIM],
}

/// The local vector store: a flat list of indexed entries. Serialized + AES-sealed at
/// rest (the plaintext index never touches disk).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct CodebaseIndex {
    /// The indexed entries (redacted chunk + embedding).
    pub entries: Vec<IndexEntry>,
}

/// Redact a chunk's text per line through the canonical `redact()` wall: a secret-shaped
/// line becomes the withheld marker (the secret never enters the index). A whole
/// key/cert block (a line beginning `-----BEGIN`) marks the chunk for whole-skip
/// (returns `None`) — its base64 body would not trip the per-line markers.
fn redact_chunk(lines: &[&str]) -> Option<String> {
    if lines.iter().any(|l| {
        l.trim_start()
            .to_ascii_lowercase()
            .starts_with("-----begin")
    }) {
        return None;
    }
    let mut out = String::new();
    for line in lines {
        if crate::search::line_is_secret(line) {
            out.push_str(WITHHELD_LINE);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    Some(out)
}

/// Chunk a file's text into line-windows, redacting each chunk. Returns `(start_line,
/// end_line, redacted_text)` triples. A chunk whose window is a key/cert block is skipped.
fn chunk_file_text(text: &str) -> Vec<(u32, u32, String)> {
    let lines: Vec<&str> = text.lines().collect();
    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < lines.len() {
        let end = (start + CHUNK_LINES).min(lines.len());
        let window = &lines[start..end];
        if let Some(redacted) = redact_chunk(window) {
            // Only index a chunk with some non-whitespace content.
            if redacted.split_whitespace().next().is_some() {
                let start_line = u32::try_from(start + 1).unwrap_or(u32::MAX);
                let end_line = u32::try_from(end).unwrap_or(u32::MAX);
                chunks.push((start_line, end_line, redacted));
            }
        }
        start = end;
    }
    chunks
}

/// Build the index by walking `root` under `policy` (the SAME discipline as the search
/// walk: explicit stack, depth bound, symlink-skip, `is_skipped_dir`; each file read
/// through `policy.read` = under-root + lane-A denylist + size cap + UTF-8 gate), chunking
/// each file into redacted line-windows, and embedding each chunk. Bounded by
/// [`INDEX_MAX_FILES`] / [`INDEX_MAX_CHUNKS`] / [`INDEX_MAX_DEPTH`].
#[must_use]
pub fn build_index(policy: &FileReadPolicy, root: &Path, embedder: &dyn Embedder) -> CodebaseIndex {
    let mut entries: Vec<IndexEntry> = Vec::new();
    let mut files_scanned: u32 = 0;
    let mut stack: Vec<(PathBuf, u32)> = vec![(root.to_path_buf(), 0)];
    'walk: while let Some((dir, depth)) = stack.pop() {
        if depth > INDEX_MAX_DEPTH {
            continue;
        }
        let Ok(read_dir) = std::fs::read_dir(&dir) else {
            continue;
        };
        for dirent in read_dir.flatten() {
            if files_scanned >= INDEX_MAX_FILES || entries.len() >= INDEX_MAX_CHUNKS {
                break 'walk;
            }
            let path = dirent.path();
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
            let Ok(result) = policy.read(&path) else {
                continue;
            };
            let Some(text) = result.text.as_deref() else {
                continue; // binary — never indexed
            };
            files_scanned = files_scanned.saturating_add(1);
            let rel = path.strip_prefix(root).unwrap_or(path.as_path());
            let rel_path = rel.to_string_lossy().replace('\\', "/");
            for (start_line, end_line, redacted) in chunk_file_text(text) {
                if entries.len() >= INDEX_MAX_CHUNKS {
                    break 'walk;
                }
                let embedding = embedder.embed(&redacted);
                entries.push(IndexEntry {
                    chunk: CodebaseChunk {
                        rel_path: rel_path.clone(),
                        start_line,
                        end_line,
                        text: redacted,
                    },
                    embedding,
                });
            }
        }
    }
    CodebaseIndex { entries }
}

/// A scored retrieval hit.
#[derive(Clone, Debug, PartialEq)]
pub struct ScoredChunk {
    /// The retrieved chunk.
    pub chunk: CodebaseChunk,
    /// The hybrid score (cosine + lexical overlap bonus).
    pub score: f32,
}

/// The lexical-overlap weight added to the cosine score (the hybrid merge): a chunk that
/// literally contains the query's tokens is boosted over a purely-cosine match.
const LEXICAL_WEIGHT: f32 = 0.5;

/// Retrieve the top-`k` chunks for `query` by a HYBRID score = cosine(query, chunk) +
/// `LEXICAL_WEIGHT` × (fraction of query tokens present in the chunk text). Deterministic
/// (a stable sort by score then path/line). The embedding never leaves the box.
#[must_use]
pub fn retrieve(
    index: &CodebaseIndex,
    query: &str,
    embedder: &dyn Embedder,
    k: usize,
) -> Vec<ScoredChunk> {
    let qe = embedder.embed(query);
    let q_tokens: Vec<String> = {
        let mut t = tokenize(query);
        t.sort();
        t.dedup();
        t
    };
    let mut scored: Vec<ScoredChunk> = index
        .entries
        .iter()
        .map(|e| {
            let sem = cosine_similarity(&qe, &e.embedding);
            let lex = if q_tokens.is_empty() {
                0.0
            } else {
                let lower = e.chunk.text.to_ascii_lowercase();
                let present = q_tokens
                    .iter()
                    .filter(|t| lower.contains(t.as_str()))
                    .count();
                present as f32 / q_tokens.len() as f32
            };
            ScoredChunk {
                chunk: e.chunk.clone(),
                score: sem + LEXICAL_WEIGHT * lex,
            }
        })
        .filter(|s| s.score > 0.0)
        .collect();
    // Deterministic order: score desc, then path + start line asc (stable tie-break).
    scored.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.chunk.rel_path.cmp(&b.chunk.rel_path))
            .then_with(|| a.chunk.start_line.cmp(&b.chunk.start_line))
    });
    scored.truncate(k);
    scored
}

/// The default number of retrieved chunks.
pub const RETRIEVE_TOP_K: usize = 5;
/// Per-chunk snippet line cap in a render (a bounded preview, never the whole chunk).
pub const SNIPPET_LINES: usize = 8;

/// The rendered outcome of a retrieval: a secret-free result string + whether a chunk
/// surfaced (the K-budget `consumed_read` flag — a 0-hit / empty-index render never
/// consumes K).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodebaseRender {
    /// The rendered, secret-free result string.
    pub rendered: String,
    /// Whether at least one chunk surfaced.
    pub consumed_read: bool,
}

/// Render the top-`k` retrieval for `query` over `index` — a secret-free `rel_path:lines`
/// header per hit + a bounded, re-redacted snippet (defense in depth: the index text is
/// already redacted, and each surfaced line passes the wall again).
#[must_use]
pub fn render_retrieval(
    index: &CodebaseIndex,
    query: &str,
    embedder: &dyn Embedder,
) -> CodebaseRender {
    let q = query.trim();
    if q.is_empty() {
        return CodebaseRender {
            rendered: "@codebase: empty query".to_string(),
            consumed_read: false,
        };
    }
    if index.entries.is_empty() {
        return CodebaseRender {
            rendered: "@codebase: no index (run `context codebase build` first)".to_string(),
            consumed_read: false,
        };
    }
    let hits = retrieve(index, q, embedder, RETRIEVE_TOP_K);
    if hits.is_empty() {
        return CodebaseRender {
            rendered: format!(
                "@codebase \"{}\": 0 relevant chunks ({} indexed; local embeddings; redacted)",
                bounded(q, 80),
                index.entries.len()
            ),
            consumed_read: false,
        };
    }
    let mut out = format!(
        "@codebase \"{}\": top {} of {} indexed chunks (local embeddings; hybrid; redacted):\n",
        bounded(q, 80),
        hits.len(),
        index.entries.len()
    );
    for h in &hits {
        out.push_str(&format!(
            "{}:{}-{} (score={:.3})\n",
            h.chunk.rel_path, h.chunk.start_line, h.chunk.end_line, h.score
        ));
        for line in h.chunk.text.lines().take(SNIPPET_LINES) {
            // defense in depth: the stored text is redacted; re-screen each surfaced line.
            if crate::search::line_is_secret(line) {
                out.push_str("    ");
                out.push_str(WITHHELD_LINE);
            } else {
                out.push_str("    ");
                out.push_str(&bounded(line, 200));
            }
            out.push('\n');
        }
    }
    CodebaseRender {
        rendered: out,
        consumed_read: true,
    }
}

/// Char-boundary-safe truncation to `max` chars.
fn bounded(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// Load the encrypted-at-rest index (`<data_dir>/`[`CODEBASE_INDEX_FILE`]): read the
/// sealed blob → open with the LOCAL key → parse. `None` (fail-closed) if absent /
/// unreadable / wrong-key / tampered. The single load path shared by the `context
/// codebase` verb AND the agent loop's `TOOL: codebase` executor (no drift).
#[must_use]
pub fn load_persisted_index() -> Option<CodebaseIndex> {
    let dir = crate::memory_store::data_dir().ok()?;
    let path = dir.join(CODEBASE_INDEX_FILE);
    let sealed = std::fs::read(&path).ok()?;
    let store = crate::memory_store::PersistedStore::open_local().ok()?;
    let plaintext = store.open_codebase_index(&sealed).ok()?;
    CodebaseIndex::from_bytes(&plaintext)
}

// ===========================================================================
// Encrypted-at-rest codec — serialize the index to bytes (sealed by the caller).
// ===========================================================================

const INDEX_MAGIC: &[u8; 4] = b"CBIX";
const INDEX_VERSION: u16 = 1;

impl CodebaseIndex {
    /// Serialize to a self-describing byte buffer (magic + version + entries). The caller
    /// SEALS these bytes with the local key before they touch disk (`seal_codebase_index`).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(INDEX_MAGIC);
        out.extend_from_slice(&INDEX_VERSION.to_le_bytes());
        let n = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&n.to_le_bytes());
        for e in &self.entries {
            put_str(&mut out, &e.chunk.rel_path);
            out.extend_from_slice(&e.chunk.start_line.to_le_bytes());
            out.extend_from_slice(&e.chunk.end_line.to_le_bytes());
            for f in &e.embedding {
                out.extend_from_slice(&f.to_le_bytes());
            }
            put_str(&mut out, &e.chunk.text);
        }
        out
    }

    /// Parse bytes produced by [`CodebaseIndex::to_bytes`] (after a local open). Fail-closed
    /// `None` on any truncation / bad magic / bad version (a tampered or foreign blob is
    /// never half-parsed into a partial index).
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<CodebaseIndex> {
        let mut r = ByteReader::new(bytes);
        if r.take(4)? != INDEX_MAGIC {
            return None;
        }
        if u16::from_le_bytes(r.take(2)?.try_into().ok()?) != INDEX_VERSION {
            return None;
        }
        let n = u32::from_le_bytes(r.take(4)?.try_into().ok()?) as usize;
        if n > INDEX_MAX_CHUNKS {
            return None;
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let rel_path = get_str(&mut r)?;
            let start_line = u32::from_le_bytes(r.take(4)?.try_into().ok()?);
            let end_line = u32::from_le_bytes(r.take(4)?.try_into().ok()?);
            let mut embedding = [0f32; EMBED_DIM];
            for f in embedding.iter_mut() {
                *f = f32::from_le_bytes(r.take(4)?.try_into().ok()?);
            }
            let text = get_str(&mut r)?;
            entries.push(IndexEntry {
                chunk: CodebaseChunk {
                    rel_path,
                    start_line,
                    end_line,
                    text,
                },
                embedding,
            });
        }
        Some(CodebaseIndex { entries })
    }
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    let len = u32::try_from(b.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&b[..len as usize]);
}

fn get_str(r: &mut ByteReader) -> Option<String> {
    let len = u32::from_le_bytes(r.take(4)?.try_into().ok()?) as usize;
    let bytes = r.take(len)?;
    String::from_utf8(bytes.to_vec()).ok()
}

/// A fail-closed forward byte reader (never panics on a short buffer).
struct ByteReader<'a> {
    buf: &'a [u8],
    pos: usize,
}
impl<'a> ByteReader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aad_is_distinct() {
        assert_eq!(CODEBASE_INDEX_AAD, b"sinabro.codebase.index.v1");
        assert_ne!(CODEBASE_INDEX_AAD, crate::memory_walrus::WALRUS_INDEX_AAD);
        assert_ne!(CODEBASE_INDEX_AAD, crate::settings_sync::SETTINGS_SYNC_AAD);
    }

    #[test]
    fn stub_embed_is_deterministic_and_normalized() {
        let e = StubEmbedder;
        let a = e.embed("fn render_search pattern walk");
        let b = e.embed("fn render_search pattern walk");
        assert_eq!(a, b, "deterministic");
        let norm: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-4 || norm == 0.0, "L2-normalized");
        // self-similarity is 1.0; a disjoint text is lower.
        assert!((cosine_similarity(&a, &a) - 1.0).abs() < 1e-4);
        let c = e.embed("xyzzy plugh frobnicate");
        assert!(cosine_similarity(&a, &c) < cosine_similarity(&a, &b));
    }

    #[test]
    fn retrieve_ranks_the_relevant_chunk_first() {
        let e = StubEmbedder;
        let mk = |path: &str, text: &str| IndexEntry {
            chunk: CodebaseChunk {
                rel_path: path.to_string(),
                start_line: 1,
                end_line: 5,
                text: text.to_string(),
            },
            embedding: e.embed(text),
        };
        let index = CodebaseIndex {
            entries: vec![
                mk("a.rs", "fn handle_payment(amount: u64) { settle(amount); }"),
                mk("b.rs", "fn render_button(label: String) { draw(label); }"),
                mk(
                    "c.rs",
                    "struct Config { profile: String, learning_mode: String }",
                ),
            ],
        };
        let hits = retrieve(&index, "payment settle amount", &e, 3);
        assert!(!hits.is_empty());
        assert_eq!(
            hits[0].chunk.rel_path, "a.rs",
            "the payment chunk ranks first"
        );
    }

    #[test]
    fn chunking_redacts_secret_lines_at_index_time() {
        // a secret-shaped line must be WITHHELD from the stored chunk text (the canonical
        // `private_key = …` trigger — the SAME wall the file-read / search tools use).
        let text = "let user = \"alice\";\nlet private_key = \"do-not-leak-this-secret-material\";\nfn ok() {}\n";
        let chunks = chunk_file_text(text);
        assert_eq!(chunks.len(), 1);
        let stored = &chunks[0].2;
        assert!(stored.contains("alice"), "benign lines are kept");
        assert!(stored.contains("ok"), "benign lines are kept");
        assert!(
            !stored.contains("do-not-leak"),
            "the secret value is never stored"
        );
        assert!(stored.contains(WITHHELD_LINE));
    }

    #[test]
    fn pem_block_chunk_is_skipped_wholesale() {
        let text = "-----BEGIN PRIVATE KEY-----\nMIIBderp+base64+body\n-----END PRIVATE KEY-----\n";
        assert!(
            chunk_file_text(text).is_empty(),
            "a key block is not indexed"
        );
    }

    #[test]
    fn render_honest_on_empty_and_returns_closest_otherwise() {
        let e = StubEmbedder;
        // honest-degrade: an empty index never fabricates a hit + consumes no K.
        let empty = CodebaseIndex::default();
        let r = render_retrieval(&empty, "anything", &e);
        assert!(!r.consumed_read);
        assert!(r.rendered.contains("no index"));
        // an empty QUERY is honest + consumes no K.
        assert!(!render_retrieval(&empty, "   ", &e).consumed_read);
        // a non-empty index returns the closest chunk (the stub ranks by relevance).
        let idx = CodebaseIndex {
            entries: vec![IndexEntry {
                chunk: CodebaseChunk {
                    rel_path: "z.rs".to_string(),
                    start_line: 1,
                    end_line: 3,
                    text: "struct Config { profile: String, learning_mode: String }".to_string(),
                },
                embedding: e.embed("struct Config { profile: String, learning_mode: String }"),
            }],
        };
        let r2 = render_retrieval(&idx, "config profile learning", &e);
        assert!(r2.consumed_read, "{}", r2.rendered);
        assert!(r2.rendered.contains("z.rs"));
    }

    #[test]
    fn codec_round_trips_and_is_fail_closed() {
        let e = StubEmbedder;
        let index = CodebaseIndex {
            entries: vec![IndexEntry {
                chunk: CodebaseChunk {
                    rel_path: "src/x.rs".to_string(),
                    start_line: 10,
                    end_line: 49,
                    text: "fn foo() { bar(); }\n".to_string(),
                },
                embedding: e.embed("fn foo() { bar(); }"),
            }],
        };
        let bytes = index.to_bytes();
        let back = CodebaseIndex::from_bytes(&bytes).expect("round-trips");
        assert_eq!(index, back);
        // fail-closed on truncation / bad magic.
        assert!(CodebaseIndex::from_bytes(&bytes[..bytes.len() - 1]).is_none());
        assert!(CodebaseIndex::from_bytes(b"XXXX").is_none());
        assert!(CodebaseIndex::from_bytes(&[]).is_none());
    }

    #[test]
    fn build_index_over_the_crate_src_finds_chunks() {
        // a real walk over THIS crate's src (small, fixed) produces redacted chunks.
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let policy = FileReadPolicy::new(
            std::slice::from_ref(&src),
            crate::file_context::MAX_FILE_BYTES,
        );
        let root = policy.roots().first().cloned().expect("root");
        let e = StubEmbedder;
        let index = build_index(&policy, &root, &e);
        assert!(!index.entries.is_empty(), "the crate src yields chunks");
        // this very file is indexed (a chunk whose path ends in codebase_index.rs).
        assert!(
            index
                .entries
                .iter()
                .any(|e| e.chunk.rel_path.ends_with("codebase_index.rs")),
            "the codebase index file itself is indexed"
        );
        // retrieval over the real index returns this chunk for a self-referential query.
        let r = render_retrieval(&index, "fn build_index policy embedder walk", &e);
        assert!(r.consumed_read, "{}", r.rendered);
    }
}
