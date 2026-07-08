//! Agent-native artifact registry — a "GitHub for agents": the PURE,
//! content-addressed artifact-registry CORE, a git-object analog for the things
//! an agent produces, letting agents coordinate and distribute files in a
//! machine-native format.
//!
//! Everything an agent makes — a skill, a LoRA adapter, a certified strategy, a memory,
//! code, an oracle — is an ARTIFACT addressed by the SHA-256 of its `(kind ‖ content
//! digest)` ([`artifact_id`]). [`RegistryManifest`] is the discoverable "repo index":
//! a deterministic, fail-closed byte codec (the [`crate::memory_walrus::WalrusMainIndex`]
//! `WMIX` codec's sibling, magic `AGRX`) that can be content-addressed and later published
//! to Walrus.
//!
//! Content addressing is the supply-chain seatbelt: two agents that produce byte-identical
//! content derive the SAME id (natural dedup), and a fetched artifact whose bytes don't
//! hash back to its id is REJECTED — tamper is impossible to hide (like git).
//!
//! This module is PURE: the model + the byte codec + the content-address derivation only.
//! NO network, NO clock, NO artifact EXECUTION here. The gated Walrus publish/fetch,
//! the AI-native wire protocol, the agent loop tool, and the sandboxed
//! fetch-then-propose build ON TOP — each its own gated + threat-modeled slice.
//! NO funds / wallet / chain-write: a content address is public, moves no money.

/// The registry-manifest magic (4 bytes) — `AGRX` = AGent Registry indeX.
pub const REGISTRY_MAGIC: [u8; 4] = *b"AGRX";

/// The manifest wire version this codec WRITES (the first byte after the magic).
pub const REGISTRY_VERSION: u8 = 1;

/// The domain-separation tag bound into every artifact's content address, so an `AGRX`
/// artifact id can never collide with another sinabro hash (the audit link, a memory id).
pub const ARTIFACT_ID_DOMAIN: &[u8] = b"sinabro.registry.artifact.v1";

/// Max summary bytes carried per artifact (a bounded single-line description).
pub const REGISTRY_SUMMARY_CAP_BYTES: usize = 96;

/// The kind of artifact an agent publishes — the "files" that live in the registry.
/// The wire byte ([`ArtifactKind::wire`]) is bound into the content address, so it is a
/// STABLE part of the format: never renumber an existing kind (append new kinds only).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum ArtifactKind {
    /// A declarative skill package (the `SkillPackageV1` analog).
    Skill,
    /// A LoRA adapter (the `provider::lora_manifest` analog).
    LoraAdapter,
    /// A certified trading / task strategy (the `skew_strategy` corpus analog).
    Strategy,
    /// An encrypted memory record (an `.mc` AEAD sub-store analog).
    Memory,
    /// Source code / a patch.
    Code,
    /// A certified oracle (the iNFT analog).
    Oracle,
}

impl ArtifactKind {
    /// The STABLE wire byte (bound into the content address; never renumber).
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            ArtifactKind::Skill => 1,
            ArtifactKind::LoraAdapter => 2,
            ArtifactKind::Strategy => 3,
            ArtifactKind::Memory => 4,
            ArtifactKind::Code => 5,
            ArtifactKind::Oracle => 6,
        }
    }

    /// Decode a wire byte back to a kind (fail-closed: an unknown byte ⇒ `None`).
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(ArtifactKind::Skill),
            2 => Some(ArtifactKind::LoraAdapter),
            3 => Some(ArtifactKind::Strategy),
            4 => Some(ArtifactKind::Memory),
            5 => Some(ArtifactKind::Code),
            6 => Some(ArtifactKind::Oracle),
            _ => None,
        }
    }

    /// A stable lower-case label (for renders).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            ArtifactKind::Skill => "skill",
            ArtifactKind::LoraAdapter => "adapter",
            ArtifactKind::Strategy => "strategy",
            ArtifactKind::Memory => "memory",
            ArtifactKind::Code => "code",
            ArtifactKind::Oracle => "oracle",
        }
    }
}

/// The content-address of an artifact: the lowercase-hex SHA-256 of
/// (`ARTIFACT_ID_DOMAIN` ‖ kind-wire ‖ `content_digest`). Deterministic + tamper-evident.
#[must_use]
pub fn artifact_id(kind: ArtifactKind, content_digest: &[u8; 32]) -> String {
    let mut buf = Vec::with_capacity(ARTIFACT_ID_DOMAIN.len() + 1 + content_digest.len());
    buf.extend_from_slice(ARTIFACT_ID_DOMAIN);
    buf.push(kind.wire());
    buf.extend_from_slice(content_digest);
    crate::hex32(&crate::sha256_32(&buf))
}

/// One registry entry: a content-addressed artifact + its provenance + optional Walrus
/// location. The `id` is DERIVED from `(kind, content_digest)` ([`artifact_id`]); it is
/// stored so the manifest is self-describing, and [`AgentArtifact::id_matches_content`]
/// re-derives + checks it (a forged id fails).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentArtifact {
    /// The content-address (lowercase-hex sha256; see [`artifact_id`]).
    pub id: String,
    /// What kind of artifact this is.
    pub kind: ArtifactKind,
    /// The SHA-256 of the artifact's canonical content (the payload lives in a blob).
    pub content_digest: [u8; 32],
    /// The producing agent's identity (a pubkey / agent-id string; NOT a secret).
    pub author: String,
    /// A bounded single-line description (plaintext; redacted before any publish).
    pub summary: String,
    /// The Walrus blob-id of the published payload, if published (`None` = local-only).
    pub blob_ref: Option<String>,
}

impl AgentArtifact {
    /// Build an artifact, DERIVING the content-address id from `(kind, content_digest)`.
    /// The `summary` is bounded via [`summarize`].
    #[must_use]
    pub fn new(
        kind: ArtifactKind,
        content_digest: [u8; 32],
        author: String,
        summary: &str,
        blob_ref: Option<String>,
    ) -> Self {
        Self {
            id: artifact_id(kind, &content_digest),
            kind,
            content_digest,
            author,
            summary: summarize(summary),
            blob_ref,
        }
    }

    /// True iff the stored `id` equals the id DERIVED from `(kind, content_digest)` — the
    /// tamper-evidence check a decoder / fetcher runs (a forged id, or a payload swapped
    /// under a fixed id, fails).
    #[must_use]
    pub fn id_matches_content(&self) -> bool {
        self.id == artifact_id(self.kind, &self.content_digest)
    }
}

/// The MAIN REGISTRY MANIFEST: the discoverable index of every artifact. The `WMIX`-analog
/// byte codec — deterministic + fail-closed — so it can be content-addressed and
/// published to Walrus.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RegistryManifest {
    /// The entries, kept sorted + deduped by content-address `id` for a canonical order.
    pub entries: Vec<AgentArtifact>,
}

/// Typed codec failures (fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum RegistryError {
    /// The bytes were shorter than a field demanded.
    Truncated,
    /// The 4-byte magic was not [`REGISTRY_MAGIC`].
    BadMagic,
    /// The version byte was not [`REGISTRY_VERSION`].
    UnknownVersion,
    /// An entry's kind byte was not a known [`ArtifactKind`].
    UnknownKind,
    /// A string field was not valid UTF-8.
    NotUtf8,
    /// Trailing garbage followed the last entry.
    TrailingBytes,
}

fn take_slice<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], RegistryError> {
    let end = at.checked_add(n).ok_or(RegistryError::Truncated)?;
    if end > bytes.len() {
        return Err(RegistryError::Truncated);
    }
    let slice = &bytes[*at..end];
    *at = end;
    Ok(slice)
}

fn take_str(bytes: &[u8], at: &mut usize) -> Result<String, RegistryError> {
    let mut l = [0u8; 2];
    l.copy_from_slice(take_slice(bytes, at, 2)?);
    let n = u16::from_le_bytes(l) as usize;
    let s = core::str::from_utf8(take_slice(bytes, at, n)?).map_err(|_| RegistryError::NotUtf8)?;
    Ok(s.to_string())
}

impl RegistryManifest {
    /// Insert (or REPLACE) an artifact, keeping entries sorted + deduped by content-address
    /// id (idempotent: publishing the same content twice is one entry).
    pub fn upsert(&mut self, artifact: AgentArtifact) {
        match self.entries.binary_search_by(|e| e.id.cmp(&artifact.id)) {
            Ok(i) => self.entries[i] = artifact,
            Err(i) => self.entries.insert(i, artifact),
        }
    }

    /// Look up an artifact by its content-address id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&AgentArtifact> {
        self.entries.iter().find(|e| e.id == id)
    }

    /// Canonical bytes: `magic | version | count(u32 LE) | [ id | kind(u8) |
    /// content_digest(32) | author | summary | blob_ref ]*` — each string is `len(u16 LE)`
    /// + bytes; an empty `blob_ref` (`len=0`) decodes as `None`. Deterministic.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&REGISTRY_MAGIC);
        out.push(REGISTRY_VERSION);
        let count = u32::try_from(self.entries.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        let put_str = |out: &mut Vec<u8>, s: &str| {
            let b = s.as_bytes();
            let len = u16::try_from(b.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&b[..len as usize]);
        };
        for e in self.entries.iter().take(count as usize) {
            put_str(&mut out, &e.id);
            out.push(e.kind.wire());
            out.extend_from_slice(&e.content_digest);
            put_str(&mut out, &e.author);
            put_str(&mut out, &e.summary);
            put_str(&mut out, e.blob_ref.as_deref().unwrap_or(""));
        }
        out
    }

    /// Fail-closed decode (every length checked before consumed; unknown kind / unknown
    /// version / trailing bytes REJECT). Does NOT trust the stored id — the caller
    /// re-checks tamper-evidence via [`AgentArtifact::id_matches_content`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, RegistryError> {
        let mut at = 0usize;
        if take_slice(bytes, &mut at, 4)? != REGISTRY_MAGIC {
            return Err(RegistryError::BadMagic);
        }
        if take_slice(bytes, &mut at, 1)?[0] != REGISTRY_VERSION {
            return Err(RegistryError::UnknownVersion);
        }
        let mut cb = [0u8; 4];
        cb.copy_from_slice(take_slice(bytes, &mut at, 4)?);
        let count = u32::from_le_bytes(cb) as usize;
        let mut entries = Vec::new();
        for _ in 0..count {
            let id = take_str(bytes, &mut at)?;
            let kind = ArtifactKind::from_wire(take_slice(bytes, &mut at, 1)?[0])
                .ok_or(RegistryError::UnknownKind)?;
            let mut cd = [0u8; 32];
            cd.copy_from_slice(take_slice(bytes, &mut at, 32)?);
            let author = take_str(bytes, &mut at)?;
            let summary = take_str(bytes, &mut at)?;
            let blob = take_str(bytes, &mut at)?;
            entries.push(AgentArtifact {
                id,
                kind,
                content_digest: cd,
                author,
                summary,
                blob_ref: if blob.is_empty() { None } else { Some(blob) },
            });
        }
        if at != bytes.len() {
            return Err(RegistryError::TrailingBytes);
        }
        Ok(Self { entries })
    }
}

/// Bound a single-line summary to [`REGISTRY_SUMMARY_CAP_BYTES`] on a char boundary
/// (control chars → space, runs of whitespace collapsed, trimmed).
#[must_use]
pub fn summarize(raw: &str) -> String {
    let mut s = String::new();
    let mut prev_space = false;
    for ch in raw.chars() {
        if ch.is_control() || ch.is_whitespace() {
            if !prev_space && !s.is_empty() {
                s.push(' ');
                prev_space = true;
            }
        } else {
            s.push(ch);
            prev_space = false;
        }
    }
    while s.ends_with(' ') {
        s.pop();
    }
    if s.len() <= REGISTRY_SUMMARY_CAP_BYTES {
        return s;
    }
    let mut end = REGISTRY_SUMMARY_CAP_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
    s
}

// ── AI-NATIVE PROTOCOL: the deterministic `AgentMessage` envelope — the compact,
// machine-parseable "language" agents speak to coordinate over the registry (announce /
// publish / request / ack an artifact). NOT prose: a canonical byte format, fail-closed +
// content-addressed (a message hashes to a stable id; a tampered field yields a different
// id). PURE (no network / clock / execution): the TRANSPORT that carries these messages is
// a later, gated slice.

/// The agent-message magic (4 bytes) — `AGMS` = AGent MeSsage.
pub const AGENT_MESSAGE_MAGIC: [u8; 4] = *b"AGMS";

/// The message wire version this codec writes.
pub const AGENT_MESSAGE_VERSION: u8 = 1;

/// Domain separation for a message's content-address (distinct from an artifact id).
pub const AGENT_MESSAGE_ID_DOMAIN: &[u8] = b"sinabro.registry.message.v1";

/// The coordination primitive an agent-message carries. The wire byte ([`MsgKind::wire`])
/// is part of the format: never renumber an existing kind (append new kinds only).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum MsgKind {
    /// "I hold this artifact" (discovery gossip).
    Announce,
    /// "Here is this artifact" (an offer; the payload rides a blob out of band).
    Publish,
    /// "I want this artifact".
    Request,
    /// "I received / acknowledge this artifact".
    Ack,
}

impl MsgKind {
    /// The STABLE wire byte (never renumber).
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            MsgKind::Announce => 1,
            MsgKind::Publish => 2,
            MsgKind::Request => 3,
            MsgKind::Ack => 4,
        }
    }

    /// Decode a wire byte back to a kind (fail-closed: an unknown byte ⇒ `None`).
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            1 => Some(MsgKind::Announce),
            2 => Some(MsgKind::Publish),
            3 => Some(MsgKind::Request),
            4 => Some(MsgKind::Ack),
            _ => None,
        }
    }

    /// A stable lower-case label (for renders).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            MsgKind::Announce => "announce",
            MsgKind::Publish => "publish",
            MsgKind::Request => "request",
            MsgKind::Ack => "ack",
        }
    }
}

/// A single agent-to-agent coordination message about one content-addressed artifact.
/// Deterministic + self-verifying: [`AgentMessage::id`] content-addresses the whole
/// envelope, so any tampered field yields a different id.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AgentMessage {
    /// The sending agent's identity (a pubkey / agent-id string; NOT a secret).
    pub from: String,
    /// What this message does.
    pub kind: MsgKind,
    /// The content-address id of the artifact this message is about (see [`artifact_id`]).
    pub artifact_ref: String,
    /// The SHA-256 of the referenced artifact's payload (integrity binding).
    pub payload_digest: [u8; 32],
    /// A replay-distinctness / ordering tag — deterministic, SUPPLIED by the caller (never
    /// a clock, so the codec stays pure + reproducible).
    pub nonce: u64,
}

/// Typed message-codec failures (fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum MessageError {
    /// The bytes were shorter than a field demanded.
    Truncated,
    /// The 4-byte magic was not [`AGENT_MESSAGE_MAGIC`].
    BadMagic,
    /// The version byte was not [`AGENT_MESSAGE_VERSION`].
    UnknownVersion,
    /// The kind byte was not a known [`MsgKind`].
    UnknownKind,
    /// A string field was not valid UTF-8.
    NotUtf8,
    /// Trailing garbage followed the message.
    TrailingBytes,
}

fn msg_take_slice<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], MessageError> {
    let end = at.checked_add(n).ok_or(MessageError::Truncated)?;
    if end > bytes.len() {
        return Err(MessageError::Truncated);
    }
    let slice = &bytes[*at..end];
    *at = end;
    Ok(slice)
}

fn msg_take_str(bytes: &[u8], at: &mut usize) -> Result<String, MessageError> {
    let mut l = [0u8; 2];
    l.copy_from_slice(msg_take_slice(bytes, at, 2)?);
    let n = u16::from_le_bytes(l) as usize;
    let s =
        core::str::from_utf8(msg_take_slice(bytes, at, n)?).map_err(|_| MessageError::NotUtf8)?;
    Ok(s.to_string())
}

impl AgentMessage {
    /// Build a message (all fields explicit; `nonce` is caller-supplied for determinism).
    #[must_use]
    pub fn new(
        from: String,
        kind: MsgKind,
        artifact_ref: String,
        payload_digest: [u8; 32],
        nonce: u64,
    ) -> Self {
        Self {
            from,
            kind,
            artifact_ref,
            payload_digest,
            nonce,
        }
    }

    /// Canonical bytes: `magic | version | from(str) | kind(u8) | artifact_ref(str) |
    /// payload_digest(32) | nonce(u64 LE)` — each string is `len(u16 LE)` + bytes.
    /// Deterministic.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&AGENT_MESSAGE_MAGIC);
        out.push(AGENT_MESSAGE_VERSION);
        let put_str = |out: &mut Vec<u8>, s: &str| {
            let b = s.as_bytes();
            let len = u16::try_from(b.len()).unwrap_or(u16::MAX);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&b[..len as usize]);
        };
        put_str(&mut out, &self.from);
        out.push(self.kind.wire());
        put_str(&mut out, &self.artifact_ref);
        out.extend_from_slice(&self.payload_digest);
        out.extend_from_slice(&self.nonce.to_le_bytes());
        out
    }

    /// Fail-closed decode (every length checked; unknown kind / unknown version / trailing
    /// bytes REJECT).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, MessageError> {
        let mut at = 0usize;
        if msg_take_slice(bytes, &mut at, 4)? != AGENT_MESSAGE_MAGIC {
            return Err(MessageError::BadMagic);
        }
        if msg_take_slice(bytes, &mut at, 1)?[0] != AGENT_MESSAGE_VERSION {
            return Err(MessageError::UnknownVersion);
        }
        let from = msg_take_str(bytes, &mut at)?;
        let kind = MsgKind::from_wire(msg_take_slice(bytes, &mut at, 1)?[0])
            .ok_or(MessageError::UnknownKind)?;
        let artifact_ref = msg_take_str(bytes, &mut at)?;
        let mut pd = [0u8; 32];
        pd.copy_from_slice(msg_take_slice(bytes, &mut at, 32)?);
        let mut nb = [0u8; 8];
        nb.copy_from_slice(msg_take_slice(bytes, &mut at, 8)?);
        let nonce = u64::from_le_bytes(nb);
        if at != bytes.len() {
            return Err(MessageError::TrailingBytes);
        }
        Ok(Self {
            from,
            kind,
            artifact_ref,
            payload_digest: pd,
            nonce,
        })
    }

    /// The content-address of this message: lowercase-hex SHA-256 of
    /// (`AGENT_MESSAGE_ID_DOMAIN` ‖ canonical bytes). Self-verifying — a tampered field ⇒
    /// a different id — so a relayed message can be checked against the id it claims.
    #[must_use]
    pub fn id(&self) -> String {
        let body = self.to_bytes();
        let mut buf = Vec::with_capacity(AGENT_MESSAGE_ID_DOMAIN.len() + body.len());
        buf.extend_from_slice(AGENT_MESSAGE_ID_DOMAIN);
        buf.extend_from_slice(&body);
        crate::hex32(&crate::sha256_32(&buf))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(payload: &[u8]) -> [u8; 32] {
        crate::sha256_32(payload)
    }

    fn art(kind: ArtifactKind, payload: &[u8], author: &str, summary: &str) -> AgentArtifact {
        AgentArtifact::new(kind, digest(payload), author.to_string(), summary, None)
    }

    // ── the AI-native AgentMessage protocol codec ──
    #[test]
    fn message_round_trips_and_kind_wire() {
        for k in [
            MsgKind::Announce,
            MsgKind::Publish,
            MsgKind::Request,
            MsgKind::Ack,
        ] {
            assert_eq!(MsgKind::from_wire(k.wire()), Some(k));
        }
        assert_eq!(MsgKind::from_wire(0), None);
        assert_eq!(MsgKind::from_wire(5), None);
        let m = AgentMessage::new(
            "agent://a".to_string(),
            MsgKind::Publish,
            artifact_id(ArtifactKind::Skill, &digest(b"x")),
            digest(b"payload"),
            42,
        );
        let back = AgentMessage::from_bytes(&m.to_bytes()).expect("decode");
        assert_eq!(m, back);
        assert_eq!(m.to_bytes(), back.to_bytes());
    }

    #[test]
    fn message_id_is_deterministic_and_tamper_evident() {
        let base = AgentMessage::new(
            "agent://a".to_string(),
            MsgKind::Announce,
            "an-artifact-id".to_string(),
            digest(b"p"),
            1,
        );
        assert_eq!(base.id(), base.clone().id());
        assert_eq!(base.id().len(), 64);
        // Any field change => a different id (the envelope is self-verifying).
        let mut n = base.clone();
        n.nonce = 2;
        assert_ne!(base.id(), n.id());
        let mut k = base.clone();
        k.kind = MsgKind::Request;
        assert_ne!(base.id(), k.id());
        let mut f = base.clone();
        f.from = "agent://b".to_string();
        assert_ne!(base.id(), f.id());
    }

    #[test]
    fn message_from_bytes_is_fail_closed() {
        let m = AgentMessage::new("a".to_string(), MsgKind::Ack, "r".to_string(), [0u8; 32], 7);
        let good = m.to_bytes();
        let mut bad = good.clone();
        bad[0] = b'Z';
        assert_eq!(AgentMessage::from_bytes(&bad), Err(MessageError::BadMagic));
        let mut ver = good.clone();
        ver[4] = 9;
        assert_eq!(
            AgentMessage::from_bytes(&ver),
            Err(MessageError::UnknownVersion)
        );
        assert_eq!(
            AgentMessage::from_bytes(&good[..good.len() - 1]),
            Err(MessageError::Truncated)
        );
        let mut trail = good.clone();
        trail.push(1);
        assert_eq!(
            AgentMessage::from_bytes(&trail),
            Err(MessageError::TrailingBytes)
        );
        // The kind byte sits at magic(4)+version(1)+from_len(2)+from("a"=1) = offset 8.
        let mut kind = good.clone();
        kind[8] = 99;
        assert_eq!(
            AgentMessage::from_bytes(&kind),
            Err(MessageError::UnknownKind)
        );
        assert_eq!(AgentMessage::from_bytes(&[]), Err(MessageError::Truncated));
    }

    #[test]
    fn artifact_id_is_deterministic_and_kind_separated() {
        let d = digest(b"the same content");
        // Same (kind, content) ⇒ same id (natural dedup).
        assert_eq!(
            artifact_id(ArtifactKind::Skill, &d),
            artifact_id(ArtifactKind::Skill, &d)
        );
        // Different KIND under the same content ⇒ different id (domain separation).
        assert_ne!(
            artifact_id(ArtifactKind::Skill, &d),
            artifact_id(ArtifactKind::Code, &d)
        );
        // Different content ⇒ different id.
        assert_ne!(
            artifact_id(ArtifactKind::Skill, &d),
            artifact_id(ArtifactKind::Skill, &digest(b"other content"))
        );
        // 64 lowercase hex chars.
        let id = artifact_id(ArtifactKind::Strategy, &d);
        assert_eq!(id.len(), 64);
        assert!(
            id.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn kind_wire_round_trips_and_rejects_unknown() {
        for k in [
            ArtifactKind::Skill,
            ArtifactKind::LoraAdapter,
            ArtifactKind::Strategy,
            ArtifactKind::Memory,
            ArtifactKind::Code,
            ArtifactKind::Oracle,
        ] {
            assert_eq!(ArtifactKind::from_wire(k.wire()), Some(k));
        }
        assert_eq!(ArtifactKind::from_wire(0), None);
        assert_eq!(ArtifactKind::from_wire(7), None);
        assert_eq!(ArtifactKind::from_wire(255), None);
    }

    #[test]
    fn id_matches_content_detects_forgery() {
        let mut a = art(
            ArtifactKind::Code,
            b"fn main() {}",
            "agent://naite",
            "a tiny program",
        );
        assert!(a.id_matches_content());
        // Forge the id ⇒ tamper is detected.
        a.id = "deadbeef".repeat(8);
        assert!(!a.id_matches_content());
        // Swap the content under a fixed (correct-shaped) id ⇒ detected.
        let mut b = art(
            ArtifactKind::Code,
            b"fn main() {}",
            "agent://naite",
            "a tiny program",
        );
        b.content_digest = digest(b"malicious payload");
        assert!(!b.id_matches_content());
    }

    #[test]
    fn manifest_round_trips_byte_exact() {
        let mut m = RegistryManifest::default();
        m.upsert(art(ArtifactKind::Skill, b"skill-a", "agent://a", "skill a"));
        m.upsert(art(
            ArtifactKind::LoraAdapter,
            b"adapter-b",
            "agent://b",
            "adapter b",
        ));
        m.upsert(AgentArtifact::new(
            ArtifactKind::Memory,
            digest(b"mem-c"),
            "agent://c".to_string(),
            "memory c",
            Some("blob-id-xyz".to_string()),
        ));
        let bytes = m.to_bytes();
        let back = RegistryManifest::from_bytes(&bytes).expect("decode");
        assert_eq!(m, back);
        // Deterministic: encoding the decoded manifest yields identical bytes.
        assert_eq!(bytes, back.to_bytes());
        // Every decoded entry's stored id verifies against its content.
        assert!(back.entries.iter().all(AgentArtifact::id_matches_content));
        // The published (Memory) entry kept its blob_ref through the round-trip; the
        // local-only ones stay None.
        let mem = back
            .entries
            .iter()
            .find(|e| e.kind == ArtifactKind::Memory)
            .expect("memory entry present");
        assert_eq!(mem.blob_ref.as_deref(), Some("blob-id-xyz"));
        assert!(back.entries.iter().filter(|e| e.blob_ref.is_none()).count() >= 2);
    }

    #[test]
    fn empty_manifest_round_trips() {
        let m = RegistryManifest::default();
        let back = RegistryManifest::from_bytes(&m.to_bytes()).expect("decode empty");
        assert!(back.entries.is_empty());
    }

    #[test]
    fn upsert_is_sorted_and_idempotent() {
        let mut m = RegistryManifest::default();
        let a = art(ArtifactKind::Skill, b"one", "agent://a", "one");
        let b = art(ArtifactKind::Code, b"two", "agent://a", "two");
        m.upsert(b.clone());
        m.upsert(a.clone());
        // Sorted by id.
        assert!(m.entries.windows(2).all(|w| w[0].id < w[1].id));
        // Re-upserting the same content is idempotent (one entry, replaced in place).
        let n = m.entries.len();
        m.upsert(a.clone());
        assert_eq!(m.entries.len(), n);
        assert!(m.get(&a.id).is_some());
    }

    #[test]
    fn from_bytes_is_fail_closed() {
        let mut m = RegistryManifest::default();
        m.upsert(art(ArtifactKind::Oracle, b"o", "agent://a", "o"));
        let good = m.to_bytes();

        // Bad magic.
        let mut bad = good.clone();
        bad[0] = b'X';
        assert_eq!(
            RegistryManifest::from_bytes(&bad),
            Err(RegistryError::BadMagic)
        );

        // Unknown version.
        let mut ver = good.clone();
        ver[4] = 9;
        assert_eq!(
            RegistryManifest::from_bytes(&ver),
            Err(RegistryError::UnknownVersion)
        );

        // Truncated (drop the last byte).
        let trunc = &good[..good.len() - 1];
        assert_eq!(
            RegistryManifest::from_bytes(trunc),
            Err(RegistryError::Truncated)
        );

        // Trailing garbage.
        let mut trail = good.clone();
        trail.push(0xAB);
        assert_eq!(
            RegistryManifest::from_bytes(&trail),
            Err(RegistryError::TrailingBytes)
        );

        // An empty buffer is truncated at the magic.
        assert_eq!(
            RegistryManifest::from_bytes(&[]),
            Err(RegistryError::Truncated)
        );
    }

    #[test]
    fn from_bytes_rejects_unknown_kind() {
        // Hand-build a 1-entry manifest with an out-of-range kind byte.
        let mut out = Vec::new();
        out.extend_from_slice(&REGISTRY_MAGIC);
        out.push(REGISTRY_VERSION);
        out.extend_from_slice(&1u32.to_le_bytes()); // count = 1
        let put = |out: &mut Vec<u8>, s: &str| {
            out.extend_from_slice(&(s.len() as u16).to_le_bytes());
            out.extend_from_slice(s.as_bytes());
        };
        put(&mut out, "an-id");
        out.push(99); // unknown kind
        out.extend_from_slice(&[0u8; 32]);
        put(&mut out, "author");
        put(&mut out, "summary");
        put(&mut out, "");
        assert_eq!(
            RegistryManifest::from_bytes(&out),
            Err(RegistryError::UnknownKind)
        );
    }

    #[test]
    fn summarize_bounds_and_collapses() {
        assert_eq!(summarize("  hello   world  "), "hello world");
        assert_eq!(summarize("line1\nline2\ttab"), "line1 line2 tab");
        let long = "x".repeat(200);
        let s = summarize(&long);
        assert!(s.len() <= REGISTRY_SUMMARY_CAP_BYTES);
        // Multi-byte: never split a char.
        let multi = "가".repeat(100);
        let ms = summarize(&multi);
        assert!(ms.len() <= REGISTRY_SUMMARY_CAP_BYTES);
        assert!(ms.chars().all(|c| c == '가'));
    }
}
