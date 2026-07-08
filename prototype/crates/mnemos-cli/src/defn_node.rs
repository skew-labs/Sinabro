//! The DEFINITION-UNIT NODE identity codec: a function/type-sized
//! semantic unit whose identity is DERIVED FROM ITS CONTENT (P-LOCK-2), never from
//! its name or its file location.
//!
//! ## Thesis
//!
//! The registry's atom so far is a file/blob ([`crate::agent_registry::artifact_id`]).
//! This codec descends one level: one definition (a function, a class, a type) = one node,
//! addressed by
//!
//! ```text
//! cid = hex(sha256(NODE_DOMAIN ‖ lang ‖ le32|normAST| ‖ normAST ‖ le32|typeSig| ‖ typeSig
//!                  ‖ le32|effectSig| ‖ effectSig ‖ le32(dep_count) ‖ dep_digest_32…))
//! ```
//!
//! Because the NAME is not hashed, a rename / a move / an independent identical
//! authoring converges to the SAME cid at codec level (diff 0, conflict 0) — the
//! name is DATA (the namespace seam), not identity. Every variable-length
//! field is le32 length-prefixed so field boundaries are unambiguous (a byte can
//! never migrate between fields under a crafted input).
//!
//! ## Conservative-approximation contract
//!
//! The normalized AST comes from a SYNTACTIC normalizer (whitespace/comments/
//! alpha-conversion — [`crate::ingest_ts`] for the first language, TypeScript).
//! Normalization is SOUND-FIRST: when the normalizer is not
//! certain two spellings are equivalent it must keep them DISTINCT (a false split
//! is allowed, a false merge is not). The [`NormToken`] encoding is kind-byte
//! disjoint, so a placeholder ([`NormToken::SelfRef`] / [`NormToken::AlphaVar`])
//! can never collide with source-derived bytes by construction.
//!
//! ## Honest v1 scope
//!
//! * `type_sig` = the normalized DECLARED signature tokens (no type checker runs;
//!   TypeScript has no `lsp.rs` oracle wired — declared-source truth only).
//! * `effect_sig` = the fixed conservative [`EFFECT_SIG_UNKNOWN_V1`] marker (no
//!   effect analysis yet; "cannot see ⇒ opaque" is the sound
//!   default).
//! * `deps` = empty (dependency-closure cids are the morphism seam).
//!
//! This module is PURE: no network, no filesystem, no clock, no execution. It
//! constructs no egress/mutate/custody capability (funds stay hard-locked
//! behind the uninhabited custody type) — a pure codec with zero side effects.

/// The domain-separation tag bound into every definition-node cid, so a node
/// id can never collide with another sinabro hash (an AGRX artifact id, an audit
/// link, a memory id). 25 bytes.
pub const NODE_DOMAIN: &[u8] = b"sinabro.nous.defn_node.v1";

/// The v1 conservative effect signature: "effects unknown / opaque" — the sound
/// default until an effect analyzer exists. 30 bytes.
pub const EFFECT_SIG_UNKNOWN_V1: &[u8] = b"sinabro.nous.effect.unknown.v1";

/// Max byte length of ONE normalized token's payload (the le16 wire width). A
/// longer token (a giant template literal) cannot be encoded — the caller must
/// degrade the unit to its opaque form ([`opaque_normalized`]), never truncate.
pub const NORM_TOKEN_MAX_BYTES: usize = 65_535;

/// The opaque-tier tag byte: a unit the normalizer could not confidently
/// tokenize/encode is identified by `0xFF ‖ raw_source_bytes` — NO normalization
/// claimed (identity = the exact spelling). Disjoint from every [`NormToken`]
/// kind byte, so an opaque body can never alias a normalized body.
pub const OPAQUE_TAG: u8 = 0xFF;

/// The language a definition unit was ingested from. The wire byte is bound into
/// the content address, so it is STABLE: never renumber (append only) — the
/// [`crate::agent_registry::ArtifactKind::wire`] discipline.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum DefnLang {
    /// The TypeScript source language.
    TypeScript,
}

impl DefnLang {
    /// The STABLE wire byte (bound into the content address; never renumber).
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            DefnLang::TypeScript => 1,
        }
    }

    /// A stable lower-case label (for renders).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            DefnLang::TypeScript => "typescript",
        }
    }
}

/// What kind of definition a node is. DATA for renders/namespacing — NOT hashed
/// separately: the kind is already spelled inside the normalized token stream
/// (`function` / `class` / `interface` / …), so hashing it again would add
/// nothing and a mismatch could add ambiguity.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum DefnKind {
    /// `function name(…) {…}` (incl. `async` / generator).
    Function,
    /// `class name … {…}`.
    Class,
    /// `interface name … {…}`.
    Interface,
    /// `type name = …`.
    TypeAlias,
    /// `enum name {…}` (incl. `const enum`).
    Enum,
    /// `const|let|var name = …` at module level (incl. arrow functions).
    ConstBinding,
}

impl DefnKind {
    /// A stable lower-case label (for renders).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            DefnKind::Function => "function",
            DefnKind::Class => "class",
            DefnKind::Interface => "interface",
            DefnKind::TypeAlias => "type",
            DefnKind::Enum => "enum",
            DefnKind::ConstBinding => "const",
        }
    }
}

/// One NORMALIZED token — the alphabet the syntactic normalizer emits. The wire
/// kind bytes are STABLE (bound into every node cid; append only):
/// `0x01 Word · 0x02 Number · 0x03 Str · 0x04 Template · 0x05 Regex · 0x06 Punct
/// · 0x07 SelfRef · 0x08 AlphaVar · 0x09 Newline`. The placeholder kinds
/// (`SelfRef`, `AlphaVar`) are DISTINCT kind bytes, so they can never collide
/// with a source identifier that happens to spell the placeholder.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NormToken {
    /// An identifier / keyword, raw text.
    Word(String),
    /// A numeric literal, raw text (`1e3` ≠ `1000` — sound, not merged).
    Number(String),
    /// A string literal, raw text INCLUDING quotes (`'a'` ≠ `"a"` — sound).
    Str(String),
    /// A template literal, raw text including backticks and any `${…}` interior.
    Template(String),
    /// A regex literal, raw text including slashes + flags.
    Regex(String),
    /// A punctuator / operator, raw text.
    Punct(String),
    /// The unit's OWN name (every clean reference position) — erased so a rename
    /// of the definition converges to the same cid.
    SelfRef,
    /// A canonically renamed local binder: the N-th alpha-eligible binder (by
    /// first occurrence) — erased so a local rename converges to the same cid.
    AlphaVar(u16),
    /// A semantically significant line break (an ASI position the normalizer
    /// could not prove droppable — kept, sound-first).
    Newline,
}

impl NormToken {
    /// The STABLE wire kind byte.
    #[must_use]
    pub const fn kind_wire(&self) -> u8 {
        match self {
            NormToken::Word(_) => 0x01,
            NormToken::Number(_) => 0x02,
            NormToken::Str(_) => 0x03,
            NormToken::Template(_) => 0x04,
            NormToken::Regex(_) => 0x05,
            NormToken::Punct(_) => 0x06,
            NormToken::SelfRef => 0x07,
            NormToken::AlphaVar(_) => 0x08,
            NormToken::Newline => 0x09,
        }
    }
}

/// Encode a normalized token stream to its canonical bytes:
/// per token `kind_byte ‖ le16(payload_len) ‖ payload` (payload of `SelfRef` /
/// `Newline` is empty; `AlphaVar(i)` is the le16 index). Deterministic and
/// prefix-unambiguous. `None` iff any payload exceeds [`NORM_TOKEN_MAX_BYTES`]
/// — the caller degrades that unit to [`opaque_normalized`] (fail-closed, never
/// truncated).
#[must_use]
pub fn encode_tokens(tokens: &[NormToken]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(tokens.len() * 8);
    for tok in tokens {
        let payload: Vec<u8> = match tok {
            NormToken::Word(s)
            | NormToken::Number(s)
            | NormToken::Str(s)
            | NormToken::Template(s)
            | NormToken::Regex(s)
            | NormToken::Punct(s) => s.as_bytes().to_vec(),
            NormToken::SelfRef | NormToken::Newline => Vec::new(),
            NormToken::AlphaVar(i) => i.to_le_bytes().to_vec(),
        };
        if payload.len() > NORM_TOKEN_MAX_BYTES {
            return None;
        }
        out.push(tok.kind_wire());
        // Bounded above: the length always fits le16.
        out.extend_from_slice(&u16::try_from(payload.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&payload);
    }
    Some(out)
}

/// The opaque-tier normalized body: `0xFF ‖ raw_source_bytes`. Used when the
/// normalizer cannot confidently normalize a unit — identity is then the exact
/// spelling (no invariance claimed; sound: two different spellings stay two
/// nodes). Disjoint from [`encode_tokens`] output by the leading tag byte.
#[must_use]
pub fn opaque_normalized(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + raw.len());
    out.push(OPAQUE_TAG);
    out.extend_from_slice(raw);
    out
}

/// Derive the P-LOCK-2 content address of a definition node. The NAME is NOT an
/// input — identity comes from content only. Every variable-length field is le32
/// length-prefixed (unambiguous field boundaries); each dependency digest is a
/// fixed 32 bytes.
#[must_use]
pub fn node_cid(
    lang: DefnLang,
    normalized: &[u8],
    type_sig: &[u8],
    effect_sig: &[u8],
    deps: &[[u8; 32]],
) -> String {
    let mut pre = Vec::with_capacity(
        NODE_DOMAIN.len()
            + 1
            + 4 * 4
            + normalized.len()
            + type_sig.len()
            + effect_sig.len()
            + deps.len() * 32,
    );
    pre.extend_from_slice(NODE_DOMAIN);
    pre.push(lang.wire());
    for field in [normalized, type_sig, effect_sig] {
        // Bounded by memory in practice; saturate is unreachable but fail-closed.
        pre.extend_from_slice(&u32::try_from(field.len()).unwrap_or(u32::MAX).to_le_bytes());
        pre.extend_from_slice(field);
    }
    pre.extend_from_slice(&u32::try_from(deps.len()).unwrap_or(u32::MAX).to_le_bytes());
    for dep in deps {
        pre.extend_from_slice(dep);
    }
    crate::hex32(&crate::sha256_32(&pre))
}

/// One ingested definition node. `cid` is DERIVED from the content fields
/// ([`node_cid`]); `name`, `kind`, and `line` are DATA (render / the N-2
/// namespace seam) — changing them alone never changes `cid`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefinitionNode {
    /// The content address (lowercase-hex sha256; see [`node_cid`]).
    pub cid: String,
    /// The source language.
    pub lang: DefnLang,
    /// What kind of definition this is (data, not identity).
    pub kind: DefnKind,
    /// The declared name (DATA — a rename does not move the node).
    pub name: String,
    /// 1-based source line of the definition head (data, not identity).
    pub line: u32,
    /// The canonical normalized body ([`encode_tokens`] or [`opaque_normalized`]).
    pub normalized: Vec<u8>,
    /// The normalized declared signature slice (empty for non-function kinds v1).
    pub type_sig: Vec<u8>,
    /// The effect signature (v1: always [`EFFECT_SIG_UNKNOWN_V1`]).
    pub effect_sig: Vec<u8>,
    /// Dependency-node digests (v1: empty; the N-3 seam).
    pub deps: Vec<[u8; 32]>,
    /// True iff the unit was stored OPAQUE (no normalization/invariance claimed)
    /// — rendered honestly.
    pub opaque: bool,
    /// How many local binders were alpha-canonicalized (0 with `opaque`).
    pub alpha_renamed: u16,
}

impl DefinitionNode {
    /// Build a node, DERIVING `cid` from the content fields. `name`/`kind`/`line`
    /// are attached as data only.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        lang: DefnLang,
        kind: DefnKind,
        name: String,
        line: u32,
        normalized: Vec<u8>,
        type_sig: Vec<u8>,
        effect_sig: Vec<u8>,
        deps: Vec<[u8; 32]>,
        opaque: bool,
        alpha_renamed: u16,
    ) -> Self {
        let cid = node_cid(lang, &normalized, &type_sig, &effect_sig, &deps);
        Self {
            cid,
            lang,
            kind,
            name,
            line,
            normalized,
            type_sig,
            effect_sig,
            deps,
            opaque,
            alpha_renamed,
        }
    }

    /// True iff the stored `cid` equals the cid re-derived from the content
    /// fields — the tamper-evidence check a consumer runs (the
    /// [`crate::agent_registry::AgentArtifact::id_matches_content`] discipline).
    #[must_use]
    pub fn cid_matches_content(&self) -> bool {
        self.cid
            == node_cid(
                self.lang,
                &self.normalized,
                &self.type_sig,
                &self.effect_sig,
                &self.deps,
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Cross-language lock: the Rust cid equals the reference golden vector for
    /// the same field bytes — SHA-256 over
    /// `NODE_DOMAIN ‖ 0x01 ‖ le32(4)‖NORM ‖ le32(3)‖SIG ‖ le32(30)‖EFFECT ‖ le32(0)`.
    #[test]
    fn node_cid_matches_python_golden_vectors() {
        let g0 = node_cid(
            DefnLang::TypeScript,
            b"NORM",
            b"SIG",
            EFFECT_SIG_UNKNOWN_V1,
            &[],
        );
        assert_eq!(
            g0,
            "eaff5dd2c355d86c851ed4a42bf62093a85fdfc92784e82fc5e3b1982fa9871c"
        );
        let mut dep = [0u8; 32];
        for (i, b) in dep.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("0..32 fits u8");
        }
        let g1 = node_cid(
            DefnLang::TypeScript,
            b"NORM",
            b"SIG",
            EFFECT_SIG_UNKNOWN_V1,
            &[dep],
        );
        assert_eq!(
            g1,
            "c3393c66d3ee356c2ef4a154fd0515d595fd172ef11c8a19ac42b6e34a54a448"
        );
    }

    /// P-LOCK-2 heart: the name is DATA — two nodes with identical content but
    /// different names share ONE cid; changing any content field changes it.
    #[test]
    fn name_is_data_not_identity() {
        let a = DefinitionNode::new(
            DefnLang::TypeScript,
            DefnKind::Function,
            "foo".to_string(),
            1,
            b"NORM".to_vec(),
            b"SIG".to_vec(),
            EFFECT_SIG_UNKNOWN_V1.to_vec(),
            vec![],
            false,
            0,
        );
        let b = DefinitionNode::new(
            DefnLang::TypeScript,
            DefnKind::Function,
            "renamed_completely".to_string(),
            999,
            b"NORM".to_vec(),
            b"SIG".to_vec(),
            EFFECT_SIG_UNKNOWN_V1.to_vec(),
            vec![],
            false,
            0,
        );
        assert_eq!(a.cid, b.cid, "name/line are data, not identity");
        assert!(a.cid_matches_content());
        // Any CONTENT change moves the cid.
        let c = node_cid(
            DefnLang::TypeScript,
            b"NORN",
            b"SIG",
            EFFECT_SIG_UNKNOWN_V1,
            &[],
        );
        assert_ne!(a.cid, c);
    }

    /// Field boundaries are le32-locked: moving a byte across the norm/type_sig
    /// boundary yields a DIFFERENT preimage (mirrors the Python check).
    #[test]
    fn field_boundary_is_unambiguous() {
        let a = node_cid(
            DefnLang::TypeScript,
            b"NORM",
            b"SIG",
            EFFECT_SIG_UNKNOWN_V1,
            &[],
        );
        let b = node_cid(
            DefnLang::TypeScript,
            b"NORMS",
            b"IG",
            EFFECT_SIG_UNKNOWN_V1,
            &[],
        );
        assert_ne!(a, b, "a shifted byte must not collide");
    }

    /// The token encoding is kind-byte disjoint and fail-closed on over-cap.
    #[test]
    fn token_encoding_is_disjoint_and_bounded() {
        let toks = vec![
            NormToken::Word("function".to_string()),
            NormToken::SelfRef,
            NormToken::Punct("(".to_string()),
            NormToken::AlphaVar(0),
            NormToken::Punct(")".to_string()),
            NormToken::Newline,
        ];
        let enc = encode_tokens(&toks).expect("small tokens encode");
        // kind ‖ le16 ‖ payload per token: 3+8 + 3 + 3+1 + 3+2 + 3+1 + 3 = 30
        assert_eq!(enc.len(), 30);
        // A source Word spelling a placeholder can NEVER alias the placeholder:
        // the kind bytes differ.
        let word = encode_tokens(&[NormToken::Word("x".to_string())]).expect("encodes");
        let alpha = encode_tokens(&[NormToken::AlphaVar(0)]).expect("encodes");
        assert_ne!(word[0], alpha[0]);
        // Over-cap payload refuses (the caller degrades to opaque, never truncates).
        let giant = "g".repeat(NORM_TOKEN_MAX_BYTES + 1);
        assert_eq!(encode_tokens(&[NormToken::Word(giant)]), None);
        // Opaque bodies are tag-disjoint from token streams.
        let opaque = opaque_normalized(b"raw src");
        assert_eq!(opaque[0], OPAQUE_TAG);
        assert_ne!(opaque[0], enc[0]);
    }

    /// Byte-length pins: the domain constants are
    /// part of the wire format — a drifted constant breaks every cid.
    #[test]
    fn domain_constants_byte_pins() {
        assert_eq!(NODE_DOMAIN.len(), 25);
        assert_eq!(EFFECT_SIG_UNKNOWN_V1.len(), 30);
        assert_eq!(DefnLang::TypeScript.wire(), 1);
    }
}
