//! Nous IR — the TYPED MORPHISM + the deterministic COMMUTE/CONFLICT JUDGE
//! (P-LOCK-3/P-LOCK-4).
//!
//! A CHANGE is an object: `before node-set → after node-set` plus class,
//! preconditions, invariants, namespace effects, evidence links — content-addressed by
//! `morphism_id = hex(sha256(MORPH_DOMAIN ‖ canonical bytes))`. "Conflict" is
//! REDEFINED: not textual overlap but PREDICATE/EFFECT incompatibility over
//! the world model `W = (nodes, names)` — exactly the node identity + the namespace
//! fold. Two morphisms with disjoint read/write surfaces auto-compose
//! ORDER-FREE; anything else ESCALATES (soundness-first: a false split is fine, a
//! false merge is the kill criterion).
//!
//! ## The judge (P-LOCK-4: compiled, deterministic, outside the LLM)
//!
//! `judge(m1, m2)` escalates iff ANY of (both directions):
//! 1. `node_touched ∩ node_touched` (write-write on nodes)
//! 2. `node_read ∩ node_touched` (read-write on nodes)
//! 3. `name_written ∩ name_written` (write-write on names — NO idempotent exception)
//! 4. `name_read ∩ name_written` (read-write on names)
//!
//! …else `AutoCompose`. Soundness is proven by TWO INDEPENDENT derivations: the
//! judge's verdict vs actual execution of both orders on the world model (the
//! property kill gate), plus a known-SAT canary showing the harness can detect
//! divergence. In v0 the verdict is ADVISORY: **no apply/pin surface is wired** —
//! pinning a morphism behind an unforgeable capability witness is the ledger seam.
//!
//! PURITY: this module is FULLY PURE — no network, no filesystem, no clock, no
//! randomness, no execution; BTree-ordered structures keep every result
//! deterministic. Custody untouched.

use std::collections::{BTreeMap, BTreeSet};

use crate::defn_node::DefinitionNode;

/// The domain-separation tag bound into every morphism id (24 bytes,
/// Python-verified) — a morphism id can never collide with an AGRX/node/namespace hash.
pub const MORPH_DOMAIN: &[u8] = b"sinabro.nous.morphism.v1";

/// The morphism-codec magic (4 bytes) — `MRPH`.
pub const MORPH_MAGIC: [u8; 4] = *b"MRPH";

/// The wire version this codec WRITES.
pub const MORPH_VERSION: u8 = 1;

/// Max bytes of the bounded intent line (the AGRX summary idiom).
pub const MORPH_INTENT_CAP_BYTES: usize = 96;

/// Max bytes of the author tag (data stub — signed authorship is the ledger seam).
pub const MORPH_AUTHOR_CAP_BYTES: usize = 96;

/// What kind of change a morphism is. DERIVED by construction (never trusted from
/// a caller), then bound into the content address as part of the object (P-LOCK-3).
/// Wire bytes are STABLE (append only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MorphismClass {
    /// No node change and no name change.
    Noop,
    /// Adds nodes only.
    Add,
    /// Removes nodes only.
    Remove,
    /// Removes and adds nodes.
    Modify,
    /// No node change; namespace effects only (the N-2 "rename is data" case).
    RenameOnly,
}

impl MorphismClass {
    /// The STABLE wire byte.
    #[must_use]
    pub const fn wire(self) -> u8 {
        match self {
            MorphismClass::Noop => 0,
            MorphismClass::Add => 1,
            MorphismClass::Remove => 2,
            MorphismClass::Modify => 3,
            MorphismClass::RenameOnly => 4,
        }
    }

    /// Decode a wire byte (fail-closed).
    #[must_use]
    pub const fn from_wire(b: u8) -> Option<Self> {
        match b {
            0 => Some(MorphismClass::Noop),
            1 => Some(MorphismClass::Add),
            2 => Some(MorphismClass::Remove),
            3 => Some(MorphismClass::Modify),
            4 => Some(MorphismClass::RenameOnly),
            _ => None,
        }
    }

    /// A stable lower-case label (for renders).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            MorphismClass::Noop => "noop",
            MorphismClass::Add => "add",
            MorphismClass::Remove => "remove",
            MorphismClass::Modify => "modify",
            MorphismClass::RenameOnly => "rename-only",
        }
    }
}

/// The CLOSED predicate vocabulary v0 — everything is checkable against
/// the world model; free-text claims do not exist here.
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Predicate {
    /// The node with this cid must be present.
    NodeExists([u8; 32]),
    /// The namespace must currently resolve `name` to this cid.
    NameResolvesTo(String, [u8; 32]),
}

/// A namespace effect a morphism performs (the N-2 event vocabulary).
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum NsEffect {
    /// Bind (or re-bind) `name` to a node cid.
    Bind(String, [u8; 32]),
    /// Remove `name` from the namespace.
    Unbind(String),
}

impl NsEffect {
    /// The effect's name (every effect has one).
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            NsEffect::Bind(n, _) | NsEffect::Unbind(n) => n,
        }
    }
}

/// Typed construction/codec failures (fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MorphError {
    /// Bytes shorter than a field demanded.
    Truncated,
    /// The magic was not [`MORPH_MAGIC`].
    BadMagic,
    /// The version byte was unknown.
    UnknownVersion,
    /// An unknown class / predicate / effect wire byte.
    UnknownKind,
    /// Trailing garbage after the last field.
    TrailingBytes,
    /// A name failed the N-2 validity rules (empty/over-cap/non-graphic/cid-shaped).
    BadName,
    /// The intent/author exceeded its cap or was not UTF-8.
    BadText,
    /// Two namespace effects share one name (self-ambiguous ordering — refused).
    DuplicateNameEffect,
    /// The predicate set contradicts itself (one name expected at two cids).
    ContradictoryPredicates,
}

impl MorphError {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            MorphError::Truncated => "truncated morphism bytes",
            MorphError::BadMagic => "bad morphism magic",
            MorphError::UnknownVersion => "unknown morphism version",
            MorphError::UnknownKind => "unknown wire kind",
            MorphError::TrailingBytes => "trailing bytes",
            MorphError::BadName => "bad name (N-2 rules; must not be cid-shaped)",
            MorphError::BadText => "intent/author over cap or not UTF-8",
            MorphError::DuplicateNameEffect => {
                "two namespace effects share one name (refused, order-ambiguous)"
            }
            MorphError::ContradictoryPredicates => {
                "self-contradictory predicates (one name, two expected cids)"
            }
        }
    }
}

/// A typed morphism — CANONICAL by construction ([`Morphism::build`] is the only
/// door): node sets sorted+deduped+disjoint, predicates/effects sorted, class
/// derived, names validated. `id` is DERIVED from the canonical bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Morphism {
    /// The content address (lowercase-hex sha256; see [`morphism_id`]).
    pub id: String,
    /// The derived change class.
    pub class: MorphismClass,
    /// Bounded human intent line (data).
    pub intent: String,
    /// Author tag (data stub; signed authorship = L-1).
    pub author: String,
    /// Node cids REMOVED by this change (sorted, deduped, disjoint from `after`).
    pub before: Vec<[u8; 32]>,
    /// Node cids ADDED by this change (sorted, deduped).
    pub after: Vec<[u8; 32]>,
    /// Preconditions (sorted; checked against the world BEFORE apply).
    pub pre: Vec<Predicate>,
    /// Invariants (sorted; checked against the world AFTER apply).
    pub inv: Vec<Predicate>,
    /// Namespace effects (sorted by name; at most one per name).
    pub ns_effects: Vec<NsEffect>,
    /// Evidence links — content addresses of receipts/proofs (opaque v0; the proof-cache seam).
    pub evidence: Vec<[u8; 32]>,
}

fn bounded_text(s: &str, cap: usize) -> Result<String, MorphError> {
    if s.len() > cap {
        return Err(MorphError::BadText);
    }
    Ok(s.to_string())
}

fn validate_predicates(preds: &[Predicate]) -> Result<(), MorphError> {
    let mut expect: BTreeMap<&str, &[u8; 32]> = BTreeMap::new();
    for p in preds {
        if let Predicate::NameResolvesTo(n, c) = p {
            if !crate::namespace::valid_name(n) {
                return Err(MorphError::BadName);
            }
            if let Some(prev) = expect.insert(n.as_str(), c) {
                if prev != c {
                    return Err(MorphError::ContradictoryPredicates);
                }
            }
        }
    }
    Ok(())
}

impl Morphism {
    /// The ONLY constructor: canonicalize + validate + derive class + derive id.
    /// Fail-closed — an invalid shape never becomes a `Morphism` value, so the
    /// judge's inputs are valid BY TYPE.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        intent: &str,
        author: &str,
        before: Vec<[u8; 32]>,
        after: Vec<[u8; 32]>,
        pre: Vec<Predicate>,
        inv: Vec<Predicate>,
        ns_effects: Vec<NsEffect>,
        evidence: Vec<[u8; 32]>,
    ) -> Result<Self, MorphError> {
        let intent = bounded_text(intent, MORPH_INTENT_CAP_BYTES)?;
        let author = bounded_text(author, MORPH_AUTHOR_CAP_BYTES)?;
        // Canonical node sets: sorted, deduped, and DISJOINT (a cid in both sets
        // is an unchanged node — dropped from both).
        let mut before_set: BTreeSet<[u8; 32]> = before.into_iter().collect();
        let mut after_set: BTreeSet<[u8; 32]> = after.into_iter().collect();
        let common: Vec<[u8; 32]> = before_set.intersection(&after_set).copied().collect();
        for c in &common {
            before_set.remove(c);
            after_set.remove(c);
        }
        // Predicates: validated (names + self-consistency), sorted, deduped.
        let mut pre = pre;
        let mut inv = inv;
        validate_predicates(&pre)?;
        validate_predicates(&inv)?;
        pre.sort();
        pre.dedup();
        inv.sort();
        inv.dedup();
        // Effects: validated names, AT MOST ONE PER NAME (order-ambiguity refused),
        // then sorted by name (semantics-free given uniqueness).
        let mut seen = BTreeSet::new();
        for e in &ns_effects {
            if !crate::namespace::valid_name(e.name()) {
                return Err(MorphError::BadName);
            }
            if !seen.insert(e.name().to_string()) {
                return Err(MorphError::DuplicateNameEffect);
            }
        }
        let mut ns_effects = ns_effects;
        ns_effects.sort();
        let mut evidence_set: Vec<[u8; 32]> = evidence
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        evidence_set.sort_unstable();
        let before: Vec<[u8; 32]> = before_set.into_iter().collect();
        let after: Vec<[u8; 32]> = after_set.into_iter().collect();
        let class = match (before.is_empty(), after.is_empty(), ns_effects.is_empty()) {
            (true, true, true) => MorphismClass::Noop,
            (true, true, false) => MorphismClass::RenameOnly,
            (true, false, _) => MorphismClass::Add,
            (false, true, _) => MorphismClass::Remove,
            (false, false, _) => MorphismClass::Modify,
        };
        let mut m = Self {
            id: String::new(),
            class,
            intent,
            author,
            before,
            after,
            pre,
            inv,
            ns_effects,
            evidence: evidence_set,
        };
        m.id = morphism_id(&m.canonical_bytes());
        Ok(m)
    }

    /// The canonical wire bytes (deterministic; the id preimage tail).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64 + 32 * (self.before.len() + self.after.len()));
        b.extend_from_slice(&MORPH_MAGIC);
        b.push(MORPH_VERSION);
        b.push(self.class.wire());
        push_text(&mut b, &self.intent);
        push_text(&mut b, &self.author);
        for set in [&self.before, &self.after] {
            b.extend_from_slice(&u32::try_from(set.len()).unwrap_or(u32::MAX).to_le_bytes());
            for c in set.iter() {
                b.extend_from_slice(c);
            }
        }
        for preds in [&self.pre, &self.inv] {
            b.extend_from_slice(&u32::try_from(preds.len()).unwrap_or(u32::MAX).to_le_bytes());
            for p in preds.iter() {
                match p {
                    Predicate::NodeExists(c) => {
                        b.push(1);
                        b.extend_from_slice(c);
                    }
                    Predicate::NameResolvesTo(n, c) => {
                        b.push(2);
                        push_text(&mut b, n);
                        b.extend_from_slice(c);
                    }
                }
            }
        }
        b.extend_from_slice(
            &u32::try_from(self.ns_effects.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for e in &self.ns_effects {
            match e {
                NsEffect::Bind(n, c) => {
                    b.push(1);
                    push_text(&mut b, n);
                    b.extend_from_slice(c);
                }
                NsEffect::Unbind(n) => {
                    b.push(2);
                    push_text(&mut b, n);
                }
            }
        }
        b.extend_from_slice(
            &u32::try_from(self.evidence.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for d in &self.evidence {
            b.extend_from_slice(d);
        }
        b
    }

    /// Tamper-evidence: the stored id re-derives from the canonical bytes (the
    /// AGRX `id_matches_content` discipline).
    #[must_use]
    pub fn id_matches_content(&self) -> bool {
        self.id == morphism_id(&self.canonical_bytes())
    }

    /// All node cids this morphism WRITES (`before ∪ after`).
    #[must_use]
    pub fn node_touched(&self) -> BTreeSet<[u8; 32]> {
        self.before
            .iter()
            .chain(self.after.iter())
            .copied()
            .collect()
    }

    /// All node cids this morphism READS (`NodeExists` in pre ∪ inv).
    #[must_use]
    pub fn node_read(&self) -> BTreeSet<[u8; 32]> {
        self.pre
            .iter()
            .chain(self.inv.iter())
            .filter_map(|p| match p {
                Predicate::NodeExists(c) => Some(*c),
                Predicate::NameResolvesTo(..) => None,
            })
            .collect()
    }

    /// All names this morphism WRITES (its namespace effects).
    #[must_use]
    pub fn name_written(&self) -> BTreeSet<String> {
        self.ns_effects
            .iter()
            .map(|e| e.name().to_string())
            .collect()
    }

    /// All names this morphism READS (`NameResolvesTo` in pre ∪ inv).
    #[must_use]
    pub fn name_read(&self) -> BTreeSet<String> {
        self.pre
            .iter()
            .chain(self.inv.iter())
            .filter_map(|p| match p {
                Predicate::NameResolvesTo(n, _) => Some(n.clone()),
                Predicate::NodeExists(_) => None,
            })
            .collect()
    }
}

fn push_text(b: &mut Vec<u8>, s: &str) {
    b.extend_from_slice(&u16::try_from(s.len()).unwrap_or(u16::MAX).to_le_bytes());
    b.extend_from_slice(s.as_bytes());
}

/// The content address of a morphism: `hex(sha256(MORPH_DOMAIN ‖ canonical_bytes))`.
#[must_use]
pub fn morphism_id(canonical_bytes: &[u8]) -> String {
    let mut pre = Vec::with_capacity(MORPH_DOMAIN.len() + canonical_bytes.len());
    pre.extend_from_slice(MORPH_DOMAIN);
    pre.extend_from_slice(canonical_bytes);
    crate::hex32(&crate::sha256_32(&pre))
}

// ---------------------------------------------------------------------------
// World model + apply (grounding: N-1 nodes + N-2 namespace fold)
// ---------------------------------------------------------------------------

/// The world a morphism acts on: the node set (N-1 identities) + the namespace
/// state (the N-2 fold). PURE VALUE — applying never touches disk.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct World {
    /// Present definition nodes (by raw cid).
    pub nodes: BTreeSet<[u8; 32]>,
    /// Current name bindings.
    pub names: BTreeMap<String, [u8; 32]>,
}

/// Why an apply refused (fail-closed; the world is returned UNCHANGED).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ApplyDeny {
    /// A precondition did not hold.
    PreconditionFailed(Predicate),
    /// A removed node was absent.
    RemovedNodeAbsent([u8; 32]),
    /// An unbind targeted an absent name.
    UnbindAbsent(String),
    /// An invariant did not hold in the RESULT.
    InvariantFailed(Predicate),
}

fn predicate_holds(w: &World, p: &Predicate) -> bool {
    match p {
        Predicate::NodeExists(c) => w.nodes.contains(c),
        Predicate::NameResolvesTo(n, c) => w.names.get(n.as_str()) == Some(c),
    }
}

/// Apply a morphism to a world (PURE): check pre → move node sets → apply name
/// effects → check inv on the result. Any refusal leaves the input untouched.
pub fn apply(w: &World, m: &Morphism) -> Result<World, ApplyDeny> {
    for p in &m.pre {
        if !predicate_holds(w, p) {
            return Err(ApplyDeny::PreconditionFailed(p.clone()));
        }
    }
    let mut out = w.clone();
    for c in &m.before {
        if !out.nodes.remove(c) {
            return Err(ApplyDeny::RemovedNodeAbsent(*c));
        }
    }
    for c in &m.after {
        out.nodes.insert(*c);
    }
    for e in &m.ns_effects {
        match e {
            NsEffect::Bind(n, c) => {
                out.names.insert(n.clone(), *c);
            }
            NsEffect::Unbind(n) => {
                if out.names.remove(n.as_str()).is_none() {
                    return Err(ApplyDeny::UnbindAbsent(n.clone()));
                }
            }
        }
    }
    for p in &m.inv {
        if !predicate_holds(&out, p) {
            return Err(ApplyDeny::InvariantFailed(p.clone()));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// The JUDGE (P-LOCK-4: pure, deterministic, escalate-by-default)
// ---------------------------------------------------------------------------

/// Why a pair escalates (rendered honestly; the escalation rate is the quality metric).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EscalateReason {
    /// Both morphisms write an overlapping node set.
    NodeWriteOverlap,
    /// One reads a node the other writes.
    NodeReadWrite,
    /// Both write the same name (no idempotent exception in v0).
    NameWriteClash,
    /// One reads a name the other writes.
    NameReadWrite,
}

impl EscalateReason {
    /// A stable label for renders.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            EscalateReason::NodeWriteOverlap => "node write-write overlap",
            EscalateReason::NodeReadWrite => "node read-write dependency",
            EscalateReason::NameWriteClash => "name write-write clash",
            EscalateReason::NameReadWrite => "name read-write dependency",
        }
    }
}

/// The judge's verdict. `AutoCompose` claims ORDER-FREE composition (-1);
/// `Escalate` hands the pair to a human/higher process — v0 wires NO apply
/// surface either way (advisory only).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JudgeVerdict {
    /// The pair provably commutes on the world model — safe to compose order-free.
    AutoCompose,
    /// Not provably safe — escalate (soundness-first).
    Escalate(EscalateReason),
}

/// The deterministic commute/conflict judge (see module docs for the 4 rules).
/// Inputs are valid BY TYPE ([`Morphism::build`] is the only door). The ONLY path
/// to `AutoCompose` is falling through every escalation rule.
#[must_use]
pub fn judge(m1: &Morphism, m2: &Morphism) -> JudgeVerdict {
    // Rule 1 — node write-write.
    if !m1.node_touched().is_disjoint(&m2.node_touched()) {
        return JudgeVerdict::Escalate(EscalateReason::NodeWriteOverlap);
    }
    // Rule 2 — node read-write (both directions).
    if !m1.node_read().is_disjoint(&m2.node_touched())
        || !m2.node_read().is_disjoint(&m1.node_touched())
    {
        return JudgeVerdict::Escalate(EscalateReason::NodeReadWrite);
    }
    // Rule 3 — name write-write (no idempotent exception).
    if !m1.name_written().is_disjoint(&m2.name_written()) {
        return JudgeVerdict::Escalate(EscalateReason::NameWriteClash);
    }
    // Rule 4 — name read-write (both directions).
    if !m1.name_read().is_disjoint(&m2.name_written())
        || !m2.name_read().is_disjoint(&m1.name_written())
    {
        return JudgeVerdict::Escalate(EscalateReason::NameReadWrite);
    }
    JudgeVerdict::AutoCompose
}

// ---------------------------------------------------------------------------
// morph_diff — derive a morphism from two ingest snapshots (old → new)
// ---------------------------------------------------------------------------

/// Derive a typed morphism from two N-1 node snapshots of one module (old → new):
/// `before/after` = the cid set difference; `ns_effects` = the name-map difference;
/// `pre` = grounded read requirements (removed nodes exist; rebound/unbound names
/// resolve to their OLD cids). A name appearing twice in one snapshot is
/// conservatively EXCLUDED from name derivation (ambiguous — sound skip). PURE.
pub fn morph_diff(
    old_nodes: &[DefinitionNode],
    new_nodes: &[DefinitionNode],
    intent: &str,
    author: &str,
) -> Result<Morphism, MorphError> {
    let cid_set = |nodes: &[DefinitionNode]| -> BTreeSet<[u8; 32]> {
        nodes
            .iter()
            .filter_map(|n| crate::namespace::cid_from_hex(&n.cid))
            .collect()
    };
    let name_map = |nodes: &[DefinitionNode]| -> BTreeMap<String, [u8; 32]> {
        let mut seen_twice = BTreeSet::new();
        let mut map: BTreeMap<String, [u8; 32]> = BTreeMap::new();
        for n in nodes {
            let Some(cid) = crate::namespace::cid_from_hex(&n.cid) else {
                continue;
            };
            if !crate::namespace::valid_name(&n.name) {
                continue;
            }
            if map.insert(n.name.clone(), cid).is_some() {
                seen_twice.insert(n.name.clone());
            }
        }
        for dup in seen_twice {
            map.remove(&dup);
        }
        map
    };
    let old_cids = cid_set(old_nodes);
    let new_cids = cid_set(new_nodes);
    let before: Vec<[u8; 32]> = old_cids.difference(&new_cids).copied().collect();
    let after: Vec<[u8; 32]> = new_cids.difference(&old_cids).copied().collect();
    let old_names = name_map(old_nodes);
    let new_names = name_map(new_nodes);
    let mut pre: Vec<Predicate> = before.iter().map(|c| Predicate::NodeExists(*c)).collect();
    let mut effects: Vec<NsEffect> = Vec::new();
    for (n, old_cid) in &old_names {
        match new_names.get(n) {
            Some(new_cid) if new_cid == old_cid => {} // unchanged binding
            Some(new_cid) => {
                pre.push(Predicate::NameResolvesTo(n.clone(), *old_cid));
                effects.push(NsEffect::Bind(n.clone(), *new_cid));
            }
            None => {
                pre.push(Predicate::NameResolvesTo(n.clone(), *old_cid));
                effects.push(NsEffect::Unbind(n.clone()));
            }
        }
    }
    for (n, new_cid) in &new_names {
        if !old_names.contains_key(n) {
            effects.push(NsEffect::Bind(n.clone(), *new_cid));
        }
    }
    // Bound the intent CHAR-SAFELY (a long file-path pair must not refuse the diff).
    let mut intent_b = intent;
    while intent_b.len() > MORPH_INTENT_CAP_BYTES {
        let mut cut = intent_b.len() - 1;
        while !intent_b.is_char_boundary(cut) {
            cut -= 1;
        }
        intent_b = &intent_b[..cut];
    }
    Morphism::build(
        intent_b,
        author,
        before,
        after,
        pre,
        Vec::new(),
        effects,
        Vec::new(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::defn_node::{DefnKind, DefnLang, EFFECT_SIG_UNKNOWN_V1};

    fn cid(b0: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("0..32");
        }
        c[0] = b0;
        c
    }

    fn cid_seq() -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("0..32");
        }
        c
    }

    fn cid_seq1() -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i + 1).expect("1..33");
        }
        c
    }

    /// Cross-language lock: the canonical bytes + ids of the
    /// golden morphisms match the Python derivation exactly.
    #[test]
    fn morphism_id_matches_python_golden_vectors() {
        let g1 = Morphism::build(
            "t",
            "o",
            vec![],
            vec![cid_seq()],
            vec![],
            vec![],
            vec![NsEffect::Bind("n/x".to_string(), cid_seq())],
            vec![],
        )
        .expect("g1 builds");
        assert_eq!(g1.canonical_bytes().len(), 106);
        assert_eq!(
            g1.id,
            "b6a48b6f4fd9756fc4575bde0121a668839dc78e28c208a293d8189c7646da8b"
        );
        assert_eq!(g1.class, MorphismClass::Add);
        let g2 = Morphism::build(
            "diff",
            "owner",
            vec![cid_seq()],
            vec![cid_seq1()],
            vec![
                Predicate::NodeExists(cid_seq()),
                Predicate::NameResolvesTo("n/x".to_string(), cid_seq()),
            ],
            vec![],
            vec![NsEffect::Bind("n/x".to_string(), cid_seq1())],
            vec![],
        )
        .expect("g2 builds");
        assert_eq!(g2.canonical_bytes().len(), 216);
        assert_eq!(
            g2.id,
            "4bfb5d2a7ac953915ab9395bb9f7f54e62b61210bd5cac587f6e922e759a0399"
        );
        assert_eq!(g2.class, MorphismClass::Modify);
        let g3 = Morphism::build(
            "t",
            "o",
            vec![],
            vec![cid_seq()],
            vec![],
            vec![],
            vec![NsEffect::Bind("n/x".to_string(), cid_seq())],
            vec![cid_seq1()],
        )
        .expect("g3 builds");
        assert_eq!(g3.canonical_bytes().len(), 138);
        assert_eq!(
            g3.id,
            "f8c1319b32f93e9630623c4426ca13c828de82693b2474fbea0e7ff2b580869a"
        );
        assert!(g1.id_matches_content() && g2.id_matches_content());
        // forged id detection (the AGRX seatbelt discipline)
        let mut forged = g1.clone();
        forged.id = g2.id.clone();
        assert!(!forged.id_matches_content());
    }

    /// -4 — canonicalization: permuted inputs and unchanged-node noise
    /// converge to ONE id; any semantic field change moves it.
    #[test]
    fn canonicalization_is_permutation_invariant() {
        let a = Morphism::build(
            "t",
            "o",
            vec![cid(1), cid(2)],
            vec![cid(3)],
            vec![Predicate::NodeExists(cid(1)), Predicate::NodeExists(cid(2))],
            vec![],
            vec![
                NsEffect::Bind("b".to_string(), cid(3)),
                NsEffect::Unbind("a".to_string()),
            ],
            vec![],
        )
        .expect("builds");
        let b = Morphism::build(
            "t",
            "o",
            vec![cid(2), cid(1), cid(1)], // permuted + duplicated
            vec![cid(3)],
            vec![Predicate::NodeExists(cid(2)), Predicate::NodeExists(cid(1))],
            vec![],
            vec![
                NsEffect::Unbind("a".to_string()), // permuted
                NsEffect::Bind("b".to_string(), cid(3)),
            ],
            vec![],
        )
        .expect("builds");
        assert_eq!(a.id, b.id, "canonical identity is order-free");
        // an unchanged node (in both before and after) is dropped from both
        let c = Morphism::build(
            "t",
            "o",
            vec![cid(1), cid(9)],
            vec![cid(3), cid(9)],
            vec![Predicate::NodeExists(cid(1)), Predicate::NodeExists(cid(2))],
            vec![],
            vec![
                NsEffect::Bind("b".to_string(), cid(3)),
                NsEffect::Unbind("a".to_string()),
            ],
            vec![],
        )
        .expect("builds");
        assert_eq!(
            c.before,
            vec![cid(1)],
            "unchanged cid(9) dropped from before"
        );
        assert_eq!(c.after, vec![cid(3)], "unchanged cid(9) dropped from after");
        // semantic change moves the id
        assert_ne!(
            a.id,
            Morphism::build(
                "t",
                "o",
                vec![cid(1), cid(2)],
                vec![cid(4)],
                vec![Predicate::NodeExists(cid(1)), Predicate::NodeExists(cid(2))],
                vec![],
                vec![
                    NsEffect::Bind("b".to_string(), cid(3)),
                    NsEffect::Unbind("a".to_string()),
                ],
                vec![],
            )
            .expect("builds")
            .id
        );
    }

    /// -5 — fail-closed construction: duplicate name effects, contradictory
    /// predicates, cid-shaped names, over-cap text are all REFUSED.
    #[test]
    fn construction_fails_closed() {
        assert_eq!(
            Morphism::build(
                "t",
                "o",
                vec![],
                vec![],
                vec![],
                vec![],
                vec![
                    NsEffect::Bind("n".to_string(), cid(1)),
                    NsEffect::Unbind("n".to_string()),
                ],
                vec![],
            ),
            Err(MorphError::DuplicateNameEffect)
        );
        assert_eq!(
            Morphism::build(
                "t",
                "o",
                vec![],
                vec![],
                vec![
                    Predicate::NameResolvesTo("n".to_string(), cid(1)),
                    Predicate::NameResolvesTo("n".to_string(), cid(2)),
                ],
                vec![],
                vec![],
                vec![],
            ),
            Err(MorphError::ContradictoryPredicates)
        );
        assert_eq!(
            Morphism::build(
                "t",
                "o",
                vec![],
                vec![],
                vec![],
                vec![],
                vec![NsEffect::Bind("a".repeat(64), cid(1))],
                vec![],
            ),
            Err(MorphError::BadName),
            "cid-shaped name refused (N-2 disjointness)"
        );
        assert_eq!(
            Morphism::build(
                &"x".repeat(97),
                "o",
                vec![],
                vec![],
                vec![],
                vec![],
                vec![],
                vec![]
            ),
            Err(MorphError::BadText)
        );
    }

    /// apply: pre/removal/unbind/inv all fail-closed; a clean apply moves the world.
    #[test]
    fn apply_fails_closed_and_moves_the_world() {
        let mut w = World::default();
        w.nodes.insert(cid(1));
        w.names.insert("n".to_string(), cid(1));
        let m = Morphism::build(
            "t",
            "o",
            vec![cid(1)],
            vec![cid(2)],
            vec![
                Predicate::NodeExists(cid(1)),
                Predicate::NameResolvesTo("n".to_string(), cid(1)),
            ],
            vec![Predicate::NameResolvesTo("n".to_string(), cid(2))],
            vec![NsEffect::Bind("n".to_string(), cid(2))],
            vec![],
        )
        .expect("builds");
        let w2 = apply(&w, &m).expect("applies");
        assert!(w2.nodes.contains(&cid(2)) && !w2.nodes.contains(&cid(1)));
        assert_eq!(w2.names.get("n"), Some(&cid(2)));
        // precondition failure (empty world)
        assert!(matches!(
            apply(&World::default(), &m),
            Err(ApplyDeny::PreconditionFailed(_))
        ));
        // unbind-absent failure
        let mu = Morphism::build(
            "t",
            "o",
            vec![],
            vec![],
            vec![],
            vec![],
            vec![NsEffect::Unbind("ghost".to_string())],
            vec![],
        )
        .expect("builds");
        assert!(matches!(apply(&w, &mu), Err(ApplyDeny::UnbindAbsent(_))));
        // invariant failure in the RESULT
        let mi = Morphism::build(
            "t",
            "o",
            vec![],
            vec![cid(5)],
            vec![],
            vec![Predicate::NameResolvesTo("n".to_string(), cid(9))],
            vec![],
            vec![],
        )
        .expect("builds");
        assert!(matches!(apply(&w, &mi), Err(ApplyDeny::InvariantFailed(_))));
    }

    /// fixtures — the judge's four escalation rules + the auto path.
    #[test]
    fn judge_fixtures_escalate_and_auto_correctly() {
        let disjoint1 = Morphism::build(
            "e1",
            "o",
            vec![cid(1)],
            vec![cid(2)],
            vec![Predicate::NodeExists(cid(1))],
            vec![],
            vec![NsEffect::Bind("a".to_string(), cid(2))],
            vec![],
        )
        .expect("builds");
        let disjoint2 = Morphism::build(
            "e2",
            "o",
            vec![cid(3)],
            vec![cid(4)],
            vec![Predicate::NodeExists(cid(3))],
            vec![],
            vec![NsEffect::Bind("b".to_string(), cid(4))],
            vec![],
        )
        .expect("builds");
        assert_eq!(judge(&disjoint1, &disjoint2), JudgeVerdict::AutoCompose);

        // rule 1 — node write-write
        let overlap = Morphism::build(
            "e3",
            "o",
            vec![cid(1)],
            vec![cid(5)],
            vec![],
            vec![],
            vec![],
            vec![],
        )
        .expect("builds");
        assert_eq!(
            judge(&disjoint1, &overlap),
            JudgeVerdict::Escalate(EscalateReason::NodeWriteOverlap)
        );
        // rule 2 — node read-write (reads cid(1) which disjoint1 removes)
        let reader = Morphism::build(
            "e4",
            "o",
            vec![],
            vec![cid(6)],
            vec![Predicate::NodeExists(cid(1))],
            vec![],
            vec![],
            vec![],
        )
        .expect("builds");
        assert_eq!(
            judge(&disjoint1, &reader),
            JudgeVerdict::Escalate(EscalateReason::NodeReadWrite)
        );
        // rule 3 — name write-write: TEXT-DISJOINT nodes, same NAME (the
        // text-non-conflicting-but-semantically-conflicting case)
        let name1 = Morphism::build(
            "e5",
            "o",
            vec![],
            vec![cid(7)],
            vec![],
            vec![],
            vec![NsEffect::Bind("helper".to_string(), cid(7))],
            vec![],
        )
        .expect("builds");
        let name2 = Morphism::build(
            "e6",
            "o",
            vec![],
            vec![cid(8)],
            vec![],
            vec![],
            vec![NsEffect::Bind("helper".to_string(), cid(8))],
            vec![],
        )
        .expect("builds");
        assert_eq!(
            judge(&name1, &name2),
            JudgeVerdict::Escalate(EscalateReason::NameWriteClash)
        );
        // rule 4 — name read-write
        let name_reader = Morphism::build(
            "e7",
            "o",
            vec![],
            vec![cid(9)],
            vec![Predicate::NameResolvesTo("a".to_string(), cid(2))],
            vec![],
            vec![],
            vec![],
        )
        .expect("builds");
        assert_eq!(
            judge(&disjoint1, &name_reader),
            JudgeVerdict::Escalate(EscalateReason::NameReadWrite)
        );
        // an EMPTY morphism (a reformat-only edit under
        // normalization) auto-composes with anything.
        let noop = Morphism::build("e8", "o", vec![], vec![], vec![], vec![], vec![], vec![])
            .expect("builds");
        assert_eq!(noop.class, MorphismClass::Noop);
        assert_eq!(judge(&noop, &disjoint1), JudgeVerdict::AutoCompose);
    }

    fn synth_node(name: &str, body: u8) -> DefinitionNode {
        DefinitionNode::new(
            DefnLang::TypeScript,
            DefnKind::Function,
            name.to_string(),
            1,
            vec![body, body, body],
            vec![],
            EFFECT_SIG_UNKNOWN_V1.to_vec(),
            vec![],
            false,
            0,
        )
    }

    fn world_of(nodes: &[DefinitionNode]) -> World {
        let mut w = World::default();
        for n in nodes {
            if let Some(c) = crate::namespace::cid_from_hex(&n.cid) {
                w.nodes.insert(c);
                w.names.insert(n.name.clone(), c);
            }
        }
        w
    }

    /// ★ -1 KILL GATE — commute soundness over a generated
    /// mini-space: two independent edits of a COMMON base; whenever the judge says
    /// AutoCompose, BOTH orders succeed and land in the IDENTICAL world (the
    /// judge's claim vs actual execution = two independent derivations).
    #[test]
    fn property_autocompose_is_order_free_zero_false_merge() {
        const NAMES: &[&str] = &["f0", "f1", "f2", "f3", "f4", "f5"];
        let mut seed: u64 = 0x0C0F_FEE0_C0FF_EE00;
        let mut lcg = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 33) as usize
        };
        let mut auto_n = 0u32;
        let mut esc_n = 0u32;
        for round in 0..48 {
            // base module: 6 functions with distinct bodies
            let base: Vec<DefinitionNode> = NAMES
                .iter()
                .enumerate()
                .map(|(i, n)| synth_node(n, u8::try_from(i).expect("small") + 10))
                .collect();
            // variant = base with one deterministic edit at a chosen index
            let edit = |kind: usize, i: usize, salt: usize| -> Vec<DefinitionNode> {
                let mut v = base.clone();
                match kind % 3 {
                    0 => {
                        // modify body (new cid, same name)
                        let nm = v[i].name.clone();
                        v[i] = synth_node(&nm, u8::try_from(100 + salt % 100).expect("u8"));
                    }
                    1 => {
                        // rename (same cid, new name)
                        let body = v[i].normalized[0];
                        let nm = format!("renamed{}", salt % 97);
                        v[i] = synth_node(&nm, body);
                    }
                    _ => {
                        // add a new function
                        v.push(synth_node(
                            &format!("added{}", salt % 89),
                            u8::try_from(200 + salt % 55).expect("u8"),
                        ));
                    }
                }
                v
            };
            let i1 = lcg() % NAMES.len();
            // Every 4th round FORCES a same-target pair (a guaranteed clash class),
            // so the space provably exercises Escalate; other rounds roam free.
            let i2 = if round % 4 == 0 {
                i1
            } else {
                lcg() % NAMES.len()
            };
            let v1 = edit(lcg(), i1, lcg());
            let v2 = edit(lcg(), i2, lcg());
            let m1 = morph_diff(&base, &v1, "m1", "o").expect("m1");
            let m2 = morph_diff(&base, &v2, "m2", "o").expect("m2");
            let w = world_of(&base);
            match judge(&m1, &m2) {
                JudgeVerdict::AutoCompose => {
                    auto_n += 1;
                    // DERIVATION 2: execute both orders — must succeed AND agree.
                    let a = apply(&apply(&w, &m1).expect("order m1;m2 step1"), &m2)
                        .expect("order m1;m2 step2");
                    let b = apply(&apply(&w, &m2).expect("order m2;m1 step1"), &m1)
                        .expect("order m2;m1 step2");
                    assert_eq!(a, b, "AutoCompose must be order-free (zero false merge)");
                }
                JudgeVerdict::Escalate(_) => {
                    esc_n += 1;
                }
            }
        }
        // the space must EXERCISE both verdicts (no vacuous pass)
        assert!(auto_n > 0, "mini-space produced no AutoCompose — vacuous");
        assert!(esc_n > 0, "mini-space produced no Escalate — vacuous");
    }

    /// Known-SAT canary: a name
    /// write-write pair — which the judge ESCALATES — demonstrably DIVERGES when
    /// force-executed in both orders, proving the harness can detect a false merge
    /// (the property above is falsifiable, not self-confirming).
    #[test]
    fn canary_name_clash_diverges_when_force_executed() {
        let base: Vec<DefinitionNode> = vec![synth_node("f0", 10)];
        // two variants both ADD a function named `helper` — different bodies.
        let mut v1 = base.clone();
        v1.push(synth_node("helper", 111));
        let mut v2 = base.clone();
        v2.push(synth_node("helper", 222));
        let m1 = morph_diff(&base, &v1, "add helper A", "o").expect("m1");
        let m2 = morph_diff(&base, &v2, "add helper B", "o").expect("m2");
        // the judge correctly escalates (text-disjoint, semantically clashing)…
        assert_eq!(
            judge(&m1, &m2),
            JudgeVerdict::Escalate(EscalateReason::NameWriteClash)
        );
        // …and force-executing anyway shows REAL divergence (canary: the detector
        // in the property test is live).
        let w = world_of(&base);
        let a = apply(&apply(&w, &m1).expect("a1"), &m2).expect("a2");
        let b = apply(&apply(&w, &m2).expect("b1"), &m1).expect("b2");
        assert_ne!(a, b, "orders diverge — the divergence detector works");
        assert_ne!(a.names.get("helper"), b.names.get("helper"));
    }

    /// morph_diff derives the cases: modify / RENAME-ONLY (same cid, name
    /// events only) / reformat-only ⇒ Noop (the normalization dividend).
    #[test]
    fn morph_diff_derives_grounded_morphisms() {
        let base = vec![synth_node("alpha", 1), synth_node("beta", 2)];
        // rename-only: same body (same cid), new name
        let renamed = vec![synth_node("alpha", 1), synth_node("gamma", 2)];
        let m = morph_diff(&base, &renamed, "rename beta", "o").expect("m");
        assert_eq!(m.class, MorphismClass::RenameOnly);
        assert!(m.before.is_empty() && m.after.is_empty());
        assert_eq!(m.ns_effects.len(), 2, "unbind beta + bind gamma");
        // reformat-only (identical nodes) ⇒ Noop
        let m0 = morph_diff(&base, &base.clone(), "reformat", "o").expect("m0");
        assert_eq!(m0.class, MorphismClass::Noop);
        assert!(m0.ns_effects.is_empty() && m0.pre.is_empty());
        // modify: beta gets a new body
        let modified = vec![synth_node("alpha", 1), synth_node("beta", 99)];
        let mm = morph_diff(&base, &modified, "modify beta", "o").expect("mm");
        assert_eq!(mm.class, MorphismClass::Modify);
        assert_eq!(mm.before.len(), 1);
        assert_eq!(mm.after.len(), 1);
        // its pre reads the OLD binding (read-your-writes grounding)
        assert!(
            mm.pre
                .iter()
                .any(|p| matches!(p, Predicate::NameResolvesTo(n, _) if n == "beta"))
        );
    }
}
