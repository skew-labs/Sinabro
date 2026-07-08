//! The LEDGER: an append-only, hash-linked operation log
//! (pin · name-binding · proof · intent) + the capability-witness PIN
//! that PROMOTES the advisory judge verdict into REAL composition.
//!
//! ## Chain (the audit-chain discipline)
//!
//! ```text
//! chain  = "LGRX" ‖ u8 version ‖ le32 op_count ‖ record…
//! record = le16 |op_bytes| ‖ op_bytes ‖ link[32]
//! link_i = sha256(LEDGER_DOMAIN ‖ link_{i-1} ‖ op_bytes_i)   (genesis prev = 32×0)
//! ```
//!
//! A rewalk recomputes every link — byte-tamper, fork, reorder, truncation ⇒ RED.
//! The 4 op kinds are: `Pin` (a morphism, by content id + its
//! ContentStore payload cid), `NameBind` (the provenance record of an APPLIED
//! namespace effect — the namespace log stays the name-STATE source of truth), `Proof`
//! (an evidence digest link), `Intent` (a bounded note).
//!
//! ## The witness
//!
//! [`LedgerPinWitness`] has a PRIVATE field and exactly ONE door:
//! [`mint_pin_witness`] with the owner ceremony phrase. [`pin_morphism`] /
//! [`compose_pair`] REQUIRE the witness type — unreachable without the ceremony,
//! unforgeable outside this module. No grant/authority mint site is touched.
//!
//! ## Promotion with structural teeth
//!
//! `compose_pair` runs the [`crate::morphism::judge`] INSIDE — an `Escalate`
//! verdict refuses before any byte moves (an escalated pair CANNOT compose).
//! Writes are ordered effect-first: the namespace log (the real effect) is
//! written BEFORE the ledger record — a crash between the two leaves an audit
//! GAP, never a false audit CLAIM. Preconditions are checked against the REAL
//! namespace fold (fail-closed, zero writes on a miss); `NodeExists`
//! preconditions are honestly counted UNVERIFIED (files are the node source of truth).
//!
//! Signatures are an HONEST STUB: the lane is keyless — the author tag
//! is data; cryptographic authorship is custody-adjacent and deferred to its own
//! gated slice. No network, no chain, no custody symbol.

use std::path::Path;

use crate::content_store::{ContentStore, PutClass};
use crate::morphism::{Morphism, NsEffect};

/// Domain tag for every chain link (27 bytes, Python-verified 2026-07-08).
pub const LEDGER_DOMAIN: &[u8] = b"sinabro.nous.ledger.link.v1";

/// The ledger-file magic (4 bytes) — `LGRX`.
pub const LEDGER_MAGIC: [u8; 4] = *b"LGRX";

/// The chain wire version this codec WRITES.
pub const LEDGER_VERSION: u8 = 1;

/// Max bytes of an intent text / author tag (the AGRX summary idiom).
pub const LEDGER_TEXT_CAP_BYTES: usize = 96;

/// The ledger file under `<data_dir>/nous/`.
pub const LEDGER_FILE: &str = "ledger.lgx";

/// The owner ceremony phrase that mints the pin witness (typed EXACTLY,
/// or nothing mints).
pub const MORPH_PIN_ARM_PHRASE: &str = "morph-pin-owner-live";

/// One ledger operation (the plan's 4 kinds). Wire kind bytes are STABLE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LedgerOp {
    /// A morphism was pinned: its content id + the ContentStore payload cid.
    Pin {
        /// The raw [`crate::morphism::morphism_id`] (32 bytes).
        morph_id: [u8; 32],
        /// The raw ContentStore cid of the canonical bytes (64-hex → 32 bytes).
        payload_cid: [u8; 32],
        /// Author tag (data stub).
        author: String,
    },
    /// The provenance record of ONE namespace effect that was APPLIED.
    NameBind {
        /// The applied effect (reuses the N-3 vocabulary — define once).
        effect: NsEffect,
        /// Author tag.
        author: String,
    },
    /// An evidence digest attached to a subject (the PF-2 seam; opaque v1).
    Proof {
        /// What the evidence is about (a morphism/node id, raw 32 bytes).
        subject: [u8; 32],
        /// The evidence digest.
        evidence: [u8; 32],
        /// Author tag.
        author: String,
    },
    /// A bounded human intent note about a subject (the N-4 seam seed).
    Intent {
        /// What the note is about.
        subject: [u8; 32],
        /// The bounded note (≤ [`LEDGER_TEXT_CAP_BYTES`]).
        text: String,
        /// Author tag.
        author: String,
    },
    /// PF-3: a RE-VERIFICATION verdict over a registered proof (kind 5 —
    /// append-only kind evolution; older chains decode unchanged).
    Audit {
        /// The proof-cache key that was audited.
        subject: [u8; 32],
        /// `sha256` of the RECOMPUTED receipt bytes (the second derivation).
        evidence: [u8; 32],
        /// True iff the claim reproduced; false = a detected mismatch (slash).
        passed: bool,
        /// The auditor tag.
        author: String,
    },
}

/// Typed codec/chain failures (fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum LedgerError {
    /// Bytes shorter than a field demanded.
    Truncated,
    /// The magic was not [`LEDGER_MAGIC`].
    BadMagic,
    /// The version byte was unknown.
    UnknownVersion,
    /// An unknown op / effect wire byte.
    UnknownKind,
    /// A name failed the N-2 validity rules.
    BadName,
    /// A text/author exceeded its cap or was not UTF-8.
    BadText,
    /// A string field was not valid UTF-8.
    NotUtf8,
    /// Trailing garbage after the last record.
    TrailingBytes,
    /// A stored link hash did not re-derive — the chain is TAMPERED (RED).
    ChainMismatch,
}

impl LedgerError {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            LedgerError::Truncated => "truncated ledger",
            LedgerError::BadMagic => "bad ledger magic",
            LedgerError::UnknownVersion => "unknown ledger version",
            LedgerError::UnknownKind => "unknown ledger op kind",
            LedgerError::BadName => "bad name in a ledger op",
            LedgerError::BadText => "text/author over cap or not UTF-8",
            LedgerError::NotUtf8 => "not valid UTF-8",
            LedgerError::TrailingBytes => "trailing bytes after the last record",
            LedgerError::ChainMismatch => "CHAIN MISMATCH — a stored link does not re-derive",
        }
    }
}

fn valid_text(s: &str) -> bool {
    s.len() <= LEDGER_TEXT_CAP_BYTES
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u16::try_from(s.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

/// Encode ONE op to its canonical bytes. `None` iff a field is invalid
/// (fail-closed at the write side too).
#[must_use]
pub fn encode_op(op: &LedgerOp) -> Option<Vec<u8>> {
    let mut b = Vec::with_capacity(80);
    match op {
        LedgerOp::Pin {
            morph_id,
            payload_cid,
            author,
        } => {
            if !valid_text(author) {
                return None;
            }
            b.push(1);
            b.extend_from_slice(morph_id);
            b.extend_from_slice(payload_cid);
            push_str(&mut b, author);
        }
        LedgerOp::NameBind { effect, author } => {
            if !valid_text(author) || !crate::namespace::valid_name(effect.name()) {
                return None;
            }
            b.push(2);
            match effect {
                NsEffect::Bind(n, c) => {
                    b.push(1);
                    push_str(&mut b, n);
                    b.extend_from_slice(c);
                }
                NsEffect::Unbind(n) => {
                    b.push(2);
                    push_str(&mut b, n);
                }
            }
            push_str(&mut b, author);
        }
        LedgerOp::Proof {
            subject,
            evidence,
            author,
        } => {
            if !valid_text(author) {
                return None;
            }
            b.push(3);
            b.extend_from_slice(subject);
            b.extend_from_slice(evidence);
            push_str(&mut b, author);
        }
        LedgerOp::Intent {
            subject,
            text,
            author,
        } => {
            if !valid_text(text) || !valid_text(author) {
                return None;
            }
            b.push(4);
            b.extend_from_slice(subject);
            push_str(&mut b, text);
            push_str(&mut b, author);
        }
        LedgerOp::Audit {
            subject,
            evidence,
            passed,
            author,
        } => {
            if !valid_text(author) {
                return None;
            }
            b.push(5);
            b.extend_from_slice(subject);
            b.extend_from_slice(evidence);
            b.push(u8::from(*passed));
            push_str(&mut b, author);
        }
    }
    Some(b)
}

/// One chain link: `sha256(LEDGER_DOMAIN ‖ prev ‖ op_bytes)`.
#[must_use]
pub fn link_hash(prev: &[u8; 32], op_bytes: &[u8]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(LEDGER_DOMAIN.len() + 32 + op_bytes.len());
    pre.extend_from_slice(LEDGER_DOMAIN);
    pre.extend_from_slice(prev);
    pre.extend_from_slice(op_bytes);
    crate::sha256_32(&pre)
}

/// Encode a whole chain (deterministic; links recomputed from genesis). `None`
/// iff any op is invalid.
#[must_use]
pub fn encode_chain(ops: &[LedgerOp]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(9 + ops.len() * 96);
    out.extend_from_slice(&LEDGER_MAGIC);
    out.push(LEDGER_VERSION);
    out.extend_from_slice(&u32::try_from(ops.len()).ok()?.to_le_bytes());
    let mut prev = [0u8; 32];
    for op in ops {
        let ob = encode_op(op)?;
        prev = link_hash(&prev, &ob);
        out.extend_from_slice(&u16::try_from(ob.len()).ok()?.to_le_bytes());
        out.extend_from_slice(&ob);
        out.extend_from_slice(&prev);
    }
    Some(out)
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], LedgerError> {
    let end = at.checked_add(n).ok_or(LedgerError::Truncated)?;
    if end > bytes.len() {
        return Err(LedgerError::Truncated);
    }
    let s = &bytes[*at..end];
    *at = end;
    Ok(s)
}

fn take_str(bytes: &[u8], at: &mut usize) -> Result<String, LedgerError> {
    let mut l = [0u8; 2];
    l.copy_from_slice(take(bytes, at, 2)?);
    let n = u16::from_le_bytes(l) as usize;
    let s = core::str::from_utf8(take(bytes, at, n)?).map_err(|_| LedgerError::NotUtf8)?;
    Ok(s.to_string())
}

fn take32(bytes: &[u8], at: &mut usize) -> Result<[u8; 32], LedgerError> {
    let mut out = [0u8; 32];
    out.copy_from_slice(take(bytes, at, 32)?);
    Ok(out)
}

fn decode_op(ob: &[u8]) -> Result<LedgerOp, LedgerError> {
    let mut at = 0usize;
    let kind = take(ob, &mut at, 1)?[0];
    let op = match kind {
        1 => {
            let morph_id = take32(ob, &mut at)?;
            let payload_cid = take32(ob, &mut at)?;
            let author = take_str(ob, &mut at)?;
            if !valid_text(&author) {
                return Err(LedgerError::BadText);
            }
            LedgerOp::Pin {
                morph_id,
                payload_cid,
                author,
            }
        }
        2 => {
            let eff_kind = take(ob, &mut at, 1)?[0];
            let name = take_str(ob, &mut at)?;
            if !crate::namespace::valid_name(&name) {
                return Err(LedgerError::BadName);
            }
            let effect = match eff_kind {
                1 => NsEffect::Bind(name, take32(ob, &mut at)?),
                2 => NsEffect::Unbind(name),
                _ => return Err(LedgerError::UnknownKind),
            };
            let author = take_str(ob, &mut at)?;
            if !valid_text(&author) {
                return Err(LedgerError::BadText);
            }
            LedgerOp::NameBind { effect, author }
        }
        3 => {
            let subject = take32(ob, &mut at)?;
            let evidence = take32(ob, &mut at)?;
            let author = take_str(ob, &mut at)?;
            if !valid_text(&author) {
                return Err(LedgerError::BadText);
            }
            LedgerOp::Proof {
                subject,
                evidence,
                author,
            }
        }
        4 => {
            let subject = take32(ob, &mut at)?;
            let text = take_str(ob, &mut at)?;
            let author = take_str(ob, &mut at)?;
            if !valid_text(&text) || !valid_text(&author) {
                return Err(LedgerError::BadText);
            }
            LedgerOp::Intent {
                subject,
                text,
                author,
            }
        }
        5 => {
            let subject = take32(ob, &mut at)?;
            let evidence = take32(ob, &mut at)?;
            let passed = take(ob, &mut at, 1)?[0] != 0;
            let author = take_str(ob, &mut at)?;
            if !valid_text(&author) {
                return Err(LedgerError::BadText);
            }
            LedgerOp::Audit {
                subject,
                evidence,
                passed,
                author,
            }
        }
        _ => return Err(LedgerError::UnknownKind),
    };
    if at != ob.len() {
        return Err(LedgerError::TrailingBytes);
    }
    Ok(op)
}

/// A decoded, REWALK-VERIFIED chain.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LedgerChain {
    /// The ops in append order.
    pub ops: Vec<LedgerOp>,
    /// The tail link (genesis zeros for an empty chain).
    pub tail: [u8; 32],
}

/// Decode + REWALK a chain: every stored link must re-derive from the
/// domain ‖ prev ‖ op bytes — any tamper/fork/reorder/truncation is a typed RED.
pub fn decode_chain(bytes: &[u8]) -> Result<LedgerChain, LedgerError> {
    let mut at = 0usize;
    if take(bytes, &mut at, 4)? != LEDGER_MAGIC {
        return Err(LedgerError::BadMagic);
    }
    if take(bytes, &mut at, 1)?[0] != LEDGER_VERSION {
        return Err(LedgerError::UnknownVersion);
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(take(bytes, &mut at, 4)?);
    let count = u32::from_le_bytes(c) as usize;
    let mut ops = Vec::with_capacity(count.min(4096));
    let mut prev = [0u8; 32];
    for _ in 0..count {
        let mut l = [0u8; 2];
        l.copy_from_slice(take(bytes, &mut at, 2)?);
        let ob = take(bytes, &mut at, u16::from_le_bytes(l) as usize)?.to_vec();
        let stored = take32(bytes, &mut at)?;
        let derived = link_hash(&prev, &ob);
        if stored != derived {
            return Err(LedgerError::ChainMismatch);
        }
        prev = derived;
        ops.push(decode_op(&ob)?);
    }
    if at != bytes.len() {
        return Err(LedgerError::TrailingBytes);
    }
    Ok(LedgerChain { ops, tail: prev })
}

/// The ledger path: `<data_dir>/nous/ledger.lgx` (dir created on demand).
#[must_use]
pub fn ledger_path() -> Option<std::path::PathBuf> {
    let dir = crate::memory_store::data_dir().ok()?.join("nous");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(LEDGER_FILE))
}

/// Load the chain at `path` (absent file = empty chain; tamper ⇒ typed RED).
pub fn load_ledger(path: &Path) -> Result<LedgerChain, LedgerError> {
    match std::fs::read(path) {
        Ok(bytes) => decode_chain(&bytes),
        Err(_) => Ok(LedgerChain::default()),
    }
}

// ---------------------------------------------------------------------------
// The witness + the PIN (P-LOCK-3 promotion)
// ---------------------------------------------------------------------------

/// The unforgeable pin witness: private field, ONE constructor door
/// ([`mint_pin_witness`]). Every state-moving fn below REQUIRES it by type.
pub struct LedgerPinWitness(());

/// The ONLY door: the exact owner ceremony phrase mints; anything else is `None`
/// (zero side effects). The MODEL has no path here; only owner dispatch reaches it.
#[must_use]
pub fn mint_pin_witness(phrase: &str) -> Option<LedgerPinWitness> {
    if phrase == MORPH_PIN_ARM_PHRASE {
        Some(LedgerPinWitness(()))
    } else {
        None
    }
}

/// Why a pin refused (fail-closed: ZERO bytes written anywhere).
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PinDeny {
    /// A `NameResolvesTo` precondition (or an unbind target) failed against the
    /// REAL namespace fold.
    NamePrecondition(String),
    /// The namespace log failed to load/append.
    NamespaceFailed,
    /// The existing ledger failed to load (incl. a ChainMismatch RED).
    LedgerFailed(LedgerError),
    /// The ContentStore refused the payload (or returned a non-64-hex cid —
    /// v1 pins persist through the local content-addressed store).
    CasRefused,
    /// The judge escalated — an escalated pair CANNOT compose.
    JudgeEscalated(&'static str),
}

impl PinDeny {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            PinDeny::NamePrecondition(n) => {
                format!("name precondition failed against the live namespace: {n}")
            }
            PinDeny::NamespaceFailed => "namespace log load/append failed".to_string(),
            PinDeny::LedgerFailed(e) => format!("ledger: {}", e.message()),
            PinDeny::CasRefused => "content store refused the payload".to_string(),
            PinDeny::JudgeEscalated(r) => {
                format!("REFUSED — the judge escalated ({r}); escalated pairs cannot compose")
            }
        }
    }
}

/// A pin receipt (render data).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PinReceipt {
    /// The pinned morphism's content id (hex).
    pub morph_id_hex: String,
    /// The ContentStore cid holding the canonical bytes (hex).
    pub payload_cid_hex: String,
    /// How many namespace effects were applied.
    pub applied_effects: usize,
    /// `NodeExists` preconditions counted honestly as UNVERIFIED (no persisted
    /// node set — files are the node SOT).
    pub unverified_node_preconds: usize,
    /// The chain length after this pin.
    pub ledger_len: usize,
    /// The chain tail link (hex) after this pin.
    pub tail_link_hex: String,
}

/// PIN one morphism: persist its canonical bytes to the ContentStore,
/// apply its namespace effects to the REAL namespace log, record Pin + NameBind +
/// Intent ops on the chain. Ordering is EFFECT-FIRST: namespace before
/// ledger. Preconditions gate everything (fail-closed, zero writes on a miss).
pub fn pin_morphism(
    _witness: &LedgerPinWitness,
    ledger_p: &Path,
    ns_p: &Path,
    store: &mut dyn ContentStore,
    m: &Morphism,
    author: &str,
) -> Result<PinReceipt, PinDeny> {
    // 1. Preconditions against the REAL namespace fold (fail-closed).
    let ns_events = crate::namespace::load_log(ns_p).map_err(|_| PinDeny::NamespaceFailed)?;
    let fold = crate::namespace::fold(&ns_events);
    let mut unverified_nodes = 0usize;
    for p in m.pre.iter().chain(m.inv.iter()) {
        match p {
            crate::morphism::Predicate::NameResolvesTo(n, c) => {
                if fold.bindings.get(n.as_str()) != Some(c) {
                    return Err(PinDeny::NamePrecondition(n.clone()));
                }
            }
            crate::morphism::Predicate::NodeExists(_) => unverified_nodes += 1,
        }
    }
    // An unbind of an unbound name would fold as an anomaly — refuse instead.
    for e in &m.ns_effects {
        if matches!(e, NsEffect::Unbind(_)) && !fold.bindings.contains_key(e.name()) {
            return Err(PinDeny::NamePrecondition(e.name().to_string()));
        }
    }
    // 2. Persist the canonical bytes (content-addressed; the M-1 substrate).
    let canonical = m.canonical_bytes();
    let cid = store
        .put(&canonical, PutClass::Public)
        .ok_or(PinDeny::CasRefused)?;
    let payload_cid = crate::namespace::cid_from_hex(&cid).ok_or(PinDeny::CasRefused)?;
    let morph_id = crate::namespace::cid_from_hex(&m.id).ok_or(PinDeny::CasRefused)?;
    // 3. Validate the LEDGER extension BEFORE any write (both images encodable).
    let chain = load_ledger(ledger_p).map_err(PinDeny::LedgerFailed)?;
    let mut ops = chain.ops;
    ops.push(LedgerOp::Pin {
        morph_id,
        payload_cid,
        author: author.to_string(),
    });
    for e in &m.ns_effects {
        ops.push(LedgerOp::NameBind {
            effect: e.clone(),
            author: author.to_string(),
        });
    }
    if !m.intent.is_empty() {
        ops.push(LedgerOp::Intent {
            subject: morph_id,
            text: m.intent.clone(),
            author: author.to_string(),
        });
    }
    let chain_bytes = encode_chain(&ops).ok_or(PinDeny::LedgerFailed(LedgerError::BadText))?;
    // 4. EFFECT FIRST: apply the namespace effects to the real namespace log.
    if !m.ns_effects.is_empty() {
        let events: Vec<crate::namespace::NsEvent> = m
            .ns_effects
            .iter()
            .map(|e| match e {
                NsEffect::Bind(n, c) => crate::namespace::NsEvent::Bind {
                    name: n.clone(),
                    cid: *c,
                    author: author.to_string(),
                },
                NsEffect::Unbind(n) => crate::namespace::NsEvent::Unbind {
                    name: n.clone(),
                    author: author.to_string(),
                },
            })
            .collect();
        crate::namespace::append_events(ns_p, &events).map_err(|_| PinDeny::NamespaceFailed)?;
    }
    // 5. RECORD second: the ledger can never claim what did not happen.
    crate::memory_store::atomic_write(ledger_p, &chain_bytes)
        .map_err(|_| PinDeny::LedgerFailed(LedgerError::Truncated))?;
    let verified = decode_chain(&chain_bytes).map_err(PinDeny::LedgerFailed)?;
    Ok(PinReceipt {
        morph_id_hex: m.id.clone(),
        payload_cid_hex: cid,
        applied_effects: m.ns_effects.len(),
        unverified_node_preconds: unverified_nodes,
        ledger_len: verified.ops.len(),
        tail_link_hex: crate::hex32(&verified.tail),
    })
}

/// PF-2: append ONE `Proof` op — the audit record of a DERIVED verification fact
/// (subject = the proof-cache key, evidence = the receipt digest). TYPED: this
/// fn can construct NOTHING but a Proof op — no Pin, no NameBind, no namespace
/// contact — so no authority moves and the pin ceremony witness is not required
/// (the E5 auto-append discipline: the chain records what happened). Returns the
/// new chain length; a chain RED refuses (never appends onto tamper).
pub fn record_proof(
    ledger_p: &Path,
    subject: [u8; 32],
    evidence: [u8; 32],
    author: &str,
) -> Result<usize, LedgerError> {
    let chain = load_ledger(ledger_p)?;
    let mut ops = chain.ops;
    ops.push(LedgerOp::Proof {
        subject,
        evidence,
        author: author.to_string(),
    });
    let bytes = encode_chain(&ops).ok_or(LedgerError::BadText)?;
    crate::memory_store::atomic_write(ledger_p, &bytes).map_err(|_| LedgerError::Truncated)?;
    Ok(ops.len())
}

/// PF-3: append ONE `Audit` op — a re-verification verdict (subject = the proof
/// key, evidence = the recomputed receipt digest, `passed` = did it reproduce).
/// TYPED Audit-ONLY (constructs no Pin/NameBind; no authority moves). A chain RED
/// refuses. Returns the new chain length.
pub fn record_audit(
    ledger_p: &Path,
    subject: [u8; 32],
    evidence: [u8; 32],
    passed: bool,
    author: &str,
) -> Result<usize, LedgerError> {
    let chain = load_ledger(ledger_p)?;
    let mut ops = chain.ops;
    ops.push(LedgerOp::Audit {
        subject,
        evidence,
        passed,
        author: author.to_string(),
    });
    let bytes = encode_chain(&ops).ok_or(LedgerError::BadText)?;
    crate::memory_store::atomic_write(ledger_p, &bytes).map_err(|_| LedgerError::Truncated)?;
    Ok(ops.len())
}

/// PROMOTE an advisory verdict into REAL composition: the judge runs INSIDE
/// — `Escalate` refuses before any byte moves; `AutoCompose` pins BOTH
/// morphisms (order-free by the judge's kill-gate property).
pub fn compose_pair(
    witness: &LedgerPinWitness,
    ledger_p: &Path,
    ns_p: &Path,
    store: &mut dyn ContentStore,
    m1: &Morphism,
    m2: &Morphism,
    author: &str,
) -> Result<(PinReceipt, PinReceipt), PinDeny> {
    match crate::morphism::judge(m1, m2) {
        crate::morphism::JudgeVerdict::Escalate(reason) => {
            Err(PinDeny::JudgeEscalated(reason.label()))
        }
        crate::morphism::JudgeVerdict::AutoCompose => {
            let r1 = pin_morphism(witness, ledger_p, ns_p, store, m1, author)?;
            let r2 = pin_morphism(witness, ledger_p, ns_p, store, m2, author)?;
            Ok((r1, r2))
        }
    }
}

// ---------------------------------------------------------------------------
// L-2: fold + checkpoint (any-time state = a deterministic fold of the log;
// checkpoints bound the replay cost).
// ---------------------------------------------------------------------------

/// The domain tag bound into a folded-state content id (28 bytes, Python-verified).
pub const LEDGER_STATE_DOMAIN: &[u8] = b"sinabro.nous.ledger.state.v1";

/// The checkpoint-file magic (4 bytes) — `CKPX`.
pub const CHECKPOINT_MAGIC: [u8; 4] = *b"CKPX";

/// The checkpoint wire version.
pub const CHECKPOINT_VERSION: u8 = 1;

/// The checkpoint file under `<data_dir>/nous/`.
pub const CHECKPOINT_FILE: &str = "ledger.ckpt";

/// The FOLDED state of the operation log at some version: pins, name bindings,
/// and derived-op counters. A pure function of the log PREFIX.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LedgerState {
    /// The version this state reflects (= number of ops folded).
    pub version: usize,
    /// Pinned morphism ids (sorted set).
    pub pins: std::collections::BTreeSet<[u8; 32]>,
    /// Name → cid provenance from `NameBind` ops (an unbind removes the name).
    pub names: std::collections::BTreeMap<String, [u8; 32]>,
    /// `Proof` op count.
    pub proofs: u64,
    /// `Audit{passed=true}` count.
    pub audits_passed: u64,
    /// `Audit{passed=false}` count (recorded slashes).
    pub audits_mismatched: u64,
}

impl LedgerState {
    /// Apply ONE op to the state (the fold step).
    fn apply(&mut self, op: &LedgerOp) {
        match op {
            LedgerOp::Pin { morph_id, .. } => {
                self.pins.insert(*morph_id);
            }
            LedgerOp::NameBind { effect, .. } => match effect {
                NsEffect::Bind(n, c) => {
                    self.names.insert(n.clone(), *c);
                }
                NsEffect::Unbind(n) => {
                    self.names.remove(n);
                }
            },
            LedgerOp::Proof { .. } => self.proofs = self.proofs.saturating_add(1),
            LedgerOp::Audit { passed: true, .. } => {
                self.audits_passed = self.audits_passed.saturating_add(1);
            }
            LedgerOp::Audit { passed: false, .. } => {
                self.audits_mismatched = self.audits_mismatched.saturating_add(1);
            }
            LedgerOp::Intent { .. } => {}
        }
        self.version += 1;
    }

    /// The canonical bytes of the folded state (deterministic; the id preimage).
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::with_capacity(64 + self.pins.len() * 32 + self.names.len() * 48);
        b.extend_from_slice(
            &u32::try_from(self.pins.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for p in &self.pins {
            b.extend_from_slice(p);
        }
        b.extend_from_slice(
            &u32::try_from(self.names.len())
                .unwrap_or(u32::MAX)
                .to_le_bytes(),
        );
        for (n, c) in &self.names {
            b.extend_from_slice(&u16::try_from(n.len()).unwrap_or(u16::MAX).to_le_bytes());
            b.extend_from_slice(n.as_bytes());
            b.extend_from_slice(c);
        }
        b.extend_from_slice(&self.proofs.to_le_bytes());
        b.extend_from_slice(&self.audits_passed.to_le_bytes());
        b.extend_from_slice(&self.audits_mismatched.to_le_bytes());
        b
    }

    /// The content id of the folded state: `sha256(STATE_DOMAIN ‖ canonical)`.
    #[must_use]
    pub fn state_id(&self) -> [u8; 32] {
        let cb = self.canonical_bytes();
        let mut pre = Vec::with_capacity(LEDGER_STATE_DOMAIN.len() + cb.len());
        pre.extend_from_slice(LEDGER_STATE_DOMAIN);
        pre.extend_from_slice(&cb);
        crate::sha256_32(&pre)
    }
}

/// Fold the FIRST `upto` ops of a chain into a state (the whole chain: `upto =
/// len`). Deterministic replay — "state at version k" is a pure function of the
/// log prefix. The `version` field excludes ops beyond the folded index
/// (a fold over the first two of five ops sets `version = 2`, not 5).
#[must_use]
pub fn fold_ledger_at(chain: &LedgerChain, upto: usize) -> LedgerState {
    let mut st = LedgerState::default();
    for op in chain.ops.iter().take(upto.min(chain.ops.len())) {
        st.apply(op);
    }
    st
}

/// Fold the whole chain.
#[must_use]
pub fn fold_ledger(chain: &LedgerChain) -> LedgerState {
    fold_ledger_at(chain, chain.ops.len())
}

/// A persisted checkpoint: a folded state BOUND to the chain link at its version
/// (the integrity anchor). On resume, the bound link must equal the live chain's
/// link at that version — otherwise the checkpoint is STALE/tampered and is
/// discarded (re-fold from genesis). This is the cost bound: `state = checkpoint
/// + fold(version..len)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerCheckpoint {
    /// The version the state reflects.
    pub version: usize,
    /// The chain link hash at `version` (the integrity anchor).
    pub link: [u8; 32],
    /// The folded state at `version`.
    pub state: LedgerState,
}

/// Encode a checkpoint (`CKPX`). `None` iff the state cannot encode.
#[must_use]
pub fn encode_checkpoint(ck: &LedgerCheckpoint) -> Option<Vec<u8>> {
    let sb = ck.state.canonical_bytes();
    let mut b = Vec::with_capacity(45 + sb.len());
    b.extend_from_slice(&CHECKPOINT_MAGIC);
    b.push(CHECKPOINT_VERSION);
    b.extend_from_slice(&u32::try_from(ck.version).ok()?.to_le_bytes());
    b.extend_from_slice(&ck.link);
    b.extend_from_slice(&u32::try_from(sb.len()).ok()?.to_le_bytes());
    b.extend_from_slice(&sb);
    Some(b)
}

/// Decode a checkpoint (fail-closed; the state is re-parsed, not trusted blind).
pub fn decode_checkpoint(bytes: &[u8]) -> Result<LedgerCheckpoint, LedgerError> {
    let mut at = 0usize;
    if take(bytes, &mut at, 4)? != CHECKPOINT_MAGIC {
        return Err(LedgerError::BadMagic);
    }
    if take(bytes, &mut at, 1)?[0] != CHECKPOINT_VERSION {
        return Err(LedgerError::UnknownVersion);
    }
    let mut w = [0u8; 4];
    w.copy_from_slice(take(bytes, &mut at, 4)?);
    let version = u32::from_le_bytes(w) as usize;
    let link = take32(bytes, &mut at)?;
    w.copy_from_slice(take(bytes, &mut at, 4)?);
    let slen = u32::from_le_bytes(w) as usize;
    let sb = take(bytes, &mut at, slen)?.to_vec();
    if at != bytes.len() {
        return Err(LedgerError::TrailingBytes);
    }
    let state = decode_state(&sb, version)?;
    Ok(LedgerCheckpoint {
        version,
        link,
        state,
    })
}

fn decode_state(sb: &[u8], version: usize) -> Result<LedgerState, LedgerError> {
    let mut at = 0usize;
    let mut w = [0u8; 4];
    w.copy_from_slice(take(sb, &mut at, 4)?);
    let npins = u32::from_le_bytes(w) as usize;
    let mut pins = std::collections::BTreeSet::new();
    for _ in 0..npins {
        pins.insert(take32(sb, &mut at)?);
    }
    w.copy_from_slice(take(sb, &mut at, 4)?);
    let nnames = u32::from_le_bytes(w) as usize;
    let mut names = std::collections::BTreeMap::new();
    for _ in 0..nnames {
        let mut l = [0u8; 2];
        l.copy_from_slice(take(sb, &mut at, 2)?);
        let n = core::str::from_utf8(take(sb, &mut at, u16::from_le_bytes(l) as usize)?)
            .map_err(|_| LedgerError::NotUtf8)?
            .to_string();
        names.insert(n, take32(sb, &mut at)?);
    }
    let mut q = [0u8; 8];
    q.copy_from_slice(take(sb, &mut at, 8)?);
    let proofs = u64::from_le_bytes(q);
    q.copy_from_slice(take(sb, &mut at, 8)?);
    let audits_passed = u64::from_le_bytes(q);
    q.copy_from_slice(take(sb, &mut at, 8)?);
    let audits_mismatched = u64::from_le_bytes(q);
    if at != sb.len() {
        return Err(LedgerError::TrailingBytes);
    }
    Ok(LedgerState {
        version,
        pins,
        names,
        proofs,
        audits_passed,
        audits_mismatched,
    })
}

/// The link hash of a chain at `version` (the checkpoint integrity anchor).
/// `version == 0` = the genesis link (32 zero bytes); `version > len` clamps.
#[must_use]
pub fn chain_link_at(chain: &LedgerChain, version: usize) -> [u8; 32] {
    if version == 0 {
        return [0u8; 32];
    }
    // Re-walk from genesis to derive the link at `version` (bounded).
    let mut prev = [0u8; 32];
    for op in chain.ops.iter().take(version.min(chain.ops.len())) {
        let ob = encode_op(op).unwrap_or_default();
        prev = link_hash(&prev, &ob);
    }
    prev
}

/// The checkpoint path: `<data_dir>/nous/ledger.ckpt`.
#[must_use]
pub fn checkpoint_path() -> Option<std::path::PathBuf> {
    let dir = crate::memory_store::data_dir().ok()?.join("nous");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(CHECKPOINT_FILE))
}

/// Write a checkpoint at the chain's CURRENT tail (version = len, link = tail).
pub fn write_checkpoint(path: &Path, chain: &LedgerChain) -> Result<LedgerCheckpoint, LedgerError> {
    let state = fold_ledger(chain);
    let ck = LedgerCheckpoint {
        version: chain.ops.len(),
        link: chain.tail,
        state,
    };
    let bytes = encode_checkpoint(&ck).ok_or(LedgerError::BadText)?;
    crate::memory_store::atomic_write(path, &bytes).map_err(|_| LedgerError::Truncated)?;
    Ok(ck)
}

/// Fold the current state using a checkpoint when it is VALID (its bound link
/// equals the live chain link at its version) — folding only `version..len`
/// (the cost bound). A STALE/tampered/absent checkpoint is discarded and the
/// state is re-folded from genesis (the result is identical either way).
/// Returns `(state, used_checkpoint)`.
#[must_use]
pub fn state_with_checkpoint(
    chain: &LedgerChain,
    checkpoint: Option<&LedgerCheckpoint>,
) -> (LedgerState, bool) {
    if let Some(ck) = checkpoint {
        if ck.version <= chain.ops.len() && chain_link_at(chain, ck.version) == ck.link {
            // Valid anchor: continue the fold from the checkpoint (cost bound).
            let mut st = ck.state.clone();
            for op in chain.ops.iter().skip(ck.version) {
                st.apply(op);
            }
            return (st, true);
        }
    }
    (fold_ledger(chain), false)
}

/// Load the checkpoint at `path` (absent / corrupt ⇒ `None`; never trusted blind).
#[must_use]
pub fn load_checkpoint(path: &Path) -> Option<LedgerCheckpoint> {
    decode_checkpoint(&std::fs::read(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::content_store::LocalCasStore;
    use crate::morphism::Predicate;

    fn cid(b0: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("0..32");
        }
        c[0] = b0;
        c
    }

    fn seq(from: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("small") + from;
        }
        c
    }

    /// Cross-language lock (Python 2026-07-08): the 2-op golden chain encodes to
    /// EXACTLY the Python bytes/links; round-trip decodes + rewalks GREEN.
    #[test]
    fn chain_matches_python_golden_vectors() {
        let ops = vec![
            LedgerOp::Pin {
                morph_id: seq(0),
                payload_cid: seq(1),
                author: "owner".to_string(),
            },
            LedgerOp::NameBind {
                effect: NsEffect::Bind("squads/fn".to_string(), seq(2)),
                author: "owner".to_string(),
            },
        ];
        let bytes = encode_chain(&ops).expect("encodes");
        assert_eq!(bytes.len(), 201, "pin=72 + bind=52 + header/links");
        assert_eq!(
            crate::hex32(&crate::sha256_32(&bytes)),
            "dd7d89a7eb4bd07c44fb8d559fdd1c5120dd1a453617ff7654539938340367ee"
        );
        let ob0 = encode_op(&ops[0]).expect("op0");
        let l1 = link_hash(&[0u8; 32], &ob0);
        assert_eq!(
            crate::hex32(&l1),
            "82bd8ddfb7cf7ea2ded665a94354965bcd482f897a0ef67dcf52389a8b35d08a"
        );
        let ob1 = encode_op(&ops[1]).expect("op1");
        assert_eq!(
            crate::hex32(&link_hash(&l1, &ob1)),
            "c0604cac32276c8d55588d8bb55c464be0fb34cbd4e8149a2530813bec783719"
        );
        let chain = decode_chain(&bytes).expect("rewalks GREEN");
        assert_eq!(chain.ops, ops);
        assert_eq!(chain.tail, link_hash(&l1, &ob1));
    }

    /// Tamper evidence: byte-flip, truncation, reorder all go RED.
    #[test]
    fn chain_rewalk_detects_tamper() {
        let ops = vec![
            LedgerOp::Intent {
                subject: seq(0),
                text: "first".to_string(),
                author: "owner".to_string(),
            },
            LedgerOp::Intent {
                subject: seq(1),
                text: "second".to_string(),
                author: "owner".to_string(),
            },
        ];
        let bytes = encode_chain(&ops).expect("encodes");
        // byte-flip inside the FIRST op's bytes ⇒ its link no longer re-derives.
        let mut flipped = bytes.clone();
        flipped[12] ^= 0x01;
        assert_eq!(decode_chain(&flipped), Err(LedgerError::ChainMismatch));
        // truncation ⇒ Truncated.
        assert_eq!(
            decode_chain(&bytes[..bytes.len() - 3]),
            Err(LedgerError::Truncated)
        );
        // REORDER: swap the two records wholesale ⇒ links break (fork-evident).
        let swapped = encode_chain(&[ops[1].clone(), ops[0].clone()]).expect("encodes");
        assert_ne!(swapped, bytes, "different order = different chain");
        // splice record 2's bytes into position 1 of the ORIGINAL file ⇒ RED.
        let mut spliced = bytes[..9].to_vec();
        spliced.extend_from_slice(&bytes[9 + 2 + 46 + 32..]); // drop record 1
        // count still says 2 ⇒ truncated/mismatch — either typed refusal is RED.
        assert!(decode_chain(&spliced).is_err());
        // trailing garbage ⇒ TrailingBytes.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_chain(&trailing), Err(LedgerError::TrailingBytes));
    }

    /// The witness mints ONLY from the exact ceremony phrase.
    #[test]
    fn witness_mints_only_from_the_exact_phrase() {
        assert!(mint_pin_witness(MORPH_PIN_ARM_PHRASE).is_some());
        assert!(mint_pin_witness("").is_none());
        assert!(mint_pin_witness("morph-pin-owner-liv").is_none());
        assert!(mint_pin_witness("MORPH-PIN-OWNER-LIVE").is_none());
        assert!(mint_pin_witness("morph-pin-owner-live ").is_none());
    }

    fn temp_dirs(tag: &str) -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let root = std::env::temp_dir().join(format!("sinabro_l1_{tag}_{}", std::process::id()));
        std::fs::create_dir_all(root.join("cas")).expect("mkdir");
        (
            root.join("ledger.lgx"),
            root.join("namespace.nsl"),
            root.join("cas"),
        )
    }

    /// ★ The PROMOTION round-trip: pin a rename morphism — preconditions checked
    /// against the REAL fold; canonical bytes land in the CAS (get round-trips);
    /// the namespace fold MOVES; the chain records Pin + NameBind(s) + Intent and
    /// rewalks GREEN.
    #[test]
    fn pin_applies_effects_and_records_provenance() {
        let (lp, np, cas_dir) = temp_dirs("pin");
        let mut store = LocalCasStore::with_dir(cas_dir.clone());
        // seed the live namespace: old/name → cid(1)
        crate::namespace::append_events(
            &np,
            &[crate::namespace::NsEvent::Bind {
                name: "old/name".to_string(),
                cid: cid(1),
                author: "owner".to_string(),
            }],
        )
        .expect("seed");
        // a rename morphism: old/name → new/name (same node), pre reads the OLD binding
        let m = Morphism::build(
            "rename old to new",
            "owner",
            vec![],
            vec![],
            vec![Predicate::NameResolvesTo("old/name".to_string(), cid(1))],
            vec![],
            vec![
                NsEffect::Unbind("old/name".to_string()),
                NsEffect::Bind("new/name".to_string(), cid(1)),
            ],
            vec![],
        )
        .expect("builds");
        let w = mint_pin_witness(MORPH_PIN_ARM_PHRASE).expect("mint");
        let r = pin_morphism(&w, &lp, &np, &mut store, &m, "owner").expect("pins");
        assert_eq!(r.applied_effects, 2);
        assert_eq!(r.morph_id_hex, m.id);
        // CAS round-trip: payload bytes ARE the canonical bytes.
        assert_eq!(
            store.get(&r.payload_cid_hex).as_deref(),
            Some(m.canonical_bytes().as_slice())
        );
        // the REAL namespace moved (rename applied).
        let fold = crate::namespace::fold(&crate::namespace::load_log(&np).expect("load"));
        assert_eq!(fold.bindings.get("new/name"), Some(&cid(1)));
        assert_eq!(fold.bindings.get("old/name"), None);
        assert_eq!(fold.anomalies, 0);
        // the chain rewalks GREEN with Pin + 2 NameBind + Intent.
        let chain = load_ledger(&lp).expect("chain GREEN");
        assert_eq!(chain.ops.len(), 4);
        assert!(matches!(chain.ops[0], LedgerOp::Pin { .. }));
        assert!(matches!(chain.ops[1], LedgerOp::NameBind { .. }));
        assert!(matches!(chain.ops[3], LedgerOp::Intent { .. }));
        assert_eq!(r.ledger_len, 4);
        let _ = std::fs::remove_dir_all(lp.parent().expect("parent"));
    }

    /// Fail-closed: a precondition miss writes ZERO bytes anywhere (both files
    /// byte-unchanged, CAS untouched).
    #[test]
    fn pin_precondition_miss_writes_nothing() {
        let (lp, np, cas_dir) = temp_dirs("miss");
        let mut store = LocalCasStore::with_dir(cas_dir.clone());
        let m = Morphism::build(
            "needs a binding that is not there",
            "owner",
            vec![],
            vec![],
            vec![Predicate::NameResolvesTo("ghost".to_string(), cid(1))],
            vec![],
            vec![NsEffect::Bind("x".to_string(), cid(2))],
            vec![],
        )
        .expect("builds");
        let w = mint_pin_witness(MORPH_PIN_ARM_PHRASE).expect("mint");
        let deny = pin_morphism(&w, &lp, &np, &mut store, &m, "owner").expect_err("must refuse");
        assert!(matches!(deny, PinDeny::NamePrecondition(_)));
        assert!(!lp.exists(), "ledger never created");
        assert!(!np.exists(), "namespace never created");
        // the CAS dir stays empty (precondition check precedes the put).
        assert_eq!(
            std::fs::read_dir(&cas_dir).expect("dir").count(),
            0,
            "no payload written"
        );
        let _ = std::fs::remove_dir_all(lp.parent().expect("parent"));
    }

    /// The PROMOTION teeth: an AutoCompose pair composes for real
    /// (both applied, chain GREEN); an ESCALATED pair is REFUSED with ZERO writes.
    #[test]
    fn compose_promotes_auto_and_structurally_refuses_escalated() {
        let (lp, np, cas_dir) = temp_dirs("compose");
        let mut store = LocalCasStore::with_dir(cas_dir.clone());
        let w = mint_pin_witness(MORPH_PIN_ARM_PHRASE).expect("mint");
        // disjoint pair: bind two different names to two different nodes
        let m1 = Morphism::build(
            "add a",
            "owner",
            vec![],
            vec![cid(1)],
            vec![],
            vec![],
            vec![NsEffect::Bind("a".to_string(), cid(1))],
            vec![],
        )
        .expect("m1");
        let m2 = Morphism::build(
            "add b",
            "owner",
            vec![],
            vec![cid(2)],
            vec![],
            vec![],
            vec![NsEffect::Bind("b".to_string(), cid(2))],
            vec![],
        )
        .expect("m2");
        let (r1, r2) = compose_pair(&w, &lp, &np, &mut store, &m1, &m2, "owner").expect("composes");
        assert_eq!(r1.applied_effects + r2.applied_effects, 2);
        let fold = crate::namespace::fold(&crate::namespace::load_log(&np).expect("load"));
        assert_eq!(fold.bindings.len(), 2);
        let before_ledger = std::fs::read(&lp).expect("ledger bytes");
        let before_ns = std::fs::read(&np).expect("ns bytes");
        // ESCALATED pair: both bind the SAME name → judge refuses INSIDE compose.
        let e1 = Morphism::build(
            "clash A",
            "owner",
            vec![],
            vec![cid(7)],
            vec![],
            vec![],
            vec![NsEffect::Bind("helper".to_string(), cid(7))],
            vec![],
        )
        .expect("e1");
        let e2 = Morphism::build(
            "clash B",
            "owner",
            vec![],
            vec![cid(8)],
            vec![],
            vec![],
            vec![NsEffect::Bind("helper".to_string(), cid(8))],
            vec![],
        )
        .expect("e2");
        let deny =
            compose_pair(&w, &lp, &np, &mut store, &e1, &e2, "owner").expect_err("must refuse");
        assert!(matches!(deny, PinDeny::JudgeEscalated(_)));
        // ZERO writes on refusal: both files byte-identical.
        assert_eq!(std::fs::read(&lp).expect("ledger"), before_ledger);
        assert_eq!(std::fs::read(&np).expect("ns"), before_ns);
        let _ = std::fs::remove_dir_all(lp.parent().expect("parent"));
    }

    // --- L-2: fold + checkpoint ---------------------------------------------

    /// A varied 5-op chain (pin + 2 name-binds + proof + audit-mismatch).
    fn varied_chain() -> LedgerChain {
        let ops = vec![
            LedgerOp::Pin {
                morph_id: seq(0),
                payload_cid: seq(1),
                author: "owner".to_string(),
            },
            LedgerOp::NameBind {
                effect: NsEffect::Bind("squads/fn".to_string(), seq(2)),
                author: "owner".to_string(),
            },
            LedgerOp::Proof {
                subject: seq(3),
                evidence: seq(4),
                author: "owner".to_string(),
            },
            LedgerOp::NameBind {
                effect: NsEffect::Bind("squads/other".to_string(), seq(5)),
                author: "owner".to_string(),
            },
            LedgerOp::Audit {
                subject: seq(3),
                evidence: seq(6),
                passed: false,
                author: "auditor".to_string(),
            },
        ];
        let bytes = encode_chain(&ops).expect("encode");
        decode_chain(&bytes).expect("rewalk GREEN")
    }

    /// Cross-language lock (Python 2026-07-08): the folded-state canonical bytes
    /// + state id + the checkpoint codec match the Python vectors.
    #[test]
    fn state_and_checkpoint_match_python_golden() {
        let mut st = LedgerState {
            version: 5,
            ..LedgerState::default()
        };
        st.pins.insert(seq(0));
        st.names.insert("squads/fn".to_string(), seq(1));
        st.proofs = 2;
        st.audits_passed = 1;
        st.audits_mismatched = 0;
        // version is NOT in the canonical bytes (it comes from the checkpoint) —
        // so the golden bytes/id are unaffected by the version field.
        assert_eq!(st.canonical_bytes().len(), 107);
        assert_eq!(
            crate::hex32(&st.state_id()),
            "62bc87078261ff0475c9ea2cbeff69e39d68c0ed618572e78f023d9a3775f2eb"
        );
        let mut link = [0u8; 32];
        for (i, b) in link.iter_mut().enumerate() {
            *b = u8::try_from(i + 9).expect("9..41");
        }
        let ck = LedgerCheckpoint {
            version: 5,
            link,
            state: st,
        };
        let bytes = encode_checkpoint(&ck).expect("encode");
        assert_eq!(bytes.len(), 152);
        assert_eq!(
            crate::hex32(&crate::sha256_32(&bytes)),
            "b1aaf3c9947e292a15de6c9bc7a55fe6ebf1f0735d2d01c802921d8f85ff7a55"
        );
        assert_eq!(decode_checkpoint(&bytes).expect("decode"), ck);
    }

    /// Versioned replay: state@k is a pure function of the prefix; the
    /// fold reflects exactly the ops folded.
    #[test]
    fn fold_at_any_prefix_is_deterministic() {
        let chain = varied_chain();
        assert_eq!(fold_ledger_at(&chain, 0), LedgerState::default());
        let s1 = fold_ledger_at(&chain, 1);
        assert_eq!(s1.version, 1);
        assert_eq!(s1.pins.len(), 1);
        assert!(s1.names.is_empty());
        let s2 = fold_ledger_at(&chain, 2);
        assert_eq!(s2.names.get("squads/fn"), Some(&seq(2)));
        let full = fold_ledger(&chain);
        assert_eq!(full.version, 5);
        assert_eq!(full.pins.len(), 1);
        assert_eq!(full.names.len(), 2);
        assert_eq!(full.proofs, 1);
        assert_eq!(full.audits_mismatched, 1);
        assert_eq!(full.audits_passed, 0);
        // determinism: same prefix, same state.
        assert_eq!(fold_ledger_at(&chain, 3), fold_ledger_at(&chain, 3));
    }

    /// EQUIVALENCE (the cost-bound heart): the state via a VALID
    /// checkpoint (fold only version..len) equals the state via a full
    /// genesis fold — two independent derivations.
    #[test]
    fn checkpoint_replay_equals_full_fold() {
        // checkpoint at version 2, then two more ops arrive.
        let head_ops = varied_chain().ops[..2].to_vec();
        let head = decode_chain(&encode_chain(&head_ops).expect("enc")).expect("dec");
        let ck = LedgerCheckpoint {
            version: 2,
            link: head.tail,
            state: fold_ledger(&head),
        };
        let full = varied_chain();
        // derivation 1: checkpoint + fold(2..5). derivation 2: fold(0..5).
        let (via_ck, used) = state_with_checkpoint(&full, Some(&ck));
        assert!(used, "a valid checkpoint anchor is used (cost bound)");
        assert_eq!(via_ck, fold_ledger(&full), "checkpoint replay == full fold");
        // canary: a checkpoint whose link is WRONG is discarded ⇒ full re-fold,
        // and the WRONG-anchor state (which would differ) is NOT trusted.
        let mut bad = ck.clone();
        bad.link[0] ^= 0xFF;
        let (via_bad, used_bad) = state_with_checkpoint(&full, Some(&bad));
        assert!(!used_bad, "a stale/tampered checkpoint is discarded");
        assert_eq!(
            via_bad,
            fold_ledger(&full),
            "re-fold from genesis is correct"
        );
        // and if the bad checkpoint HAD been trusted, it would have diverged —
        // prove the detector is live by folding from the bad state directly.
        let mut wrong = bad.state.clone();
        for op in full.ops.iter().skip(bad.version) {
            wrong.apply(op);
        }
        // (bad.state is actually the same content here, so force a divergence to
        // show the anchor check is what protects us, not luck.)
        let mut poisoned = ck.clone();
        poisoned.state.proofs = 999;
        poisoned.link[0] ^= 0xFF; // also break the anchor
        let (safe, used_poison) = state_with_checkpoint(&full, Some(&poisoned));
        assert!(!used_poison);
        assert_ne!(
            safe.proofs, 999,
            "a poisoned checkpoint never leaks its state (anchor rejected it)"
        );
    }

    /// Checkpoint persistence round-trips; a corrupt file loads as None.
    #[test]
    fn checkpoint_persist_round_trips() {
        let dir = std::env::temp_dir().join(format!("sinabro_l2_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(CHECKPOINT_FILE);
        let chain = varied_chain();
        let ck = write_checkpoint(&path, &chain).expect("write");
        assert_eq!(ck.version, 5);
        assert_eq!(load_checkpoint(&path), Some(ck));
        // corrupt ⇒ None (never trusted blind).
        let mut bytes = std::fs::read(&path).expect("read");
        bytes[0] ^= 1;
        std::fs::write(&path, &bytes).expect("tamper");
        assert_eq!(load_checkpoint(&path), None);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
