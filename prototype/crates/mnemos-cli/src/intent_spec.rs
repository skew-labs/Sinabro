//! The INTENT SPEC: a change's "why" as SEVEN machine-queryable
//! fields, content-addressed so a later agent reads the intent
//! from STRUCTURE, never by parsing prose back.
//!
//! ## The seven fields
//!
//! ```text
//! intent = "INTX" ‖ ver
//!          ‖ le16|goal| ‖ goal                       (1) goal
//!          ‖ le32 npre  ‖ Predicate…                 (2) preconditions       (reuse N-3)
//!          ‖ le32 ninv  ‖ Predicate…                 (3) invariants     (reuse N-3)
//!          ‖ le32 nalt  ‖ cid[32]…  (sorted)         (4) considered-alternatives   (counterfactual cids)
//!          ‖ le16|uncertainty| ‖ uncertainty         (5) uncertainty
//!          ‖ le32 nev   ‖ cid[32]…  (sorted)         (6) evidence       (evidence cids)
//!          ‖ le32 nprov ‖ (le16|author|‖author)…     (7) provenance   (author chain)
//! intent_id = sha256(INTENT_DOMAIN ‖ intent bytes)
//! ```
//!
//! * The considered-alternatives field is a COUNTERFACTUAL cid array — a
//!   PROVABLE record of rejected options (a later agent can fetch each and see
//!   what was NOT chosen), not free text.
//! * [`render_prose`] projects the STRUCTURE to a human paragraph (one-way:
//!   structure → prose). The machine fields are the source of truth; prose is
//!   never parsed back. A change's `intent_id` can be recorded as the
//!   subject of the `Intent` op — giving the seed op its real content.
//!
//! PURE: no network, no fs, no clock, no execution, no custody. A pure codec
//! with no threat surface.

use crate::morphism::{Morphism, Predicate};

/// The domain tag bound into every intent id (22 bytes).
pub const INTENT_DOMAIN: &[u8] = b"sinabro.nous.intent.v1";

/// The intent-spec magic (4 bytes) — `INTX`.
pub const INTENT_MAGIC: [u8; 4] = *b"INTX";

/// The wire version.
pub const INTENT_VERSION: u8 = 1;

/// Max bytes of the goal / uncertainty text fields.
pub const INTENT_TEXT_CAP_BYTES: usize = 512;

/// Max bytes of one author (provenance) tag.
pub const INTENT_AUTHOR_CAP_BYTES: usize = 96;

/// The seven-field intent spec. Canonical by construction
/// ([`IntentSpec::build`]): predicate lists validated, cid arrays sorted+deduped.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntentSpec {
    /// The content id (hex sha256; see [`intent_id`]).
    pub id: String,
    /// (1) Goal — what the change is FOR.
    pub goal: String,
    /// (2) Preconditions — reuse the predicate vocabulary.
    pub preconditions: Vec<Predicate>,
    /// (3) Invariants — invariants the change preserves.
    pub invariants: Vec<Predicate>,
    /// (4) Considered alternatives — counterfactual node/morphism cids that were REJECTED.
    pub considered: Vec<[u8; 32]>,
    /// (5) Uncertainty — what remains uncertain (honest).
    pub uncertainty: String,
    /// (6) Evidence — evidence cids (receipts/proofs supporting the change).
    pub evidence: Vec<[u8; 32]>,
    /// (7) Provenance — the author chain (signed identity stubs).
    pub provenance: Vec<String>,
}

/// Typed codec/build failures (fail-closed).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IntentError {
    /// Bytes shorter than a field demanded.
    Truncated,
    /// The magic was not [`INTENT_MAGIC`].
    BadMagic,
    /// The version byte was unknown.
    UnknownVersion,
    /// An unknown predicate wire byte.
    UnknownKind,
    /// A text field was over cap or not UTF-8.
    BadText,
    /// A name in a predicate failed the N-2 rules.
    BadName,
    /// Trailing garbage after the last field.
    TrailingBytes,
}

impl IntentError {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            IntentError::Truncated => "truncated intent spec",
            IntentError::BadMagic => "bad intent magic",
            IntentError::UnknownVersion => "unknown intent version",
            IntentError::UnknownKind => "unknown predicate kind",
            IntentError::BadText => "text over cap or not UTF-8",
            IntentError::BadName => "bad name in a predicate",
            IntentError::TrailingBytes => "trailing bytes",
        }
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&u16::try_from(s.len()).unwrap_or(u16::MAX).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn push_preds(out: &mut Vec<u8>, preds: &[Predicate]) {
    out.extend_from_slice(&u32::try_from(preds.len()).unwrap_or(u32::MAX).to_le_bytes());
    for p in preds {
        match p {
            Predicate::NodeExists(c) => {
                out.push(1);
                out.extend_from_slice(c);
            }
            Predicate::NameResolvesTo(n, c) => {
                out.push(2);
                push_str(out, n);
                out.extend_from_slice(c);
            }
        }
    }
}

fn push_cids(out: &mut Vec<u8>, cids: &[[u8; 32]]) {
    out.extend_from_slice(&u32::try_from(cids.len()).unwrap_or(u32::MAX).to_le_bytes());
    for c in cids {
        out.extend_from_slice(c);
    }
}

/// The canonical wire bytes of an intent spec (deterministic; the id preimage).
#[must_use]
pub fn intent_bytes(spec: &IntentSpec) -> Vec<u8> {
    let mut b = Vec::with_capacity(64);
    b.extend_from_slice(&INTENT_MAGIC);
    b.push(INTENT_VERSION);
    push_str(&mut b, &spec.goal);
    push_preds(&mut b, &spec.preconditions);
    push_preds(&mut b, &spec.invariants);
    push_cids(&mut b, &spec.considered);
    push_str(&mut b, &spec.uncertainty);
    push_cids(&mut b, &spec.evidence);
    b.extend_from_slice(
        &u32::try_from(spec.provenance.len())
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for a in &spec.provenance {
        push_str(&mut b, a);
    }
    b
}

/// The content id of an intent spec: `sha256(INTENT_DOMAIN ‖ intent bytes)`.
#[must_use]
pub fn intent_id(bytes: &[u8]) -> String {
    let mut pre = Vec::with_capacity(INTENT_DOMAIN.len() + bytes.len());
    pre.extend_from_slice(INTENT_DOMAIN);
    pre.extend_from_slice(bytes);
    crate::hex32(&crate::sha256_32(&pre))
}

fn valid_text(s: &str, cap: usize) -> bool {
    s.len() <= cap
}

impl IntentSpec {
    /// The ONLY constructor: validate text + predicate names, sort/dedup the cid
    /// arrays, derive the id. Fail-closed.
    #[allow(clippy::too_many_arguments)]
    pub fn build(
        goal: &str,
        preconditions: Vec<Predicate>,
        invariants: Vec<Predicate>,
        considered: Vec<[u8; 32]>,
        uncertainty: &str,
        evidence: Vec<[u8; 32]>,
        provenance: Vec<String>,
    ) -> Result<Self, IntentError> {
        if !valid_text(goal, INTENT_TEXT_CAP_BYTES)
            || !valid_text(uncertainty, INTENT_TEXT_CAP_BYTES)
        {
            return Err(IntentError::BadText);
        }
        for p in preconditions.iter().chain(invariants.iter()) {
            if let Predicate::NameResolvesTo(n, _) = p {
                if !crate::namespace::valid_name(n) {
                    return Err(IntentError::BadName);
                }
            }
        }
        for a in &provenance {
            if a.len() > INTENT_AUTHOR_CAP_BYTES {
                return Err(IntentError::BadText);
            }
        }
        let considered = dedup_sorted(considered);
        let evidence = dedup_sorted(evidence);
        let mut spec = Self {
            id: String::new(),
            goal: goal.to_string(),
            preconditions,
            invariants,
            considered,
            uncertainty: uncertainty.to_string(),
            evidence,
            provenance,
        };
        spec.id = intent_id(&intent_bytes(&spec));
        Ok(spec)
    }

    /// True iff the stored id re-derives from the content (tamper-evidence).
    #[must_use]
    pub fn id_matches_content(&self) -> bool {
        self.id == intent_id(&intent_bytes(self))
    }

    /// Derive an intent spec from a MORPHISM (grounding: the pre/invariants/
    /// evidence come from the change itself; goal/uncertainty/provenance are the
    /// author's contribution). The considered-alternatives are supplied
    /// separately (rejected counterfactuals).
    pub fn from_morphism(
        m: &Morphism,
        goal: &str,
        uncertainty: &str,
        considered: Vec<[u8; 32]>,
        provenance: Vec<String>,
    ) -> Result<Self, IntentError> {
        Self::build(
            goal,
            m.pre.clone(),
            m.inv.clone(),
            considered,
            uncertainty,
            m.evidence.clone(),
            provenance,
        )
    }
}

fn dedup_sorted(mut v: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    v.sort_unstable();
    v.dedup();
    v
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], IntentError> {
    let end = at.checked_add(n).ok_or(IntentError::Truncated)?;
    if end > bytes.len() {
        return Err(IntentError::Truncated);
    }
    let s = &bytes[*at..end];
    *at = end;
    Ok(s)
}

fn take_str(bytes: &[u8], at: &mut usize, cap: usize) -> Result<String, IntentError> {
    let mut l = [0u8; 2];
    l.copy_from_slice(take(bytes, at, 2)?);
    let n = u16::from_le_bytes(l) as usize;
    let s = core::str::from_utf8(take(bytes, at, n)?).map_err(|_| IntentError::BadText)?;
    if s.len() > cap {
        return Err(IntentError::BadText);
    }
    Ok(s.to_string())
}

fn take32(bytes: &[u8], at: &mut usize) -> Result<[u8; 32], IntentError> {
    let mut o = [0u8; 32];
    o.copy_from_slice(take(bytes, at, 32)?);
    Ok(o)
}

fn take_preds(bytes: &[u8], at: &mut usize) -> Result<Vec<Predicate>, IntentError> {
    let mut w = [0u8; 4];
    w.copy_from_slice(take(bytes, at, 4)?);
    let n = u32::from_le_bytes(w) as usize;
    let mut out = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        let kind = take(bytes, at, 1)?[0];
        match kind {
            1 => out.push(Predicate::NodeExists(take32(bytes, at)?)),
            2 => {
                let name = take_str(bytes, at, INTENT_TEXT_CAP_BYTES)?;
                if !crate::namespace::valid_name(&name) {
                    return Err(IntentError::BadName);
                }
                out.push(Predicate::NameResolvesTo(name, take32(bytes, at)?));
            }
            _ => return Err(IntentError::UnknownKind),
        }
    }
    Ok(out)
}

fn take_cids(bytes: &[u8], at: &mut usize) -> Result<Vec<[u8; 32]>, IntentError> {
    let mut w = [0u8; 4];
    w.copy_from_slice(take(bytes, at, 4)?);
    let n = u32::from_le_bytes(w) as usize;
    let mut out = Vec::with_capacity(n.min(4096));
    for _ in 0..n {
        out.push(take32(bytes, at)?);
    }
    Ok(out)
}

/// Decode an intent spec (fail-closed; the id is re-derived, not trusted blind).
pub fn decode_intent(bytes: &[u8]) -> Result<IntentSpec, IntentError> {
    let mut at = 0usize;
    if take(bytes, &mut at, 4)? != INTENT_MAGIC {
        return Err(IntentError::BadMagic);
    }
    if take(bytes, &mut at, 1)?[0] != INTENT_VERSION {
        return Err(IntentError::UnknownVersion);
    }
    let goal = take_str(bytes, &mut at, INTENT_TEXT_CAP_BYTES)?;
    let preconditions = take_preds(bytes, &mut at)?;
    let invariants = take_preds(bytes, &mut at)?;
    let considered = take_cids(bytes, &mut at)?;
    let uncertainty = take_str(bytes, &mut at, INTENT_TEXT_CAP_BYTES)?;
    let evidence = take_cids(bytes, &mut at)?;
    let mut w = [0u8; 4];
    w.copy_from_slice(take(bytes, &mut at, 4)?);
    let nprov = u32::from_le_bytes(w) as usize;
    let mut provenance = Vec::with_capacity(nprov.min(4096));
    for _ in 0..nprov {
        provenance.push(take_str(bytes, &mut at, INTENT_AUTHOR_CAP_BYTES)?);
    }
    if at != bytes.len() {
        return Err(IntentError::TrailingBytes);
    }
    let id = intent_id(bytes);
    Ok(IntentSpec {
        id,
        goal,
        preconditions,
        invariants,
        considered,
        uncertainty,
        evidence,
        provenance,
    })
}

/// Project the STRUCTURE to a human paragraph (one-way: structure → prose). The
/// machine fields remain the source of truth — this render is NEVER parsed back.
/// A predicate becomes a phrase; a cid becomes a short hex handle.
#[must_use]
pub fn render_prose(spec: &IntentSpec) -> String {
    let mut out = format!("Goal: {}.", spec.goal);
    if !spec.preconditions.is_empty() {
        out.push_str(" It assumes ");
        out.push_str(&pred_phrase(&spec.preconditions));
        out.push('.');
    }
    if !spec.invariants.is_empty() {
        out.push_str(" It preserves ");
        out.push_str(&pred_phrase(&spec.invariants));
        out.push('.');
    }
    if !spec.considered.is_empty() {
        out.push_str(&format!(
            " {} alternative(s) were considered and rejected ({}).",
            spec.considered.len(),
            handles(&spec.considered)
        ));
    }
    if !spec.evidence.is_empty() {
        out.push_str(&format!(" Evidence: {}.", handles(&spec.evidence)));
    }
    if !spec.uncertainty.is_empty() {
        out.push_str(&format!(" Uncertainty: {}.", spec.uncertainty));
    }
    if !spec.provenance.is_empty() {
        out.push_str(&format!(" Authored by {}.", spec.provenance.join(" → ")));
    }
    out
}

fn pred_phrase(preds: &[Predicate]) -> String {
    let parts: Vec<String> = preds
        .iter()
        .map(|p| match p {
            Predicate::NodeExists(c) => format!("node {} exists", short_hex(c)),
            Predicate::NameResolvesTo(n, c) => format!("{n} resolves to {}", short_hex(c)),
        })
        .collect();
    parts.join(", ")
}

fn handles(cids: &[[u8; 32]]) -> String {
    cids.iter().map(short_hex).collect::<Vec<_>>().join(", ")
}

fn short_hex(c: &[u8; 32]) -> String {
    crate::hex32(c)[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seq(from: u8) -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("small") + from;
        }
        c
    }

    /// Cross-language lock: the 7-field golden encodes to
    /// EXACTLY the reference 172 bytes / id.
    #[test]
    fn intent_matches_python_golden_vector() {
        let spec = IntentSpec::build(
            "rename fn safely",
            vec![Predicate::NameResolvesTo("old/name".to_string(), seq(0))],
            vec![],
            vec![seq(1)],
            "none material",
            vec![seq(0)],
            vec!["owner".to_string()],
        )
        .expect("builds");
        let bytes = intent_bytes(&spec);
        assert_eq!(bytes.len(), 172);
        assert_eq!(
            spec.id,
            "6471f1c89c8b61c37a070ef2200d45b0e4cf0fd51d5621a113e0ba3dc5f9f4c2"
        );
        assert_eq!(decode_intent(&bytes).expect("decodes"), spec);
        assert!(spec.id_matches_content());
    }

    /// The considered-alternatives field is a counterfactual cid array (provable rejection
    /// record), and the machine fields are queryable directly (no prose parsing).
    #[test]
    fn considered_alternatives_are_machine_queryable() {
        let spec = IntentSpec::build(
            "adopt approach A",
            vec![],
            vec![],
            vec![seq(9), seq(5), seq(9)], // B and C rejected (deduped)
            "perf under load unmeasured",
            vec![],
            vec!["agent-1".to_string(), "owner".to_string()],
        )
        .expect("builds");
        // machine query: the rejected alternatives are a sorted, deduped cid set.
        assert_eq!(spec.considered, vec![seq(5), seq(9)]);
        assert_eq!(spec.uncertainty, "perf under load unmeasured");
        assert_eq!(spec.provenance, vec!["agent-1", "owner"]);
        // the prose is DERIVED and mentions the count — but is never parsed back.
        let prose = render_prose(&spec);
        assert!(prose.contains("2 alternative(s) were considered and rejected"));
        assert!(prose.contains("perf under load unmeasured"));
        assert!(prose.contains("agent-1 → owner"));
    }

    /// A morphism grounds the pre/invariants/evidence; the author adds goal +
    /// uncertainty + provenance.
    #[test]
    fn from_morphism_grounds_the_structural_fields() {
        let m = Morphism::build(
            "diff",
            "owner",
            vec![],
            vec![seq(2)],
            vec![Predicate::NameResolvesTo("n".to_string(), seq(0))],
            vec![],
            vec![crate::morphism::NsEffect::Bind("n".to_string(), seq(2))],
            vec![seq(7)],
        )
        .expect("morph");
        let spec = IntentSpec::from_morphism(
            &m,
            "bind n to the new node",
            "no downstream impact analysis yet",
            vec![],
            vec!["owner".to_string()],
        )
        .expect("spec");
        assert_eq!(spec.preconditions, m.pre);
        assert_eq!(spec.evidence, m.evidence);
        assert!(spec.id_matches_content());
    }

    /// Fail-closed decode + tamper: a byte flip changes the id; malformations refuse.
    #[test]
    fn decode_fails_closed() {
        let spec =
            IntentSpec::build("g", vec![], vec![], vec![], "u", vec![], vec![]).expect("builds");
        let bytes = intent_bytes(&spec);
        assert_eq!(decode_intent(&bytes[..3]), Err(IntentError::Truncated));
        let mut bad = bytes.clone();
        bad[0] = b'X';
        assert_eq!(decode_intent(&bad), Err(IntentError::BadMagic));
        let mut ver = bytes.clone();
        ver[4] = 9;
        assert_eq!(decode_intent(&ver), Err(IntentError::UnknownVersion));
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(decode_intent(&trailing), Err(IntentError::TrailingBytes));
        // over-cap goal refused at build.
        assert_eq!(
            IntentSpec::build(&"x".repeat(513), vec![], vec![], vec![], "", vec![], vec![]),
            Err(IntentError::BadText)
        );
    }
}
