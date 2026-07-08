//! Stage B trace-link embedding.
//!
//! Every Stage B chunk header ([`StageBChunkHeaderV1`]) already carries
//! a non-optional [`StageBTraceLink`] field, so a chunk can never be
//! detached from its replay/measurement stamp *at the type level*. This module
//! mints the canonical OUT: [`StageBTraceEvidence`] — the
//! **content-free** evidence carrier that the log / metrics seam reads so that
//! memory and measurement are never separated: this
//! becomes an executable invariant, not only a struct field.
//!
//! # Invariants
//!
//! * **Missing trace reject (fail-closed).** A header is allowed to *hold* a
//!   trace whose `atom_id_u16 == 0` — Stage A atom `#0` is `RESET`, never a real
//!   memory-producing action, so an all-zero / unstamped trace is the
//!   "missing evidence" sentinel (the same all-zero-means-missing convention
//!   the sibling [`EvidenceBundleManifestV1`](crate::EvidenceBundleManifestV1)
//!   uses for its hash slots). [`StageBTraceEvidence::embed`] /
//!   [`from_trace`](StageBTraceEvidence::from_trace) reject that sentinel,
//!   returning `None`, so no evidence record can be minted for a chunk whose
//!   action is not bound to a real atom. Reject-as-`Option` (no new
//!   [`StageBChunkError`](crate::StageBChunkError) variant) mirrors the earlier
//!   precedent; the frozen `#[non_exhaustive]` error set is not
//!   widened here.
//!
//! * **Atom id preserved.** Embedding copies the header's trace verbatim; the
//!   evidence's [`atom_id_u16`](StageBTraceEvidence::atom_id_u16),
//!   [`trace_id_u64`](StageBTraceEvidence::trace_id_u64) and
//!   [`attempt_u8`](StageBTraceEvidence::attempt_u8) equal the header's trace
//!   components exactly. The measurement side reads the *same* atom number the
//!   memory side stamped.
//!
//! * **Trace id redaction safe (content-free by construction).**
//!   [`StageBTraceEvidence`] holds **only** the [`StageBTraceLink`] (three
//!   opaque, caller-assigned ids) — no body, no owner [`SuiAddress`], no parent
//!   blob, no content bytes. The three trace ids are not content-derived secrets
//!   (the trace id is an opaque per-run counter, not a hash of memory), so they
//!   are safe to emit to a log / metrics line as-is; everything that *would*
//!   require redaction is structurally absent. Two headers that differ only in
//!   their (potentially sensitive) `owner` produce byte-identical evidence,
//!   which proves the owner is never carried into the measurement trail.
//!
//! # Reuse map
//!
//! * **[`StageBTraceLink`]** — the `(trace_id, atom_id, attempt)`
//!   stamp, used verbatim from [`stage_b_handoff`](crate::stage_b_handoff). No
//!   second trace/stamp type is minted.
//! * **[`StageBChunkHeaderV1`]** — the content-free chunk header,
//!   read verbatim from [`chunk_schema`](crate::chunk_schema). Embedding reads
//!   its `trace` field; it constructs no new header and mutates nothing.
//!
//! # Scope note — the a-core log / metrics *emission* seam is deferred
//!
//! Every chunk points to its trace **and** to a-core log/metrics evidence.
//! This module intentionally does not pull in the Stage A `a-core`
//! logging/metrics canonical, and `mnemos-b-memory` carries no `mnemos-a-core`
//! dependency. Adding one here would step outside this module's scope and into a
//! later integration (the same deferral discipline by which the sign path stays
//! in `g-wallet` and the publish owner-flag stays with the publish path). So
//! this module mints the content-free, redaction-safe **projection**
//! ([`evidence_ids`] / [`StageBTraceEvidence`]) that the a-core log/metrics seam
//! will consume, and defers the actual `a-core` emission wiring to that seam.
//!
//! [`evidence_ids`]: StageBTraceEvidence::evidence_ids

use crate::chunk_schema::StageBChunkHeaderV1;
use crate::stage_b_handoff::StageBTraceLink;

/// Content-free evidence that a Stage B chunk is bound to a real per-action
/// trace stamp.
///
/// This is the canonical OUT: an *evidence* type combining the header with its
/// [`StageBTraceLink`] (a receipt/evidence record composed from earlier
/// canonical types). It carries **only** the trace — never the chunk body,
/// owner address, or parent blob — so it is redaction-safe by construction and
/// can be emitted to a log / metrics line without any content leaving the
/// machine.
///
/// Construct it via [`embed`](Self::embed) (from a validated header) or
/// [`from_trace`](Self::from_trace) (from a bare trace); both reject the
/// missing/unstamped sentinel (`atom_id_u16 == 0`) fail-closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct StageBTraceEvidence {
    /// The per-action stamp this evidence binds. Private so the only way to
    /// obtain a value is through the fail-closed constructors (a raw struct
    /// literal that bypasses the missing-trace reject is not expressible
    /// outside this module).
    trace: StageBTraceLink,
}

impl StageBTraceEvidence {
    /// Embed the trace carried by a chunk `header` into a content-free evidence
    /// record. Returns `None` if the header's trace is the missing/unstamped
    /// sentinel (`atom_id_u16 == 0`) — fail-closed "missing trace reject".
    ///
    /// Only the header's `trace` field is read; the owner, parent and declared
    /// content length are deliberately **not** copied (redaction-safe).
    #[inline]
    pub const fn embed(header: &StageBChunkHeaderV1) -> Option<Self> {
        Self::from_trace(header.trace)
    }

    /// Bind a bare [`StageBTraceLink`] into evidence, rejecting the
    /// missing/unstamped sentinel (`atom_id_u16 == 0`) fail-closed.
    ///
    /// `atom_id_u16 == 0` is treated as "missing" because atom id `0` is the
    /// `RESET` sentinel — never a real memory-producing action — so a zero atom
    /// id means the action is not bound to any atom and its evidence trail would
    /// be detached from measurement.
    #[inline]
    pub const fn from_trace(trace: StageBTraceLink) -> Option<Self> {
        if trace.atom_id_u16 == 0 {
            return None;
        }
        Some(Self { trace })
    }

    /// The bound trace stamp (verbatim copy of the header's `trace`).
    #[inline]
    pub const fn trace(&self) -> StageBTraceLink {
        self.trace
    }

    /// The opaque per-run trace identifier.
    #[inline]
    pub const fn trace_id_u64(&self) -> u64 {
        self.trace.trace_id_u64
    }

    /// The atom number this action belongs to (always non-zero — the
    /// missing-trace reject guarantees it).
    #[inline]
    pub const fn atom_id_u16(&self) -> u16 {
        self.trace.atom_id_u16
    }

    /// The retry attempt counter for the action.
    #[inline]
    pub const fn attempt_u8(&self) -> u8 {
        self.trace.attempt_u8
    }

    /// The redaction-safe log / metrics projection: the three trace ids as a
    /// plain tuple `(trace_id_u64, atom_id_u16, attempt_u8)`.
    ///
    /// This is the only data an a-core log / metrics seam needs to bind a
    /// measurement record to the chunk that produced it. It is content-free by
    /// construction — there is no field here that could carry memory body,
    /// owner or provider text — so emitting it never leaks user content.
    #[inline]
    pub const fn evidence_ids(&self) -> (u64, u16, u8) {
        (
            self.trace.trace_id_u64,
            self.trace.atom_id_u16,
            self.trace.attempt_u8,
        )
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use crate::chunk_schema::{StageBChunkFlags, StageBChunkHeaderV1};
    use mnemos_c_walrus::{ChunkKind, MemoryRole, PublishPayloadClass};
    use mnemos_d_move::SuiAddress;

    /// Build a content-free genesis header (no parent, no flags) with the given
    /// `owner` and `trace`, reusing the validated constructor.
    fn header(owner: SuiAddress, trace: StageBTraceLink) -> StageBChunkHeaderV1 {
        StageBChunkHeaderV1::new(
            ChunkKind::UserMessage,
            MemoryRole::User,
            PublishPayloadClass::SyntheticPublicFixture,
            StageBChunkFlags::None as u8,
            0,
            owner,
            None,
            trace,
        )
        .expect("genesis header valid")
    }

    /// test 1 (missing trace reject): a header may *hold* an all-zero /
    /// `atom_id == 0` trace, but embedding it is rejected fail-closed (`None`);
    /// a real atom-stamped trace embeds (`Some`).
    #[test]
    fn b1_13_missing_trace_reject() {
        let owner = SuiAddress::new([0u8; 32]);

        // Fully-missing sentinel.
        let missing = header(owner, StageBTraceLink::new(0, 0, 0));
        assert!(StageBTraceEvidence::embed(&missing).is_none());

        // atom_id == 0 with a non-zero trace id is still "missing" — the atom
        // binding is what couples memory to measurement.
        let no_atom = header(owner, StageBTraceLink::new(42, 0, 0));
        assert!(StageBTraceEvidence::embed(&no_atom).is_none());
        assert!(StageBTraceEvidence::from_trace(StageBTraceLink::new(42, 0, 0)).is_none());

        // A real atom-stamped trace embeds.
        let present = header(owner, StageBTraceLink::new(7, 94, 0));
        assert!(StageBTraceEvidence::embed(&present).is_some());
    }

    /// test 2 (atom id preserved): embedding copies the trace verbatim — the
    /// evidence reports the same atom id (and trace id / attempt) the header
    /// stamped.
    #[test]
    fn b1_13_atom_id_preserved() {
        let owner = SuiAddress::new([0x11; 32]);
        let trace = StageBTraceLink::new(0xDEAD_BEEF, 94, 3);
        let ev = StageBTraceEvidence::embed(&header(owner, trace))
            .expect("real atom-stamped trace embeds");

        assert_eq!(ev.atom_id_u16(), 94);
        assert_eq!(ev.trace_id_u64(), 0xDEAD_BEEF);
        assert_eq!(ev.attempt_u8(), 3);
        assert_eq!(ev.trace(), trace);
        assert_eq!(ev.evidence_ids(), (0xDEAD_BEEF, 94, 3));
    }

    /// test 3 (trace id redaction safe): the evidence is content-free — two
    /// headers that differ ONLY in their (sensitive) owner produce identical
    /// evidence, proving the owner is never carried into the measurement trail;
    /// and the `Debug` projection exposes the trace ids but no owner bytes.
    #[test]
    fn b1_13_trace_id_redaction_safe() {
        let trace = StageBTraceLink::new(7, 94, 0);

        // Distinctive owners that, if leaked, would be visible in any textual
        // projection (0xAB = 171). The trace ids deliberately avoid those bytes.
        let ev_a = StageBTraceEvidence::embed(&header(SuiAddress::new([0xAB; 32]), trace))
            .expect("embeds");
        let ev_b = StageBTraceEvidence::embed(&header(SuiAddress::new([0xCD; 32]), trace))
            .expect("embeds");

        // Owner does not affect evidence ⇒ owner is not carried (redaction safe).
        assert_eq!(ev_a, ev_b);
        assert_eq!(ev_a.evidence_ids(), (7, 94, 0));

        // The Debug projection carries the (safe) trace ids and no owner bytes.
        let dbg = format!("{ev_a:?}");
        assert!(dbg.contains("94"), "atom id must be visible: {dbg}");
        assert!(
            !dbg.contains("171") && !dbg.contains("205"),
            "owner bytes (0xAB=171 / 0xCD=205) must never appear: {dbg}"
        );
    }
}
