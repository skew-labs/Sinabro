//! Local / community registry review queue.
//!
//! ## Review policy
//!
//! A local, self-hostable review queue. The public catalog accepts
//! a candidate skill only after: the import dry-run report
//! ([`CommunitySkillImport`]), the author checklist
//! ([`AuthorChecklist`]), AND an explicit maintainer review state. There is **no
//! auto-publish**: an import that passed every automated gate
//! ([`CommunitySkillDecision::Accepted`]) is still only `Pending` until a
//! maintainer explicitly approves it ([`ReviewQueue::review`]).
//!
//! ## Reuse
//!
//! [`ReviewQueue::submit`] requires a complete [`AuthorChecklist`] and
//! stores the [`CommunitySkillImport`] verbatim; the queue never
//! re-decides the import. A re-submission for the same package (an updated
//! candidate) resets the maintainer verdict so the update is re-reviewed.
//!
//! ## Determinism + offline boundary
//!
//! [`ReviewQueue::replay_hash`] is a stable digest over the sorted entries
//! (queue replay deterministic). Pure, offline; no network,
//! wallet, secret, or chain action.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::author_check::AuthorChecklist;
use crate::community_import::{CommunitySkillDecision, CommunitySkillImport};
use crate::package::{SkillPackageDigest32, blake2b_256};

/// Domain tag for the review-queue replay digest.
const DOMAIN_REVIEW_QUEUE: &[u8] = b"mnemos.d.review_queue.v1";

// ===========================================================================
// 1. MaintainerVerdict — the explicit human review state
// ===========================================================================

/// The maintainer's explicit verdict on a queued candidate. Absent until a
/// maintainer reviews — and a missing verdict can never publish.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MaintainerVerdict {
    /// Approved for the catalog (only meaningful when the import was Accepted).
    Approved = 1,
    /// Rejected by the maintainer.
    Rejected = 2,
    /// Quarantined for further investigation.
    Quarantined = 3,
}

// ===========================================================================
// 2. ReviewState — the queue-entry surface state
// ===========================================================================

/// The surface state of a review-queue entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReviewState {
    /// Awaiting maintainer review (or the import is not Accepted yet).
    Pending,
    /// Maintainer-approved AND import-accepted — publishable.
    Approved,
    /// Rejected (by the import or the maintainer).
    Rejected,
    /// Quarantined (by the import or the maintainer).
    Quarantined,
}

// ===========================================================================
// 3. ReviewQueueError
// ===========================================================================

/// Why a queue operation failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReviewQueueError {
    /// The submission's author checklist is incomplete.
    IncompleteAuthorChecklist,
    /// No queued entry for the requested package.
    NotFound,
}

// ===========================================================================
// 4. ReviewEntry
// ===========================================================================

/// One review-queue entry: the imported candidate plus the maintainer verdict.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ReviewEntry {
    /// The import dry-run report.
    pub import: CommunitySkillImport,
    /// The maintainer verdict, absent until reviewed.
    pub maintainer: Option<MaintainerVerdict>,
}

impl ReviewEntry {
    /// The surface state, folding the import decision and the maintainer
    /// verdict. A maintainer verdict never *upgrades* a non-accepted import
    /// (you cannot approve a Rejected/Quarantined import into publishable).
    #[must_use]
    pub fn state(&self) -> ReviewState {
        match self.import.decision {
            CommunitySkillDecision::Rejected => ReviewState::Rejected,
            CommunitySkillDecision::Quarantined => ReviewState::Quarantined,
            CommunitySkillDecision::Pending | CommunitySkillDecision::Accepted => {
                match self.maintainer {
                    None => ReviewState::Pending,
                    Some(MaintainerVerdict::Approved) if self.import.decision.is_accepted() => {
                        ReviewState::Approved
                    }
                    Some(MaintainerVerdict::Approved) => ReviewState::Pending,
                    Some(MaintainerVerdict::Rejected) => ReviewState::Rejected,
                    Some(MaintainerVerdict::Quarantined) => ReviewState::Quarantined,
                }
            }
        }
    }

    /// `true` iff this entry may be published to the public catalog: the import
    /// was Accepted (every automated gate passed) AND a maintainer explicitly
    /// approved it. No auto-publish.
    #[inline]
    #[must_use]
    pub fn is_publishable(&self) -> bool {
        self.import.decision.is_accepted()
            && matches!(self.maintainer, Some(MaintainerVerdict::Approved))
    }
}

// ===========================================================================
// 5. ReviewQueue
// ===========================================================================

/// A local, self-hostable review queue keyed by package digest.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ReviewQueue {
    entries: Vec<ReviewEntry>,
}

impl ReviewQueue {
    /// An empty queue.
    #[inline]
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Submit (or re-submit) a candidate. Requires a complete author checklist.
    /// A re-submission for the same package replaces the import and
    /// **resets the maintainer verdict** so the update is re-reviewed (never
    /// inheriting the prior approval).
    pub fn submit(
        &mut self,
        import: CommunitySkillImport,
        author_checklist: &AuthorChecklist,
    ) -> Result<(), ReviewQueueError> {
        if !author_checklist.is_complete() {
            return Err(ReviewQueueError::IncompleteAuthorChecklist);
        }
        if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|e| e.import.package == import.package)
        {
            existing.import = import;
            existing.maintainer = None; // re-review after update
        } else {
            self.entries.push(ReviewEntry {
                import,
                maintainer: None,
            });
        }
        Ok(())
    }

    /// Record a maintainer verdict for a queued package.
    pub fn review(
        &mut self,
        package: SkillPackageDigest32,
        verdict: MaintainerVerdict,
    ) -> Result<(), ReviewQueueError> {
        let entry = self
            .entries
            .iter_mut()
            .find(|e| e.import.package == package)
            .ok_or(ReviewQueueError::NotFound)?;
        entry.maintainer = Some(verdict);
        Ok(())
    }

    /// Look up an entry by package digest.
    #[must_use]
    pub fn get(&self, package: SkillPackageDigest32) -> Option<&ReviewEntry> {
        self.entries.iter().find(|e| e.import.package == package)
    }

    /// The packages currently publishable to the catalog (Accepted + maintainer
    /// Approved), sorted by digest.
    #[must_use]
    pub fn publishable(&self) -> Vec<SkillPackageDigest32> {
        let mut out: Vec<SkillPackageDigest32> = self
            .entries
            .iter()
            .filter(|e| e.is_publishable())
            .map(|e| e.import.package)
            .collect();
        out.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
        out
    }

    /// Stable digest over the queue, independent of submission order: entries
    /// are sorted by package digest, then each contributes its package, import
    /// decision byte, and maintainer-verdict byte (`0` = none). The same set of
    /// `(import, verdict)` always replays the same hash.
    #[must_use]
    pub fn replay_hash(&self) -> [u8; 32] {
        let mut sorted: Vec<&ReviewEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.import.package.as_bytes().cmp(b.import.package.as_bytes()));
        let count = (sorted.len() as u64).to_le_bytes();
        let mut buf: Vec<u8> = Vec::with_capacity(sorted.len() * 34);
        for e in sorted {
            buf.extend_from_slice(e.import.package.as_bytes());
            buf.push(e.import.decision as u8);
            buf.push(e.maintainer.map_or(0u8, |v| v as u8));
        }
        blake2b_256(&[DOMAIN_REVIEW_QUEUE, &count, &buf])
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::community_import::CommunityImportEvidence;

    fn complete_checklist() -> AuthorChecklist {
        AuthorChecklist {
            manifest_ok: true,
            fixtures_ok: true,
            eval_command_ok: true,
            capability_declared_ok: true,
            provenance_signed_ok: true,
            dry_run_ok: true,
        }
    }

    fn evidence(all_good: bool) -> CommunityImportEvidence {
        CommunityImportEvidence {
            signature_present: all_good,
            provenance_ok: true,
            capability_consistent: true,
            malicious_fixture_clean: true,
            eval_present: true,
            no_commerce_clean: true,
        }
    }

    fn import(tag: u8, accepted: bool) -> CommunitySkillImport {
        CommunitySkillImport::evaluate(
            [tag; 32],
            SkillPackageDigest32::new([tag; 32]),
            &evidence(accepted),
            [0u8; 32],
        )
    }

    #[test]
    fn submit_requires_complete_checklist() {
        let mut q = ReviewQueue::new();
        let incomplete = AuthorChecklist {
            dry_run_ok: false,
            ..complete_checklist()
        };
        assert_eq!(
            q.submit(import(0x01, true), &incomplete),
            Err(ReviewQueueError::IncompleteAuthorChecklist)
        );
    }

    #[test]
    fn accepted_import_is_pending_then_approved() {
        let mut q = ReviewQueue::new();
        let imp = import(0x02, true);
        q.submit(imp, &complete_checklist()).expect("submit");
        // pending: accepted import, no maintainer verdict yet.
        let pkg = SkillPackageDigest32::new([0x02; 32]);
        assert_eq!(q.get(pkg).unwrap().state(), ReviewState::Pending);
        assert!(!q.get(pkg).unwrap().is_publishable(), "no auto-publish");
        // approved: maintainer approves -> publishable.
        q.review(pkg, MaintainerVerdict::Approved).expect("review");
        assert_eq!(q.get(pkg).unwrap().state(), ReviewState::Approved);
        assert!(q.get(pkg).unwrap().is_publishable());
        assert_eq!(q.publishable(), alloc::vec![pkg]);
    }

    #[test]
    fn rejected_import_state() {
        let mut q = ReviewQueue::new();
        q.submit(import(0x03, false), &complete_checklist())
            .expect("submit");
        let pkg = SkillPackageDigest32::new([0x03; 32]);
        // signature_present=false -> import Rejected.
        assert_eq!(q.get(pkg).unwrap().state(), ReviewState::Rejected);
        assert!(!q.get(pkg).unwrap().is_publishable());
    }

    #[test]
    fn maintainer_reject_and_quarantine() {
        let mut q = ReviewQueue::new();
        let pkg = SkillPackageDigest32::new([0x04; 32]);
        q.submit(import(0x04, true), &complete_checklist())
            .expect("submit");
        q.review(pkg, MaintainerVerdict::Rejected).expect("reject");
        assert_eq!(q.get(pkg).unwrap().state(), ReviewState::Rejected);
        q.review(pkg, MaintainerVerdict::Quarantined)
            .expect("quarantine");
        assert_eq!(q.get(pkg).unwrap().state(), ReviewState::Quarantined);
        assert!(!q.get(pkg).unwrap().is_publishable());
    }

    #[test]
    fn re_review_after_update_resets_approval() {
        let mut q = ReviewQueue::new();
        let pkg = SkillPackageDigest32::new([0x05; 32]);
        q.submit(import(0x05, true), &complete_checklist())
            .expect("submit");
        q.review(pkg, MaintainerVerdict::Approved).expect("approve");
        assert!(q.get(pkg).unwrap().is_publishable());
        // An updated submission for the same package must be re-reviewed.
        q.submit(import(0x05, true), &complete_checklist())
            .expect("resubmit");
        assert_eq!(q.get(pkg).unwrap().state(), ReviewState::Pending);
        assert!(
            !q.get(pkg).unwrap().is_publishable(),
            "update must re-review"
        );
    }

    #[test]
    fn queue_replay_is_order_independent() {
        let mut a = ReviewQueue::new();
        a.submit(import(0x06, true), &complete_checklist())
            .expect("a1");
        a.submit(import(0x07, true), &complete_checklist())
            .expect("a2");
        let mut b = ReviewQueue::new();
        b.submit(import(0x07, true), &complete_checklist())
            .expect("b1");
        b.submit(import(0x06, true), &complete_checklist())
            .expect("b2");
        assert_eq!(a.replay_hash(), b.replay_hash());
        assert_ne!(a.replay_hash(), [0u8; 32]);
    }
}
