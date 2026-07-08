//! `sinabro review` — SDK / public-docs / review-queue controls.
//!
//! Two read-only projections an external author / maintainer sees before a
//! skill reaches the public catalog:
//!
//! 1. [`ReviewQueueView`] — a projection over the canonical Stage D
//!    [`mnemos_e_skill::review_queue::ReviewQueue`]: the per-package review state,
//!    the maintainer verdict (approval audit), and the publishable set. It
//!    **cannot bypass** the D malicious-fixture / security gates: a
//!    quarantined / rejected import stays non-publishable and renders `Red`, and
//!    a maintainer "approve" never upgrades a non-accepted import (the canonical
//!    [`ReviewEntry::state`] fold enforces this — this view only reads it).
//! 2. [`PublicDocsChecklist`] — the public-docs status. The docs optimise for
//!    first success before philosophy, in a fixed canonical order: quickstart,
//!    installation, FAQ, skills, providers, self-host gas, contributing.
//!
//! Reuse (no reinvention): the review queue, its [`ReviewState`] /
//! [`MaintainerVerdict`], and the [`SkillPackageDigest32`] key are the canonical
//! Stage D types; the verdict is the cockpit [`crate::tui::RenderTruth`]. This
//! module mints no review/docs truth and performs no network / fs / live action
//! (local status p95 ≤ 100ms).

use crate::tui::RenderTruth;
use mnemos_e_skill::package::SkillPackageDigest32;
use mnemos_e_skill::review_queue::{MaintainerVerdict, ReviewQueue, ReviewState};

/// A short, colorless label for a review-queue state.
const fn state_label(state: ReviewState) -> &'static str {
    match state {
        ReviewState::Pending => "pending",
        ReviewState::Approved => "approved",
        ReviewState::Rejected => "rejected",
        ReviewState::Quarantined => "quarantined",
    }
}

/// A short, colorless label for a maintainer verdict (the approval audit).
const fn verdict_label(verdict: MaintainerVerdict) -> &'static str {
    match verdict {
        MaintainerVerdict::Approved => "approved",
        MaintainerVerdict::Rejected => "rejected",
        MaintainerVerdict::Quarantined => "quarantined",
    }
}

/// First 16 hex characters of a package digest — a redacted, display-only id.
fn redact_digest(digest: &SkillPackageDigest32) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let bytes = digest.as_bytes();
    let n = bytes.len().min(8);
    let mut out = String::with_capacity(16);
    for &b in &bytes[..n] {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

/// One row of the review-queue projection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReviewRow {
    /// The package digest (rendered redacted).
    pub package: SkillPackageDigest32,
    /// The folded review state.
    pub state: ReviewState,
    /// The maintainer verdict (the approval audit), absent until reviewed.
    pub maintainer: Option<MaintainerVerdict>,
    /// Whether this entry may be published (Accepted import + maintainer Approved).
    pub publishable: bool,
}

/// A read-only projection over the canonical review queue for a set of packages
/// of interest. Holds no queue truth — every value is read from the queue's
/// public API.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReviewQueueView {
    rows: Vec<ReviewRow>,
    replay_hash_32: [u8; 32],
    publishable_count: usize,
}

impl ReviewQueueView {
    /// Project the review queue for the given `packages`. Each package is looked
    /// up via the canonical [`ReviewQueue::get`]; unknown packages are skipped.
    /// The deterministic [`ReviewQueue::replay_hash`] and the publishable count
    /// come straight from the canonical queue.
    #[must_use]
    pub fn project(queue: &ReviewQueue, packages: &[SkillPackageDigest32]) -> Self {
        let mut rows = Vec::with_capacity(packages.len());
        for &package in packages {
            if let Some(entry) = queue.get(package) {
                rows.push(ReviewRow {
                    package,
                    state: entry.state(),
                    maintainer: entry.maintainer,
                    publishable: entry.is_publishable(),
                });
            }
        }
        Self {
            rows,
            replay_hash_32: queue.replay_hash(),
            publishable_count: queue.publishable().len(),
        }
    }

    /// The projected rows.
    #[must_use]
    pub fn rows(&self) -> &[ReviewRow] {
        &self.rows
    }

    /// The number of publishable packages (Accepted + maintainer Approved).
    #[must_use]
    pub const fn publishable_count(&self) -> usize {
        self.publishable_count
    }

    /// The render truth, worst-state-wins (no false green): any
    /// rejected / quarantined entry is `Red` (the security gate caught it), any
    /// pending entry is `Yellow`, an all-approved non-empty queue is `Green`, and
    /// an empty projection is `Unknown` (never a false green).
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        if self.rows.is_empty() {
            return RenderTruth::Unknown;
        }
        let mut any_red = false;
        let mut any_yellow = false;
        for row in &self.rows {
            match row.state {
                ReviewState::Rejected | ReviewState::Quarantined => any_red = true,
                ReviewState::Pending => any_yellow = true,
                ReviewState::Approved => {}
            }
        }
        if any_red {
            RenderTruth::Red
        } else if any_yellow {
            RenderTruth::Yellow
        } else {
            RenderTruth::Green
        }
    }

    /// Redacted, colorless review-list lines bounded by `rows_limit`.
    #[must_use]
    pub fn render(&self, rows_limit: u16) -> Vec<String> {
        let mut lines = vec![
            format!("review_rows={}", self.rows.len()),
            format!("publishable={}", self.publishable_count),
            format!("replay_hash={}", redact32(&self.replay_hash_32)),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        for row in &self.rows {
            let maintainer = row.maintainer.map_or("none", verdict_label);
            lines.push(format!(
                "pkg={} state={} maintainer={} publishable={}",
                redact_digest(&row.package),
                state_label(row.state),
                maintainer,
                row.publishable,
            ));
        }
        lines.into_iter().take(rows_limit as usize).collect()
    }
}

/// First 16 hex characters of a 32-byte hash — a redacted, display-only prefix.
fn redact32(bytes: &[u8; 32]) -> String {
    crate::hex32(bytes).chars().take(16).collect()
}

/// The public docs that must exist before launch, in the canonical
/// first-success-before-philosophy order.
pub const PUBLIC_DOCS: [&str; 7] = [
    "quickstart",
    "installation",
    "faq",
    "skills",
    "providers",
    "self-host-gas",
    "contributing",
];

/// A status checklist over the [`PUBLIC_DOCS`] set. Tracks which canonical docs
/// are present; an all-present checklist is the SDK/public-docs `Green` status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicDocsChecklist {
    /// One bit per [`PUBLIC_DOCS`] entry, in canonical order.
    present_mask_u8: u8,
}

impl PublicDocsChecklist {
    /// The mask with all seven docs present.
    const ALL_MASK: u8 = (1 << (PUBLIC_DOCS.len() as u8)) - 1;

    /// Build a checklist from the set of present doc names. A name not in
    /// [`PUBLIC_DOCS`] is ignored (the public-docs surface is closed).
    #[must_use]
    pub fn from_present(present: &[&str]) -> Self {
        let mut mask = 0u8;
        for (i, doc) in PUBLIC_DOCS.iter().enumerate() {
            if present.contains(doc) {
                mask |= 1 << (i as u8);
            }
        }
        Self {
            present_mask_u8: mask,
        }
    }

    /// Whether every canonical public doc is present.
    #[must_use]
    pub const fn all_present(&self) -> bool {
        self.present_mask_u8 == Self::ALL_MASK
    }

    /// The canonical docs that are still missing, in canonical order.
    #[must_use]
    pub fn missing(&self) -> Vec<&'static str> {
        PUBLIC_DOCS
            .iter()
            .enumerate()
            .filter(|(i, _)| self.present_mask_u8 & (1 << (*i as u8)) == 0)
            .map(|(_, doc)| *doc)
            .collect()
    }

    /// The render truth: `Green` only when every public doc is present (no false
    /// green), otherwise `Red`.
    #[must_use]
    pub const fn render_truth(&self) -> RenderTruth {
        if self.all_present() {
            RenderTruth::Green
        } else {
            RenderTruth::Red
        }
    }

    /// Colorless docs-status lines bounded by `rows_limit`.
    #[must_use]
    pub fn render(&self, rows_limit: u16) -> Vec<String> {
        let mut lines = vec![
            format!("docs_total={}", PUBLIC_DOCS.len()),
            format!("all_present={}", self.all_present()),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        for doc in self.missing() {
            lines.push(format!("missing={doc}"));
        }
        lines.into_iter().take(rows_limit as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;
    use mnemos_e_skill::author_check::AuthorChecklist;
    use mnemos_e_skill::community_import::{CommunityImportEvidence, CommunitySkillImport};

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

    fn evidence(malicious_clean: bool) -> CommunityImportEvidence {
        CommunityImportEvidence {
            signature_present: true,
            provenance_ok: true,
            capability_consistent: true,
            malicious_fixture_clean: malicious_clean,
            eval_present: true,
            no_commerce_clean: true,
        }
    }

    fn import(tag: u8, malicious_clean: bool) -> CommunitySkillImport {
        CommunitySkillImport::evaluate(
            [tag; 32],
            SkillPackageDigest32::new([tag; 32]),
            &evidence(malicious_clean),
            [0u8; 32],
        )
    }

    #[test]
    fn review_list_shows_states_and_publishable() {
        let mut q = ReviewQueue::new();
        let good = import(0x10, true); // Accepted
        let pending = import(0x20, true); // Accepted but unreviewed
        q.submit(good, &complete_checklist()).unwrap();
        q.submit(pending, &complete_checklist()).unwrap();
        q.review(good.package, MaintainerVerdict::Approved).unwrap();

        let view = ReviewQueueView::project(&q, &[good.package, pending.package]);
        assert_eq!(view.rows().len(), 2);
        assert_eq!(view.publishable_count(), 1); // only the approved one
        // The approved+accepted entry is publishable; the unreviewed one is not.
        let approved = view
            .rows()
            .iter()
            .find(|r| r.package == good.package)
            .unwrap();
        assert_eq!(approved.state, ReviewState::Approved);
        assert!(approved.publishable);
        let waiting = view
            .rows()
            .iter()
            .find(|r| r.package == pending.package)
            .unwrap();
        assert_eq!(waiting.state, ReviewState::Pending);
        assert!(!waiting.publishable);
    }

    #[test]
    fn malicious_fixture_cannot_be_bypassed_by_maintainer() {
        let mut q = ReviewQueue::new();
        let bad = import(0x30, false); // malicious fixture dirty -> Quarantined
        q.submit(bad, &complete_checklist()).unwrap();
        // Even an explicit maintainer "approve" cannot publish a quarantined import.
        q.review(bad.package, MaintainerVerdict::Approved).unwrap();
        let view = ReviewQueueView::project(&q, &[bad.package]);
        let row = view.rows()[0];
        assert_eq!(row.state, ReviewState::Quarantined);
        assert!(!row.publishable);
        assert_eq!(view.publishable_count(), 0);
        // The security gate surfaces as Red in the cockpit.
        assert_eq!(view.render_truth(), RenderTruth::Red);
    }

    #[test]
    fn approval_audit_shows_maintainer_verdict() {
        let mut q = ReviewQueue::new();
        let good = import(0x40, true);
        q.submit(good, &complete_checklist()).unwrap();
        q.review(good.package, MaintainerVerdict::Approved).unwrap();
        let view = ReviewQueueView::project(&q, &[good.package]);
        assert_eq!(view.rows()[0].maintainer, Some(MaintainerVerdict::Approved));
        assert!(
            view.render(64)
                .iter()
                .any(|l| l.contains("maintainer=approved"))
        );
    }

    #[test]
    fn empty_review_projection_is_unknown_not_green() {
        let q = ReviewQueue::new();
        let view = ReviewQueueView::project(&q, &[]);
        assert_eq!(view.render_truth(), RenderTruth::Unknown);
    }

    #[test]
    fn public_docs_checklist_all_present_is_green() {
        let view = PublicDocsChecklist::from_present(&PUBLIC_DOCS);
        assert!(view.all_present());
        assert!(view.missing().is_empty());
        assert_eq!(view.render_truth(), RenderTruth::Green);
    }

    #[test]
    fn sdk_docs_status_red_when_a_doc_is_missing() {
        // Missing the FAQ: status is Red and the gap is reported.
        let present: Vec<&str> = PUBLIC_DOCS
            .iter()
            .copied()
            .filter(|d| *d != "faq")
            .collect();
        let view = PublicDocsChecklist::from_present(&present);
        assert!(!view.all_present());
        assert_eq!(view.missing(), vec!["faq"]);
        assert_eq!(view.render_truth(), RenderTruth::Red);
        assert!(view.render(64).iter().any(|l| l == "missing=faq"));
    }

    #[test]
    fn render_is_bounded_and_no_commerce() {
        let mut q = ReviewQueue::new();
        let good = import(0x50, true);
        q.submit(good, &complete_checklist()).unwrap();
        let view = ReviewQueueView::project(&q, &[good.package]);
        assert!(view.render(2).len() <= 2);
        const COMMERCE: &[&str] = &["price", "buy", "sell", "checkout", "refund", "$"];
        for line in view.render(64) {
            for t in COMMERCE {
                assert!(!line.contains(*t), "commerce token {t} leaked: {line}");
            }
        }
    }
}
