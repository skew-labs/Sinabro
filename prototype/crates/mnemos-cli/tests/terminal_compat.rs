//! Terminal compatibility / accessibility matrix (atom #478 · F.8.11).
//!
//! Colorless, narrow, screen-reader-ish plain mode, and SSH/WSL/macOS/Linux
//! terminals must all stay usable, and config/grammar/schema migration must not
//! change what a status *means*. These integration tests assert those invariants
//! against the colorless ASCII renders the F-WP-08 surfaces expose.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use sinabro::commands::audit::{AuditAction, AuditEntry, AuditTrail, render_truth_label};
use sinabro::commands::release_secret_scan::{ReleaseSecretScan, ReleaseSurface};
use sinabro::tui::RenderTruth;
use sinabro::{StageFEvidenceRef, StageFTraceLink, sha256_32};

fn sample_trail() -> AuditTrail {
    let mut t = AuditTrail::new();
    let link = StageFTraceLink::new(sha256_32(b"x"), 472, 100);
    let ev = StageFEvidenceRef {
        path_hash_32: sha256_32(b"e"),
        trace: link,
    };
    t.push(AuditEntry::seal(AuditAction::Kill, link, ev));
    t
}

#[test]
fn render_truth_labels_are_stable_ascii_words_not_colors() {
    // Colorless / screen-reader mode: the truth is the WORD, never a color.
    assert_eq!(render_truth_label(RenderTruth::Green), "GREEN");
    assert_eq!(render_truth_label(RenderTruth::Yellow), "YELLOW");
    assert_eq!(render_truth_label(RenderTruth::Red), "RED");
    assert_eq!(render_truth_label(RenderTruth::Unknown), "UNKNOWN");
    for t in [
        RenderTruth::Green,
        RenderTruth::Yellow,
        RenderTruth::Red,
        RenderTruth::Unknown,
    ] {
        let l = render_truth_label(t);
        assert!(l.is_ascii() && l.chars().all(|c| c.is_ascii_uppercase()));
    }
}

#[test]
fn plain_renders_are_colorless_and_fit_narrow_terminals() {
    let trail = sample_trail();
    let mut scan = ReleaseSecretScan::new();
    scan.add(ReleaseSurface::Repo, "clean readme\n");
    for line in [trail.render_plain(), scan.render_plain()] {
        // no ANSI / color escape (colorless terminals + no-color env)
        assert!(!line.contains('\u{1b}'), "no ANSI escape: {line}");
        // pure ASCII (unicode/ascii mode interoperable + copyable)
        assert!(line.is_ascii(), "ASCII only: {line}");
        // single copyable line (no embedded control characters)
        assert!(!line.contains('\n') && !line.contains('\t'));
        // fits the standard 80x24 terminal without wrapping (the 60x20 fallback
        // may wrap, but a wrapped status line never overlaps — atom #478 criterion)
        assert!(
            line.len() <= 80,
            "line {} chars exceeds 80: {line}",
            line.len()
        );
    }
}

#[test]
fn renders_are_deterministic_across_platforms_and_migration() {
    // macOS / Linux / WSL: pure string projections with no platform call → the
    // same bytes on every run (a migration-compatibility snapshot: the meaning of
    // a status survives schema/grammar migration).
    let a = sample_trail().render_plain();
    let b = sample_trail().render_plain();
    assert_eq!(a, b);
    assert!(a.starts_with("audit entries=1 "));
    assert!(a.ends_with("truth=GREEN"));
}

#[test]
fn every_surface_label_is_ascii_and_copyable() {
    for s in ReleaseSurface::all() {
        let l = s.label();
        assert!(l.is_ascii() && !l.is_empty());
        assert!(l.chars().all(|c| c.is_ascii_lowercase() || c == '_'));
    }
}
