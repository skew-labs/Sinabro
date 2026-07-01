//! Deterministic, PURE payoff-diagram SVG renderer for the Skew §8 GUI payoff pane (WAVE G).
//!
//! Renders a piecewise-affine payoff `f(S)` over the collar lattice `D = {lo, lo+tau, ..=hi}` as
//! an SVG polyline with axes + a zero baseline. The piecewise form is exactly piecewise-LINEAR, so
//! the curve is reproduced EXACTLY by sampling each segment's two endpoints (`m <= 16` segments ⇒
//! `<= 32` vertices). NO float, NO clock, NO network, NO randomness ⇒ byte-deterministic (the same
//! descriptor always produces the same SVG bytes), so the GUI can fetch it via a Tauri read command
//! and an inline test can pin it. The agent PROPOSES a payoff; this VISUALIZES it (money 0, no key,
//! no chain). Mirrors the SETTLE-time eval in `mode_c::eval_piecewise_at` (the Skew source).

/// One sampled payoff vertex: `f(s)` at an on-lattice settlement price `s`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoffPoint {
    /// The settlement price `S` (signed, on-lattice).
    pub s: i128,
    /// The payoff `f(S)` at that price (signed).
    pub f: i128,
}

/// A piecewise segment for the renderer (mirrors `solana_codec::PieceSegment` / `mode_c::PieceSegment`):
/// `f(S) = konst + coeff·S` on `[x_lo, x_hi]` (`x_lo` = the previous segment's `x_hi + tau`, or `lo`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PayoffSeg {
    /// Inclusive upper breakpoint of this segment.
    pub x_hi: i128,
    /// Slope on this segment.
    pub coeff: i128,
    /// Intercept on this segment.
    pub konst: i128,
}

/// Sample a piecewise-affine payoff at its segment endpoints — an EXACT vertex list for the
/// piecewise-linear curve (each segment is linear ⇒ its two endpoints suffice). Returns `None`
/// (fail-closed) on a degenerate domain (`lo >= hi`, `tau == 0`, `m == 0`) or any `i128` overflow,
/// so the renderer never draws a malformed payoff.
#[must_use]
pub fn sample_piecewise(
    lo: i128,
    hi: i128,
    tau: u128,
    segments: &[PayoffSeg],
) -> Option<Vec<PayoffPoint>> {
    if lo >= hi || tau == 0 || segments.is_empty() {
        return None;
    }
    let tau_i = i128::try_from(tau).ok()?;
    let mut pts: Vec<PayoffPoint> = Vec::with_capacity(segments.len() * 2);
    let mut x_lo = lo;
    for seg in segments {
        // Defensive: the segment must be in [x_lo, hi] and ascending (a malformed list ⇒ None).
        if seg.x_hi < x_lo || seg.x_hi > hi {
            return None;
        }
        let f_lo = seg.coeff.checked_mul(x_lo)?.checked_add(seg.konst)?;
        let f_hi = seg.coeff.checked_mul(seg.x_hi)?.checked_add(seg.konst)?;
        pts.push(PayoffPoint { s: x_lo, f: f_lo });
        pts.push(PayoffPoint {
            s: seg.x_hi,
            f: f_hi,
        });
        x_lo = seg.x_hi.checked_add(tau_i)?;
    }
    Some(pts)
}

/// Build an affine-forward segment list (`f = coeff·S + konst` over the whole collar, one segment).
/// The `list_wcc_template` affine leg as a single piece — for the payoff pane's affine view.
#[must_use]
pub fn affine_forward_segments(hi: i128, coeff: i128, konst: i128) -> Vec<PayoffSeg> {
    vec![PayoffSeg {
        x_hi: hi,
        coeff,
        konst,
    }]
}

/// Build the straddle long-leg payoff segments (`f = |S−strike| − premium`) over `[.., hi]` — the
/// SAME shape the agent PROPOSES via `daemon trade … form-piecewise` (`dispatch::build_straddle_legs`):
/// `[x_hi=strike: −S + (strike−premium)]` then `[x_hi=hi: S − (strike+premium)]`. PURE; the renderer
/// fail-closes on a degenerate domain, so this only shapes the two pieces.
#[must_use]
pub fn straddle_payoff_segs(hi: i128, strike: i128, premium: i128) -> Vec<PayoffSeg> {
    vec![
        PayoffSeg {
            x_hi: strike,
            coeff: -1,
            konst: strike.saturating_sub(premium),
        },
        PayoffSeg {
            x_hi: hi,
            coeff: 1,
            konst: strike.saturating_add(premium).saturating_neg(),
        },
    ]
}

/// Map a value in `[lo_v, hi_v]` onto a pixel span `[lo_px, hi_px]` (integer, clamped). When the
/// value range is degenerate (`hi_v == lo_v`) the midpoint is returned. PURE integer arithmetic.
fn map_px(v: i128, lo_v: i128, hi_v: i128, lo_px: i64, hi_px: i64) -> i64 {
    if hi_v <= lo_v {
        return lo_px + (hi_px - lo_px) / 2;
    }
    let span_v = hi_v - lo_v; // > 0
    let span_px = i128::from(hi_px - lo_px);
    let off = (v - lo_v).clamp(0, span_v);
    let px = i128::from(lo_px) + off.saturating_mul(span_px) / span_v;
    // px is within [lo_px, hi_px] by construction; the cast is safe.
    i64::try_from(px).unwrap_or(lo_px)
}

/// Render a deterministic SVG of the sampled payoff (polyline + S/f axes + a zero baseline +
/// min/max f labels). `width`/`height` are the pixel canvas; an internal margin frames the axes.
/// The output is a self-contained `<svg …>…</svg>` string (no external refs). Returns an honest
/// empty-state SVG when `points` is empty.
#[must_use]
pub fn render_payoff_svg(title: &str, points: &[PayoffPoint], width: u32, height: u32) -> String {
    let w = i64::from(width.max(120));
    let h = i64::from(height.max(80));
    let margin: i64 = 28;
    let title_esc = xml_escape(title);
    if points.is_empty() {
        return format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{h}\" viewBox=\"0 0 {w} {h}\">\
             <rect width=\"{w}\" height=\"{h}\" fill=\"#0b0f14\"/>\
             <text x=\"{tx}\" y=\"{ty}\" fill=\"#8b98a5\" font-size=\"12\" font-family=\"monospace\">{title_esc}: no payoff to render</text></svg>",
            tx = margin,
            ty = h / 2,
        );
    }
    // Data extents (S on x, f on y).
    let mut s_lo = points[0].s;
    let mut s_hi = points[0].s;
    let mut f_lo = points[0].f;
    let mut f_hi = points[0].f;
    for p in points {
        s_lo = s_lo.min(p.s);
        s_hi = s_hi.max(p.s);
        f_lo = f_lo.min(p.f);
        f_hi = f_hi.max(p.f);
    }
    // Always include f=0 in the visible range so the zero baseline is meaningful.
    f_lo = f_lo.min(0);
    f_hi = f_hi.max(0);

    let x_lo_px = margin;
    let x_hi_px = w - margin;
    let y_lo_px = margin; // top (f_hi)
    let y_hi_px = h - margin; // bottom (f_lo)

    // The payoff polyline points.
    let mut poly = String::new();
    for (i, p) in points.iter().enumerate() {
        let px = map_px(p.s, s_lo, s_hi, x_lo_px, x_hi_px);
        // y is inverted: f_hi → top (y_lo_px), f_lo → bottom (y_hi_px).
        let py = map_px(f_hi - p.f, 0, f_hi - f_lo, y_lo_px, y_hi_px);
        if i > 0 {
            poly.push(' ');
        }
        poly.push_str(&format!("{px},{py}"));
    }
    // The zero baseline (f = 0).
    let zero_y = map_px(f_hi, 0, f_hi - f_lo, y_lo_px, y_hi_px);

    format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{w}\" height=\"{h}\" viewBox=\"0 0 {w} {h}\" font-family=\"monospace\">\
         <rect width=\"{w}\" height=\"{h}\" fill=\"#0b0f14\"/>\
         <line x1=\"{x_lo_px}\" y1=\"{y_lo_px}\" x2=\"{x_lo_px}\" y2=\"{y_hi_px}\" stroke=\"#2a3340\" stroke-width=\"1\"/>\
         <line x1=\"{x_lo_px}\" y1=\"{y_hi_px}\" x2=\"{x_hi_px}\" y2=\"{y_hi_px}\" stroke=\"#2a3340\" stroke-width=\"1\"/>\
         <line x1=\"{x_lo_px}\" y1=\"{zero_y}\" x2=\"{x_hi_px}\" y2=\"{zero_y}\" stroke=\"#3d4b5c\" stroke-width=\"1\" stroke-dasharray=\"4 3\"/>\
         <polyline points=\"{poly}\" fill=\"none\" stroke=\"#4ea1ff\" stroke-width=\"2\"/>\
         <text x=\"{tx}\" y=\"16\" fill=\"#c8d2dc\" font-size=\"12\">{title_esc}</text>\
         <text x=\"{x_lo_px}\" y=\"{ylab}\" fill=\"#8b98a5\" font-size=\"10\">S {s_lo}..{s_hi}</text>\
         <text x=\"{x_lo_px}\" y=\"{flab}\" fill=\"#8b98a5\" font-size=\"10\">f {f_lo}..{f_hi}</text></svg>",
        tx = margin,
        ylab = h - 6,
        flab = margin + 12,
    )
}

/// Minimal XML/SVG text escape (`&`, `<`, `>`, `"`) so an untrusted title can't break the SVG.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The deployed straddle (`f = |S−50| − 8` over [0,100] τ10): segment endpoints reproduce the
    /// apex (−8 at S=50) and the band ends (+42 at S=0/100) — the EXACT piecewise-linear vertices.
    fn straddle_long() -> Vec<PayoffSeg> {
        vec![
            PayoffSeg {
                x_hi: 50,
                coeff: -1,
                konst: 42,
            },
            PayoffSeg {
                x_hi: 100,
                coeff: 1,
                konst: -58,
            },
        ]
    }

    #[test]
    fn sample_straddle_hits_the_apex_and_band_ends() {
        let pts = sample_piecewise(0, 100, 10, &straddle_long()).expect("samples");
        // 2 segments ⇒ 4 endpoint vertices: (0,42)(50,-8)(60,2)(100,42).
        assert_eq!(pts.len(), 4);
        assert_eq!(pts[0], PayoffPoint { s: 0, f: 42 });
        assert_eq!(pts[1], PayoffPoint { s: 50, f: -8 }); // the apex = −premium
        assert_eq!(pts[2], PayoffPoint { s: 60, f: 2 });
        assert_eq!(pts[3], PayoffPoint { s: 100, f: 42 });
    }

    #[test]
    fn sample_fail_closed_on_degenerate_domain() {
        assert!(sample_piecewise(100, 0, 10, &straddle_long()).is_none()); // lo >= hi
        assert!(sample_piecewise(0, 100, 0, &straddle_long()).is_none()); // tau == 0
        assert!(sample_piecewise(0, 100, 10, &[]).is_none()); // m == 0
    }

    #[test]
    fn affine_forward_segments_is_single_piece() {
        // f = S − 40 over [0,100]: one segment; endpoints (0,−40) and (100,60).
        let segs = affine_forward_segments(100, 1, -40);
        let pts = sample_piecewise(0, 100, 1, &segs).expect("samples");
        assert_eq!(pts.len(), 2);
        assert_eq!(pts[0], PayoffPoint { s: 0, f: -40 });
        assert_eq!(pts[1], PayoffPoint { s: 100, f: 60 });
    }

    #[test]
    fn render_is_deterministic_and_self_contained() {
        let pts = sample_piecewise(0, 100, 10, &straddle_long()).unwrap();
        let a = render_payoff_svg("straddle K=50 prem=8", &pts, 320, 200);
        let b = render_payoff_svg("straddle K=50 prem=8", &pts, 320, 200);
        assert_eq!(a, b, "byte-deterministic for the same input");
        assert!(a.starts_with("<svg"));
        assert!(a.ends_with("</svg>"));
        assert!(a.contains("<polyline"));
        assert!(a.contains("stroke-dasharray")); // the f=0 baseline
        assert!(a.contains("S 0..100"));
        // no external refs / scripts (self-contained, safe to inline).
        assert!(!a.contains("<script"));
        assert!(!a.contains("http://www.w3.org/2000/svg\"></svg>"));
    }

    #[test]
    fn render_escapes_the_title() {
        let pts = sample_piecewise(0, 100, 10, &straddle_long()).unwrap();
        let svg = render_payoff_svg("<x>&\"", &pts, 320, 200);
        assert!(svg.contains("&lt;x&gt;&amp;&quot;"));
        assert!(!svg.contains("<x>&\""));
    }

    #[test]
    fn render_empty_is_honest_not_fake() {
        let svg = render_payoff_svg("none", &[], 320, 200);
        assert!(svg.contains("no payoff to render"));
        assert!(!svg.contains("<polyline"));
    }
}
