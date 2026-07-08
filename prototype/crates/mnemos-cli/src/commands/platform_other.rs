//! `sinabro platform slack|discord` — Slack / Discord future-adapter controls.
//!
//! This surface exposes an honest *disabled / preview* state for the Slack and
//! Discord adapters; it never pretends they are generally available and never
//! fakes a successful bind. The only available state is
//! [`PlatformAvailability::DisabledPreview`], whose render truth is the explicit
//! [`RenderTruth::Unknown`] (never a false `Green`), and
//! [`OtherPlatformView::try_bind`] always refuses. The real adapters are
//! deferred to a future release.
//!
//! Reuse: the red/yellow/green/unknown verdict is the cockpit
//! [`crate::tui::RenderTruth`]; the adapter set + bind/availability semantics are
//! concept-only for now. This module performs no live action.

use crate::tui::RenderTruth;

/// A future chat-platform adapter. Both are disabled previews.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OtherPlatform {
    /// Slack adapter (future).
    Slack = 1,
    /// Discord adapter (future).
    Discord = 2,
}

impl OtherPlatform {
    /// Both future platforms, in discriminant order.
    pub const ALL: [OtherPlatform; 2] = [OtherPlatform::Slack, OtherPlatform::Discord];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The lowercase platform label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            OtherPlatform::Slack => "slack",
            OtherPlatform::Discord => "discord",
        }
    }
}

/// The current availability of a future adapter. This surface only ever produces
/// [`Self::DisabledPreview`]; [`Self::GenerallyAvailable`] exists so the type can
/// *describe* a future state, but it is never constructed here (no false GA).
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlatformAvailability {
    /// Disabled, preview-only — the current state.
    DisabledPreview = 1,
    /// Generally available — a future state, never reached here.
    GenerallyAvailable = 2,
}

impl PlatformAvailability {
    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Why a Slack / Discord control was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PlatformOtherReject {
    /// The adapter is a disabled preview; it is not generally available.
    #[error("platform not generally available (disabled preview)")]
    NotGenerallyAvailable,
}

/// A read-only view of a future adapter's current posture. The feature flag is
/// off, availability is a disabled preview, and a bind attempt always fails — so
/// the UI can show the adapter exists without pretending it works.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OtherPlatformView {
    /// Which future platform this view describes.
    pub platform: OtherPlatform,
    /// Whether the future feature flag is enabled. Always `false`.
    pub feature_flag_enabled: bool,
    /// The current availability — always [`PlatformAvailability::DisabledPreview`].
    pub availability: PlatformAvailability,
}

impl OtherPlatformView {
    /// The view for `platform`: feature flag off, disabled preview.
    #[must_use]
    pub const fn preview(platform: OtherPlatform) -> Self {
        Self {
            platform,
            feature_flag_enabled: false,
            availability: PlatformAvailability::DisabledPreview,
        }
    }

    /// Whether the adapter is generally available. Always `false`.
    #[must_use]
    pub const fn is_generally_available(&self) -> bool {
        matches!(self.availability, PlatformAvailability::GenerallyAvailable)
    }

    /// Attempt to bind the adapter. Always refuses — there is no fake
    /// successful bind.
    pub fn try_bind(&self) -> Result<(), PlatformOtherReject> {
        Err(PlatformOtherReject::NotGenerallyAvailable)
    }

    /// The render truth. A disabled preview is the explicit
    /// [`RenderTruth::Unknown`] — never a false `Green`.
    #[must_use]
    pub fn render_truth(&self) -> RenderTruth {
        match self.availability {
            PlatformAvailability::DisabledPreview => RenderTruth::Unknown,
            PlatformAvailability::GenerallyAvailable => RenderTruth::Green,
        }
    }

    /// A stable, colorless docs snapshot line describing the current posture.
    #[must_use]
    pub fn docs_snapshot(&self) -> String {
        format!(
            "platform={} availability=disabled_preview feature_flag=off ga=false bind=refused",
            self.platform.label()
        )
    }

    /// Redacted, colorless status lines bounded by `rows`.
    #[must_use]
    pub fn render(&self, rows: u16) -> Vec<String> {
        let lines = vec![
            format!("platform_u8={}", self.platform.as_u8()),
            format!("feature_flag_enabled={}", self.feature_flag_enabled),
            format!("availability_u8={}", self.availability.as_u8()),
            format!("generally_available={}", self.is_generally_available()),
            format!("truth_u8={}", self.render_truth() as u8),
        ];
        lines.into_iter().take(rows as usize).collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    #[test]
    fn slack_and_discord_are_disabled_preview() {
        for p in OtherPlatform::ALL {
            let v = OtherPlatformView::preview(p);
            assert_eq!(v.availability, PlatformAvailability::DisabledPreview);
            assert!(!v.is_generally_available());
        }
    }

    #[test]
    fn feature_flag_is_off_in_stage_f() {
        let v = OtherPlatformView::preview(OtherPlatform::Slack);
        assert!(!v.feature_flag_enabled);
    }

    #[test]
    fn disabled_preview_never_renders_green_and_no_fake_bind() {
        let v = OtherPlatformView::preview(OtherPlatform::Discord);
        // No false green — a disabled preview is the explicit `Unknown`.
        assert_eq!(v.render_truth(), RenderTruth::Unknown);
        assert!(!v.render_truth().is_healthy());
        // No fake successful bind.
        assert_eq!(
            v.try_bind(),
            Err(PlatformOtherReject::NotGenerallyAvailable)
        );
    }

    #[test]
    fn docs_snapshot_is_stable_and_truthful() {
        let slack = OtherPlatformView::preview(OtherPlatform::Slack);
        assert_eq!(
            slack.docs_snapshot(),
            "platform=slack availability=disabled_preview feature_flag=off ga=false bind=refused"
        );
        let discord = OtherPlatformView::preview(OtherPlatform::Discord);
        assert_eq!(
            discord.docs_snapshot(),
            "platform=discord availability=disabled_preview feature_flag=off ga=false bind=refused"
        );
        // Render is bounded and shows no false green (truth_u8=4 == Unknown).
        assert!(discord.render(2).len() <= 2);
        assert!(discord.render(64).iter().any(|l| l == "truth_u8=4"));
    }
}
