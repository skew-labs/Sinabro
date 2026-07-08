//! Skill recommend operational layer.
//!
//! An earlier stage minted the skill registry / trust surface (the canonical
//! `SkillCardView` listing card, the `OfficialTrustDecision` trust verdict, and the
//! `SkillUseLaunch` install flow — all no-commerce). This layer adds the recommend /
//! inspect / use-install dry-run surface: it lists id / installs / capability /
//! eval / provenance / trust, never ranks a quarantined or insecure card above a
//! healthy one, and opens no buy / sell / checkout / revenue / refund path; an
//! install requires an explicit approval and a sandbox tier. This module performs
//! no live action.

pub mod recommend;
