//! Evidence pack + replay operational layer (Stage G, G-WP-05 atoms #531–#532).
//!
//! Stage F minted the evidence command surface ([`crate::commands::evidence`]:
//! `EvidencePackView` / `EvidenceReplayView` over the canonical Stage E
//! [`mnemos_l_dataset::export::shard::EvidenceLakeReceipt`] and Stage B
//! `EvidenceBundleManifestV1`). Stage G groups the per-task/session evidence kinds
//! (provider consult, audit candidate, memory replay, Telegram event, command
//! trace, gate result, local repro receipt) into one stable-hashed
//! [`pack_manifest::EvidencePackManifest`], and explains a pack offline via
//! [`replay::EvidenceReplayDryRun`] — never re-running a live provider / tool /
//! wallet / gas side effect. Every type here is a pure local projection holding no
//! secret; no model weight training happens in Stage G.

pub mod pack_manifest;
pub mod replay;
