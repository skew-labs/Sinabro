//! Memory ownership operational command layer.
//!
//! The core minted the memory portability surface
//! ([`crate::commands::memory_portability`]: `MemoryExportView` /
//! `MemoryDeleteReceipt` / `MemoryReplayView` over the canonical
//! `PortableMemoryBundle` / `TombstonePolicy` / `ReplayPortabilityReport`). This layer
//! composes them into one `status / export / delete / replay` command surface that
//! holds no secret or wallet material (every field is a redacted hash, a count, or
//! an enum tag), keeps `status` off the full-replay hot path, and never resurrects
//! a deleted tombstone. This module performs no live
//! action.

pub mod commands;
