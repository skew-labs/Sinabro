//! Memory ownership operational command layer (Stage G, G-WP-05 atom #533).
//!
//! Stage F minted the memory portability surface
//! ([`crate::commands::memory_portability`]: `MemoryExportView` /
//! `MemoryDeleteReceipt` / `MemoryReplayView` over the canonical Stage B/D
//! `PortableMemoryBundle` / `TombstonePolicy` / `ReplayPortabilityReport`). Stage G
//! composes them into one `status / export / delete / replay` command surface that
//! holds no secret or wallet material (every field is a redacted hash, a count, or
//! an enum tag), keeps `status` off the full-replay hot path, and never resurrects
//! a deleted tombstone (`G-G-MEMORY-OWNERSHIP`). This module performs no live
//! action.

pub mod commands;
