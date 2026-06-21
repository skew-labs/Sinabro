//! `mnemos-e-skill::wasm_tier2::hostcalls` — atom #262 · D.1.6 — the closed,
//! versioned hostcall table.
//!
//! ## Canonical OUT (§4.2)
//!
//! - [`SkillHostcall`] — the `#[repr(u8)]` closed 6-variant set `{ReadInput=1,
//!   WriteOutput=2, ToolInvoke=3, MemoryRead=4, MemoryWrite=5, ChainDryRun=6}`.
//!   It is **closed, versioned, logged, and measured**: an unknown import name
//!   resolves to `None` and must be rejected *before* instantiation, each
//!   hostcall maps to the runtime permission it requires, and the whole table
//!   has a stable [`hostcall_table_hash`] so any drift is detectable.
//!
//! There is deliberately **no signing / wallet-key / chain-write hostcall** —
//! `ChainDryRun` is read-only, so the "signing hostcall absent" invariant holds
//! by construction (asserted in [`tests`] and relied on by
//! [`crate::wasm_tier2::secret_policy`]).

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::capability_diff::SkillRuntimePermission;
use crate::package::blake2b_256;

/// Domain tag for the hostcall-table digest (distinct per digest position).
pub(crate) const DOMAIN_HOSTCALL_TABLE: &[u8] = b"mnemos.d.hostcall_table.v1";

/// Version of the closed hostcall table. Bumped only by an intentional,
/// reviewed change to the set; folded into [`hostcall_table_hash`].
pub const HOSTCALL_TABLE_VERSION_U16: u16 = 1;

/// §4.2 closed hostcall set. `#[repr(u8)]` 1-byte discriminant (`1..=6`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum SkillHostcall {
    /// Read a declared virtual input (gated by `FileRead`).
    ReadInput = 1,
    /// Write to the capped output buffer (no permission required).
    WriteOutput = 2,
    /// Invoke a declared tool id (gated by `ToolInvoke`).
    ToolInvoke = 3,
    /// Read a memory chunk (gated by `MemoryRead`).
    MemoryRead = 4,
    /// Write a memory chunk (gated by `MemoryWrite`).
    MemoryWrite = 5,
    /// Simulate a read-only chain call (gated by `Chain`; never a write).
    ChainDryRun = 6,
}

impl SkillHostcall {
    /// The closed table in discriminant order. Iterating this is the only way
    /// to enumerate the hostcall set.
    pub const ALL: [SkillHostcall; 6] = [
        Self::ReadInput,
        Self::WriteOutput,
        Self::ToolInvoke,
        Self::MemoryRead,
        Self::MemoryWrite,
        Self::ChainDryRun,
    ];

    /// The stable WASM import name a guest must use to reach this hostcall.
    #[must_use]
    pub const fn import_name(self) -> &'static str {
        match self {
            Self::ReadInput => "mnemos_read_input",
            Self::WriteOutput => "mnemos_write_output",
            Self::ToolInvoke => "mnemos_tool_invoke",
            Self::MemoryRead => "mnemos_memory_read",
            Self::MemoryWrite => "mnemos_memory_write",
            Self::ChainDryRun => "mnemos_chain_dry_run",
        }
    }

    /// Resolve a WASM import name to a hostcall, or `None` for an unknown
    /// import — which the linker must reject *before* instantiation.
    #[must_use]
    pub fn from_import_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|h| h.import_name() == name)
    }

    /// Decode a 1-byte discriminant, or `None` for an unknown value.
    #[must_use]
    pub const fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::ReadInput),
            2 => Some(Self::WriteOutput),
            3 => Some(Self::ToolInvoke),
            4 => Some(Self::MemoryRead),
            5 => Some(Self::MemoryWrite),
            6 => Some(Self::ChainDryRun),
            _ => None,
        }
    }

    /// The runtime permission this hostcall requires, if any. `WriteOutput`
    /// needs none (it only writes the capped output buffer); the rest map to a
    /// single [`SkillRuntimePermission`]. There is no signing / wallet / secret
    /// / chain-write hostcall — `ChainDryRun` requires only `Chain` and is
    /// read-only.
    #[must_use]
    pub const fn required_permission(self) -> Option<SkillRuntimePermission> {
        match self {
            Self::ReadInput => Some(SkillRuntimePermission::FileRead),
            Self::WriteOutput => None,
            Self::ToolInvoke => Some(SkillRuntimePermission::ToolInvoke),
            Self::MemoryRead => Some(SkillRuntimePermission::MemoryRead),
            Self::MemoryWrite => Some(SkillRuntimePermission::MemoryWrite),
            Self::ChainDryRun => Some(SkillRuntimePermission::Chain),
        }
    }

    /// The trace event id (the discriminant) carried as the
    /// `mnemos_a_core::StageDTraceLink` `sandbox_event_u16` when this hostcall
    /// is logged.
    #[inline]
    #[must_use]
    pub const fn trace_event_u16(self) -> u16 {
        self as u16
    }
}

/// Stable Blake2b-256 of the versioned hostcall table: the version, the entry
/// count, then each `(discriminant, length-framed import_name)` in
/// [`SkillHostcall::ALL`] order. Any add / remove / rename / reorder of the
/// closed set moves this hash, so a hostcall-table drift is detectable.
#[must_use]
pub fn hostcall_table_hash() -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::new();
    buf.extend_from_slice(&HOSTCALL_TABLE_VERSION_U16.to_le_bytes());
    buf.extend_from_slice(&(SkillHostcall::ALL.len() as u32).to_le_bytes());
    for h in SkillHostcall::ALL {
        buf.push(h as u8);
        let name = h.import_name().as_bytes();
        buf.extend_from_slice(&(name.len() as u32).to_le_bytes());
        buf.extend_from_slice(name);
    }
    blake2b_256(&[DOMAIN_HOSTCALL_TABLE, &buf])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_import_rejects() {
        assert_eq!(SkillHostcall::from_import_name("evil_syscall"), None);
        assert_eq!(SkillHostcall::from_import_name(""), None);
        assert_eq!(SkillHostcall::from_u8(0), None);
        assert_eq!(SkillHostcall::from_u8(7), None);
    }

    #[test]
    fn allowed_hostcall_round_trips() {
        for h in SkillHostcall::ALL {
            assert_eq!(SkillHostcall::from_import_name(h.import_name()), Some(h));
            assert_eq!(SkillHostcall::from_u8(h as u8), Some(h));
        }
        assert_eq!(
            SkillHostcall::from_import_name("mnemos_read_input"),
            Some(SkillHostcall::ReadInput)
        );
    }

    #[test]
    fn permission_required_mapping() {
        assert_eq!(
            SkillHostcall::ReadInput.required_permission(),
            Some(SkillRuntimePermission::FileRead)
        );
        assert_eq!(SkillHostcall::WriteOutput.required_permission(), None);
        assert_eq!(
            SkillHostcall::ToolInvoke.required_permission(),
            Some(SkillRuntimePermission::ToolInvoke)
        );
        assert_eq!(
            SkillHostcall::ChainDryRun.required_permission(),
            Some(SkillRuntimePermission::Chain)
        );
    }

    #[test]
    fn trace_event_is_discriminant() {
        assert_eq!(SkillHostcall::ReadInput.trace_event_u16(), 1);
        assert_eq!(SkillHostcall::MemoryRead.trace_event_u16(), 4);
        assert_eq!(SkillHostcall::ChainDryRun.trace_event_u16(), 6);
    }

    #[test]
    fn table_hash_is_stable() {
        assert_eq!(hostcall_table_hash(), hostcall_table_hash());
    }

    #[test]
    fn no_signing_or_chain_write_hostcall_exists() {
        for h in SkillHostcall::ALL {
            let name = h.import_name();
            assert!(
                !name.contains("sign"),
                "{name} must not be a signing hostcall"
            );
            assert!(!name.contains("submit"), "{name} must not submit");
            assert!(!name.contains("publish"), "{name} must not publish");
            assert!(
                !name.contains("write")
                    || h == SkillHostcall::WriteOutput
                    || h == SkillHostcall::MemoryWrite,
                "{name}: only output/memory writes exist, never a chain/file write"
            );
        }
    }
}
