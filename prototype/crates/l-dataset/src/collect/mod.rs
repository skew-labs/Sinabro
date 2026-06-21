//! Read-only signal-collector orchestration (atom #351 · E.1.0).
//!
//! Cluster 2 of Stage E turns the validated 21-file A-D sidecar into typed
//! *signal facts*: did fmt/clippy/test pass, did the Move build/prover succeed,
//! was a blob id locally verified, did a secret leak. Every collector in this
//! module tree is **read-only**: it borrows already-read sidecar text, or reads
//! a discovered file through [`read_present`] (which refuses to follow a symlink
//! — an attempted-writer / escape vector — and never opens a file for writing).
//! No collector runs a live network call, charges payment, signs a transaction,
//! or trains a model; those surfaces do not exist in the API.
//!
//! Collectors emit *facts and reward preconditions only*. Stream routing into
//! S1/S2 records is `stream_split` (#367); the scalar layered reward is E-WP-04
//! (#386+). A collector never grants a positive reward.
use crate::diet_kind::DietFileKind;
use crate::discover::DiscoveredAtom;
use crate::error::{DietError, DietResult};
use crate::gate_results::{GateOutcome, GateStatus};

pub mod audit_repo_pair;
pub mod dependency;
pub mod gas;
pub mod gas_station;
pub mod memory;
pub mod move_basic;
pub mod move_prover;
pub mod perf;
pub mod rust_basic;
pub mod rust_deep;
pub mod secrets;
pub mod skill_registry;
pub mod walrus_blob;
pub mod walrus_roundtrip;

/// The fixed set of signal collectors in Cluster 2, in deterministic run order.
/// The order is part of the contract: two runs over the same corpus emit signals
/// in the same sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CollectorKind {
    /// Rust fmt/clippy/test basic signal (#352).
    RustBasic = 1,
    /// Rust miri/fuzz/property deep signal (#353).
    RustDeep = 2,
    /// criterion/perf/allocation signal (#354).
    Perf = 3,
    /// dependency/security audit signal (#355).
    Dependency = 4,
    /// Move build/test signal (#356).
    MoveBasic = 5,
    /// Move Prover/spec signal (#357).
    MoveProver = 6,
    /// Move gas trace signal (#358).
    Gas = 7,
    /// Sui effect-shape / Gas Station signal (#359).
    GasStation = 8,
    /// Walrus BCS/blob-id signal (#360).
    WalrusBlob = 9,
    /// Walrus PUT/GET roundtrip signal (#361).
    WalrusRoundtrip = 10,
    /// wallet/secret/key isolation signal (#362).
    Secrets = 11,
    /// skill / WASM / registry signal (#363).
    SkillRegistry = 12,
    /// memory intelligence / replay signal (#364).
    Memory = 13,
    /// audit-log to repo pairing (#365).
    AuditRepoPair = 14,
}

impl CollectorKind {
    /// All collectors in deterministic run order (#352 … #365).
    pub const ALL: [CollectorKind; 14] = [
        Self::RustBasic,
        Self::RustDeep,
        Self::Perf,
        Self::Dependency,
        Self::MoveBasic,
        Self::MoveProver,
        Self::Gas,
        Self::GasStation,
        Self::WalrusBlob,
        Self::WalrusRoundtrip,
        Self::Secrets,
        Self::SkillRegistry,
        Self::Memory,
        Self::AuditRepoPair,
    ];

    /// Numeric discriminant (`1..=14`).
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Read one present sidecar file of `kind` from a discovered atom directory,
/// read-only. Returns `Ok(None)` when the kind is absent (a fact, not an error).
/// Refuses to follow a symlink (an attempted-writer / escape vector) with
/// [`DietError::SymlinkEscape`], and maps any read failure to a redacted
/// [`DietError::IoUntrusted`].
pub fn read_present(discovered: &DiscoveredAtom, kind: DietFileKind) -> DietResult<Option<String>> {
    for (k, path) in &discovered.present {
        if *k == kind {
            let meta =
                std::fs::symlink_metadata(path).map_err(|_| DietError::IoUntrusted { kind })?;
            if meta.file_type().is_symlink() {
                return Err(DietError::SymlinkEscape);
            }
            let text =
                std::fs::read_to_string(path).map_err(|_| DietError::IoUntrusted { kind })?;
            return Ok(Some(text));
        }
    }
    Ok(None)
}

/// The explicit status of a named gate, [`GateStatus::Unknown`] when absent
/// (never silently green). Gates are matched by `sha256(name)`, mirroring the
/// gate parser's id hashing.
pub fn gate_status(gates: &[GateOutcome], name: &str) -> GateStatus {
    let id = crate::sha256(name.as_bytes());
    gates
        .iter()
        .find(|g| g.gate_id_hash_32 == id)
        .map_or(GateStatus::Unknown, |g| g.status)
}

/// Whether a named gate is an explicit `PASS`. Fail-closed: absent / unknown /
/// any non-pass status yields `false`.
pub fn gate_pass(gates: &[GateOutcome], name: &str) -> bool {
    matches!(gate_status(gates, name), GateStatus::Pass)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;
    use crate::gate_results::parse_gates;
    use std::path::PathBuf;

    fn discovered_with(present: Vec<(DietFileKind, PathBuf)>, dir: PathBuf) -> DiscoveredAtom {
        DiscoveredAtom {
            source: DietSourceStage::Phase0,
            atom_u16: 7,
            is_workpackage: false,
            dir,
            present,
            unknown_count: 0,
        }
    }

    #[test]
    fn collector_order_is_deterministic_and_dense() {
        assert_eq!(CollectorKind::ALL.len(), 14);
        for (i, c) in CollectorKind::ALL.into_iter().enumerate() {
            assert_eq!(c.as_u8(), (i + 1) as u8);
        }
        // First and last are stable contract anchors.
        assert_eq!(CollectorKind::ALL[0], CollectorKind::RustBasic);
        assert_eq!(CollectorKind::ALL[13], CollectorKind::AuditRepoPair);
    }

    #[test]
    fn read_present_is_read_only_and_absent_is_none() -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;
        let root = std::env::temp_dir().join("mnemos_ld_collect_ro");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let path = root.join("env_lock.json");
        let content = b"{\"host\":{\"os\":\"x\"}}\n";
        fs::write(&path, content)?;
        let discovered = discovered_with(vec![(DietFileKind::EnvLock, path.clone())], root.clone());

        let before = fs::read(&path)?;
        let files_before = fs::read_dir(&root)?.count();
        let got = read_present(&discovered, DietFileKind::EnvLock)?;
        assert_eq!(got.as_deref(), Some("{\"host\":{\"os\":\"x\"}}\n"));
        // Reading did not create, modify, or delete anything.
        assert_eq!(fs::read(&path)?, before);
        assert_eq!(fs::read_dir(&root)?.count(), files_before);
        // An absent kind is a fact, not an error.
        assert!(read_present(&discovered, DietFileKind::CommandManifest)?.is_none());

        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn attempted_writer_symlink_is_denied() -> Result<(), Box<dyn std::error::Error>> {
        use std::fs;
        let root = std::env::temp_dir().join("mnemos_ld_collect_sym");
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root)?;
        let real = root.join("real.json");
        fs::write(&real, b"{}\n")?;
        let link = root.join("gate_results.json");
        std::os::unix::fs::symlink(&real, &link)?;
        let discovered = discovered_with(vec![(DietFileKind::GateResults, link)], root.clone());
        assert!(matches!(
            read_present(&discovered, DietFileKind::GateResults),
            Err(DietError::SymlinkEscape)
        ));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn gate_status_and_pass_are_fail_closed() -> DietResult<()> {
        let doc = r#"{"gate_set":["G-FMT","G-CLIPPY"],"G-FMT":{"status":"PASS"},"G-CLIPPY":{"status":"FAIL"}}"#;
        let gates = parse_gates(doc)?;
        assert!(gate_pass(&gates, "G-FMT"));
        assert!(!gate_pass(&gates, "G-CLIPPY"));
        // A gate that was never listed is Unknown, never green.
        assert_eq!(gate_status(&gates, "G-NEVER"), GateStatus::Unknown);
        assert!(!gate_pass(&gates, "G-NEVER"));
        Ok(())
    }
}
