//! Walrus BCS / blob-id signal (atom #360 · E.1.9, §4.4 `WalrusSignal`).
//!
//! A reported blob id is never a signal unless a *local derive verify* passed in
//! the source evidence — modelled here as the `G-WALRUS-BLOBID-LOCAL` gate (the
//! in-process oracle == CLI == walrus-core parity check). A self-reported blob
//! id with no local-verify gate yields `blob_verify_pass = false`. BCS roundtrip
//! correctness is the `G-WALRUS-BCS` gate; a noncanonical encoding fails it.
use crate::collect::gate_pass;
use crate::diet_kind::AtomDietKey;
use crate::error::DietResult;
use crate::gate_results::parse_gates;

/// Walrus BCS / blob-id signal (§4.4 `WalrusSignal`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct WalrusSignal {
    /// The source atom.
    pub key: AtomDietKey,
    /// `G-WALRUS-BCS` was an explicit pass (canonical BCS roundtrip).
    pub bcs_pass: bool,
    /// A *local* blob-id derive verify passed (`G-WALRUS-BLOBID-LOCAL`); a bare
    /// self-reported blob id does not set this.
    pub blob_verify_pass: bool,
    /// Roundtrip anchor: the local-verify gate's command hash, else `"none"`.
    pub roundtrip_hash_32: [u8; 32],
}

/// Collect a [`WalrusSignal`] from a `gate_results.json` document.
pub fn collect(key: AtomDietKey, gate_results_json: &str) -> DietResult<WalrusSignal> {
    let gates = parse_gates(gate_results_json)?;
    let id = crate::sha256(b"G-WALRUS-BLOBID-LOCAL");
    let roundtrip_hash_32 = gates
        .iter()
        .find(|g| g.gate_id_hash_32 == id)
        .and_then(|g| g.command_hash_32)
        .unwrap_or_else(|| crate::sha256(b"none"));
    Ok(WalrusSignal {
        key,
        bcs_pass: gate_pass(&gates, "G-WALRUS-BCS"),
        blob_verify_pass: gate_pass(&gates, "G-WALRUS-BLOBID-LOCAL"),
        roundtrip_hash_32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diet_kind::DietSourceStage;

    fn key() -> AtomDietKey {
        AtomDietKey::new(DietSourceStage::StageB, 360)
    }

    #[test]
    fn locally_verified_blob_sets_verify_pass() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-WALRUS-BCS","G-WALRUS-BLOBID-LOCAL"],"G-WALRUS-BCS":{"status":"PASS"},"G-WALRUS-BLOBID-LOCAL":{"status":"PASS","tool":"walrus-core derive == cli"}}"#;
        let s = collect(key(), gates)?;
        assert!(s.bcs_pass);
        assert!(s.blob_verify_pass);
        assert_ne!(s.roundtrip_hash_32, crate::sha256(b"none"));
        Ok(())
    }

    #[test]
    fn self_report_only_blob_is_not_verified() -> DietResult<()> {
        // a self-reported blob id (a different, non-local gate) does not verify.
        let gates = r#"{"gate_set":["G-WALRUS-BLOBID-SELFREPORT"],"G-WALRUS-BLOBID-SELFREPORT":{"status":"PASS"}}"#;
        let s = collect(key(), gates)?;
        assert!(!s.blob_verify_pass);
        assert_eq!(s.roundtrip_hash_32, crate::sha256(b"none"));
        Ok(())
    }

    #[test]
    fn bcs_roundtrip_pass() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-WALRUS-BCS"],"G-WALRUS-BCS":{"status":"PASS"}}"#;
        assert!(collect(key(), gates)?.bcs_pass);
        Ok(())
    }

    #[test]
    fn noncanonical_bcs_rejects() -> DietResult<()> {
        let gates = r#"{"gate_set":["G-WALRUS-BCS"],"G-WALRUS-BCS":{"status":"FAIL"}}"#;
        assert!(!collect(key(), gates)?.bcs_pass);
        Ok(())
    }
}
