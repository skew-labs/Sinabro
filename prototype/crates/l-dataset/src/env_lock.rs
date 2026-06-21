//! `env_lock.json` parser → per-component environment hashes (atom #339 ·
//! E.0.8, §4.2 `EnvLock`).
//!
//! OS / Rust / Sui / GPU / deps are hashed *separately* so infrastructure drift
//! (a Rust bump, an absent GPU) can be tracked without masking or erasing a
//! model fault. A string descriptor is hashed verbatim; a nested object (e.g.
//! `rust: {rustc, cargo}`) is hashed as canonical JSON so either sub-field's
//! drift flips the hash; an absent component hashes the `"none"` sentinel.
use crate::diet_kind::DietFileKind;
use crate::error::DietResult;
use crate::parse_json;
use serde_json::Value;

const KIND: DietFileKind = DietFileKind::EnvLock;
const ABSENT: &str = "none";

/// Per-component environment hashes (§4.2 `EnvLock`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct EnvLock {
    /// `sha256` of the OS descriptor.
    pub os_hash_32: [u8; 32],
    /// `sha256` of the Rust toolchain descriptor.
    pub rust_hash_32: [u8; 32],
    /// `sha256` of the Sui toolchain descriptor.
    pub sui_hash_32: [u8; 32],
    /// `sha256` of the GPU descriptor (`"none"` when absent).
    pub gpu_hash_32: [u8; 32],
    /// `sha256` of the dependency/build-flags descriptor.
    pub deps_hash_32: [u8; 32],
}

fn dig<'a>(root: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cur = root;
    for key in path {
        cur = cur.as_object()?.get(*key)?;
    }
    Some(cur)
}

/// First descriptor found among candidate dotted paths, else `"none"`. A string
/// is used verbatim; any other value is rendered as canonical JSON.
fn descriptor(root: &Value, candidates: &[&[&str]]) -> String {
    for path in candidates {
        if let Some(v) = dig(root, path) {
            if v.is_null() {
                continue;
            }
            return match v.as_str() {
                Some(s) => s.to_string(),
                None => v.to_string(),
            };
        }
    }
    ABSENT.to_string()
}

/// Parse `env_lock.json` into the five per-component hashes.
pub fn parse(text: &str) -> DietResult<EnvLock> {
    let v = parse_json(KIND, text)?;
    let os = descriptor(&v, &[&["host", "os"], &["os"]]);
    let rust = descriptor(&v, &[&["rust"], &["rustc"]]);
    let sui = descriptor(&v, &[&["tooling_available", "sui"], &["sui"]]);
    let gpu = descriptor(
        &v,
        &[&["tooling_available", "gpu"], &["gpu"], &["host", "gpu"]],
    );
    let deps = descriptor(
        &v,
        &[
            &["deps"],
            &["deps_hash"],
            &["cargo_lock_hash"],
            &["build_flags"],
        ],
    );
    Ok(EnvLock {
        os_hash_32: crate::sha256(os.as_bytes()),
        rust_hash_32: crate::sha256(rust.as_bytes()),
        sui_hash_32: crate::sha256(sui.as_bytes()),
        gpu_hash_32: crate::sha256(gpu.as_bytes()),
        deps_hash_32: crate::sha256(deps.as_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gpu_absent_hashes_none_sentinel() -> DietResult<()> {
        let e = parse(r#"{"host":{"os":"macOS Darwin 25.5.0 arm64"},"rust":{"rustc":"1.94.1"}}"#)?;
        assert_eq!(e.gpu_hash_32, crate::sha256(b"none"));
        Ok(())
    }

    #[test]
    fn rust_version_drift_changes_hash() -> DietResult<()> {
        let a = parse(r#"{"rust":{"rustc":"1.94.1","cargo":"1.94.1"}}"#)?;
        let b = parse(r#"{"rust":{"rustc":"1.95.0","cargo":"1.94.1"}}"#)?;
        assert_ne!(a.rust_hash_32, b.rust_hash_32);
        Ok(())
    }

    #[test]
    fn sui_version_drift_changes_hash() -> DietResult<()> {
        let a = parse(r#"{"tooling_available":{"sui":"present (1.72.1-homebrew)"}}"#)?;
        let b = parse(r#"{"tooling_available":{"sui":"present (1.73.0-homebrew)"}}"#)?;
        assert_ne!(a.sui_hash_32, b.sui_hash_32);
        Ok(())
    }

    #[test]
    fn deps_hash_is_deterministic() -> DietResult<()> {
        let a = parse(r#"{"build_flags":"--locked --offline --workspace"}"#)?;
        let b = parse(r#"{"build_flags":"--locked --offline --workspace"}"#)?;
        assert_eq!(a.deps_hash_32, b.deps_hash_32);
        assert_ne!(a.deps_hash_32, crate::sha256(b"none"));
        Ok(())
    }
}
