//! Streaming artifact hash verification (atom #337 · E.0.6).
//!
//! Hashes are immutable: a moved or rewritten evidence file invalidates the
//! downstream sample. Large logs/diffs are hashed in a bounded 8 KiB window
//! (see [`crate::sha256_reader`]) so a 10 MB artifact never materializes in RAM.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::manifest::DietFileRef;
use crate::{hex32_decode, sha256, sha256_reader};
use std::path::Path;

/// `sha256` of a path string — the content-addressed *provenance of where* a
/// file lives. A moved file changes this even if its bytes are identical, so a
/// reference is valid only when both the content hash and the path hash agree.
pub fn path_hash_str(path_str: &str) -> [u8; 32] {
    sha256(path_str.as_bytes())
}

/// [`path_hash_str`] over a real path (lossless for ASCII build paths).
pub fn path_hash(path: &Path) -> [u8; 32] {
    path_hash_str(&path.to_string_lossy())
}

/// Hash a file's content in bounded memory and return `(content_hash, bytes)`.
pub fn hash_file(kind: DietFileKind, path: &Path) -> DietResult<([u8; 32], u64)> {
    let file = std::fs::File::open(path).map_err(|_| DietError::IoUntrusted { kind })?;
    let bytes = file
        .metadata()
        .map_err(|_| DietError::IoUntrusted { kind })?
        .len();
    let hash = sha256_reader(std::io::BufReader::new(file))
        .map_err(|_| DietError::IoUntrusted { kind })?;
    Ok((hash, bytes))
}

/// Build a [`DietFileRef`] from a file on disk (content + path hash + size).
pub fn ref_from_disk(kind: DietFileKind, path: &Path) -> DietResult<DietFileRef> {
    let (content_hash, bytes) = hash_file(kind, path)?;
    Ok(DietFileRef::new(kind, path_hash(path), content_hash, bytes))
}

/// Verify a stored [`DietFileRef`] against the file currently at `path`. Any
/// content, path, or size drift is a hard [`DietError::HashMismatch`].
pub fn verify_ref(reference: &DietFileRef, path: &Path) -> DietResult<()> {
    let (content_hash, bytes) = hash_file(reference.kind, path)?;
    if content_hash != reference.content_hash_32
        || path_hash(path) != reference.path_hash_32
        || bytes != reference.bytes_u64
    {
        return Err(DietError::HashMismatch {
            kind: reference.kind,
        });
    }
    Ok(())
}

/// Parse a stored 64-hex artifact hash, rejecting an empty string up front.
pub fn parse_stored_hash(kind: DietFileKind, hex: &str) -> DietResult<[u8; 32]> {
    if hex.is_empty() {
        return Err(DietError::EmptyHash { kind });
    }
    hex32_decode(hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn tmp_file(label: &str, content: &[u8]) -> std::io::Result<PathBuf> {
        let dir = std::env::temp_dir().join("mnemos_ld_artifacts");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{label}.bin"));
        fs::write(&path, content)?;
        Ok(path)
    }

    #[test]
    fn ref_from_disk_then_verify_round_trips() -> Result<(), Box<dyn std::error::Error>> {
        let path = tmp_file("rt", b"hello stage e")?;
        let r = ref_from_disk(DietFileKind::EnvLock, &path)?;
        assert_eq!(r.bytes_u64, 13);
        assert_eq!(r.content_hash_32, sha256(b"hello stage e"));
        verify_ref(&r, &path)?;
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn content_drift_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let path = tmp_file("drift", b"original")?;
        let r = ref_from_disk(DietFileKind::CommandManifest, &path)?;
        fs::write(&path, b"tampered!")?;
        assert!(matches!(
            verify_ref(&r, &path),
            Err(DietError::HashMismatch { .. })
        ));
        let _ = fs::remove_file(&path);
        Ok(())
    }

    #[test]
    fn missing_file_is_io_untrusted() {
        let path = std::env::temp_dir().join("mnemos_ld_artifacts_absent_zzz.bin");
        let _ = std::fs::remove_file(&path);
        assert!(matches!(
            hash_file(DietFileKind::PrivacyReport, &path),
            Err(DietError::IoUntrusted {
                kind: DietFileKind::PrivacyReport
            })
        ));
    }

    #[test]
    fn empty_hash_string_rejects() {
        assert!(matches!(
            parse_stored_hash(DietFileKind::CodeDiff, ""),
            Err(DietError::EmptyHash {
                kind: DietFileKind::CodeDiff
            })
        ));
    }

    #[test]
    fn path_hash_distinguishes_paths() {
        assert_ne!(
            path_hash_str("/a/env_lock.json"),
            path_hash_str("/b/env_lock.json")
        );
        assert_eq!(path_hash_str("/a/x"), path_hash_str("/a/x"));
    }
}
