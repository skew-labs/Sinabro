//! Deterministic, read-only sidecar discovery scanner.
//!
//! Walks `<training-root>/<stage>/{atom_###,wp_*}/`, refusing symlink escape and
//! path traversal. A missing stage directory is not an error (the stage simply
//! has no corpus yet) — it yields an empty list. Results are sorted so the same
//! tree always produces the same record order.
use crate::diet_kind::{DietFileKind, DietSourceStage};
use crate::error::{DietError, DietResult};
use std::path::{Path, PathBuf};

/// A discovered source-atom (or WorkPackage) directory and its present sidecar
/// files. `present` is sorted by file-kind discriminant for determinism.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveredAtom {
    /// Source stage the directory belongs to.
    pub source: DietSourceStage,
    /// Atom number (legacy `atom_###`), or `0` for a compressed `wp_*` package.
    pub atom_u16: u16,
    /// `true` if the directory is a compressed WorkPackage (`wp_*`).
    pub is_workpackage: bool,
    /// Absolute path to the directory.
    pub dir: PathBuf,
    /// Recognized sidecar files present, sorted by kind.
    pub present: Vec<(DietFileKind, PathBuf)>,
    /// Count of files in the directory that are not one of the 21 kinds.
    pub unknown_count: u32,
}

impl DiscoveredAtom {
    /// The distinct recognized kinds present, deduplicated, in canonical order.
    pub fn present_kinds(&self) -> Vec<DietFileKind> {
        let mut seen = 0u32;
        let mut out = Vec::new();
        for (k, _) in &self.present {
            let bit = 1u32 << (k.as_u8() - 1);
            if seen & bit == 0 {
                seen |= bit;
                out.push(*k);
            }
        }
        out.sort_by_key(|k| k.as_u8());
        out
    }
}

fn parse_atom_dir(name: &str) -> Option<(u16, bool)> {
    if let Some(rest) = name.strip_prefix("atom_") {
        rest.parse::<u16>().ok().map(|n| (n, false))
    } else if name.starts_with("wp_") {
        Some((0, true))
    } else {
        None
    }
}

fn reject_symlink(path: &Path) -> DietResult<()> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| DietError::DiscoveryIo)?;
    if meta.file_type().is_symlink() {
        return Err(DietError::SymlinkEscape);
    }
    Ok(())
}

fn check_name(name: &str) -> DietResult<()> {
    if name.contains("..") || name.contains('/') || name.contains('\0') {
        return Err(DietError::PathTraversal);
    }
    Ok(())
}

/// Scan one stage directory under `training_root`.
pub fn discover_stage(
    training_root: &Path,
    source: DietSourceStage,
) -> DietResult<Vec<DiscoveredAtom>> {
    let stage_dir = training_root.join(source.dir_name());
    if !stage_dir.exists() {
        return Ok(Vec::new());
    }
    let mut atoms = Vec::new();
    let entries = std::fs::read_dir(&stage_dir).map_err(|_| DietError::DiscoveryIo)?;
    for entry in entries {
        let entry = entry.map_err(|_| DietError::DiscoveryIo)?;
        let name_os = entry.file_name();
        let name = name_os.to_str().ok_or(DietError::PathTraversal)?;
        check_name(name)?;
        let dir_path = entry.path();
        reject_symlink(&dir_path)?;
        let file_type = entry.file_type().map_err(|_| DietError::DiscoveryIo)?;
        if !file_type.is_dir() {
            continue;
        }
        let (atom_u16, is_workpackage) = match parse_atom_dir(name) {
            Some(v) => v,
            None => continue,
        };
        let (present, unknown_count) = scan_atom_dir(&dir_path)?;
        atoms.push(DiscoveredAtom {
            source,
            atom_u16,
            is_workpackage,
            dir: dir_path,
            present,
            unknown_count,
        });
    }
    atoms.sort_by(|a, b| a.atom_u16.cmp(&b.atom_u16).then_with(|| a.dir.cmp(&b.dir)));
    Ok(atoms)
}

fn scan_atom_dir(dir: &Path) -> DietResult<(Vec<(DietFileKind, PathBuf)>, u32)> {
    let mut present = Vec::new();
    let mut unknown_count = 0u32;
    let entries = std::fs::read_dir(dir).map_err(|_| DietError::DiscoveryIo)?;
    for entry in entries {
        let entry = entry.map_err(|_| DietError::DiscoveryIo)?;
        let path = entry.path();
        reject_symlink(&path)?;
        let file_type = entry.file_type().map_err(|_| DietError::DiscoveryIo)?;
        if !file_type.is_file() {
            continue;
        }
        let name_os = entry.file_name();
        match name_os.to_str().and_then(DietFileKind::from_file_name) {
            Some(kind) => present.push((kind, path)),
            None => unknown_count = unknown_count.saturating_add(1),
        }
    }
    present.sort_by_key(|(k, _)| k.as_u8());
    Ok((present, unknown_count))
}

/// Scan every known stage under `training_root`, concatenated in stage order.
pub fn discover_all(training_root: &Path) -> DietResult<Vec<DiscoveredAtom>> {
    let mut all = Vec::new();
    for source in DietSourceStage::ALL {
        all.extend(discover_stage(training_root, source)?);
    }
    Ok(all)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fresh(label: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("mnemos_ld_discover_{label}"));
        let _ = fs::remove_dir_all(&base);
        base
    }

    fn write_sidecar(dir: &Path, name: &str) -> std::io::Result<()> {
        fs::create_dir_all(dir)?;
        fs::write(dir.join(name), b"{}\n")
    }

    #[test]
    fn discovers_atom_and_wp_dirs_sorted() -> Result<(), Box<dyn std::error::Error>> {
        let root = fresh("disc1");
        let phase0 = root.join("phase_0");
        write_sidecar(&phase0.join("atom_002"), "env_lock.json")?;
        write_sidecar(&phase0.join("atom_001"), "command_manifest.json")?;
        fs::write(phase0.join("atom_001").join("stray_note.txt"), b"x")?;
        write_sidecar(
            &root.join("stage_d").join("wp_D_WP_01A"),
            "privacy_report.json",
        )?;

        let p0 = discover_stage(&root, DietSourceStage::Phase0)?;
        assert_eq!(p0.len(), 2);
        assert_eq!(p0[0].atom_u16, 1);
        assert_eq!(p0[1].atom_u16, 2);
        assert_eq!(p0[0].unknown_count, 1);
        assert_eq!(p0[0].present_kinds(), vec![DietFileKind::CommandManifest]);

        let sd = discover_stage(&root, DietSourceStage::StageD)?;
        assert_eq!(sd.len(), 1);
        assert!(sd[0].is_workpackage);
        assert_eq!(sd[0].atom_u16, 0);

        let _ = fs::remove_dir_all(&root);
        Ok(())
    }

    #[test]
    fn missing_stage_dir_is_empty_not_error() -> DietResult<()> {
        let root = std::env::temp_dir().join("mnemos_ld_discover_absent_xyz");
        let _ = std::fs::remove_dir_all(&root);
        assert!(discover_stage(&root, DietSourceStage::StageC)?.is_empty());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn symlink_in_atom_dir_rejects() -> Result<(), Box<dyn std::error::Error>> {
        let root = fresh("disc_sym");
        let atom = root.join("phase_0").join("atom_003");
        write_sidecar(&atom, "env_lock.json")?;
        std::os::unix::fs::symlink(atom.join("env_lock.json"), atom.join("input_context.jsonl"))?;
        assert!(matches!(
            discover_stage(&root, DietSourceStage::Phase0),
            Err(DietError::SymlinkEscape)
        ));
        let _ = fs::remove_dir_all(&root);
        Ok(())
    }
}
