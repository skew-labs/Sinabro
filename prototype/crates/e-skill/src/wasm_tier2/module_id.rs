//! [`WasmTier2ModuleId`], the content address of a sandbox module.
//!
//! ## Content address
//!
//! - [`WasmTier2ModuleId`] — `#[repr(transparent)]` 32-byte Blake2b-256 of the
//!   *canonical module bytes* under a distinct domain tag. The id is derived
//!   from the bytes alone — never from a package name, download URL, or author
//!   claim — so two byte-identical modules map to one id and any byte mutation
//!   moves the id. It is a sibling of [`crate::package::SkillPackageDigest32`]
//!   and reuses the same crate-internal [`crate::package::blake2b_256`] spine.
//!
//! ## Structural validation, never execution
//!
//! [`WasmTier2ModuleId::from_wasm_bytes`] first runs a minimal **offline**
//! structural check ([`validate_wasm_structure`]) — the `\0asm` magic, the
//! supported binary-format version, and a section-length walk that confirms no
//! declared section runs past the end of the input. It never instantiates or
//! executes the module (this cluster ships no WASM engine); it only rejects byte
//! strings that are not well-formed WASM so a non-module blob cannot acquire a
//! module id.

#![deny(missing_docs)]

extern crate alloc;

use alloc::vec::Vec;

use crate::package::blake2b_256;

/// Domain tag for the module-id content digest (distinct per digest position).
pub(crate) const DOMAIN_MODULE_ID: &[u8] = b"mnemos.d.wasm_module_id.v1";

/// The 4-byte WASM magic `\0asm`.
const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6d];
/// The only supported WASM binary-format version (`1`, little-endian).
const WASM_VERSION: [u8; 4] = [0x01, 0x00, 0x00, 0x00];

/// Why a byte string was rejected as a Tier-2 module.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ModuleIdError {
    /// Fewer than the 8-byte magic+version header.
    TooShort,
    /// The leading 4 bytes were not the `\0asm` magic.
    BadMagic,
    /// The 4-byte version field was not the supported version `1`.
    UnsupportedVersion,
    /// A section length ran past the end of the input (truncated/overlong).
    MalformedSection,
    /// A section-size LEB128 was malformed (overlong or overflowed `u32`).
    MalformedLeb128,
}

/// 32-byte content address of a Tier-2 WASM module. `#[repr(transparent)]` over
/// `[u8; 32]` ⇒ `size_of::<WasmTier2ModuleId>() == 32` byte-exact. Equality and
/// hashing are byte-equal on the array.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(transparent)]
pub struct WasmTier2ModuleId([u8; 32]);

impl WasmTier2ModuleId {
    /// Derive the module id from candidate WASM `bytes`. The bytes are first
    /// structurally validated and only a well-formed module is hashed; a
    /// malformed input is rejected, never hashed.
    ///
    /// The preimage is internally length-prefixed
    /// (`len_u32_le ++ bytes`) under [`DOMAIN_MODULE_ID`] so it satisfies the
    /// [`crate::package::blake2b_256`] unambiguous-framing contract.
    ///
    /// # Errors
    ///
    /// A [`ModuleIdError`] if `bytes` is not well-formed WASM.
    pub fn from_wasm_bytes(bytes: &[u8]) -> Result<Self, ModuleIdError> {
        validate_wasm_structure(bytes)?;
        let mut buf: Vec<u8> = Vec::with_capacity(4usize.saturating_add(bytes.len()));
        buf.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        buf.extend_from_slice(bytes);
        Ok(Self(blake2b_256(&[DOMAIN_MODULE_ID, &buf])))
    }

    /// Wrap a precomputed 32-byte id (e.g. a value stored in a manifest).
    #[inline]
    #[must_use]
    pub const fn from_bytes(id: [u8; 32]) -> Self {
        Self(id)
    }

    /// Borrow the 32 id bytes.
    #[inline]
    #[must_use]
    pub const fn bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Read an unsigned LEB128 `u32` from `bytes` starting at `*pos`, advancing
/// `*pos` past the consumed bytes. Rejects an overlong encoding, one that
/// overflows `u32`, AND a non-minimal (underlong) encoding — the WASM spec
/// mandates *minimal* uLEB128, so a redundant trailing zero group (e.g.
/// `0x80 0x00` for value 0) is rejected, not silently accepted. Panic-free:
/// every read is a checked [`slice::get`].
fn read_uleb128_u32(bytes: &[u8], pos: &mut usize) -> Result<u32, ModuleIdError> {
    let mut result: u32 = 0;
    let mut shift: u32 = 0;
    loop {
        if shift >= 32 {
            // A 6th continuation byte cannot fit in a u32.
            return Err(ModuleIdError::MalformedLeb128);
        }
        let byte = *bytes.get(*pos).ok_or(ModuleIdError::MalformedLeb128)?;
        *pos = pos.saturating_add(1);
        // On the 5th byte (shift == 28) only the low 4 bits are valid for a u32.
        if shift == 28 && (byte & 0x70) != 0 {
            return Err(ModuleIdError::MalformedLeb128);
        }
        result |= u32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            // Minimal-encoding check: a terminal `0x00` group at a non-zero
            // shift is a redundant trailing-zero group (the value fit in fewer
            // bytes). Non-canonical per the WASM spec ⇒ reject, so two
            // encodings of one module can never mint two module ids.
            if shift > 0 && byte == 0 {
                return Err(ModuleIdError::MalformedLeb128);
            }
            return Ok(result);
        }
        shift = shift.saturating_add(7);
    }
}

/// Minimal structural WASM validation. Confirms the `\0asm` magic and the
/// supported version, then walks every section `(id: u8, size: uLEB128,
/// payload: size bytes)` to confirm no length runs past the end. Never
/// executes the module.
///
/// # Errors
///
/// A [`ModuleIdError`] describing the first structural defect found.
pub fn validate_wasm_structure(bytes: &[u8]) -> Result<(), ModuleIdError> {
    if bytes.len() < 8 {
        return Err(ModuleIdError::TooShort);
    }
    if !bytes.starts_with(&WASM_MAGIC) {
        return Err(ModuleIdError::BadMagic);
    }
    if bytes.get(4..8) != Some(WASM_VERSION.as_slice()) {
        return Err(ModuleIdError::UnsupportedVersion);
    }
    let len = bytes.len();
    let mut pos: usize = 8;
    while pos < len {
        // Consume the 1-byte section id (its semantic value is not validated
        // here — only the structural framing is).
        pos = pos.saturating_add(1);
        let size = read_uleb128_u32(bytes, &mut pos)? as usize;
        let end = pos
            .checked_add(size)
            .ok_or(ModuleIdError::MalformedSection)?;
        if end > len {
            return Err(ModuleIdError::MalformedSection);
        }
        pos = end;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A minimal well-formed module: header + one empty custom section
    /// `(id=0, size=0)`.
    fn minimal_module() -> [u8; 10] {
        [
            0x00, 0x61, 0x73, 0x6d, // magic
            0x01, 0x00, 0x00, 0x00, // version 1
            0x00, // section id 0 (custom)
            0x00, // section size 0 (uLEB128)
        ]
    }

    #[test]
    fn same_bytes_same_id() {
        let m = minimal_module();
        let a = WasmTier2ModuleId::from_wasm_bytes(&m).expect("valid module");
        let b = WasmTier2ModuleId::from_wasm_bytes(&m).expect("valid module");
        assert_eq!(a, b);
    }

    #[test]
    fn byte_mutation_changes_id() {
        let m = minimal_module();
        let a = WasmTier2ModuleId::from_wasm_bytes(&m).expect("valid module");
        // Mutate the section-id byte (still structurally valid: id=1, size=0).
        let mut m2 = m;
        m2[8] = 0x01;
        let b = WasmTier2ModuleId::from_wasm_bytes(&m2).expect("valid module");
        assert_ne!(a, b, "any byte change must move the id");
    }

    #[test]
    fn header_only_module_is_valid() {
        let header = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert!(WasmTier2ModuleId::from_wasm_bytes(&header).is_ok());
    }

    #[test]
    fn too_short_rejected() {
        assert_eq!(
            WasmTier2ModuleId::from_wasm_bytes(&[0x00, 0x61, 0x73]),
            Err(ModuleIdError::TooShort)
        );
    }

    #[test]
    fn bad_magic_rejected() {
        let bytes = [0xde, 0xad, 0xbe, 0xef, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(
            WasmTier2ModuleId::from_wasm_bytes(&bytes),
            Err(ModuleIdError::BadMagic)
        );
    }

    #[test]
    fn bad_version_rejected() {
        let bytes = [0x00, 0x61, 0x73, 0x6d, 0x02, 0x00, 0x00, 0x00];
        assert_eq!(
            WasmTier2ModuleId::from_wasm_bytes(&bytes),
            Err(ModuleIdError::UnsupportedVersion)
        );
    }

    #[test]
    fn underlong_leb128_rejected() {
        // Header + section id 0 + a NON-MINIMAL size LEB128 `0x80 0x00` (value 0
        // encoded in 2 bytes instead of 1). The WASM spec mandates minimal
        // uLEB128, so this must reject — otherwise one logical module could mint
        // two distinct module ids.
        let bytes = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
        ];
        assert_eq!(
            WasmTier2ModuleId::from_wasm_bytes(&bytes),
            Err(ModuleIdError::MalformedLeb128)
        );
        // The canonical single-byte size 0x00 stays accepted.
        let canonical = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert!(WasmTier2ModuleId::from_wasm_bytes(&canonical).is_ok());
    }

    #[test]
    fn truncated_section_rejected() {
        // Header + section id 0 + size 5 but only 1 payload byte present.
        let bytes = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x05, 0xaa,
        ];
        assert_eq!(
            WasmTier2ModuleId::from_wasm_bytes(&bytes),
            Err(ModuleIdError::MalformedSection)
        );
    }

    #[test]
    fn overlong_leb128_rejected() {
        // Header + section id 0 + a 6-byte continuation LEB128 (never terminates
        // within u32 range).
        let bytes = [
            0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x80, 0x80, 0x80, 0x80, 0x80,
            0x80,
        ];
        assert_eq!(
            WasmTier2ModuleId::from_wasm_bytes(&bytes),
            Err(ModuleIdError::MalformedLeb128)
        );
    }

    #[test]
    fn from_bytes_roundtrip() {
        let raw = [7u8; 32];
        let id = WasmTier2ModuleId::from_bytes(raw);
        assert_eq!(id.bytes(), &raw);
    }
}
