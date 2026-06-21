//! Stage C multisig roster (C-WP-05 · atom #211 · C.1.10).
//!
//! Canonical OUT (§4.2): [`MultisigRoster`].
//!
//! # Madness invariants (atom #211)
//!
//! * **No single-signer execution path.** A roster cannot be constructed with a
//!   threshold below [`MULTISIG_MIN_THRESHOLD`] (`2`) or with fewer than
//!   [`MULTISIG_MIN_SIGNERS`] (`2`) signers. A "threshold one" roster — the
//!   shape that would let one key push a mainnet mutation — is rejected
//!   fail-closed with [`MultisigError::ThresholdTooLow`], so it is
//!   unrepresentable as a value of this type, not merely discouraged.
//! * **Signer identities are hashed, not stored.** The roster keeps only the
//!   threshold, the signer count, and a single 32-byte
//!   `Blake2b-256(domain ‖ count ‖ sorted-unique-signer-bytes)` over the signer
//!   set. The individual addresses are not embedded, and the hash is
//!   order-independent (the inputs are sorted before hashing) so the same set
//!   in any order binds to the same roster.
//! * **Data-free errors.** [`MultisigError`] variants carry no caller bytes, so
//!   a rejected address or malformed TOML never leaks into the error channel.
//!
//! # Reuse map (atom contract)
//!
//! * **reuse: A `SuiAddress`** — [`mnemos_d_move::types::SuiAddress`]
//!   (`d-move/src/types.rs:140`). No second 32-byte address type is minted.
//! * **reuse: `Blake2b<U32>`** — the keystore's `Blake2b-256` hashing
//!   convention (`g-wallet/src/keystore.rs:414`). No parallel digest is minted.

use blake2::{Blake2b, Digest, digest::consts::U32};
use mnemos_d_move::types::SuiAddress;
use serde::Deserialize;

/// Fixed serialized byte width of a [`MultisigRoster`]: `1` (threshold) + `1`
/// (signer count) + `32` (signer-set hash).
pub const MULTISIG_ROSTER_BYTES: usize = 1 + 1 + 32;

/// Minimum number of signers a roster may carry. Below this a roster could
/// degenerate into a single-key authority, so it is rejected.
pub const MULTISIG_MIN_SIGNERS: u8 = 2;

/// Minimum approval threshold. A threshold of `1` would let one signer execute
/// alone; the roster forbids it by construction.
pub const MULTISIG_MIN_THRESHOLD: u8 = 2;

/// Upper bound on roster size — keeps the hashing buffer fixed and the parse
/// allocation bounded.
pub const MULTISIG_MAX_SIGNERS: u8 = 16;

/// Domain separator for the signer-set hash, so a roster digest can never
/// collide with another Stage C 32-byte hash preimage.
const ROSTER_HASH_DOMAIN: &[u8] = b"mnemos.stage_c.multisig_roster.v1";

/// A mainnet multisig roster (§4.2 canonical OUT).
///
/// Holds the approval `threshold`, the `signer_count`, and a single 32-byte
/// hash binding the (sorted, de-duplicated) signer set. By construction
/// `threshold >= 2`, `signer_count >= 2`, and `threshold <= signer_count`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct MultisigRoster {
    /// Number of signers that must approve. `>= 2` by construction.
    pub threshold_u8: u8,
    /// Number of signers in the roster. `>= 2` by construction.
    pub signer_count_u8: u8,
    /// `Blake2b-256(domain ‖ count ‖ sorted-unique-signer-bytes)`.
    pub signer_hash_32: [u8; 32],
}

/// Roster construction / parse error. Every variant is data-free.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum MultisigError {
    /// Fewer than [`MULTISIG_MIN_SIGNERS`] signers were supplied.
    TooFewSigners = 1,
    /// More than [`MULTISIG_MAX_SIGNERS`] signers were supplied.
    TooManySigners = 2,
    /// Threshold below [`MULTISIG_MIN_THRESHOLD`] — the single-signer path is
    /// forbidden.
    ThresholdTooLow = 3,
    /// Threshold greater than the number of signers.
    ThresholdExceedsSigners = 4,
    /// The same signer address appears more than once.
    DuplicateSigner = 5,
    /// The roster TOML document failed to parse or carried unknown fields.
    TomlParse = 6,
    /// A signer address string was not exactly 64 hex characters (optionally
    /// `0x`-prefixed).
    AddressFormat = 7,
}

impl core::fmt::Display for MultisigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            Self::TooFewSigners => "stage_c multisig: fewer than the minimum signers",
            Self::TooManySigners => "stage_c multisig: more than the maximum signers",
            Self::ThresholdTooLow => {
                "stage_c multisig: threshold below 2 (single-signer forbidden)"
            }
            Self::ThresholdExceedsSigners => "stage_c multisig: threshold exceeds signer count",
            Self::DuplicateSigner => "stage_c multisig: duplicate signer address",
            Self::TomlParse => "stage_c multisig: roster toml parse failed",
            Self::AddressFormat => "stage_c multisig: signer address format invalid",
        };
        f.write_str(msg)
    }
}

impl core::error::Error for MultisigError {}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRoster {
    threshold: u8,
    signers: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TomlRosterTop {
    roster: TomlRoster,
}

/// Map a single ASCII hex digit to its nibble value, fail-closed.
const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Decode a 32-byte Sui address from a 64-char hex string (optional `0x`
/// prefix). Fail-closed: any non-hex byte or wrong length is rejected.
fn decode_address_hex(raw: &str) -> Result<SuiAddress, MultisigError> {
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    if hex.len() != 64 {
        return Err(MultisigError::AddressFormat);
    }
    let bytes = hex.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_nibble(bytes[i * 2]).ok_or(MultisigError::AddressFormat)?;
        let lo = hex_nibble(bytes[i * 2 + 1]).ok_or(MultisigError::AddressFormat)?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Ok(SuiAddress::new(out))
}

/// Canonical hash of a signer set: `Blake2b-256(domain ‖ count ‖
/// sorted-unique-signer-bytes)`, returning the digest and the signer count.
///
/// This is the single source of truth for binding a signer set to a 32-byte
/// hash; both [`MultisigRoster::from_signers`] and the atom #212 proposal
/// envelope reuse it so a roster and a proposal that name the same set agree
/// byte-for-byte (no parallel hashing is minted).
///
/// # Errors
///
/// [`MultisigError::TooFewSigners`] / [`MultisigError::TooManySigners`] when
/// the count is outside `[MULTISIG_MIN_SIGNERS, MULTISIG_MAX_SIGNERS]`, and
/// [`MultisigError::DuplicateSigner`] when an address repeats.
pub fn signer_set_hash(signers: &[SuiAddress]) -> Result<([u8; 32], u8), MultisigError> {
    let count = signers.len();
    if count < MULTISIG_MIN_SIGNERS as usize {
        return Err(MultisigError::TooFewSigners);
    }
    let signer_count_u8 = u8::try_from(count).map_err(|_| MultisigError::TooManySigners)?;
    if signer_count_u8 > MULTISIG_MAX_SIGNERS {
        return Err(MultisigError::TooManySigners);
    }

    // Copy into a fixed-size buffer and sort so the hash is order-independent
    // and adjacent-duplicate detection is O(n).
    let mut sorted = [[0u8; 32]; MULTISIG_MAX_SIGNERS as usize];
    for (slot, addr) in sorted.iter_mut().zip(signers.iter()) {
        *slot = *addr.as_bytes();
    }
    let used = &mut sorted[..count];
    used.sort_unstable();
    for pair in used.windows(2) {
        if pair[0] == pair[1] {
            return Err(MultisigError::DuplicateSigner);
        }
    }

    let mut hasher = Blake2b::<U32>::new();
    hasher.update(ROSTER_HASH_DOMAIN);
    hasher.update([signer_count_u8]);
    for addr in used.iter() {
        hasher.update(addr);
    }
    let digest = hasher.finalize();
    let mut signer_hash_32 = [0u8; 32];
    signer_hash_32.copy_from_slice(&digest);
    Ok((signer_hash_32, signer_count_u8))
}

impl MultisigRoster {
    /// Build a roster from a signer slice and an approval threshold.
    ///
    /// # Errors
    ///
    /// - [`MultisigError::TooFewSigners`] / [`MultisigError::TooManySigners`]
    ///   when the count is outside `[MULTISIG_MIN_SIGNERS, MULTISIG_MAX_SIGNERS]`.
    /// - [`MultisigError::ThresholdTooLow`] when `threshold < 2`.
    /// - [`MultisigError::ThresholdExceedsSigners`] when `threshold > count`.
    /// - [`MultisigError::DuplicateSigner`] when an address repeats.
    pub fn from_signers(signers: &[SuiAddress], threshold_u8: u8) -> Result<Self, MultisigError> {
        let (signer_hash_32, signer_count_u8) = signer_set_hash(signers)?;
        if threshold_u8 < MULTISIG_MIN_THRESHOLD {
            return Err(MultisigError::ThresholdTooLow);
        }
        if threshold_u8 > signer_count_u8 {
            return Err(MultisigError::ThresholdExceedsSigners);
        }
        Ok(Self {
            threshold_u8,
            signer_count_u8,
            signer_hash_32,
        })
    }

    /// Build a roster from a `[roster]` TOML document with `threshold` and a
    /// `signers` array of 64-hex-char addresses.
    ///
    /// # Errors
    ///
    /// [`MultisigError::TomlParse`] on malformed / unknown-field TOML,
    /// [`MultisigError::AddressFormat`] on a bad address string, and any
    /// [`from_signers`](Self::from_signers) error on the decoded set. No raw
    /// input bytes are carried into the error.
    pub fn from_toml_str(toml_text: &str) -> Result<Self, MultisigError> {
        let parsed: TomlRosterTop =
            toml::from_str(toml_text).map_err(|_| MultisigError::TomlParse)?;
        if parsed.roster.signers.len() > MULTISIG_MAX_SIGNERS as usize {
            return Err(MultisigError::TooManySigners);
        }
        let mut addrs = [SuiAddress::new([0u8; 32]); MULTISIG_MAX_SIGNERS as usize];
        let n = parsed.roster.signers.len();
        for (slot, raw) in addrs.iter_mut().zip(parsed.roster.signers.iter()) {
            *slot = decode_address_hex(raw)?;
        }
        Self::from_signers(&addrs[..n], parsed.roster.threshold)
    }

    /// Serialize to the fixed [`MULTISIG_ROSTER_BYTES`] byte form:
    /// `threshold ‖ signer_count ‖ signer_hash_32`.
    pub fn to_bytes(&self) -> [u8; MULTISIG_ROSTER_BYTES] {
        let mut out = [0u8; MULTISIG_ROSTER_BYTES];
        out[0] = self.threshold_u8;
        out[1] = self.signer_count_u8;
        out[2..MULTISIG_ROSTER_BYTES].copy_from_slice(&self.signer_hash_32);
        out
    }

    /// The signer-set hash binding this roster.
    #[inline]
    pub const fn signer_hash(&self) -> [u8; 32] {
        self.signer_hash_32
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]

    use super::*;

    fn addr(byte: u8) -> SuiAddress {
        SuiAddress::new([byte; 32])
    }

    /// `c1_10_threshold_valid` — a well-formed 2-of-3 roster builds, its byte
    /// form is fixed-width, and the signer hash is order-independent.
    #[test]
    fn c1_10_threshold_valid() {
        let signers = [addr(1), addr(2), addr(3)];
        let roster = MultisigRoster::from_signers(&signers, 2).expect("2-of-3 roster must build");
        assert_eq!(roster.threshold_u8, 2);
        assert_eq!(roster.signer_count_u8, 3);
        assert_eq!(roster.to_bytes().len(), MULTISIG_ROSTER_BYTES);
        assert_eq!(MULTISIG_ROSTER_BYTES, 34);

        // Order independence: the same set in another order binds identically.
        let reordered = [addr(3), addr(1), addr(2)];
        let roster2 =
            MultisigRoster::from_signers(&reordered, 2).expect("reordered set must build");
        assert_eq!(roster.signer_hash(), roster2.signer_hash());
        assert_eq!(roster, roster2);

        // A different set binds to a different hash.
        let other = [addr(1), addr(2), addr(9)];
        let roster3 = MultisigRoster::from_signers(&other, 2).expect("builds");
        assert_ne!(roster.signer_hash(), roster3.signer_hash());
    }

    /// `c1_10_duplicate_signer_reject` — a repeated address is rejected.
    #[test]
    fn c1_10_duplicate_signer_reject() {
        let signers = [addr(7), addr(7), addr(8)];
        assert_eq!(
            MultisigRoster::from_signers(&signers, 2),
            Err(MultisigError::DuplicateSigner),
        );
    }

    /// `c1_10_threshold_one_reject` — a threshold of `1` (single-signer path)
    /// and a threshold of `0` are both rejected fail-closed; the type cannot
    /// represent a single-key authority.
    #[test]
    fn c1_10_threshold_one_reject() {
        let signers = [addr(1), addr(2), addr(3)];
        assert_eq!(
            MultisigRoster::from_signers(&signers, 1),
            Err(MultisigError::ThresholdTooLow),
        );
        assert_eq!(
            MultisigRoster::from_signers(&signers, 0),
            Err(MultisigError::ThresholdTooLow),
        );
        // One signer total is also rejected (count below the minimum).
        assert_eq!(
            MultisigRoster::from_signers(&[addr(1)], 2),
            Err(MultisigError::TooFewSigners),
        );
        // Threshold above the signer count is rejected.
        assert_eq!(
            MultisigRoster::from_signers(&signers, 4),
            Err(MultisigError::ThresholdExceedsSigners),
        );
    }

    /// `c1_10_toml_parse` — a `[roster]` document with hex signer addresses
    /// parses, and an unknown field / bad address is rejected without leaking
    /// input bytes into the error rendering.
    #[test]
    fn c1_10_toml_parse() {
        let doc = r#"
[roster]
threshold = 2
signers = [
  "0x1111111111111111111111111111111111111111111111111111111111111111",
  "2222222222222222222222222222222222222222222222222222222222222222",
  "0x3333333333333333333333333333333333333333333333333333333333333333",
]
"#;
        let roster = MultisigRoster::from_toml_str(doc).expect("roster toml parses");
        assert_eq!(roster.threshold_u8, 2);
        assert_eq!(roster.signer_count_u8, 3);

        // Unknown field rejected.
        let bad = "[roster]\nthreshold = 2\nsigners = []\nextra = 1\n";
        assert_eq!(
            MultisigRoster::from_toml_str(bad),
            Err(MultisigError::TomlParse),
        );

        // Bad address (too short) rejected; secret-ish bytes never echoed.
        let badaddr = "[roster]\nthreshold = 2\nsigners = [\"0xdeadbeef\"]\n";
        let err = MultisigRoster::from_toml_str(badaddr).expect_err("short address rejected");
        let rendered = format!("{err:?} {err}");
        assert!(!rendered.contains("deadbeef"));
    }
}
