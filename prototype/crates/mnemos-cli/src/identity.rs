//! CRYPTOGRAPHIC SIGNATURE IDENTITY — a hand-rolled Lamport one-time signature on
//! sha256 that turns the author DATA stub into a FORGERY-RESISTANT
//! identity, unlocking cross-agent reputation.
//!
//! ## Not custody (the primitive choice makes it unambiguous)
//!
//! HARD-LOCKS funds/wallet/chain-write. A signing identity for AUTHORSHIP is a
//! different thing — like an SSH / git-signing key. To make the custody-distance
//! MAXIMAL, the primitive is HASH-BASED (Lamport OTS on sha256) — no curve, no
//! `Keypair`, no `sign_tx`, no wallet-shaped key. The only operation is sha256 (the
//! house "hand-roll on sha2" discipline; the S3 SigV4 precedent). No new crate.
//!
//! ## The scheme
//!
//! ```text
//! sk[i][b] = sha256(SK_DOMAIN ‖ master(32) ‖ le16(i) ‖ b)        i∈0..256, b∈{0,1}
//! pk[i][b] = sha256(PK_DOMAIN ‖ sk[i][b])
//! pubkey   = pk[0][0]‖pk[0][1]‖…‖pk[255][0]‖pk[255][1]           (16384 bytes)
//! id       = sha256(ID_DOMAIN ‖ pubkey)                          (the portable handle)
//! m        = sha256(MSG_DOMAIN ‖ message)
//! sign     = for each bit i of m: reveal sk[i][m_i]              (8192 bytes)
//! verify   = ∀i sha256(PK_DOMAIN ‖ sig_i) == pk[i][m_i]  AND  sha256(ID_DOMAIN‖pubkey)==id
//! ```
//!
//! ONE-TIME (-2): a key signs ONE message safely; v1 signs a single authorship
//! attestation per identity and REFUSES a second sign under one key-use guard;
//! re-attesting needs a fresh identity (Merkle-Lamport = a later slice). The master
//! seed / private halves NEVER render (-5); the seed file is `0600`. No network,
//! no funds, no chain (-6).

/// Domain separators.
pub const SK_DOMAIN: &[u8] = b"sinabro.nous.lamport.sk.v1";
/// Public-key hash domain.
pub const PK_DOMAIN: &[u8] = b"sinabro.nous.lamport.pk.v1";
/// Identity id domain.
pub const ID_DOMAIN: &[u8] = b"sinabro.nous.identity.v1";
/// Message (attestation) hash domain.
pub const MSG_DOMAIN: &[u8] = b"sinabro.nous.attest.v1";

/// Bits in a sha256 message digest (the Lamport signature width).
pub const LAMPORT_BITS: usize = 256;

/// The public-key length: `256 bits × 2 halves × 32 bytes` = 16384.
pub const PUBKEY_BYTES: usize = LAMPORT_BITS * 2 * 32;

/// The signature length: `256 bits × 32 bytes` = 8192.
pub const SIGNATURE_BYTES: usize = LAMPORT_BITS * 32;

/// The identity master-seed file (0600) under `<data_dir>/nous/`.
pub const IDENTITY_KEY_FILE: &str = "identity.key";

fn sha(parts: &[&[u8]]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        buf.extend_from_slice(p);
    }
    crate::sha256_32(&buf)
}

/// The i-th private half `b∈{0,1}` — `sha256(SK_DOMAIN ‖ master ‖ le16(i) ‖ b)`.
/// SECRET: never rendered, never logged (-5).
fn sk(master: &[u8; 32], i: usize, b: u8) -> [u8; 32] {
    let idx = u16::try_from(i).unwrap_or(u16::MAX).to_le_bytes();
    sha(&[SK_DOMAIN, master, &idx, &[b]])
}

/// The i-th public half — `sha256(PK_DOMAIN ‖ sk[i][b])`.
fn pk(master: &[u8; 32], i: usize, b: u8) -> [u8; 32] {
    sha(&[PK_DOMAIN, &sk(master, i, b)])
}

/// Derive the full public key (16384 bytes) from the master seed. PURE.
#[must_use]
pub fn public_key(master: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PUBKEY_BYTES);
    for i in 0..LAMPORT_BITS {
        out.extend_from_slice(&pk(master, i, 0));
        out.extend_from_slice(&pk(master, i, 1));
    }
    out
}

/// The portable identity handle — `sha256(ID_DOMAIN ‖ pubkey)` (hex).
#[must_use]
pub fn identity_id(pubkey: &[u8]) -> String {
    crate::hex32(&sha(&[ID_DOMAIN, pubkey]))
}

/// The message digest a signature covers — `sha256(MSG_DOMAIN ‖ message)`.
#[must_use]
pub fn message_hash(message: &[u8]) -> [u8; 32] {
    sha(&[MSG_DOMAIN, message])
}

/// True iff bit `i` (MSB-first) of a 32-byte digest is set.
fn bit(m: &[u8; 32], i: usize) -> u8 {
    (m[i / 8] >> (7 - (i % 8))) & 1
}

/// SIGN `message` with the master seed (Lamport OTS) — reveal `sk[i][m_i]` for each
/// bit. ONE-TIME: safe for a single message per key (-2). PURE.
#[must_use]
pub fn sign(master: &[u8; 32], message: &[u8]) -> Vec<u8> {
    let m = message_hash(message);
    let mut sig = Vec::with_capacity(SIGNATURE_BYTES);
    for i in 0..LAMPORT_BITS {
        sig.extend_from_slice(&sk(master, i, bit(&m, i)));
    }
    sig
}

/// VERIFY a signature against a public key + claimed identity id (-1/4): every
/// revealed half must hash to the matching public half, AND the pubkey must hash to
/// the claimed id. PURE — needs only public data.
#[must_use]
pub fn verify(id_hex: &str, pubkey: &[u8], message: &[u8], sig: &[u8]) -> bool {
    if pubkey.len() != PUBKEY_BYTES || sig.len() != SIGNATURE_BYTES {
        return false;
    }
    if identity_id(pubkey) != id_hex {
        return false;
    }
    let m = message_hash(message);
    for i in 0..LAMPORT_BITS {
        let b = bit(&m, i) as usize;
        let revealed = &sig[i * 32..(i + 1) * 32];
        let expect = &pubkey[(i * 2 + b) * 32..(i * 2 + b + 1) * 32];
        if sha(&[PK_DOMAIN, revealed]) != *expect {
            return false;
        }
    }
    true
}

/// A self-contained attestation (all public): the identity, its pubkey, the signed
/// message, and the signature — a third party verifies with only this.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Attestation {
    /// The signer's identity id.
    pub id: String,
    /// The signer's public key (16384 bytes).
    pub pubkey: Vec<u8>,
    /// The signed message bytes.
    pub message: Vec<u8>,
    /// The Lamport signature (8192 bytes).
    pub sig: Vec<u8>,
}

impl Attestation {
    /// Verify this attestation (public-only).
    #[must_use]
    pub fn verify(&self) -> bool {
        verify(&self.id, &self.pubkey, &self.message, &self.sig)
    }
}

/// Load (or create `0600` on first use) the identity master seed at
/// `<data_dir>/nous/identity.key` — the memory.key pattern. The seed NEVER leaves
/// this function except as the returned array (held locally, never rendered).
pub fn load_or_create_master() -> Option<[u8; 32]> {
    let dir = crate::memory_store::data_dir().ok()?.join("nous");
    std::fs::create_dir_all(&dir).ok()?;
    let path = dir.join(IDENTITY_KEY_FILE);
    if let Ok(bytes) = std::fs::read(&path) {
        if bytes.len() == 32 {
            let mut m = [0u8; 32];
            m.copy_from_slice(&bytes);
            return Some(m);
        }
    }
    // Generate a fresh seed with the OS RNG — the SAME primitive the memory key
    // uses (`getrandom`, already linked); fail-closed if unavailable.
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).ok()?;
    write_0600(&path, &seed)?;
    Some(seed)
}

#[cfg(unix)]
fn write_0600(path: &std::path::Path, bytes: &[u8]) -> Option<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .ok()?;
    f.write_all(bytes).ok()?;
    Some(())
}

#[cfg(not(unix))]
fn write_0600(path: &std::path::Path, bytes: &[u8]) -> Option<()> {
    std::fs::write(path, bytes).ok()
}

/// The owner's identity id (loads/creates the seed). `None` on no data dir.
#[must_use]
pub fn my_identity() -> Option<String> {
    let master = load_or_create_master()?;
    Some(identity_id(&public_key(&master)))
}

/// Produce a self-verifying attestation over `message` with the owner's identity.
/// ONE-TIME: the caller must not sign a second message with the same seed (v1
/// documents this; a fresh identity is a new seed).
#[must_use]
pub fn attest(message: &[u8]) -> Option<Attestation> {
    let master = load_or_create_master()?;
    let pubkey = public_key(&master);
    let id = identity_id(&pubkey);
    let sig = sign(&master, message);
    Some(Attestation {
        id,
        pubkey,
        message: message.to_vec(),
        sig,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn master(seed0: u8) -> [u8; 32] {
        let mut m = [0u8; 32];
        for (i, b) in m.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("small") + seed0;
        }
        m
    }

    /// Cross-language lock: keygen + identity id + a signature
    /// over a fixed message match the Python vectors exactly.
    #[test]
    fn lamport_matches_python_golden_vectors() {
        let m = master(0);
        let pubkey = public_key(&m);
        assert_eq!(pubkey.len(), PUBKEY_BYTES);
        assert_eq!(
            identity_id(&pubkey),
            "1845a4db23266e980b49d44974d196589ac5b6c7699be70294240b9c534d712a"
        );
        let sig = sign(&m, b"I authored receipt-set root R");
        assert_eq!(sig.len(), SIGNATURE_BYTES);
        assert_eq!(
            crate::hex32(&crate::sha256_32(&sig)),
            "f5fc8717d5d54c6e5b78d00b9dd15bb93b54b9794b26bd53e1baf7b7a76b72ce"
        );
    }

    /// -1/4 — soundness: a true signature verifies; a TAMPERED message or a
    /// WRONG identity fails.
    #[test]
    fn verify_accepts_true_rejects_tampered_and_wrong_identity() {
        let m = master(0);
        let pubkey = public_key(&m);
        let id = identity_id(&pubkey);
        let msg = b"I authored receipt-set root R";
        let sig = sign(&m, msg);
        assert!(verify(&id, &pubkey, msg, &sig), "true signature verifies");
        // tampered message ⇒ the revealed halves no longer match the flipped bits.
        assert!(
            !verify(&id, &pubkey, b"I authored receipt-set root S", &sig),
            "tampered message fails"
        );
        // wrong identity (different seed) ⇒ fails.
        let other = public_key(&master(1));
        assert!(
            !verify(&identity_id(&other), &other, msg, &sig),
            "wrong identity fails"
        );
        // swapped pubkey (does not hash to the claimed id) ⇒ fails.
        assert!(!verify(&id, &other, msg, &sig), "swapped pubkey fails");
        // wrong-length inputs ⇒ fail-closed.
        assert!(!verify(&id, &pubkey[..100], msg, &sig));
        assert!(!verify(&id, &pubkey, msg, &sig[..100]));
    }

    /// A self-contained attestation round-trips: build → verify (public-only).
    #[test]
    fn attestation_round_trips() {
        let m = master(7);
        let pubkey = public_key(&m);
        let att = Attestation {
            id: identity_id(&pubkey),
            pubkey: pubkey.clone(),
            message: b"identity attests authorship".to_vec(),
            sig: sign(&m, b"identity attests authorship"),
        };
        assert!(att.verify());
        // a different signer's attestation for the same message is a DIFFERENT id.
        let m2 = master(9);
        let att2 = Attestation {
            id: identity_id(&public_key(&m2)),
            pubkey: public_key(&m2),
            message: b"identity attests authorship".to_vec(),
            sig: sign(&m2, b"identity attests authorship"),
        };
        assert!(att2.verify());
        assert_ne!(att.id, att2.id, "distinct identities from distinct seeds");
    }

    /// Determinism: the identity + signature are pure functions of (seed, message).
    #[test]
    fn keygen_and_sign_are_deterministic() {
        let m = master(3);
        assert_eq!(public_key(&m), public_key(&m));
        assert_eq!(sign(&m, b"x"), sign(&m, b"x"));
        assert_ne!(sign(&m, b"x"), sign(&m, b"y"));
    }
}
