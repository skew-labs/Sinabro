//! `oracle_inft` — O-5: capitalize a CERTIFIED oracle as an ERC-7857 iNFT (the Oracle
//! Bootstrap's ownership step; master plan §6.9 O-5 + §6.6 economics). The W3 plan mints a
//! *pattern* ([`crate::zerog_chain::W2D_PATTERN_HASH`]) or a fine-tuned *expert* (a LoRA
//! adapter rootHash) as an iNFT; O-5 mints a third thing: **a certified ORACLE itself** — "an
//! oracle is a verifiable, owned, tradeable asset" (§6.6). It COMPOSES the LOCKED
//! [`crate::zerog_inft::encode_mint_calldata`] byte-encoder (selector `0xa3acac17`, the
//! Python+`solc`+Rust golden) — NO second mint surface — binding the iNFT's `dataHash` to a
//! DETERMINISTIC commitment over a certified oracle.
//!
//! ## the certification is TYPED — [`OracleCert`] (the O-5 generalization)
//! Different ladder oracles are certified by different physics, so the cert is a typed value and
//! the mint gate dispatches on it:
//! * **`Conformal { k, n }`** — the recognition oracle (O-3b/O-3c): a STATISTICAL bound, certified
//!   iff [`crate::conformal::certify_far_default`] (FAR ≤ α*_safe @ `1−δ`, `k` held-out
//!   false-accepts in `n` negatives). The "O(10) recognition-anchors per oracle-mint" unit (§6.6).
//! * **`DeterministicSound`** — the reconcile (O-1, R1) / metamorphic (O-4, R2) oracles: SOUND BY
//!   CONSTRUCTION (pure total fail-closed checkers, no statistical bound), certified iff the
//!   verification-ladder CANARY is intact ([`crate::verification::canary_intact`]) — the held-out
//!   tripwire (which pins the reconcile + metamorphic verdict boundaries) proving the deterministic
//!   verdicts have NOT collapsed. A suspect ladder ⇒ UN-mintable.
//!
//! ## ★ THE MINT GATE — certified-only, fail-CLOSED (owner-locked O-5 seam Q3)
//! You can ONLY mint a CERTIFIED oracle. [`oracle_data_hash`] returns `None` (⇒ no calldata, no
//! mintable envelope) unless [`OracleCert::is_certified`]. There is no path that capitalizes
//! provenance for an oracle that did not clear its cert (the conformal α-budget, or the
//! deterministic-soundness canary).
//!
//! ## the commitment (owner-locked O-5 seam Q2 — a deterministic LOCAL content-commitment)
//! `dataHash = sha256("sinabro.oracle.inft.v1" ‖ kind ‖ identity ‖ cert)` (length-prefixed, so the
//! preimage is unambiguous). It binds the oracle's IDENTITY (for recognition: the order-independent
//! anchor-set hash + the induced rule's box bounds; for reconcile/metamorphic: the fixed
//! invariant/relation SPEC) AND its CERTIFICATION (the typed cert kind + params) — so re-deriving it
//! from the same inputs is byte-identical (drift-0; anyone can verify the mint binds a genuinely
//! certified oracle). The encrypted private artifact (recognition's anchor capital) rides a SEPARATE
//! [`crate::zerog_storage`] availability leg in the runbook, owner-uploaded at go-live; a
//! deterministic oracle's SPEC is public (no private artifact).
//!
//! ## funds-safe posture (PD-6 — the agent NEVER holds a signing key)
//! 100% PURE: this module only builds the commitment + the ABI calldata (via the W3 encoder) +
//! the exact OWNER-run mint/upload commands. No transaction, no signature, no wallet, no
//! `reqwest`, no network, no feature gate — nothing here can spend. The funds-bearing mint +
//! Storage upload run OUTSIDE the binary. `CustodyCapability` stays uninhabited (PD-6); names no
//! custody symbol.
//!
//! ## ★ HONEST LOCK (§6.7 — never market past it)
//! Minting proves OWNED PROVENANCE — this transferable identity points at an oracle that cleared
//! its cert (the conformal FAR bound ON THE ANCHOR DISTRIBUTION, or deterministic soundness on its
//! stated invariant/relation) — NOT per-user correctness on arbitrary inputs (the same
//! aggregate/provenance boundary each oracle's own honest LOCK carries). custody/funds/mainnet
//! HARD-LOCKED.

use crate::zerog_inft::{GOLDEN_RECIPIENT, MINT_SIGNATURE, encode_mint_calldata};

/// The recognition oracle kind (O-3b/O-3c; the conformal-certified, anchor-derived oracle).
pub const RECOGNITION_ORACLE_KIND: &str = "recognition";
/// The finance reconciliation oracle kind (O-1, R1; deterministic-forever, sound by construction).
pub const RECONCILE_ORACLE_KIND: &str = "reconcile";
/// The summarization metamorphic oracle kind (O-4, R2; deterministic-forever sound rejector).
pub const METAMORPHIC_ORACLE_KIND: &str = "metamorphic";

/// The domain separator for the deterministic certified-oracle commitment (v1). Binds the hash
/// to THIS preimage layout so a future layout change is a different (un-confusable) commitment.
pub const ORACLE_COMMIT_DOMAIN: &[u8] = b"sinabro.oracle.inft.v1";

/// The TYPED certification of an oracle — the mint gate dispatches on the cert KIND (the O-5
/// generalization: different ladder oracles are certified by different physics).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OracleCert {
    /// A conformal α-budget cert (recognition, O-3c): FAR ≤ α*_safe @ `1−δ`, `k` held-out
    /// false-accepts in `n` negatives — a STATISTICAL bound on the anchor distribution.
    Conformal {
        /// Held-out false-accepts.
        k: u64,
        /// Held-out negatives.
        n: u64,
    },
    /// A DETERMINISTIC-FOREVER oracle (reconcile O-1 / metamorphic O-4): SOUND BY CONSTRUCTION
    /// (a pure total fail-closed checker), certified iff the verification-ladder CANARY is intact.
    DeterministicSound,
}

impl OracleCert {
    /// THE MINT GATE: is this oracle CERTIFIED (mintable)? Dispatches on the cert kind — the
    /// conformal α-budget for a statistical oracle, the ladder CANARY for a deterministic one.
    /// `crate::conformal` / `crate::verification` are the ONLY judges (the model never reaches them).
    #[must_use]
    pub fn is_certified(&self) -> bool {
        match *self {
            OracleCert::Conformal { k, n } => crate::conformal::certify_far_default(k, n),
            OracleCert::DeterministicSound => crate::verification::canary_intact(),
        }
    }

    /// A static cert label for the iNFT descriptor (honest, human-readable).
    fn label(&self) -> String {
        match *self {
            OracleCert::Conformal { k, n } => format!(
                "conformal(FAR<={}/{}@{}%,k={k},n={n})",
                crate::conformal::ALPHA_SAFE_NUM,
                crate::conformal::ALPHA_SAFE_DEN,
                confidence_pct(),
            ),
            OracleCert::DeterministicSound => "deterministic-sound(canary-intact)".to_string(),
        }
    }

    /// Fold the cert (a domain-separated KIND tag + its params) into the commitment preimage, so
    /// the commitment is to a *certified* oracle — and a Conformal and a DeterministicSound oracle
    /// with the same identity bytes commit to DIFFERENT dataHashes (the cert is part of identity).
    fn commit(&self, buf: &mut Vec<u8>) {
        match *self {
            OracleCert::Conformal { k, n } => {
                push_bytes(buf, b"conformal");
                for v in [
                    crate::conformal::ALPHA_SAFE_NUM,
                    crate::conformal::ALPHA_SAFE_DEN,
                    crate::conformal::DELTA_NUM,
                    crate::conformal::DELTA_DEN,
                    k,
                    n,
                ] {
                    buf.extend_from_slice(&v.to_be_bytes());
                }
            }
            OracleCert::DeterministicSound => push_bytes(buf, b"deterministic-sound"),
        }
    }
}

/// Append a length-prefixed byte string (`len:u64-be ‖ bytes`) — unambiguous concatenation (no
/// two distinct inputs share a preimage). The basis of the drift-0 commitment.
fn push_bytes(buf: &mut Vec<u8>, b: &[u8]) {
    buf.extend_from_slice(&(b.len() as u64).to_be_bytes());
    buf.extend_from_slice(b);
}

/// Append a length-prefixed `i64` slice (`len:u64-be ‖ each i64 big-endian`).
fn push_i64s(buf: &mut Vec<u8>, xs: &[i64]) {
    buf.extend_from_slice(&(xs.len() as u64).to_be_bytes());
    for &x in xs {
        buf.extend_from_slice(&x.to_be_bytes());
    }
}

/// THE iNFT `dataHash` for a CERTIFIED oracle — a deterministic LOCAL content-commitment,
/// FAIL-CLOSED on the typed cert gate. Returns `None` (⇒ UN-mintable) unless [`OracleCert::is_certified`]
/// (owner-locked O-5 seam Q3, certified-only). The `Some` commitment binds the `kind` + the oracle
/// `identity` bytes + the typed `cert` — so re-deriving it from the same inputs is byte-identical
/// (drift-0). The model never reaches the judge; only the deterministic cert does (§6.5).
#[must_use]
pub fn oracle_data_hash(kind: &str, identity: &[u8], cert: &OracleCert) -> Option<[u8; 32]> {
    // THE MINT GATE (O-5 Q3): the typed cert — uncertified ⇒ un-mintable.
    if !cert.is_certified() {
        return None;
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(ORACLE_COMMIT_DOMAIN);
    push_bytes(&mut buf, kind.as_bytes());
    push_bytes(&mut buf, identity);
    cert.commit(&mut buf);
    Some(crate::sha256_32(&buf))
}

/// The IDENTITY bytes for a RECOGNITION oracle: the order-independent anchor-set hash (the capital)
/// + the induced rule's box bounds (length-prefixed). The conformal cert rides separately.
#[must_use]
pub fn recognition_identity(anchor_set_hash: &str, box_lo: &[i64], box_hi: &[i64]) -> Vec<u8> {
    let mut buf = Vec::new();
    push_bytes(&mut buf, anchor_set_hash.as_bytes());
    push_i64s(&mut buf, box_lo);
    push_i64s(&mut buf, box_hi);
    buf
}

/// The fixed IDENTITY/SPEC of a DETERMINISTIC-FOREVER oracle — the invariant/relation it
/// deterministically enforces (the checker is code, not data; its identity is the PROPERTY).
/// `None` for an unknown kind (fail-closed — never a guessed spec). The bytes are the commitment
/// identity; the SPEC is public (no private artifact to upload).
#[must_use]
pub fn deterministic_oracle_spec(kind: &str) -> Option<&'static str> {
    match kind {
        RECONCILE_ORACLE_KIND => Some(
            "invariant: Sum(reserve)>=Sum(liability) AND NAV==Sum(qty*price); fail-closed (O-1, R1)",
        ),
        METAMORPHIC_ORACLE_KIND => Some(
            "metamorphic: summary subset-of source (quoted-span + number containment) + compression target; sound rejector (O-4, R2)",
        ),
        _ => None,
    }
}

/// The confidence percent `1 − δ` (e.g. `δ = 5/100 ⇒ 95`). Integer, from the conformal consts.
#[must_use]
fn confidence_pct() -> u64 {
    (crate::conformal::DELTA_DEN - crate::conformal::DELTA_NUM) * 100 / crate::conformal::DELTA_DEN
}

/// The honest iNFT `dataDescription` for a CERTIFIED oracle — names the oracle KIND, its typed
/// CERT, and its identity LABEL. Read back by `intelligentDatasOf` on chainscan. Honest: it names
/// a *certified* oracle's provenance, NOT per-user correctness (the §6.7 LOCK).
#[must_use]
pub fn oracle_descriptor(kind: &str, identity_label: &str, cert: &OracleCert) -> String {
    format!(
        "sinabro-oracle:{kind}; cert={}:CERTIFIED; identity={identity_label}",
        cert.label()
    )
}

/// ABI-encode the iNFT mint calldata for a certified oracle — COMPOSES the LOCKED W3 encoder
/// [`crate::zerog_inft::encode_mint_calldata`] (selector `0xa3acac17`; same `mint((string,
/// bytes32)[],address)` surface), with `dataHash` = the certified-oracle commitment and the
/// descriptor naming the oracle + cert. NO second mint path — the byte surface is the W3 golden.
#[must_use]
pub fn oracle_mint_calldata(descriptor: &str, data_hash: &[u8; 32], to: &[u8; 20]) -> Vec<u8> {
    encode_mint_calldata(descriptor, data_hash, to)
}

/// Build the OWNER-run runbook to mint a CERTIFIED oracle as an iNFT (PURE — only strings). The
/// agent emits these; the OWNER fires the funds-bearing mint with their own testnet key. The
/// availability leg is cert-aware (recognition uploads the encrypted anchor capital; a
/// deterministic oracle's spec is public). `proxy_addr`/`recipient` `None` ⇒ placeholders.
#[must_use]
pub fn oracle_mint_bundle_lines(
    kind: &str,
    data_hash: &[u8; 32],
    descriptor: &str,
    cert: &OracleCert,
    proxy_addr: Option<&str>,
    recipient: Option<&str>,
) -> Vec<String> {
    use crate::zerog_chain::{ZEROG_TESTNET_EVM_RPC, hex_encode};
    let data_hash_hex = hex_encode(data_hash);
    let calldata = oracle_mint_calldata(descriptor, data_hash, &GOLDEN_RECIPIENT);
    let proxy = proxy_addr.unwrap_or("<AgentNFT proxy — the W3 deploy>");
    let to = recipient.unwrap_or("<RECIPIENT — owner's fresh testnet address>");
    let availability = match cert {
        OracleCert::Conformal { .. } => {
            "  availability leg (owner, FUNDS): upload the ENCRYPTED oracle (checker + anchor capital) to 0G Storage"
        }
        OracleCert::DeterministicSound => {
            "  availability leg: the oracle is a FIXED deterministic checker — its SPEC is the public identity (no private artifact to upload)"
        }
    };
    vec![
        "0G certified-oracle iNFT mint PREPARE (O-5) — agent PREPARES, owner FIRES (PD-6 funds-lock)"
            .to_string(),
        "  an oracle is a verifiable, owned, tradeable asset (ERC-7857); this iNFT OWNS a CERTIFIED oracle"
            .to_string(),
        format!("  oracle kind : {kind}"),
        format!("  cert        : {} (certified — the mint precondition)", cert.label()),
        format!("  descriptor  : {descriptor} ({}B)", descriptor.len()),
        format!(
            "  dataHash    : 0x{data_hash_hex}  (deterministic certified-oracle commitment; re-derivable)"
        ),
        format!(
            "  mint        : {MINT_SIGNATURE}  (composes the LOCKED W3 encoder; calldata {} bytes)",
            calldata.len()
        ),
        String::new(),
        availability.to_string(),
        String::new(),
        "  owner mint on the EXISTING AgentNFT (FUNDS — owner key; mint is payable):".to_string(),
        format!("    cast send {proxy} \"{MINT_SIGNATURE}\" \\"),
        format!("      \"[(\\\"{descriptor}\\\",0x{data_hash_hex})]\" {to} \\"),
        format!("      --rpc-url {ZEROG_TESTNET_EVM_RPC} --legacy --gas-price 6000000000 \\"),
        "      --private-key $OG_TESTNET_PRIVATE_KEY".to_string(),
        String::new(),
        "  verify after mint (keyless read — the iNFT's bound certified oracle):".to_string(),
        format!(
            "    cast call {proxy} \"intelligentDatasOf(uint256)((string,bytes32)[])\" <TOKEN_ID> --rpc-url {ZEROG_TESTNET_EVM_RPC}"
        ),
        String::new(),
        "  the agent holds NO key; mainnet/funds HARD-LOCKED (the binary signs nothing).".to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    // a comfortably-certified conformal oracle: 0/12 ⇒ certify_far_default(0,12)=true (boundary n=10).
    fn conformal_cert() -> OracleCert {
        OracleCert::Conformal { k: 0, n: 12 }
    }
    fn rec_id() -> Vec<u8> {
        recognition_identity("abc123def456", &[0, 0], &[10, 10])
    }

    #[test]
    fn a_certified_conformal_oracle_gets_a_commitment() {
        assert!(oracle_data_hash(RECOGNITION_ORACLE_KIND, &rec_id(), &conformal_cert()).is_some());
    }

    /// THE MINT GATE (O-5 Q3): an UN-certified oracle has NO commitment — fail-closed (both kinds).
    #[test]
    fn an_uncertified_oracle_is_unmintable() {
        // conformal: 0/9 does NOT certify (the §6.5 n≈10 boundary: 0.73^9=0.0589>0.05).
        assert!(!OracleCert::Conformal { k: 0, n: 9 }.is_certified());
        assert!(
            oracle_data_hash(
                RECOGNITION_ORACLE_KIND,
                &rec_id(),
                &OracleCert::Conformal { k: 0, n: 9 }
            )
            .is_none(),
            "an un-certified (0/9) conformal oracle is UN-mintable"
        );
        // a held-out false-accept un-certifies too.
        assert!(!OracleCert::Conformal { k: 1, n: 12 }.is_certified());
    }

    /// THE DETERMINISTIC GATE: reconcile/metamorphic are SOUND BY CONSTRUCTION — certified iff the
    /// ladder CANARY is intact (it is, in a healthy build) ⇒ mintable. Distinct specs ⇒ distinct
    /// dataHashes; an unknown kind has no spec (fail-closed).
    #[test]
    fn deterministic_oracles_mint_when_canary_intact() {
        assert!(
            OracleCert::DeterministicSound.is_certified(),
            "the deterministic cert gate is canary_intact() (true in a healthy ladder)"
        );
        let rec_spec = deterministic_oracle_spec(RECONCILE_ORACLE_KIND).expect("reconcile spec");
        let meta_spec =
            deterministic_oracle_spec(METAMORPHIC_ORACLE_KIND).expect("metamorphic spec");
        assert!(
            deterministic_oracle_spec("nonexistent").is_none(),
            "unknown kind ⇒ no spec"
        );
        let r = oracle_data_hash(
            RECONCILE_ORACLE_KIND,
            rec_spec.as_bytes(),
            &OracleCert::DeterministicSound,
        )
        .expect("reconcile is mintable when canary intact");
        let m = oracle_data_hash(
            METAMORPHIC_ORACLE_KIND,
            meta_spec.as_bytes(),
            &OracleCert::DeterministicSound,
        )
        .expect("metamorphic is mintable");
        assert_ne!(
            r, m,
            "reconcile and metamorphic commit to distinct dataHashes"
        );
    }

    /// DETERMINISM + identity/cert binding: the same certified oracle ⇒ byte-identical commitment;
    /// a different identity OR a different cert ⇒ a different commitment.
    #[test]
    fn commitment_is_deterministic_and_identity_plus_cert_bound() {
        let a = oracle_data_hash(RECOGNITION_ORACLE_KIND, &rec_id(), &conformal_cert()).unwrap();
        let b = oracle_data_hash(RECOGNITION_ORACLE_KIND, &rec_id(), &conformal_cert()).unwrap();
        assert_eq!(a, b, "same certified oracle ⇒ same dataHash");
        // a different identity ⇒ a different commitment.
        let c = oracle_data_hash(
            RECOGNITION_ORACLE_KIND,
            &recognition_identity("DIFFERENT0001", &[0, 0], &[10, 10]),
            &conformal_cert(),
        )
        .unwrap();
        assert_ne!(a, c, "a different anchor-set commits to a different oracle");
        // the cert is part of identity: a Conformal vs a (hypothetical) different cert ⇒ different.
        let d = oracle_data_hash(
            RECOGNITION_ORACLE_KIND,
            &rec_id(),
            &OracleCert::Conformal { k: 0, n: 20 },
        )
        .unwrap();
        assert_ne!(
            a, d,
            "the certification evidence (n) is part of the identity"
        );
    }

    #[test]
    fn descriptor_names_the_oracle_and_its_typed_cert() {
        let d = oracle_descriptor(RECOGNITION_ORACLE_KIND, "abc123def456", &conformal_cert());
        assert!(d.contains("sinabro-oracle:recognition"));
        assert!(d.contains("cert=conformal(FAR<=27/100@95%,k=0,n=12):CERTIFIED"));
        assert!(d.contains("identity=abc123def456"));
        // a deterministic oracle's descriptor names the deterministic-sound cert.
        let dd = oracle_descriptor(
            RECONCILE_ORACLE_KIND,
            "deadbeef",
            &OracleCert::DeterministicSound,
        );
        assert!(dd.contains("sinabro-oracle:reconcile"));
        assert!(dd.contains("cert=deterministic-sound(canary-intact):CERTIFIED"));
    }

    #[test]
    fn mint_calldata_composes_the_locked_w3_encoder() {
        let descriptor =
            oracle_descriptor(RECOGNITION_ORACLE_KIND, "abc123def456", &conformal_cert());
        let dh = oracle_data_hash(RECOGNITION_ORACLE_KIND, &rec_id(), &conformal_cert()).unwrap();
        let cd = oracle_mint_calldata(&descriptor, &dh, &GOLDEN_RECIPIENT);
        // byte-identical to the LOCKED W3 encoder — NO second mint surface, the golden 0xa3acac17.
        assert_eq!(
            cd,
            encode_mint_calldata(&descriptor, &dh, &GOLDEN_RECIPIENT)
        );
        assert_eq!(&cd[0..4], &crate::zerog_inft::MINT_SELECTOR);
        assert_eq!(&cd[164..196], &dh); // dataHash in the bytes32 slot
    }

    #[test]
    fn mint_bundle_is_owner_run_and_funds_safe_for_both_cert_kinds() {
        for (kind, cert, avail_needle) in [
            (RECOGNITION_ORACLE_KIND, conformal_cert(), "anchor capital"),
            (
                RECONCILE_ORACLE_KIND,
                OracleCert::DeterministicSound,
                "FIXED deterministic checker",
            ),
        ] {
            let dh = [0x11u8; 32];
            let descriptor = oracle_descriptor(kind, "idlabel0", &cert);
            let blob =
                oracle_mint_bundle_lines(kind, &dh, &descriptor, &cert, None, None).join("\n");
            assert!(blob.contains("agent PREPARES, owner FIRES"));
            assert!(blob.contains("$OG_TESTNET_PRIVATE_KEY")); // env-ref, never a value
            assert!(blob.contains("HARD-LOCKED"));
            assert!(
                blob.contains(avail_needle),
                "cert-aware availability leg: {kind}"
            );
            assert!(!blob.contains("PRIVATE_KEY=")); // no key VALUE
        }
    }
}
