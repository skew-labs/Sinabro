//! Signed-package property tests — atom #253 · D.0.12.
//!
//! Property: every generated package either canonicalizes into a unique
//! content digest or rejects with a stable reason — no ambiguous middle
//! (§253 광기). The headline totality property runs the §253 "10k generated
//! cases" criterion; the typed properties cover the schema, signature
//! mutation, forbidden-commerce, capability-mask, provenance-graph,
//! SBOM-mutation, and trust-state generators (§253 test list).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use mnemos_c_walrus::codec::SignatureBytes;
use mnemos_d_move::types::SuiAddress;
use mnemos_m_agent::tool_schema::ToolId;

use mnemos_e_skill::capability_diff::{CapabilityDiff, a_capabilities_for_mask};
use mnemos_e_skill::eval::{MAX_EVAL_SCORE, SkillEvalScore, reproducible_command_hash};
use mnemos_e_skill::package::{
    SkillPackageDigest32, SkillPackageV1, SkillSecurityState, SkillSupplyChainReceipt,
};
use mnemos_e_skill::package_policy::{
    FORBIDDEN_COMMERCE_EXACT, FORBIDDEN_COMMERCE_SUBSTRINGS, no_commerce_policy_hash,
    scan_no_commerce,
};
use mnemos_e_skill::provenance::{MAX_PROVENANCE_DEPTH, ProvenanceNode};
use mnemos_e_skill::signature::SkillPackageSignature;
use mnemos_e_skill::verify::{VerifyError, sample_valid_package_toml, verify_skill_package};

// A small typed valid package builder parameterized by tests_digest, so we
// can exercise digest uniqueness without re-rendering TOML.
fn typed_package(tests_digest: [u8; 32]) -> (SkillPackageV1, SuiAddress, [u8; 32]) {
    let manifest = mnemos_e_skill::manifest::load_manifest(
        "id = 7\nname = \"p\"\nversion = 1\ntool_ids = [1]\ntoken_cost_estimate = 1\n",
    )
    .expect("manifest");
    let author = SuiAddress::new([0x11; 32]);
    let pkg = SkillPackageV1 {
        manifest: manifest.clone(),
        capability_diff: CapabilityDiff::new(0, 0, vec![ToolId(1)]),
        eval: SkillEvalScore {
            rust_u16: 1,
            move_u16: 1,
            prover_u16: 1,
            gas_u16: 1,
            security_u16: 1,
            korean_u16: 1,
            reproducible_command_hash_32: reproducible_command_hash(&["x"]),
        },
        provenance: ProvenanceNode {
            skill: manifest.id(),
            package: SkillPackageDigest32::new([0xA0; 32]),
            parent: None,
            author,
            provenance_depth_u16: 0,
        },
        supply_chain: SkillSupplyChainReceipt {
            sbom_hash_32: [1; 32],
            reproducible_build_hash_32: [2; 32],
            dependency_lock_hash_32: [3; 32],
            deny_audit_hash_32: [4; 32],
            license_hash_32: [5; 32],
            build_script_network_denied: true,
        },
        tests_digest_32: tests_digest,
        artifact_digest_32: [0xAF; 32],
        signature: SkillPackageSignature::new(SignatureBytes([0u8; 64])),
    };
    let compat_digest = [0x42u8; 32];
    (pkg, author, compat_digest)
}

proptest! {
    // §253 headline: the verifier is a total function over arbitrary bytes.
    // 10_000 generated cases.
    #![proptest_config(ProptestConfig { cases: 10_000, ..ProptestConfig::default() })]

    #[test]
    fn verify_is_total_and_deterministic(s in prop_oneof![
        any::<String>(),
        "\\PC{0,200}",
        "[a-z_]{1,10} = [0-9]{1,6}\\n",
        Just(sample_valid_package_toml()),
    ]) {
        // Never panics; returns the same verdict twice (stable reason).
        let a = verify_skill_package(&s);
        let b = verify_skill_package(&s);
        prop_assert_eq!(a, b, "verdict must be deterministic");
    }
}

proptest! {
    // capability mask: CapabilityDiff::new is always self-consistent and its
    // A-capability projection equals the canonical mask projection.
    #[test]
    fn capability_mask_is_always_consistent(
        added in any::<u64>(),
        removed in any::<u64>(),
        tools in prop::collection::vec(any::<u16>(), 0..8),
    ) {
        let tool_ids: Vec<ToolId> = tools.into_iter().map(ToolId).collect();
        let diff = CapabilityDiff::new(added, removed, tool_ids);
        prop_assert!(diff.is_consistent());
        prop_assert_eq!(&diff.a_capabilities, &a_capabilities_for_mask(added));
    }

    // eval: is_valid exactly matches the spec predicate.
    #[test]
    fn eval_validity_matches_predicate(
        axes in prop::array::uniform6(0u16..=20_000),
        has_hash in any::<bool>(),
    ) {
        let score = SkillEvalScore {
            rust_u16: axes[0],
            move_u16: axes[1],
            prover_u16: axes[2],
            gas_u16: axes[3],
            security_u16: axes[4],
            korean_u16: axes[5],
            reproducible_command_hash_32: if has_hash { [9u8; 32] } else { [0u8; 32] },
        };
        let expected = has_hash && axes.iter().all(|&a| a <= MAX_EVAL_SCORE);
        prop_assert_eq!(score.is_valid(), expected);
    }

    // provenance graph: is_well_formed matches the spec predicate and the
    // digest is deterministic.
    #[test]
    fn provenance_well_formed_matches_predicate(
        skill in any::<u16>(),
        pkg in prop::array::uniform32(any::<u8>()),
        has_parent in any::<bool>(),
        parent in prop::array::uniform32(any::<u8>()),
        author in prop::array::uniform32(any::<u8>()),
        depth in 0u16..=2_000,
    ) {
        let node = ProvenanceNode {
            skill: mnemos_e_skill::SkillId(skill),
            package: SkillPackageDigest32::new(pkg),
            parent: if has_parent { Some(SkillPackageDigest32::new(parent)) } else { None },
            author: SuiAddress::new(author),
            provenance_depth_u16: depth,
        };
        let author_nonzero = author != [0u8; 32];
        let depth_ok = depth <= MAX_PROVENANCE_DEPTH;
        let expected = author_nonzero && depth_ok && match node.parent {
            None => depth == 0,
            Some(p) => depth >= 1 && *p.as_bytes() != pkg,
        };
        prop_assert_eq!(node.is_well_formed(), expected);
        // Determinism: the predicate is a pure function of the node.
        prop_assert_eq!(node.is_well_formed(), node.is_well_formed());
    }

    // SBOM mutation: zeroing any supply-chain hash makes the receipt incomplete.
    #[test]
    fn sbom_mutation_breaks_completeness(which in 0usize..5) {
        let mut r = SkillSupplyChainReceipt {
            sbom_hash_32: [1; 32],
            reproducible_build_hash_32: [2; 32],
            dependency_lock_hash_32: [3; 32],
            deny_audit_hash_32: [4; 32],
            license_hash_32: [5; 32],
            build_script_network_denied: true,
        };
        prop_assert!(r.is_complete());
        match which {
            0 => r.sbom_hash_32 = [0; 32],
            1 => r.reproducible_build_hash_32 = [0; 32],
            2 => r.dependency_lock_hash_32 = [0; 32],
            3 => r.deny_audit_hash_32 = [0; 32],
            _ => r.license_hash_32 = [0; 32],
        }
        prop_assert!(!r.is_complete());
    }

    // trust-state: only Quarantined/Revoked are non-installable.
    #[test]
    fn trust_state_installability(tag in 1u8..=5) {
        let st = match tag {
            1 => SkillSecurityState::Unknown,
            2 => SkillSecurityState::SandboxPass,
            3 => SkillSecurityState::AuditPass,
            4 => SkillSecurityState::Quarantined,
            _ => SkillSecurityState::Revoked,
        };
        let expected = !matches!(tag, 4 | 5);
        prop_assert_eq!(st.is_installable(), expected);
    }

    // digest uniqueness: two packages differing only in tests_digest produce
    // different content digests (no ambiguous middle).
    #[test]
    fn distinct_content_yields_distinct_digest(
        a in prop::array::uniform32(any::<u8>()),
        b in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(a != b);
        let (pa, _, cda) = typed_package(a);
        let (pb, _, cdb) = typed_package(b);
        let da = pa.content_digest(no_commerce_policy_hash(), cda);
        let db = pb.content_digest(no_commerce_policy_hash(), cdb);
        prop_assert_ne!(da.as_bytes(), db.as_bytes());
    }

    // signature mutation: flipping any signature nibble breaks verification
    // of an otherwise-valid package.
    #[test]
    fn signature_mutation_rejects(nibble_idx in 0usize..128) {
        let fixture = sample_valid_package_toml();
        // Locate the signature hex (after `bytes = "`).
        let marker = "bytes = \"";
        let start = fixture.rfind(marker).expect("sig marker") + marker.len();
        let mut chars: Vec<char> = fixture.chars().collect();
        let sig_char_pos = fixture[..start].chars().count() + nibble_idx;
        let orig = chars[sig_char_pos];
        // Flip to a different hex digit (keep it hex so we reach Signature,
        // not Encoding). The map ('0'->'1', else->'0') never fixes a point.
        let replacement = if orig == '0' { '1' } else { '0' };
        chars[sig_char_pos] = replacement;
        let mutated: String = chars.into_iter().collect();
        prop_assert_ne!(&mutated, &fixture);
        prop_assert_eq!(verify_skill_package(&mutated), Err(VerifyError::Signature));
    }

    // forbidden-commerce (substring list): any forbidden substring embedded
    // in a key rejects — both standalone and through the full verifier.
    #[test]
    fn forbidden_commerce_substring_rejects(idx in 0usize..FORBIDDEN_COMMERCE_SUBSTRINGS.len()) {
        let token = FORBIDDEN_COMMERCE_SUBSTRINGS[idx];
        let key = format!("{token}_field");
        let toml_text = format!("name_hash = \"x\"\n{key} = 1\n");
        prop_assert!(scan_no_commerce(&toml_text).is_err());
        // And via the full verifier in the extensions table.
        let pkg = format!("{}\n[extensions]\n{key} = 1\n", sample_valid_package_toml());
        prop_assert_eq!(verify_skill_package(&pkg), Err(VerifyError::Commerce));
    }

    // forbidden-commerce (exact list): any exact forbidden key rejects. The
    // exact tokens only match a whole key, so the key IS the token.
    #[test]
    fn forbidden_commerce_exact_rejects(idx in 0usize..FORBIDDEN_COMMERCE_EXACT.len()) {
        let token = FORBIDDEN_COMMERCE_EXACT[idx];
        let toml_text = format!("name_hash = \"x\"\n{token} = 1\n");
        prop_assert!(scan_no_commerce(&toml_text).is_err());
        let pkg = format!("{}\n[extensions]\n{token} = 1\n", sample_valid_package_toml());
        prop_assert_eq!(verify_skill_package(&pkg), Err(VerifyError::Commerce));
    }
}
