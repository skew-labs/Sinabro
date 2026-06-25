//! `zerog_finetune` — 0G Compute fine-tune PREPARE for a sinabro expert (W3-B).
//!
//! This is where the two lanes MERGE: the self-evolving orchestrator's ONLY-verified
//! patterns (the R-E-W WRITE corpus — see [`crate::autonomy_evolve`]) become the training
//! set for a REAL LoRA expert, fine-tuned on **0G Compute**, that then replaces the stub
//! internal executor and is minted as an ERC-7857 iNFT (W3, `zerog_inft`). It PREPARES the
//! fine-tune; it never performs the (paid) training run.
//!
//! ## what this targets (pinned to the package, not the docs — the W2-B lesson)
//! `0g-compute-cli` (bin of `@0gfoundation/0g-compute-ts-sdk@0.8.4`). Flow (package-
//! grounded): `uploadDataset(privateKey, dataPath) → datasetRootHash` → `createTask(
//! preTrainedModel, datasetType, config)` → poll → `acknowledge*` → `download` +
//! `decryptModel`. Dataset = a `.jsonl`; `datasetType` ∈ {`alpaca`, `chatml`}; fixed bases
//! `Qwen2.5-0.5B-Instruct` / `Qwen3-32B`; output = encrypted weights (decrypt + serve
//! locally — 0G does not host your tuned expert). TEE-trust, not ZK; no from-scratch.
//!
//! ## funds-safe posture (PD-6 — the agent NEVER holds a signing key)
//! `uploadDataset` + `createTask` are gas/fee-bearing 0G txs needing a key = FUNDS. So this
//! module is **100% PURE**: it only (a) builds the Alpaca `.jsonl` from the owner's already-
//! verified patterns and (b) emits the exact OWNER-RUN `0g-compute-cli fine-tuning` command
//! sequence. No network, no key, no `reqwest`, no feature, no subprocess — nothing here can
//! spend. The paid training runs OUTSIDE the binary (the owner's `0g-compute-cli` with their
//! own compute account). `CustodyCapability` stays uninhabited; names no custody symbol.
//!
//! ## ★ the P-HALL discipline carries into training (honest scope)
//! The dataset is built ONLY from patterns the deterministic ORACLE verified + that were
//! cross-memory-consistent (the `autonomy_evolve` WRITE gate). The model's un-verified text
//! never becomes training data — so the fine-tune reinforces *oracle-verified* behaviour,
//! not self-reported "success". This proves OWNED, VERIFIED-PROVENANCE training data; it
//! does NOT prove the resulting model is correct (that stays the runtime oracle's job).

/// The fixed 0G Compute fine-tune base model (the smaller of the two fixed bases — tiny +
/// cheap for the first expert). The other fixed base is `Qwen3-32B`.
pub const FINETUNE_BASE_MODEL: &str = "Qwen2.5-0.5B-Instruct";

/// The 0G fine-tune dataset type for single-turn (instruction → output) examples.
pub const FINETUNE_DATASET_TYPE: &str = "alpaca";

/// The local dataset filename written under the data dir (the owner uploads this).
pub const FINETUNE_DATASET_FILE: &str = "finetune_dataset.jsonl";

/// Escape a string for a JSON string literal (std-only — the default/offline build does
/// not link `serde_json`). Handles the control + special chars so verified content with
/// quotes/newlines/tabs/unicode (e.g. Move source) is a valid JSON value.
#[must_use]
pub fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// One Alpaca SFT row: `{"instruction":<i>,"input":"","output":<o>}` (single-turn, the
/// `input` field empty). Each value is JSON-escaped. Single-line (a JSONL row).
#[must_use]
pub fn alpaca_row(instruction: &str, output: &str) -> String {
    format!(
        "{{\"instruction\":\"{}\",\"input\":\"\",\"output\":\"{}\"}}",
        json_escape(instruction),
        json_escape(output)
    )
}

/// Build the Alpaca `.jsonl` training set from `(instruction, output)` pairs (one row per
/// line, trailing newline). The caller passes ONLY oracle-verified patterns (the
/// `autonomy_evolve` corpus) — this function does not invent or trust any content.
#[must_use]
pub fn export_alpaca_jsonl(pairs: &[(String, String)]) -> String {
    let mut out = String::with_capacity(pairs.len() * 64);
    for (instruction, output) in pairs {
        out.push_str(&alpaca_row(instruction, output));
        out.push('\n');
    }
    out
}

/// Build the OWNER-runbook lines for the W3-B fine-tune (PURE — only strings). The agent
/// writes the dataset + emits these; the OWNER runs the funds-bearing `0g-compute-cli
/// fine-tuning` flow with their own compute account. `dataset_path` is the written `.jsonl`;
/// `n_examples` the verified-pattern count.
#[must_use]
pub fn finetune_bundle_lines(dataset_path: &str, n_examples: usize) -> Vec<String> {
    vec![
        "0G Compute fine-tune PREPARE (W3-B) — agent PREPARES, owner FIRES (PD-6 funds-lock)"
            .to_string(),
        format!(
            "  dataset     : {dataset_path} ({n_examples} verified-pattern examples, {FINETUNE_DATASET_TYPE})"
        ),
        "                (built ONLY from oracle-verified + cross-memory-consistent patterns".to_string(),
        "                 — the autonomy_evolve WRITE corpus; un-verified text never trains)".to_string(),
        format!("  base model  : {FINETUNE_BASE_MODEL} (fixed 0G base; other = Qwen3-32B)"),
        "  CLI         : 0g-compute-cli (bin of @0gfoundation/0g-compute-ts-sdk@0.8.4)".to_string(),
        String::new(),
        "  owner fine-tune (FUNDS — the owner runs this, never the agent; compute account at".to_string(),
        "  pc.testnet.0g.ai / pc.0g.ai; exact flags: `0g-compute-cli fine-tuning --help`):".to_string(),
        format!(
            "    1. upload dataset → datasetRootHash:  0g-compute-cli ... uploadDataset {dataset_path}"
        ),
        "         (signs an upload tx with $OG_TESTNET_PRIVATE_KEY — FUNDS; 0G gas gotcha:".to_string(),
        "          pass an explicit --gas-price ~6gwei, base fee is ~0 so auto-estimate fails)".to_string(),
        format!(
            "    2. create task: base={FINETUNE_BASE_MODEL} datasetType={FINETUNE_DATASET_TYPE} datasetRootHash=<from 1> +config"
        ),
        "         (config = SFT/LoRA: num_train_epochs, learning_rate, batch — owner tunes)".to_string(),
        "    3. poll the task → 4. acknowledge → 5. download + decryptModel → local LoRA adapter"
            .to_string(),
        String::new(),
        "  then (follow-on slices, agent-buildable):".to_string(),
        "    • serve the decrypted LoRA on a local server (ollama/vLLM/MLX, owner box) and add".to_string(),
        "      it to the executor routing table as a real model_id (replaces the stub expert)".to_string(),
        "    • mint the expert as an ERC-7857 iNFT (W3 `memory mint-0g`): dataHash = the".to_string(),
        "      adapter's 0G Storage rootHash, descriptor names base + training provenance".to_string(),
        String::new(),
        "  the agent holds NO key; the dataset is the owner's own verified corpus (local file,".to_string(),
        "  owner reviews before upload); mainnet/funds HARD-LOCKED (the binary holds no signing key)."
            .to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_escape_handles_control_and_special_chars() {
        assert_eq!(json_escape("plain"), "plain");
        assert_eq!(json_escape("a\"b"), "a\\\"b");
        assert_eq!(json_escape("a\\b"), "a\\\\b");
        assert_eq!(json_escape("line1\nline2"), "line1\\nline2");
        assert_eq!(json_escape("tab\there"), "tab\\there");
        assert_eq!(json_escape("cr\r"), "cr\\r");
        // a control char below 0x20 (not one of the named escapes) → \u00XX.
        assert_eq!(json_escape("\u{01}"), "\\u0001");
        // unicode passes through (valid in a JSON string).
        assert_eq!(json_escape("café 한글"), "café 한글");
    }

    #[test]
    fn alpaca_row_is_valid_single_line_json() {
        let row = alpaca_row("sui_move: build a counter", "module a::c {}");
        assert_eq!(
            row,
            "{\"instruction\":\"sui_move: build a counter\",\"input\":\"\",\"output\":\"module a::c {}\"}"
        );
        // exactly one line (no embedded raw newline — the JSONL invariant).
        assert!(!row.contains('\n'));
    }

    #[test]
    fn alpaca_row_escapes_code_with_quotes_and_newlines() {
        // verified Move content with a string literal + a newline must stay one JSON line.
        let content = "module a::c {\n  let s = b\"hi\";\n}";
        let row = alpaca_row("g", content);
        assert!(
            !row.contains('\n'),
            "embedded newline must be escaped to \\n"
        );
        assert!(row.contains("\\n"));
        assert!(row.contains("b\\\"hi\\\""), "inner quotes escaped");
    }

    #[test]
    fn export_jsonl_is_one_row_per_line() {
        let pairs = vec![
            ("g1".to_string(), "o1".to_string()),
            ("g2".to_string(), "o2".to_string()),
        ];
        let jsonl = export_alpaca_jsonl(&pairs);
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("{\"instruction\":\"g1\""));
        assert!(lines[1].starts_with("{\"instruction\":\"g2\""));
        assert!(jsonl.ends_with('\n'));
        // empty corpus ⇒ empty dataset (no rows).
        assert_eq!(export_alpaca_jsonl(&[]), "");
    }

    #[test]
    fn bundle_is_owner_run_and_funds_safe() {
        let lines = finetune_bundle_lines("/data/finetune_dataset.jsonl", 7);
        let blob = lines.join("\n");
        assert!(blob.contains("agent PREPARES, owner FIRES"));
        assert!(blob.contains(FINETUNE_BASE_MODEL));
        assert!(blob.contains("datasetType=alpaca"));
        assert!(blob.contains("7 verified-pattern examples"));
        assert!(blob.contains("0g-compute-cli fine-tuning --help"));
        // funds-safety + the P-HALL provenance + the gas gotcha are stated.
        assert!(blob.contains("$OG_TESTNET_PRIVATE_KEY"));
        assert!(blob.contains("oracle-verified"));
        assert!(blob.contains("HARD-LOCKED"));
        assert!(blob.contains("gas gotcha") || blob.contains("--gas-price"));
        // no private key VALUE, only an env reference.
        assert!(!blob.contains("0xbc7c"));
    }
}
