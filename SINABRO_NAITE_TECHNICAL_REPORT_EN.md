# Sinabro and Naite Technical Report

> A local-first, evidence-gated coding agent and training system
>
> Draft v0.1 | May 26, 2026

## Abstract

Sinabro is a local-first coding agent that runs close to a developer's workspace, tools, credentials, memory, and approval boundaries. Naite is the project coding model trained from the evidence Sinabro produces. The two systems are deliberately separated: Sinabro is the control plane, and Naite is an accelerator that can be replaced, upgraded, or bypassed without changing the safety model.

The central claim of this report is that a capable coding agent should not be judged only by model benchmarks or chat quality. It should be judged by the quality of the loop it operates: reading a codebase, reducing a task into atomic work units, implementing changes, running tests and static analysis, collecting proof, refusing unsafe actions, preserving user-owned memory, and turning verified work into training data. Sinabro is the agent layer for that loop. Naite is trained only from data that survives the loop.

The current design targets Rust, Move, Sui, Walrus, local command execution, web research with citations, skill discovery, wallet/gas policy, and long-context coding workflows. The system is open-source by default, conservative by default, and opt-in for any learning artifact that leaves a user's machine.

This document is a design report, not a deployment claim. Implementation status is tracked separately through stage build states, gate results, and evidence bundles.

## 1. Motivation

Most coding agents still have weak continuity. They can solve a local problem, but the work product is often a patch plus an informal transcript. The transcript may contain useful reasoning, failed attempts, command output, performance data, security decisions, and human feedback, but those signals are rarely normalized. They are difficult to audit and difficult to train on.

Sinabro starts from a different assumption: the unit of progress is not a chat turn. It is an evidence-bearing atom. An atom is small enough to review and large enough to merge. It has a target file, one canonical output, explicit tests, gates, reuse constraints, and a pointer to the next atom. Every atom leaves a sidecar that records what was attempted, what was denied, what passed, what failed, and why the result is safe to carry forward.

This gives the project a concrete path from agent work to model improvement. Naite is not trained on vague praise or self-reported success. It is trained on traces that include compiler results, test outcomes, Move Prover signals, gas measurements, red-team decisions, dependency audits, approval events, and rejected actions.

## 2. Scope and Status

The public product names are Sinabro for the agent and Naite for the project coding model.

The initial release track covers Stages A through H:

- Stage A: core runtime, trace collection, Telegram and CLI foundations.
- Stage B: memory ownership on testnet through signed chunks, Walrus, and Sui anchors.
- Stage C: GA hardening, mainnet gates, gas policy, key isolation.
- Stage D: skill runtime, open registry, provenance, install receipts, memory intelligence.
- Stage E: dataset builder and training-rights firewall.
- Stage F: CLI cockpit and first-run user experience.
- Stage G: first A100 fine-tuning pass for Naite.
- Stage H: vLLM serving, router integration, and no-silent-fallback proof.

Stages I through K extend the system into read-only mainnet measurement, public open-source readiness, controlled self-improvement, and later model/GPU promotion. They are not required for the first working open-source release.

The plan intentionally excludes several tempting paths from the initial release surface. There is no paid skill marketplace, no unapproved chain write, no silent provider fallback, no Solana/Anchor tool execution, and no training on private user data by default.

## 3. Design Principles

### 3.1 Agent first

Sinabro must remain useful with an external model, a local model, or no fine-tuned model at all. The agent owns the workflow: tool permissions, memory retrieval, routing, budget policy, trace collection, and user approval. Naite improves the agent, but it does not become the authority.

### 3.2 Evidence over narration

A green status must point to concrete evidence. Examples include command output, artifact hashes, test reports, prover results, gas traces, redaction reports, and approval receipts. A model statement such as "tests passed" is not evidence.

### 3.3 User-owned memory

Long-term memory is treated as a user-owned asset rather than a model artifact. Walrus provides blob storage, and Sui anchors memory roots and audit events. A model can be swapped, but the memory root remains.

### 3.4 No silent side effects

Sinabro does not silently execute tools, install skills, spend gas, sign transactions, publish packages, switch providers, or fall back to a different model. Side effects require explicit capability checks, policy gates, budget checks, and user-visible traces.

### 3.5 Learning is opt-in

Open-source users may choose no learning artifacts, local-only evidence, a private Naite diet, a private adapter, or redacted public contribution. The default is no data egress and no training artifact generation.

## 4. System Overview

Sinabro is organized as a local control plane around a Rust core.

```text
User
  -> CLI / TUI / Telegram
  -> CommandEnvelope / MessageEnvelope
  -> Sinabro Rust Core
       - runtime supervisor
       - tool dispatcher
       - provider and model router
       - memory engine
       - skill runtime
       - wallet and gas policy
       - evidence collector
  -> Model backend
       - external provider
       - local Naite
       - vLLM endpoint
  -> Substrates
       - cargo, clippy, miri, Kani
       - Sui CLI, Move tests, Move Prover
       - Walrus
       - web research and browser tools
  -> Evidence bundle
  -> Dataset builder
  -> Naite training and evaluation
```

The router can call external providers or local models, but tool authority remains outside the model. A model may propose a command, web search, memory write, skill install, or transaction. Sinabro decides whether the proposal is executable.

## 5. The Atom Protocol

An atom is the smallest planned unit that can produce a meaningful, reviewable change. The Stage A atom grammar has nine fields:

- `id`: atom number and PR identifier.
- `file`: target files.
- `canonical OUT`: the single canonical artifact produced by the atom.
- `constraint spec`: strict performance, safety, boundary, and unit constraints.
- `tests`: required tests or explicit `not_verified` entries.
- `criterion`: the condition for accepting the atom.
- `gate`: the gate identifier used to verify the atom.
- `reuse`: canonical inputs that must not be reinvented.
- `next-atom`: the next dependency pointer.

The protocol is deliberately narrow. It prevents broad, unfalsifiable work from entering the main plan. It also makes each implementation step trainable: the model can see the task, the context, the change, the tests, the review, and the outcome.

## 6. Evidence Sidecars

Each atom writes a sidecar directory under `ops/training/{phase_or_stage}/atom_###/`.

```text
input_context.md
action_trace.jsonl
command_manifest.json
terminal_redacted.log
env_lock.json
artifact_hashes.json
code_diff.patch
failed_attempts.jsonl
no_op_decisions.jsonl
test_results.json
gate_results.json
review_5pack.json
deny_audit.json
redteam_decision.json
human_review.json
approval_events.jsonl
privacy_report.json
sft_chat.jsonl
preference_pairs.jsonl
reward_labels.json
eval_summary.json
```

These files form an `AtomDietRecord`. The sidecar is not an afterthought; it is part of the definition of done. In particular:

- `review_5pack.json` records performance, security, chain, agent-token budget, and developer-experience review.
- `deny_audit.json` records dependency, license, advisory, ban, and source checks.
- `terminal_redacted.log` records command output without leaking secrets.
- `reward_labels.json` distinguishes verified success from self-report, infra failure, policy denial, and unsafe behavior.

Only data that passes rights, redaction, and verification gates can become Naite training data. Private memory, secrets, provider bodies, sponsor keys, payment material, and rights-unclear web content are excluded.

## 7. Memory and Replay

Sinabro's memory design separates user continuity from model weights.

Messages, tool results, skill artifacts, and system memories are encoded as typed chunks. The chunks can be stored through Walrus, verified by local digest and blob-id checks, and anchored through Sui `memory_root` and `audit_log` objects. Replay is accepted only if the reconstructed transcript hash matches the expected evidence.

This structure has three goals:

1. Keep memory portable across model upgrades.
2. Make memory ownership auditable.
3. Prevent unverified bytes from entering retrieval or training paths.

The memory engine later adds importance scoring, compaction, deletion semantics, export/import, and deterministic replay. These operations are visible through CLI commands and evidence records.

## 8. Skills

The initial skill system is adoption-first, not commerce-first. The initial release scope does not include `skill buy`, checkout, paid licenses, refunds, royalties, or revenue sharing. A later marketplace can be proposed only after the open registry has real usage.

The planned skill commands are:

- `skill search`
- `skill inspect`
- `skill recommend`
- `skill use`
- `skill install`
- `skill enable`
- `skill disable`
- `skill update`
- `skill remove`
- `skill fork`
- `skill publish`
- `skill eval`
- `skill provenance`

Search uses progressive disclosure. The first response shows a compact card: name, description, capability summary, compatibility, evaluation status, security status, provenance, verified installs, and permission diff. Full manifests, WASM metadata, documentation, and eval logs are loaded only after selection.

Skill execution requires capability checks and user confirmation. Install receipts, provenance, malicious fixture tests, and compatibility checks are part of the registry model. A skill cannot become trusted because it is popular; verified installs require evidence.

## 9. Tools, Web Research, and Routing

Sinabro treats tools as proposed side effects, not model privileges. A model-generated tool call moves through this sequence:

```text
proposal -> capability diff -> policy gate -> budget gate -> approval -> execution -> evidence
```

Web research has a similar rule. A search result is not a source of truth unless it carries:

- source URL
- retrieval time
- fetch hash
- rights or robots decision
- citation evidence
- credential redaction status

This matters for public releases. Web content can guide an answer, but it should not silently become training data. Public Naite training candidates must pass source, rights, and redaction checks.

Provider routing follows the same evidence standard. Sinabro may support OpenAI, Anthropic, Gemini, local Naite, and vLLM endpoints, but a fallback must be explicit. The user should be able to see which model answered, why it was selected, what it cost, and whether any privacy boundary changed.

## 10. Wallet, Gas, and Chain Safety

The gasless user experience is designed around a keyless open-source client and a policy-gated Gas Station. Sponsor keys do not appear in the repository, client binary, container image, or documentation examples.

The Gas Station assumes its endpoint is public. Security is not based on hiding a URL. It is based on making unsafe signatures unreachable.

Core invariants include:

- No raw `GasData` lending endpoint.
- No signing of opaque transaction bytes.
- Package and function allowlists.
- Exact effect-shape checks through dry-run or dev-inspect.
- Gas, storage, object count, command count, and failure caps.
- Per-user, per-wallet, per-IP, per-ASN, per-package, per-skill, per-epoch, and global burn quotas.
- One gas coin lease per transaction.
- Small hot wallet balances behind cold treasury and multisig refill.
- Automatic pause on anomaly signals such as dry-run failure spikes or gas coin lock spikes.

Gas sponsorship is separated from skill usage. The initial release plan allows bounded memory, audit, and registry writes under policy. It does not pay skill prices or unlock paid content.

## 11. Training Naite

Naite training begins only after Stage E produces a valid unlock packet. Stage G starts with SFT smoke tests on an A100 using a Strand-14B lineage and QLoRA/LoRA style training. Reinforcement-style methods such as GRPO, MURPHY, or FGO remain locked until the SFT path passes evaluation.

Promotion is not based on loss alone. A candidate must preserve or improve results across:

- Rust compile and test outcomes.
- `cargo clippy`, `cargo miri`, fuzz, and property tests.
- Kani checks.
- Move tests and Move Prover repair.
- Gas and byte-size behavior.
- Walrus integrity tasks.
- Korean technical instruction following.
- Long-context retrieval and packing tests.
- Held-out security and optimization tasks.

The training split distinguishes verifiable data from narrative data. Compiler and prover output can support reward labels. Self-report, praise, and unsupported summaries cannot. Infrastructure failures such as OOM or provider timeout are masked rather than treated as model failures.

## 12. Evaluation

The evaluation plan combines model quality, agent behavior, and system safety.

| Area | Examples |
| --- | --- |
| Rust | fmt, clippy, test, miri, fuzz, criterion, Kani |
| Move and Sui | move test, Move Prover, BCS parity, gas trace, owner invariants |
| Walrus | PUT/GET round trip, blob-id derivation, integrity verification |
| Memory | replay determinism, transcript hashes, deletion and export semantics |
| Skills | malicious fixtures, capability diffs, signed package checks, no-commerce scans |
| Web | source metadata, retrieval hashes, rights checks, credential redaction |
| Router | no silent fallback, route receipts, cost and quality scorecards |
| Gas | allowlist, dry-run, quotas, gas caps, coin leases, hot-wallet burn caps |
| Dataset | PII0, secret0, S1/S2 split, reward firewall, dependency audit |
| Korean | technical parity with equivalent English prompts |

The strongest evaluation target is not memorization of the project itself. The system must improve on held-out Rust, Move, gas, security, and Korean-language technical tasks without relaxing safety gates.

## 13. Open-Source Controls

Sinabro is intended to be open-source and user-controlled. The default configuration is conservative:

```toml
mode = "off" # off | evidence_only | local_diet | private_adapter | contribute_redacted
external_model_output_training = "never"
```

Users may run Sinabro without producing training artifacts. They may also choose local evidence, a private Naite dataset, a private adapter, or an explicitly redacted contribution path. The safety kernel is not optional: secret redaction, capability diffs, no silent fallback, no auto-merge, wallet/gas/mainnet approval, and source-evidence requirements remain enforced.

## 14. Roadmap

The staged roadmap leaves a working artifact at each step.

- Stage A: core runtime, trace collection, Telegram and CLI foundations.
- Stage B: signed chunks, Walrus testnet, Sui testnet anchors, replay proof.
- Stage C: GA hardening, gas trace harness, mainnet gate, key isolation.
- Stage D: skill runtime, open registry, provenance, install receipts, memory intelligence.
- Stage E: AtomDietRecord builder, redaction, rights checks, reward firewall, training unlock.
- Stage F: CLI cockpit, provider/tool/web/skill/memory/wallet/gas/train/eval controls.
- Stage G: first Naite SFT pass and evaluation on A100.
- Stage H: vLLM serving, local model router, no-silent-fallback proof, CLI/Telegram sync.
- Stage I: read-only mainnet measurement for gas, cycle, and security telemetry.
- Stage J: open-source readiness, SDKs, public docs, review queue.
- Stage K: larger-model promotion only after controlled self-improvement is measured under gates.

## 15. Expected Advantages

Sinabro and Naite compound in ways a plain chat interface does not.

The agent keeps state outside the model. Memory, skills, evidence, and approval records survive provider changes and model upgrades. The training system learns from complete work trajectories instead of isolated answers. The safety model is enforced by the runtime rather than by prompt text alone. The skill registry can grow without requiring an early payment market. External frontier models can still be used, but their outputs pass through the same trace, privacy, and approval boundaries.

This makes the project broader than a Web3 assistant and more specific than a general chatbot. Its first deep specialization is Rust, Move, Sui, and Walrus, but the underlying loop is a general coding loop: plan, implement, test, prove, measure, review, record, and learn.

## 16. Limitations

The design has clear limits.

- The report describes a staged design, not a completed production deployment.
- The initial release scope does not include Solana or Anchor execution paths.
- The initial release scope does not include paid skill-market execution.
- Naite is not assumed to outperform frontier models at launch.
- Walrus/Sui memory ownership, Gas Station operation, vLLM serving, and mainnet measurement require evidence before public claims.
- Self-improvement does not imply permission escalation. A better model does not get broader authority.
- Public training contributions require opt-in consent, redaction, rights checks, and provenance.

## 17. Conclusion

Sinabro is the agent layer. Naite is the model trained from the agent's verified work. The system is built around a simple constraint: improvement should leave evidence. Every accepted atom should make the codebase better, make the agent safer, and leave a usable training record for the next model.

If the project succeeds, its strength will not come from a single model release. It will come from the loop: user-owned memory, open skills, strict approvals, reproducible traces, and training data that was earned by real tests rather than asserted by a model.

## References

- Ryan Teknium, Jeffrey Quesnelle, Chen Guang. "Hermes 3 Technical Report." arXiv:2408.11857, 2024. https://arxiv.org/abs/2408.11857
- Nous Research. "Hermes 3." https://nousresearch.com/hermes3/
- OpenAI. "GPT-4 Technical Report." arXiv:2303.08774, 2023; revised 2024. https://arxiv.org/abs/2303.08774
- OpenAI. "GPT-4o System Card." 2024. https://openai.com/index/gpt-4o-system-card/
