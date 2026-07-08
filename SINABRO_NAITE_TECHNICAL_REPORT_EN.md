# Sinaite Technical Report

## Sinabro: A Local-First Coding Agent with User-Owned Memory and Evidence-Gated Model Improvement

Draft v0.4 | May 28, 2026

## Abstract

We introduce Sinaite, an open-source project composed of Sinabro, a local-first coding agent runtime, and Naite, a coding model trained from Sinabro's verified development trajectories. The project is motivated by a simple observation: modern coding agents produce useful work, but most of the signal that made the work possible is discarded. Repository reads, failed attempts, compiler diagnostics, test results, proof attempts, gas traces, red-team decisions, tool approvals, memory writes, and human corrections are usually compressed into an opaque chat transcript. Sinaite treats these trajectories as first-class data.

Sinabro is a Rust control plane that decomposes software work into atomic units, executes tools under capability and approval boundaries, records evidence sidecars, preserves user-owned memory, and exposes a CLI/TUI/Telegram control surface. Naite is not the authority of the system. It is a replaceable accelerator trained from evidence that survives Sinabro's gates. The first specialization is Rust, Move, Sui, Walrus-backed memory, and long-context coding workflows, but the architecture is designed as a general agent loop: plan, act, test, prove, measure, review, record, and learn.

This report describes the system design, data pipeline, safety invariants, serving policy, and evaluation protocol. It is not a production benchmark claim. We intentionally separate completed implementation evidence from design targets. Performance claims must be backed by build states, gate reports, reproducible commands, and signed evidence bundles.

## 1. Introduction

Open-source language models improved rapidly by making model weights, training recipes, and evaluation results inspectable. Coding agents need the same discipline at the systems layer. A patch is not enough. A chat log is not enough. A model saying "I fixed it" is not evidence. The missing unit is a verifiable work trajectory.

Sinaite follows a measured engineering posture: fewer slogans, more evidence. We optimize the loop before optimizing the narrative. Every useful improvement should either reduce cost, reduce latency, preserve safety, improve verified pass rate, or produce better training data. If it does none of these, it is probably decoration.

The central thesis is:

> A coding agent improves only when its work leaves evidence that can be replayed, audited, filtered, and learned from.

Sinabro therefore owns the runtime boundary. It decides what tools can run, what memory can be read or written, what provider can answer, what output can be trusted, what side effect needs approval, and what data is eligible for Naite training. Naite learns from the traces, but it does not get broader authority because it becomes better.

## 2. Contributions

This report describes eight contributions.

1. **Atom Protocol.** A staged development protocol in which each work unit has one canonical output, explicit reuse constraints, required gates, and a closed evidence sidecar.
2. **AtomDiet.** A training-data pipeline that converts verified software work into SFT, preference, reward, and evaluation records while rejecting self-reported success.
3. **User-Owned Memory.** A memory architecture based on user-signed chunks, content digests, Sui `memory_root` and `audit_log` records, deterministic replay, and backend-neutral storage receipts.
4. **Sinabro Runtime.** A local-first Rust agent control plane with CLI/TUI/Telegram interfaces, provider routing, tool adapters, skill registry, wallet/gas policy, task inbox, checkpoint/rollback, and audit trails.
5. **Safety by Construction.** No silent fallback, no silent side effects, no hidden permission escalation, no training on private data by default, and no gas sponsorship based on endpoint secrecy.
6. **Evidence-Backed Optimization.** Trajectory health, route state, prompt-cache boundaries, specialized token compression, and A/B scorecards are recorded as typed evidence rather than prompt-only guidance.
7. **Compute as Curriculum.** A Naite Didactica Engine that turns evidence sidecars into mastery estimates, spaced recall queues, transfer probes, validity checks, and compute-learning-gain ledgers before spending additional GPU time.
8. **Naite Training and Serving Plan.** A staged QLoRA/LoRA SFT track on a license-permissive 14B coding base, followed by strict evaluation, vLLM serving, no-silent-fallback routing, and larger-model promotion only after measured gains.

## 3. System Overview

Sinaite separates the agent from the model.

```text
User
  -> CLI / TUI / Telegram / API
  -> MessageEnvelope / CommandEnvelope
  -> Sinabro Rust Core
       - runtime supervisor
       - atomic planner
       - turn orchestrator
       - LLM provider router
       - tool adapter dispatcher
       - skill registry and WASM runtime
       - memory engine
       - wallet and gas policy
       - checkpoint and rollback manager
       - evidence collector
       - dataset builder
  -> Execution substrates
       - cargo, rustc, clippy, miri, fuzz, Kani
       - Sui CLI, Move tests, Move Prover
       - Walrus and StorageBackend adapters
       - web research with source evidence
       - local and remote model providers
  -> Evidence bundle
  -> Naite training / evaluation / serving
```

The model proposes actions. Sinabro decides whether they can happen. This distinction is the core safety boundary. A model can propose a tool call, memory write, skill installation, provider fallback, wallet signature, gas-sponsored transaction, or chain write. Sinabro checks capability, policy, budget, approval, redaction, and evidence requirements before execution.

The initial public surface is intentionally CLI-first:

```bash
sinabro doctor
sinabro setup memory
sinabro
sinabro tui
```

The product should feel simple at the top and strict underneath. A user should be able to install and reach the first dry run quickly, while every risky action remains auditable.

## 4. The Atom Protocol

An atom is the smallest unit of planned work that can produce a meaningful, reviewable change. Each atom has nine fields:

```text
id
file
canonical OUT
constraint spec
tests
criterion
gate
reuse
next-atom
```

The purpose of this shape is to prevent scope drift. An atom does not finish when code is written. It finishes when code, tests, command output, review records, redaction reports, dependency audits, and evidence hashes agree.

The protocol enforces several rules:

- One atom has one canonical output.
- Existing canonical types must be reused instead of redefined.
- Tool absence is recorded as `not_verified`, not converted into success.
- Failed attempts, no-op decisions, denials, and repairs are training data.
- A model statement is never a gate result.
- A stage cannot advance without evidence that the previous stage produced its handoff.

This gives the project a property that ordinary agent transcripts lack: every improvement has a provenance chain.

## 5. Evidence Sidecars

Each implementation atom emits a closed sidecar contract. The current atom sidecar contains 21 files:

```text
input_context.jsonl
action_trace.jsonl
command_manifest.json
terminal_redacted.jsonl
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
human_review.jsonl
approval_events.jsonl
privacy_report.json
sft_chat.jsonl
preference_pairs.jsonl
reward_labels.json
eval_summary.json
```

This sidecar is the bridge between engineering and learning. It records what the agent read, what it changed, what it ran, what failed, what passed, what was denied, and what can be replayed.

Two files are mandatory in every atom:

- `review_5pack.json`: performance, security, chain, agent-token budget, and developer-experience review.
- `deny_audit.json`: dependency, license, advisory, banned surface, and source audit.

These are not paperwork. They prevent Naite from learning that "fast but unsafe" is acceptable. A trajectory that passes tests but violates security, chain, privacy, or gas policy is a negative or no-reward example.

## 6. AtomDiet Data Pipeline

Naite is trained from verified trajectories, not from raw chat logs. The data pipeline is designed around three separations.

### 6.1 Ground Truth vs Narrative

S1 records are ground-truth candidates: compiler output, tests, proof attempts, gas traces, replay checks, dependency audits, and verified command results. S2 records are narrative context: explanations, human preferences, failed paths, and review discussion. S2 can be useful for SFT or preference pairs, but it cannot directly produce reward.

### 6.2 Data Rights vs Storage Rights

Storing memory is not permission to train on memory. User-owned memory, private repositories, provider outputs, browser bodies, sponsor keys, wallet material, and rights-unclear web content are excluded from public training unless explicit rights, redaction, and contribution gates pass.

### 6.3 Compression vs Evidence

Context compression is allowed only if evidence remains replayable. Compiler, test, log, and tool outputs use specialized compression policies. The compressed view must preserve first failure, file and line, command hash, root cause, redaction proof, and a raw replay hash or path.

The resulting dataset can produce:

- SFT conversations from verified work.
- Preference pairs from failed vs repaired attempts.
- Reward labels from reverified S1 evidence.
- Red-team examples from denied unsafe actions.
- Evaluation records from held-out gates.
- Trajectory-health labels for loop, drift, contradiction, and verification-skip failures.

## 7. Compute as Curriculum

Naite is not meant to improve by eating more data in dataset order. The training loop treats compute as a scarce instructional resource. Additional GPU time is spent only when the system can explain what concept is being trained, why the model has not mastered it, how the concept transfers to unseen work, and whether the measured gain is worth the cost.

This layer is called the Naite Didactica Engine. It borrows from a long educational tradition without pretending that human pedagogy transfers directly to machines. The useful abstraction is not classroom metaphor. It is control theory for learning: prerequisites, mastery thresholds, delayed recall, desirable difficulty, transfer, validity, and metacognitive uncertainty.

Stage E emits a `DidacticConceptMap` from verified AtomDiet records:

```text
DidacticConceptMap
  concept
  prerequisite
  failure_cause
  gate_axis
  domain_axis
  transfer_probe
  evidence_hash
```

Stage G uses that map to schedule training:

```text
MasteryVector
  per-concept mastery estimate

SpacedRecallQueue
  delayed recall probes and due steps

DesirableDifficultyMixer
  interleaving, perturbation, bilingual variants, failure contrast, and context-length mix

TransferProbe
  unseen repository, unseen atom shape, invariant axis, proof axis, and gas axis

TransferProbeReceipt
  probe hash, result hash, no-leakage bit, pass/fail receipt

ValidityJudgeReport
  construct validity, leakage risk, evaluator tamper risk, shortcut risk, and generalization gap

MetacognitiveTrace
  uncertainty, missing evidence, assumptions, and abstain-or-repair decisions

ComputeLearningGainLedger
  GPU minutes, dollars, tokens, eval delta, held-out delta, mastery delta, and continue/stop decision
```

The scheduler selects batches by expected mastery gain per GPU-minute, not by row order, recency, popularity, or loss alone. A low-loss sample can be skipped if it teaches nothing new. A difficult sample can be delayed if prerequisites are missing. A promising sample is denied if the transfer probe leaks, the evaluator can be gamed, or the improvement appears only on training-shaped tasks.

The hard rule is:

```text
no additional compute without positive held-out transfer gain
and positive mastery gain per GPU-minute
under a green validity report
```

This is the resource-limited version of the project. Model-side efficiency compresses the inference path; the Didactica layer compresses the curriculum. It tries to make a smaller model learn like a careful apprentice: not by seeing everything, but by being repeatedly tested on the right thing, at the right difficulty, with proof that the lesson transfers.

## 8. User-Owned Memory

Sinabro memory is not a hidden prompt cache. It is a user-owned asset.

The root of trust is:

```text
user signature
  -> typed chunk
  -> content digest
  -> storage receipt
  -> Sui memory_root / audit_log
  -> deterministic replay hash
```

A memory chunk can represent a user instruction, code change, tool result, test result, approval event, skill artifact, red-team decision, or system state. Chunks are addressed by digest and stored through a `StorageBackend`.

Walrus is the first Sui-native primary backend. It is not the definition of memory ownership. Local encrypted storage, Walrus, IPFS/Filecoin mirrors or archives, and future backends must pass through the same ownership, deletion, export, replay, and training-rights semantics.

The memory layer is designed to give users five properties:

1. Model upgrades do not erase memory.
2. Provider changes do not erase memory.
3. Storage migrations do not change ownership.
4. Deletion semantics override retrieval and training.
5. Replay can prove what was known at the time of a decision.

## 9. Provider, Tool, and Command Boundaries

Sinabro uses external systems without surrendering its safety model.

### 9.1 LLM Provider Abstraction

OpenAI, Anthropic, Gemini, local Naite, and vLLM endpoints are called through one provider interface. Each route records model identity, route decision, cost estimate, latency bucket, prompt redaction hash, output hash, and fallback policy.

No silent fallback is allowed. If the route changes from local Naite to a hosted provider, or from one hosted provider to another, the user-visible route state changes and approval may be required.

### 9.2 Tool Adapter Abstraction

Python tools, MCP servers, CLI binaries, HTTP/FastAPI services, and WASM skills normalize into a common `ToolCall` and `ToolResult`. Capability diff, sandbox tier, budget, approval, revocation, and evidence records are enforced before execution.

This prevents the model from bypassing safety by choosing a convenient tool surface.

### 9.3 Message and Command Envelope

CLI, TUI, Telegram, future mobile apps, and APIs share the same command semantics. `/kill`, `/approve`, `task resume`, `budget cap`, and `provider route` must mean the same thing everywhere.

### 9.4 Evidence and Trace Layer

Provider choice, tool execution, cost, latency, output hashes, failures, and approval receipts are recorded. Without this layer, a model or tool could spend money, mutate files, or change routes without leaving a reproducible trail.

## 10. Trajectory Health and Evidence-Backed Hints

Long-running agents often fail before they produce a bad final answer. They loop, skip verification, contradict earlier evidence, drift off task, compress away the important failure, or continue spending tokens after the task is stuck.

Sinabro tracks these states as typed `TrajectoryHealth` records. Planned signals include:

- semantic loop
- verification skip
- claim contradiction
- scope sprawl
- topic drift
- cyclic compression
- evidence mismatch
- sidecar or gate drift
- approval bypass attempt
- memory tombstone resurrection
- provider silent fallback
- gas sponsor risk
- secret surface touch
- stale proof acceptance
- tool capability escalation

Route state is user-visible:

```text
FAST
NORMAL
SLOW
STUCK
AUDIT
LOCKDOWN
USER_FULL
```

The route state may change the model, retrieval depth, compression policy, tool allowance, or approval level. It cannot bypass no-silent-fallback, budget, or approval gates.

Sinabro also uses evidence-backed hints instead of prompt-only steering. A hint must carry:

```text
source_atom
evidence_hash
memory_root
gate_result
expiry
scope
redaction_class
```

If a prior lesson cannot point to evidence, it is not injected as operational truth.

## 11. Skills

The initial skill system is adoption-first. It focuses on discovery, inspection, recommendation, dry-run, installation, provenance, compatibility, and verified use.

Planned commands include:

```text
skill search
skill inspect
skill recommend
skill use
skill install
skill enable
skill disable
skill update
skill remove
skill fork
skill publish
skill eval
skill provenance
```

Search uses progressive disclosure. The first result is a compact card: name, description, capability summary, compatibility, evaluation status, security status, provenance, verified installs, and permission diff. Full manifests, WASM metadata, documentation, and eval logs load only after inspection.

Skill execution requires package signatures, compatibility checks, malicious-fixture tests, sandbox evidence, capability diff, dry-run, explicit confirmation, and install receipts.

## 12. Web Research and Source Truth

Web research is a tool action, not ambient knowledge. A fetched source becomes usable only when it carries:

- source URL
- retrieval time
- fetch hash
- content type
- rights or robots decision
- citation evidence
- credential redaction status

Web content can guide an answer. It does not automatically become Naite training data. Public training candidates require explicit rights checks, redaction, and user approval.

## 13. Wallet, Gas, and Chain Safety

The gasless user experience is designed around a keyless open-source client and a policy-gated Gas Station. Sponsor keys do not appear in the repository, binary, container image, or examples.

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
- Automatic pause on anomaly signals.

Gas sponsorship is separated from memory ownership and skill usage. A sponsor can pay for policy-limited operations. It cannot become the user's memory owner.

## 14. Speed Law

Sinaite follows a dual compression speed law.

### 14.1 Model-Side Efficiency

Model-side efficiency reduces the cost of inference itself:

- KV-cache policy.
- BF16/FP8/TurboQuant-style candidates.
- Active adapter identity.
- Quantized serving canaries.
- Speculative draft/verify routes.
- Prefix and KV hit-rate measurement.

These are route-visible. A faster route that hides quality regression is not stable.

### 14.2 Serving-Side Efficiency

Serving-side efficiency reduces system overhead around the model:

- prompt-cache boundaries
- paged trace rendering
- background work admission
- interactive-first queue priority
- prefill/decode split candidates
- zero-allocation hot paths
- explicit full/deep jobs

Stable routes must report TTFT, TPOT, stream gap, queue time, prefill time, decode time, throughput, hot-path allocation count, prefix cache hit-rate, KV reuse hit-rate, VRAM, and quality deltas.

Full operations are supported, but only explicitly. `--full`, `--deep`, `export`, `replay`, and `audit` are product features. They run as budgeted, killable, resumable background jobs with progress, paged output, and evidence. They are not allowed to block the interactive hot path.

## 15. Training Naite

Naite training begins only after dataset and rights gates produce a valid unlock packet. The first training track uses a license-permissive 14B coding base with QLoRA/LoRA-style fine-tuning on A100-class hardware. The exact base identity, license, tokenizer, chat template, and trainability proof must be disclosed in the Stage G model card before any adapter is promoted. Reinforcement-style methods such as GRPO, MURPHY, and FGO remain locked until SFT smoke tests and evaluations pass.

The first curriculum is controlled by the Naite Didactica Engine. A full SFT run must carry `MasteryVector`, `SpacedRecallQueue`, `DesirableDifficultyMixer`, `TransferProbe`, `TransferProbeReceipt`, `ValidityJudgeReport`, `MetacognitiveTrace`, and `ComputeLearningGainLedger` artifacts. Loss curves are weak signals. Promotion requires held-out transfer gain, mastery gain per GPU-minute, and validity checks that rule out leakage, shortcut learning, and evaluator gaming.

Promotion is not based on loss alone. A candidate must preserve or improve:

- Rust compile and test outcomes.
- `cargo fmt`, `cargo clippy`, `cargo miri`, fuzzing, property tests, and Kani.
- Move tests and Move Prover repair.
- Gas and byte-size behavior.
- Walrus and storage integrity tasks.
- Korean technical instruction following.
- Long-context retrieval and packing tests.
- Held-out security and optimization tasks.
- Trajectory-health behavior.
- Token/cost/pass/latency A/B scorecards.
- Didactica artifacts: mastery, spacing, transfer, validity, metacognitive uncertainty, and compute-learning-gain.

Infrastructure failures such as OOM, timeout, and provider failure are masked from model reward. They are operational signals, not model-success labels.

## 16. Evaluation Protocol

Evaluation covers model quality, agent behavior, system safety, and serving performance.

| Area | Examples |
| --- | --- |
| Rust | fmt, clippy, test, miri, fuzz, criterion, Kani |
| Move and Sui | move test, Move Prover, BCS parity, gas trace, owner invariants |
| Storage | Walrus PUT/GET, blob-id verification, backend receipts, replay determinism |
| Memory | root hash, audit log, deletion, export/import, replay hash |
| Skills | malicious fixtures, capability diffs, signed package checks |
| Web | source metadata, retrieval hashes, rights checks, credential redaction |
| Router | no silent fallback, route receipts, cost and quality scorecards |
| Gas | allowlist, dry-run, quotas, gas caps, coin leases, burn caps |
| Dataset | PII0, secret0, S1/S2 split, reward firewall, dependency audit |
| Curriculum | mastery vector, spaced recall, transfer probe receipt, validity report, compute-learning-gain ledger |
| Korean | technical parity with equivalent English prompts |
| Serving | TTFT, TPOT, prefill/decode, prefix/KV hit-rate, allocation, VRAM, quality |
| Trajectory | loop, drift, verification skip, contradiction, compression failure |

The strongest evaluation target is not memorization of the project itself. The system must improve on held-out Rust, Move, gas, security, and Korean-language technical tasks without relaxing safety gates.

## 17. Open-Source Controls

Sinaite is open-source by design and conservative by default.

```toml
[learning]
mode = "off" # off | evidence_only | local_diet | private_adapter | contribute_redacted
global_contribution = false
external_model_output_training = "never"
private_repo_training = "never"

[features]
trace = "minimal"
startup_full_scan = false
hot_path_full_scan = false
trace_render = "paged"
memory_replay = "background"
skill_manifest_load = "lazy_inspect"
full_operation_mode = "explicit_background"
full_operation_budget_prompt = true
speculation = true
prompt_cache = true
context_compression = true
prefix_cache = true
kv_cache_hit_rate = "measure"
ttft_tpot_split = true
prefill_decode_split = "candidate"
hot_path_allocation = "zero"
background_queue_priority = "interactive_first"
trajectory_health = "typed"
route_fsm = "visible"
evidence_backed_hints = true
tool_output_compression = "typed_by_output_kind"
speculative_route = "visible"
quantized_serving = "canary_only"
didactica_engine = true
compute_learning_gain_gate = true
```

The safety kernel is not optional. Secret redaction, capability diffs, no silent fallback, no auto-merge, wallet preview, gas drain invariants, mainnet approval, and source-evidence requirements remain enforced.

## 18. Roadmap

The staged roadmap is designed so each stage leaves a working artifact and an evidence bundle.

- **Stage A:** core runtime, trace collection, agent loop, typed units, sidecar grammar.
- **Stage B:** signed memory chunks, Walrus testnet, Sui memory roots, replay proof.
- **Stage C:** GA hardening, gas trace harness, mainnet gate, key isolation.
- **Stage D:** skill runtime, open registry, provenance, install receipts, memory intelligence.
- **Stage E:** AtomDiet builder, redaction, rights checks, reward firewall, DidacticConceptMap, training unlock.
- **Stage F:** CLI cockpit, provider and tool adapters, web, skill, memory, wallet, gas, train, eval, and feature controls.
- **Stage G:** first Naite SFT pass and evaluation on A100, controlled by MasteryVector, spaced recall, transfer probes, validity reports, and compute-learning-gain ledgers.
- **Stage H:** vLLM serving, local model router, speed law, no-silent-fallback proof, CLI/Telegram sync.
- **Stage I:** read-only mainnet measurement for gas, cycle, and security telemetry.
- **Stage J:** open-source readiness, SDKs, public docs, contributor dry-run, review queue.
- **Stage K:** larger-model promotion after controlled self-improvement is measured under gates.

## 19. Expected Advantages

Sinaite compounds in ways a plain chat interface does not.

The agent keeps state outside the model. Memory, skills, evidence, and approval records survive provider changes and model upgrades. The training system learns from complete work trajectories instead of isolated answers. The curriculum system decides what is worth training next instead of burning compute in dataset order. The safety model is enforced by runtime policy rather than prompt text. External frontier models can still be used, but their outputs pass through the same trace, privacy, and approval boundaries.

The system is broader than a Web3 assistant and more specific than a general chatbot. Its first deep specialization is Rust, Move, Sui, and storage-backed memory, but the underlying loop is a general coding loop.

## 20. Related Work

SWE-agent shows that agent-computer interfaces matter: the model performs better when the edit, test, and shell environment is shaped for software engineering rather than ordinary chat. Sinaite adopts that systems view, but closes a different loop. The interface is not only a way to solve a task; it is also a way to produce a typed trajectory with command manifests, gate results, redaction reports, reward labels, and replayable evidence. In short, SWE-agent focuses on the agent-computer interface; Sinaite makes the trajectory a first-class training and audit artifact.

Voyager demonstrates that an agent can accumulate reusable skills through open-ended exploration. Sinaite shares the idea that capability should compound outside the model weights, but its skill system is stricter and less autonomous by default. Skills carry provenance, capability diffs, sandbox tiers, malicious-fixture checks, install receipts, and explicit user approval. The goal is not only to discover useful behaviors, but to make every reusable behavior inspectable, revocable, and safe to compose in a local developer environment.

MemGPT frames memory as an operating-system problem for LLMs: limited context requires explicit memory management. Sinaite agrees with that premise, but changes the ownership boundary. Memory is not just a hidden context-management layer for the model. It is a user-owned asset with signed chunks, content digests, storage receipts, Sui memory roots, audit logs, deletion semantics, export/import, and deterministic replay. The agent may use memory, but it does not own memory.

Hermes 3 is relevant because it treats instruction following, tool use, and open-model behavior as an integrated training problem. Sinaite is narrower at first: Rust, Move, Sui, storage-backed memory, and coding trajectories. The intended difference is not breadth at launch, but trace quality. Naite training data is allowed to enter the pipeline only after evidence gates, privacy checks, reward firewalls, and held-out evaluation rules decide that the trajectory is learnable.

## 21. Limitations

This report describes a staged design, not a completed production deployment.

Naite is not assumed to outperform frontier models at launch. The Didactica Engine is a training-control design until its ledgers show measured held-out transfer gains. Walrus/Sui memory ownership, Gas Station operation, vLLM serving, and mainnet measurement require implementation evidence before public performance claims. Self-improvement does not imply permission escalation. A better model does not get broader authority.

Public training contributions require opt-in consent, redaction, source rights, provider-policy compliance, and provenance. Some evaluation tools may be unavailable in a given local environment; tool absence must be recorded as `not_verified`, not as success.

## 22. Conclusion

Sinaite is built around one constraint: improvement must leave evidence.

Sinabro is the agent layer that owns memory, tools, approvals, routing, and traces. Naite is the model trained from the agent's verified work under a curriculum that spends compute only when learning gain is measurable. The long-term goal is not a louder assistant. It is a quieter and more efficient system where every token, tool call, memory write, and model update can be measured against evidence.

## Appendix A. Mini Atom Sidecar Example

The following is a compressed example of the kind of atom that enters the AtomDiet pipeline. It is illustrative rather than a claim about a specific released build.

```text
atom_id: A.0.3
canonical_out: RuntimeSupervisor<CAP>
target_file: prototype/crates/a-core/src/runtime.rs
reuse: RedactionClass from atom A.0.2
gate: G-CORE + G-GREP-PANIC
```

The corresponding sidecar records are small, typed, and evidence-oriented:

```jsonl
input_context.jsonl
{"source":"MNEMOS_ATOM_PLAN.md#A.0.3","extract":"RuntimeSupervisor with fixed capacity, typed task ids, drain report, cancel/release results","evidence_hash":"h_ctx_01"}
{"source":"prototype/crates/a-core/src/redaction.rs","extract":"Reuse RedactionClass; do not redefine a privacy label enum","evidence_hash":"h_ctx_02"}

action_trace.jsonl
{"action":"read","path":"prototype/crates/a-core/src/lib.rs","result":"module boundary found"}
{"action":"edit","path":"prototype/crates/a-core/src/runtime.rs","result":"added RuntimeSupervisor, RuntimeTaskId, Attempt, lease/report/drain types"}
{"action":"edit","path":"prototype/crates/a-core/src/lib.rs","result":"re-exported runtime module"}

command_manifest.json
{"commands":[{"cmd":"cargo fmt --all --check","exit":0},{"cmd":"cargo clippy --workspace --all-targets -- -D warnings","exit":0},{"cmd":"cargo test --workspace runtime","exit":0}]}

terminal_redacted.jsonl
{"cmd":"cargo test --workspace runtime","summary":"runtime supervisor tests passed","secret_hits":0,"raw_output_hash":"h_term_01"}

env_lock.json
{"os":"macOS arm64","rustc":"1.94.1","cargo":"1.94.1","sui":"not_used","walrus":"not_used","miri":"not_run_tool_absent"}

artifact_hashes.json
{"prototype/crates/a-core/src/runtime.rs":"h_runtime_rs","prototype/crates/a-core/src/lib.rs":"h_lib_rs","code_diff.patch":"h_patch"}

code_diff.patch
{"summary":"Added fixed-capacity runtime supervisor and public re-exports","patch_hash":"h_patch"}

failed_attempts.jsonl
{"attempt":"miri","status":"not_run","reason":"tool unavailable in local environment; not claimed as pass"}

no_op_decisions.jsonl
{"decision":"do_not_spawn_tokio_tasks","reason":"task spawning belongs to a later atom"}
{"decision":"do_not_add_anyhow","reason":"library crate error types stay typed"}

test_results.json
{"cargo_fmt":"pass","cargo_clippy":"pass","cargo_test":"pass","miri":"not_verified"}

gate_results.json
{"G-CORE":"pass","G-GREP-PANIC":"pass","G-MIRI":"not_verified_tool_absent"}

review_5pack.json
{"perf":"fixed-capacity state; no unbounded queue","security":"no secrets, no network","chain":"not applicable","agent_token":"sidecar concise","devex":"typed result enums"}

deny_audit.json
{"new_dependencies":[],"banned_error_crates":[],"license_findings":[],"status":"pass"}

redteam_decision.json
{"panic_surface":"none in production path","secret_surface":"none","live_side_effect":"none","decision":"green"}

human_review.jsonl
{"instruction":"implement one atom only; reuse canonical RedactionClass","interpretation":"scope locked before edit"}

approval_events.jsonl
{"event":"no_live_action_requested","approval_required":false}

privacy_report.json
{"secrets":0,"provider_bodies":0,"wallet_material":0,"private_memory":0}

sft_chat.jsonl
{"user":"Implement atom A.0.3 runtime supervisor using the existing redaction type.","assistant":"I will reuse RedactionClass, add RuntimeSupervisor, run fmt/clippy/test, and emit sidecar evidence."}

preference_pairs.jsonl
{"rejected":"Define a new PrivacyClass enum and skip miri explanation.","chosen":"Reuse RedactionClass and mark miri as not_verified_tool_absent."}

reward_labels.json
{"execution_correctness":1.0,"evidence_integrity":1.0,"scope_reuse":1.0,"security":1.0,"perf":0.8,"reward_allowed":true}

eval_summary.json
{"atom_status":"implemented_waiting_for_independent_verification","promotion":"no_training_promotion_until_session_2"}
```

This is the unit Naite is meant to learn from: not just the final code, but the context, constraint, failed option, command evidence, security review, and reward boundary.

## References

- DeepSeek-AI. "DeepSeek LLM: Scaling Open-Source Language Models with Longtermism." arXiv:2401.02954, 2024. https://arxiv.org/abs/2401.02954
- DeepSeek-AI. "DeepSeek-Coder: When the Large Language Model Meets Programming - The Rise of Code Intelligence." arXiv:2401.14196, 2024. https://arxiv.org/abs/2401.14196
- DeepSeek-AI. "DeepSeekMoE: Towards Ultimate Expert Specialization in Mixture-of-Experts Language Models." arXiv:2401.06066, 2024. https://arxiv.org/abs/2401.06066
- DeepSeek-AI. "DeepSeekMath: Pushing the Limits of Mathematical Reasoning in Open Language Models." arXiv:2402.03300, 2024. https://arxiv.org/abs/2402.03300
- DeepSeek-AI. "DeepSeek-V3 Technical Report." arXiv:2412.19437, 2024. https://arxiv.org/abs/2412.19437
- Bloom, Benjamin S. "Learning for Mastery." Evaluation Comment, 1968.
- Bjork, Robert A. "Memory and metamemory considerations in the training of human beings." Metacognition: Knowing about Knowing, 1994.
- Roediger, Henry L., and Jeffrey D. Karpicke. "Test-enhanced learning: Taking memory tests improves long-term retention." Psychological Science, 2006.
- Google Research. "TurboQuant: Redefining AI efficiency with extreme compression." March 24, 2026. https://research.google/blog/turboquant-redefining-ai-efficiency-with-extreme-compression/
- Kwon et al. "Efficient Memory Management for Large Language Model Serving with PagedAttention." arXiv:2309.06180, 2023. https://arxiv.org/abs/2309.06180
- Qin et al. "Mooncake: A KVCache-centric Disaggregated Architecture for LLM Serving." arXiv:2407.00079, 2024. https://arxiv.org/abs/2407.00079
- Zhong et al. "DistServe: Disaggregating Prefill and Decoding for Goodput-optimized Large Language Model Serving." arXiv:2401.09670, 2024. https://arxiv.org/abs/2401.09670
- Packer et al. "MemGPT: Towards LLMs as Operating Systems." arXiv:2310.08560, 2023. https://arxiv.org/abs/2310.08560
- Yang et al. "SWE-agent: Agent-Computer Interfaces Enable Automated Software Engineering." arXiv:2405.15793, 2024. https://arxiv.org/abs/2405.15793
- Wang et al. "Voyager: An Open-Ended Embodied Agent with Large Language Models." arXiv:2305.16291, 2023. https://arxiv.org/abs/2305.16291
- Ryan Teknium, Jeffrey Quesnelle, Chen Guang. "Hermes 3 Technical Report." arXiv:2408.11857, 2024. https://arxiv.org/abs/2408.11857
- OpenAI. "GPT-4 Technical Report." arXiv:2303.08774, 2023. https://arxiv.org/abs/2303.08774
- OpenAI. "GPT-4o System Card." 2024. https://openai.com/index/gpt-4o-system-card/
