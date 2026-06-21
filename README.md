<div align="center">

<img src="assets/sinabro_logo.png" width="148" alt="sinabro" />

# sinabro

**A self-evolving, two-brain AI agent — a frontier model reasons, a local model executes across per-domain LoRA adapters, and it learns only what an oracle has verified.**

![platform](https://img.shields.io/badge/platform-macOS%20%7C%20Windows%20%7C%20Linux-1f2430)
![desktop](https://img.shields.io/badge/desktop-Tauri%202-24c8db)
![core](https://img.shields.io/badge/core-Rust-orange)
![local](https://img.shields.io/badge/inference-local%20%2B%20frontier-6ee7a8)
![adapters](https://img.shields.io/badge/routing-dynamic%20LoRA-9b8cff)
![memory](https://img.shields.io/badge/memory-Walrus%20encrypted-2bd4a8)
![license](https://img.shields.io/badge/license-MIT-555)

</div>

---

sinabro (시나브로, Korean for *“little by little”*) is a controlled, **self-improving** coding and
ops agent that runs as a **desktop app** (Tauri) and a **terminal cockpit** over one Rust core. It
splits cognition across **two brains** — a *frontier* model that reasons and plans, and a **local**
model that executes — and it gets sharper the longer you use it, because it writes a pattern back
into memory only after a build/test oracle has actually proven it works.

It runs **local-first**. Your executor brain lives on your machine — a base model plus a library of
**LoRA adapters**, one specialist per domain — and a deterministic router switches adapters per
sub-task. The frontier model is optional and egress-gated; the agent thinks, recalls, reads your
codebase, searches the web, and runs its tool loop without sending anything off the box until you
arm it to.

And it’s built to be **handed real autonomy safely**. Every side effect runs fail-closed inside a
network-cut sandbox under a capability-type system: reads are free, changes are propose-then-approve,
and the ability to touch your keys, wallet, or shell-without-bounds is not *disabled* — it’s
**unrepresentable**. You can let it run, arm a bold session for bounded auto-execution, or drive it
from your phone, without giving it the keys to your machine.

## Two brains, dynamic LoRA

The reasoning/execution split is the core idea. A **frontier** model (any OpenAI-compatible or
OpenRouter endpoint) plans and reasons in natural language; sinabro decomposes the plan into typed
sub-tasks; a **local** model carries them out. The local brain isn’t one model — it’s a base model
plus a set of **per-domain LoRA adapters** (`sui_move`, `solana_anchor`, `personal_memory`, `audit`,
`research`, …). For every sub-task sinabro emits a pure, deterministic `kind → (port, adapter)`
route, so the right specialist runs each step — **dynamic LoRA switching**, served sequentially or
co-resident (vLLM Multi-LoRA on Linux/CUDA, MLX on Apple Silicon).

The control plane that picks routes is **deterministic Rust — zero LLM tokens, zero network IO**.
The model is advisory; routing, gating, and verification are code. That’s deliberate: it means the
part of the system that decides what runs and what gets remembered cannot hallucinate or drift.

## Self-evolution — Read → Execute → Write

sinabro improves itself with a closed loop that refuses to learn its own mistakes:

1. **Read** — recall relevant memory, read the codebase, fetch context.
2. **Execute** — propose and (once approved) run the change in the sandbox.
3. **Write** — a pattern becomes **permanent** memory only when **(1)** an **oracle** — a compiler
   or test suite (`cargo build`, `sui move build`, `sui move test`, your project’s own checks) —
   has **verified** it, **and (2)** it doesn’t contradict existing memory (contradictions are
   *quarantined*, never silently overwritten).

The decision core is deterministic Rust with no model in the loop, which is exactly what stops the
RAG↔hallucination spiral that makes naive self-improving agents reinforce their own errors until
they collapse. Nothing enters long-term memory on a model’s say-so — only on ground truth.

## Memory you own — encrypted, on Walrus

Most agents keep their memory in someone else’s cloud: wiped on a whim, impossible to verify, never
really yours. sinabro’s long-term memory is a first-class, decentralized store on
**[Walrus](https://walrus.xyz)** — encrypted with keys only you hold, so it survives, it’s portable,
and no vendor can read or revoke it.

It’s **two-tier**: an encrypted **MAIN INDEX** blob — the `(id, topic, sub-pointer)` manifest — over
per-memory **SUB** blobs holding the detail. Everything is AEAD-encrypted **before it leaves the
machine**, *including the index itself*, so on the public Walrus network your topics and ids are
opaque ciphertext (**secret-zero**) — only your local key turns them back into memories.

**How the agent uses it — on its own.** Walrus memory is wired straight into the agent’s reasoning
loop as autonomous **READ tools**. Mid-thought, with no approval, the agent decides to call
`memory walrus-index` to see what it already knows and `memory walrus-fetch <id>` to pull a specific
encrypted memory — it fetches the blob from Walrus, decrypts and redacts it locally, and folds the
result into its answer, all inside a single train of thought. (This is live, not a mock: in a real
run the agent issues `walrus-index → walrus-fetch → answer` over genuine testnet round-trips,
`trail=[walrus-index, walrus-fetch]`.) Writing memory *out* to Walrus is an **owner-armed** encrypted
sync (PUT → byte-verified blob id → GET → byte-match), so what leaves your machine is always your
call — the same READ-free / write-armed rule as everything else. Local AES-256-GCM-SIV at-rest is the
offline fallback.

Provenance is anchored on **[Sui](https://sui.io) Move**: `memory_root` and `mnemos_skill_registry`
give each memory and skill an on-chain hash + install graph, with **Move-Prover** specs and
`sui move test` coverage.

## Controlled autonomy

The runtime is the reason you can let it act. Generated, read, or owner-armed code runs **fail-closed
inside a network-cut Seatbelt sandbox** (it refuses to run unsandboxed), under capability types,
propose-then-approve, automatic per-mutation checkpoints, and a hash-linked **audit chain**. Reads
are autonomous; mutations are proposed and only execute on your approval. **Arm a bold session** and
it auto-executes pending edits/runs *within the bound you set* — no per-action clicks — while
escalations (force-push, key export, anything funds- or chain-write-shaped) stay refused in every
mode. Approve or drive any of it remotely **from your phone over Telegram**, behind a redaction wall.

## Capabilities

| | |
|---|---|
| **Two-brain orchestration** | frontier reasons → typed sub-tasks → local executes; deterministic router |
| **Dynamic-LoRA routing** | per-domain adapters, one specialist per `kind`; sequential or co-resident serving |
| **Self-evolving R-E-W loop** | learns only oracle-verified, cross-memory-consistent patterns |
| **Two-tier encrypted memory** | autonomous MAIN INDEX → SUB round-trip, local or on Walrus, secret-zero |
| **`@codebase` semantic index** | embeddings-based code search; vectors never leave the box |
| **Agentic tool loop** | typed READ tools — file read, search, LSP diagnostics, git read, test run, web fetch/search, audit, MCP, memory & Walrus recall |
| **PROPOSE-EXEC / EDIT** | the agent’s hands — propose, then owner-gated execute inside the sandbox |
| **Bold session** | armed, bounded auto-execution with auto-checkpoints + revoke |
| **Web fetch / search** | SSRF-walled, secret-zero GET, redacted, advisory-only |
| **Audit detect** | candidate security *leads* over a source tree (propose-only; never auto-promoted) |
| **Telegram remote control** | approve or drive the agent from your phone, with a redaction wall |
| **Desktop cockpit** | ⌘K inline edit · Plan Mode · find-in-files · `@`-mention · `/` command palette · memory & routing panels |

## Install

### Prebuilt

```bash
# macOS / Linux — CLI on your PATH
curl -fsSL https://github.com/skew-labs/Sinabro/releases/latest/download/install.sh | bash
```
```powershell
# Windows — CLI on your PATH
irm https://github.com/skew-labs/Sinabro/releases/latest/download/install.ps1 | iex
```
Desktop app: grab the **`.dmg`** (macOS) or **`.msi`** (Windows) from the
[latest Release](https://github.com/skew-labs/Sinabro/releases).

### Build from source (macOS · Windows · Linux)

**Prerequisites** — [Rust](https://rustup.rs) (stable). For the desktop app, the
[Tauri 2 prerequisites](https://v2.tauri.app/start/prerequisites/) for your OS (macOS: Xcode
Command-Line Tools · Windows: *Microsoft C++ Build Tools* + *WebView2*) and `cargo install tauri-cli --version "^2"`.

```bash
git clone https://github.com/skew-labs/Sinabro.git && cd Sinabro

# CLI (all three platforms)
cd prototype
cargo build --release -p sinabro
./target/release/sinabro --help          # Windows: target\release\sinabro.exe --help

# Desktop app  →  .app / .dmg / .msi
cd ../apps/desktop/src-tauri
cargo tauri build                         # bundle: target/release/bundle/
```

The CodeMirror editor bundle is **vendored** (`apps/desktop/ui/vendor/`), so **no `npm install`** is
needed to build the desktop app.

## Getting started

```bash
sinabro                                   # launch the terminal cockpit (splash + chat)

# Memory — local, encrypted, redacted
sinabro memory save "a fact worth remembering"
sinabro memory index                      # opaque, secret-zero catalog
sinabro memory walrus-index               # list memory stored on Walrus
sinabro memory walrus-fetch <id>          # fetch + decrypt + redact one memory

# Two-brain consult — local by default; frontier is egress-gated
export OPENROUTER_API_KEY=...             # read only at the TLS boundary, never logged
sinabro provider consult consult-frontier-provider-live "write a Move function summing a vector<u64>"

# Autonomy — bounded, owner-armed
sinabro daemon run "<task>"               # local, READ-class, zero egress
sinabro daemon bold <ARM_PHRASE> "<task>" # armed bold-within-bounds, auto-checkpointed
```

In the desktop app the same lives behind the chat box, the ⛁ **memory** panel, the
*Settings → LoRA / Routing* editor, the `@`-mention file picker, and the `/` command palette — every
namespace badged with its capability tier (free / owner-armed / locked) straight from the core.

## Safety — capability types

Autonomy is safe here because permission is a **type**, not a runtime flag:

- **READ** — free and autonomous (recall, search, file/git/LSP, web fetch, Walrus index/fetch).
- **EGRESS / MUTATE** — **owner-armed** (a one-time phrase, approvable from your phone).
- **CUSTODY** — an **uninhabited type**. Keys, wallet, signing, chain-write are *unrepresentable*,
  not merely “disabled”: such an action is denied at propose-time and never even drafted.

Defense in depth: a **network-cut sandbox** that refuses to run unsandboxed, a **redaction wall**
(secret-shaped output is withheld before any egress), per-mutation **checkpoints**, and a
hash-linked **audit chain** you can replay.

## Architecture

```
prototype/        Rust workspace — surface-neutral core + CLI (crate `sinabro`)
  crates/         a-core, b-memory, c-walrus, d-move, e-skill, … (capability-typed crates)
  move/           Sui Move contracts (memory_root, mnemos_skill_registry) + Move-Prover specs
apps/desktop/     Tauri 2 desktop app (Rust backend + WKWebView UI)
.github/workflows/ reproducible release CI (macOS / Windows / Linux)
ops/release/      install.sh / install.ps1
```

One surface-neutral core drives both the terminal and the desktop app, so a capability is wired,
gated, and tested **once** and shows up identically on both.

## License

[MIT](LICENSE).

---

<div align="center">
<sub><b>sinabro</b> — two brains, local-first, grows with you, and never holds what isn’t yours.</sub>
</div>
