# 0G Compute TEE attestation sidecar (W2-B)

sinabro × 0G Buildathon, Wave-2 deliverable **W2-B**: verify that a **0G Compute provider
runs genuine TEE-attested inference** — the "TEE-verified Compute" gate (the wedge 0G's
prize tracks rewarded). This is the *second independent gate*: 0G attests that *compute
ran in a TEE*; sinabro's own oracle still gates *semantic correctness*.

> **Funds-safe (PD-6) — keyless, no funds, no on-chain write.** 0G's attestation verifier
> ships only as the TS `@0gfoundation/0g-compute-ts-sdk` (`broker.verifyService` → a
> dstack/TDX TEE quote + verdict), so this Node sidecar drives it. `verifyService` is
> **read-only**: it uses the SDK's read-only broker for discovery and an **ephemeral,
> unfunded `Wallet.createRandom()`** (never persisted; balance 0 ⇒ structurally cannot
> spend) only to instantiate the verify call. There is **no signer key, no funds, no
> chain write** — the live verify succeeds with a 0-balance wallet, proving it is pure
> verification. `CustodyCapability` stays uninhabited.

## Run

```bash
cd prototype/sidecar/zerog-attestation
npm install                 # ~180 MB: @0gfoundation/0g-compute-ts-sdk + ethers (isolated)
node verify.js              # auto-discovers a provider + verifies its TEE attestation
node verify.js 0x<provider> # or verify a specific provider
```

Output is one line of JSON:

```json
{"ok":true,"mode":"ephemeral-wallet",
 "provider":"0xa48f01287233509FD694a22Bf840225062E67836",
 "model":"qwen/qwen2.5-omni-7b","serviceCount":2,
 "verification":{"success":true,"teeVerifier":"dstack",
   "verifierURL":"https://github.com/Dstack-TEE/dstack/releases/tag/verifier-v0.5.8",
   "reportsData":{"broker":{"quote":"0400020081…"}}},
 "reportDir":"/tmp/zerog-attest-…"}
```

`ok:true` ⇔ the provider's TEE attestation verified. The raw TDX/dstack quote + collateral
are written to `reportDir`.

## In sinabro

The Rust side (`crates/mnemos-cli/src/zerog_attestation.rs`) drives this sidecar through
the same bounded `exec_local` runner W2-C uses (fixed argv `node verify.js [provider]`, no
shell). Surfaced as:

```bash
ZEROG_ATTESTATION_SIDECAR=$PWD/verify.js \
  cargo run -p sinabro --bin sinabro --features zerog-attestation -- provider attest-0g
# => verified : true / teeVerifier : dstack / provider : 0x… / model : qwen/qwen2.5-omni-7b
```

Without `--features zerog-attestation` the verb renders an honest "not compiled" surface
(the external Node sidecar is isolated behind the off-default feature).

The funds-safety proof is `ops/evidence/stage_g/zerog_attestation_w2b_grep.sh`.
