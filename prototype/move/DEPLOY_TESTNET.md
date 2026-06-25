---
llmp: 1
artifact_type: operator_runbook
doc_id: MNEMOS_DEPLOY_TESTNET
status: draft_session_1_implemented_pending_verification
stage: A
phase: 0
atom: 19
atom_name: D.0.5
canonical_out: testnet_deploy_artifact + procedure_doc
gate: G-MOVE-NET
reuse: atom_18_memory_root_spec_move
created_utc: 2026-05-27T03:00:00Z
session_1_role: IMPLEMENTER
session_1_advances_build_state: false
verifier_session: 2
---

# MNEMOS Testnet Deploy Procedure (atom #19 · D.0.5)

> **NOT a live action document.** This is the operator runbook for the
> testnet deploy of the MNEMOS `mnemos::memory_root` Move package. Session 1
> (the atom-#19 implementer) produced this file plus
> `scripts/deploy_testnet.sh` + `prototype/move/Move.toml` updates. Session 1
> **did not execute a live publish.** Live publish requires the four
> preconditions in §3 plus an in-message user approval recorded in
> `ops/training/phase_0/atom_019/approval_events.jsonl`.

---

## 1. Atom contract recap

| Field           | Value                                                                                                                                                                          |
|-----------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Atom            | #19 · D.0.5                                                                                                                                                                    |
| Files (target)  | `prototype/move/Move.toml`, `scripts/deploy_testnet.sh`, this doc                                                                                                              |
| Canonical OUT   | testnet 배포 산출물 (package_id 기록 경로) + 배포 절차 문서                                                                                                                    |
| 광기 사양       | **testnet 전용** (mainnet ban §11 NOT-DO / §10.3 multisig+timelock 너머); 배포 키 G.0 분리; dry-run 우선                                                                       |
| Tests           | dry-run 성공 → testnet 배포 1회 → `add_chunk` 1건 실행 확인 (synthetic)                                                                                                       |
| Gate            | **G-MOVE-NET** (사용자 인메시지 승인 필수, mainnet 금지)                                                                                                                       |
| Reuse           | atom #18 (proved `memory_root.spec.move`), atom #16/#17 (production `memory_root.move`)                                                                                       |

---

## 2. Hard ban surface (mainnet)

The script `scripts/deploy_testnet.sh` enforces mainnet rejection at three
independent points. Removing or weakening any one of them is a
`[[no-disabled-path-workaround]]` violation:

| Layer | Mechanism                                          | Exit code |
|-------|----------------------------------------------------|-----------|
| 1     | `NETWORK` env must equal `"testnet"`               | 10        |
| 2     | `sui client active-env` must equal `"testnet"`     | 13        |
| 3     | active RPC URL must not contain `"mainnet"` substring; must contain `"testnet"` | 16 / 17 |

Additionally, the production module `mnemos::memory_root` is itself
chain-agnostic — no Sui chain id / network id is hard-coded — so the bans
are *deploy-time* surfaces only. Once published, the on-chain package is
network-specific by virtue of its assigned `package_id`.

---

## 3. Preconditions for live publish (G-MOVE-NET)

The script **refuses to execute `PHASE=publish`** until ALL of the
following are satisfied. Each is a separately-recorded approval boundary
and they are AND-ed.

1. **Stage G keypair separation** — a `DEPLOY_KEYPAIR_PATH` env points at
   a deploy keystore that is NOT the operator's default
   `~/.sui/sui_config/sui.keystore`. The keystore is produced by the
   Stage G atom that introduces wallet/deploy key separation (per
   ATOM_PLAN §G.0; phase 0 has no such atom yet, so this precondition
   is impossible to satisfy this session).
2. **CI deploy infra (atom #46 K.0.1)** — `prototype/deny.toml` + CI
   nightly job that watches for accidental key/secret commit. Session 1
   notes the dependency; the script does not check for it (the K.0.1
   atom will add a precondition probe here).
3. **User in-message approval** — captured verbatim in
   `ops/training/phase_0/atom_019/approval_events.jsonl` (or the
   per-atom approval log of the deploying atom, if `#19` itself is
   re-opened by a future session). Required envs: `USER_APPROVAL=YES`
   AND `DEPLOY_LIVE=1`.
4. **Operator manual removal of `die 99` guard** — the script's
   `phase_publish()` function ends with `die 99 "phase_publish() refuses
   to execute. Remove this die() line ONLY after the three preconditions
   above are all satisfied (and document the removal in
   approval_events.jsonl)."`. The operator must hand-edit this line
   before the function can complete a real publish. This is intentional
   friction per `[[mainnet-safety-over-speed]]`.

---

## 4. Operator runbook (when preconditions are met)

```
# 1. Local offline build sanity (Session 1 may auto-run this).
bash /Users/heoun/mnemos/scripts/deploy_testnet.sh --phase=build

# 2. Dry-run synthesis (writes the synthesized cmd to evidence dir).
NETWORK=testnet \
DEPLOY_KEYPAIR_PATH=/path/to/separated/deploy.keystore \
bash /Users/heoun/mnemos/scripts/deploy_testnet.sh --phase=dry-run

# 3. Run the synthesized dry-run cmd manually + inspect.
#    (Operator action — script does NOT auto-execute.)
sui client publish --gas-budget 100000000 --dry-run /Users/heoun/mnemos/prototype/move

# 4. After dry-run green + 사용자 in-message approval:
#    a. record the approval in approval_events.jsonl (verbatim quote).
#    b. remove the die() guard line in phase_publish().
#    c. set USER_APPROVAL=YES and DEPLOY_LIVE=1 and re-run --phase=publish.
USER_APPROVAL=YES DEPLOY_LIVE=1 \
NETWORK=testnet \
DEPLOY_KEYPAIR_PATH=/path/to/separated/deploy.keystore \
bash /Users/heoun/mnemos/scripts/deploy_testnet.sh --phase=publish

# 5. Capture the returned package_id into:
#    ops/evidence/phase_0/atom_019/deploy_run/published_at.txt
#    Then manually update prototype/move/Move.toml:
#      [package]
#      published-at = "0x<package_id>"
#      [addresses]
#      mnemos = "0x<package_id>"
```

---

## 5. Sui rev pinning policy (carve-out)

ATOM_PLAN atom #19 specifies "Sui rev pinning to the latest official
testnet branch tag prior to the on-chain deploy" (`prototype/move/Move.toml`
header comment, atom #15 carve-out). atom #19 Session 1 deliberately did
**NOT** bump the rev from atom #15's vendored value
(`73dd2c2ba6f9fdb21d7ffde2b50a3f2f0ac39bc1`) because:

- Bumping the rev invalidates the offline cached resolution under
  `~/.move/git/`, forcing a network fetch (Phase 0 ban + macOS offline
  preference).
- Bumping the rev may invalidate the test fixtures verified by atoms
  #16 / #17 (`add_chunk_by_owner_succeeds`, `transfer_by_owner_changes_owner`,
  etc.) and would require re-running atom #18 spec compilation.
- Per `[[ai-advisory-user-decides]]`, the bump is an operator decision
  carried by this advisory: before live publish, the operator should
  evaluate whether the cached rev is recent enough for testnet
  compatibility, or whether a fresh `sui move build --skip-fetch-latest-git-deps=false`
  fetch is required.

Resolution path: when a Stage G or post-K.0.1 deploy atom lands, that
atom (not atom #19) should perform the rev bump as part of its
canonical-OUT surface, accompanied by an explicit `sui move build` +
`cargo test` re-run.

---

## 6. Disparity flag — `add_chunk` synthetic call not reachable

**Disparity** (atom-#2 / atom-#3 precedent pattern): ATOM_PLAN line 987
prescribes the `add_chunk` 1건 실행 확인 (synthetic) test for atom #19,
but the production module exposes no entry function that **creates** a
`MemoryRoot` object on-chain. Concretely:

| Function                                  | Exposure        | Creates MemoryRoot?      |
|-------------------------------------------|-----------------|--------------------------|
| `mnemos::memory_root::add_chunk(...)`     | `public entry`  | NO — requires `&mut`     |
| `mnemos::memory_root::transfer_root(...)` | `public entry`  | NO — requires `MemoryRoot` by value |
| `mnemos::memory_root::new_root_for_test(...)` | `#[test_only]`  | YES, but unreachable from on-chain |

There is no `init_memory_root` / `mint_root` / `share_root` entry. A
testnet `add_chunk` PTB therefore has nothing to pass as the
`&mut MemoryRoot` first argument until a follow-up atom introduces such
an entry. This is a **canonical-OUT scope gap** in the atom #19
prescription, *not* an implementation regression in atom #19's own
surface.

**Resolution path (advisory, user decision)**:

- *Option A*: introduce a new production entry `public entry fun
  init_memory_root(ctx: &mut TxContext)` as a separate atom (e.g.,
  Stage D extension D.0.5b or Stage G G.0.x). Once it lands, atom #19's
  `PHASE=add-chunk-ptb` phase can target the freshly-created root.
- *Option B*: defer the synthetic `add_chunk` smoke test entirely to
  Stage M m-agent activation (atom #21+), when the agent runtime itself
  needs to bootstrap a MemoryRoot via the same future-entry that Option
  A would introduce.
- *Option C*: accept the gap and document `add_chunk` synthetic call as
  permanently `NOT_RUN_FACTORY_ABSENT` for atom #19. Live `add_chunk`
  validation moves into the atom that introduces the factory entry.

Session 1 records this disparity in
`ops/training/phase_0/atom_019/no_op_decisions.jsonl` (verbatim) and in
`ops/evidence/phase_0/atom_019/VERIFY_TODO.json::known_skipped[]` so
Session 2 can ratify the gap rather than treat it as failure.

---

## 7. Session 1 ↔ Session 2 handoff

| Surface                              | Session 1 (this)                                  | Session 2 (verifier)                                      |
|--------------------------------------|---------------------------------------------------|-----------------------------------------------------------|
| `Move.toml` edit                     | applied (header doc + carve-out)                  | byte-level diff verify; ensure `mnemos="0x0"` retained    |
| `scripts/deploy_testnet.sh`          | written, executable, `bash -n` syntax check pass  | re-run `bash -n`; verify mainnet bans grep-present        |
| `DEPLOY_TESTNET.md`                  | written (this file)                               | verify §6 disparity flag still matches code reality       |
| `sui move build` (PHASE=build)       | optional autonomous run; result in evidence       | re-run; compare exit code                                 |
| `PHASE=dry-run`                      | NOT RUN (G.0 keypair absent)                      | NOT REQUIRED to run; verify the require-fail path         |
| `PHASE=publish`                      | NOT RUN (G-MOVE-NET + die guard)                  | NOT TO RUN                                                |
| `PHASE=add-chunk-ptb`                | NOT RUN (factory entry absent)                    | NOT TO RUN; verify the die error message accuracy         |
| BUILD_STATE advance                  | NOT MODIFIED                                      | only Session 2 advances on PASS                           |

