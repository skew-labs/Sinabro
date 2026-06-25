# Sinabro & Naite 백서

> Local-first, evidence-gated, self-improving coding agent architecture
>
> 공개 초안 v0.1 · 2026-05-26

## 초록

Sinabro(시나브로)는 로컬에서 사용자의 개발 환경, 도구, 기억, 스킬, 지갑, 평가 루프를 직접 조종하는 Rust 기반 코딩 에이전트다. Naite(나이테)는 Sinabro가 남기는 검증된 작업 증거를 기반으로 개선되는 프로젝트 코딩 모델이다. 이 백서는 Sinabro/Naite를 하나의 챗봇이나 모델 릴리스가 아니라, **개발 작업을 원자 단위로 분해하고, 구현하고, 검증하고, 증거화하고, 다시 학습 레코드로 환류하는 전체 시스템**으로 정의한다.

핵심 주장은 단순하다. 더 강한 코딩 에이전트는 더 큰 모델만으로 만들어지지 않는다. 사용자의 기억이 모델 밖에 소유되어야 하고, 도구 실행은 권한과 증거 뒤에 있어야 하며, 모델 학습 데이터는 사람이 칭찬한 대화가 아니라 컴파일러, 테스트, Prover, gas trace, red-team, human approval이 같은 방향을 가리키는 구조화된 증거 번들이어야 한다. Sinabro는 이 원칙을 제품 구조로 만들고, Naite는 그 구조가 만든 데이터를 통해 Rust, Move, Sui/Walrus, 보안, 한국어 개발 지시에서 점진적으로 강해진다.

이 문서는 구현 완료 보고서가 아니다. 현재 공개 가능한 설계를 정리한 기술 백서다. 실제 구현 상태는 릴리스 노트, 빌드 상태, 테스트 결과, evidence bundle을 통해 별도로 추적한다.

## 1. 문제 정의

현대 코딩 에이전트는 빠르게 강해지고 있지만 네 가지 결핍을 반복한다.

1. **기억이 약하다.** 대화 컨텍스트와 벡터 DB는 쉽게 날아가고, 모델을 바꾸면 사용자의 장기 맥락도 흔들린다.
2. **증거가 약하다.** "테스트했다", "안전하다", "최적화했다"는 자기보고는 실제 컴파일러, static analysis, proof, gas trace, red-team 로그와 다르다.
3. **권한 경계가 약하다.** LLM 출력이 곧 tool call, write, 결제, 지갑, mainnet action으로 이어지면 편리해 보이지만 사고도 함께 열린다.
4. **학습 루프가 약하다.** 실제 개발에서 나온 실패, 거부, 리뷰, no-op, 보안 감사, 성능 측정은 모델을 강화하는 고품질 데이터지만 대부분 흩어진 로그로 버려진다.

Sinabro/Naite는 이 결핍을 "완화"가 아니라 구조로 줄이려고 한다. 에이전트는 모델보다 먼저 독립적으로 동작해야 하고, 모델은 에이전트가 만든 검증된 trace를 기반으로 개선되는 가속기여야 한다.

## 2. 핵심 원칙

Sinabro/Naite의 핵심 원칙은 다음과 같다.

- **Agent first, model second.** Sinabro는 외부 API, local Naite, vLLM, 또는 future model 중 무엇을 쓰더라도 같은 권한 경계와 evidence pipeline을 유지한다.
- **Memory is owned, not rented.** 기억은 Walrus blob과 Sui root/audit anchor로 사용자 소유 자산이 된다. 모델을 바꿔도 기억은 남는다.
- **No silent action.** silent fallback, silent spend, silent write, silent skill install, silent tool execution은 모두 금지된다.
- **Evidence beats narration.** 컴파일, 테스트, clippy, miri, Kani, Move test, Move Prover, gas trace, Walrus verify, red-team, human approval이 자기보고보다 우선한다.
- **Every atom trains the next model.** 각 atom 작업은 코드 diff뿐 아니라 `AtomDietRecord` sidecar를 남긴다. 이 기록이 Naite의 SFT, preference, reward, eval 데이터가 된다.
- **Open source users choose the learning boundary.** 기본값은 학습 산출물 생성 off, 데이터 외부반출 off다. 사용자는 evidence-only, local diet, private adapter, redacted contribution을 직접 고른다.

## 3. 산출물

완성 시 산출물은 하나의 앱이 아니라 닫힌 개발 생태계다.

- `sinabro` CLI/TUI/REPL: provider, model, tool, web research, skill, memory, wallet, gas, chain, dataset, train, eval, measure, privacy, learning을 한 터미널에서 조종한다.
- Rust core: runtime supervisor, message/trace schema, tool dispatcher, capability engine, memory engine, provider router, budget ledger, redaction/logging, deterministic replay를 담당한다.
- Telegram adapter: CLI와 같은 `MessageEnvelope`와 run state를 공유하는 원격 조종창이다.
- Walrus/Sui memory layer: chunk schema, blob-id verify, `memory_root`, `audit_log`, owner invariant, replay hash를 제공한다.
- Skill runtime/open registry: 무료/오픈 adoption-first registry, progressive disclosure, signed package, capability diff, eval/security/provenance, install receipt를 제공한다.
- Gas Station/self-host relayer: open-source client에 sponsor key를 넣지 않고, 서버형 policy gate와 quota로 gasless onboarding을 지원한다.
- AtomDietRecord dataset builder: atom별 sidecar를 SFT/preference/reward/eval shard로 변환한다.
- Naite training stack: Stage E dataset을 기반으로 Strand-14B 계열 QLoRA/LoRA SFT smoke, eval, model card, signed artifact chain, vLLM serving handoff를 만든다.
- Public docs and SDK: quickstart, install, provider, skill author guide, self-host gas station, contributor dry-run, security policy를 제공한다.

## 4. 시스템 구조

Sinabro는 다음 계층으로 구성된다.

```text
User
  -> CLI/TUI/Telegram
  -> CommandEnvelope / MessageEnvelope
  -> Sinabro Rust Core
       - runtime supervisor
       - tool dispatcher
       - provider/model router
       - memory engine
       - skill runtime
       - wallet/gas/chain policy
       - evidence collector
  -> External or local model
       - OpenAI / Anthropic / Gemini / local Naite / vLLM
  -> Tools and substrates
       - cargo / clippy / miri / Kani
       - Sui CLI / Move test / Move Prover
       - Walrus
       - web research/browser with source evidence
  -> Evidence bundle
  -> Dataset builder
  -> Naite training/eval/serving
```

모델은 권한자가 아니다. 모델은 제안한다. Sinabro core가 capability diff, approval gate, budget gate, gas policy, source evidence, redaction policy를 통과시킨 뒤에만 tool, skill, memory, wallet, chain action이 실행된다.

## 5. Atom 계획

Sinabro 개발은 atom 단위로 진행된다. atom은 "작은 할 일"이 아니라 merge 가능한 최소 증거 단위다. Stage A 기준 atom 문법은 다음 9개 필드를 가진다.

- `id`: atom 번호와 PR-id
- `file`: 수정 대상 파일
- `canonical OUT`: 이 atom이 만들어야 하는 단 하나의 정준 산출물
- `제약 사양`: 성능, 보안, 단위, boundary를 엄격히 고정하는 구현 조건
- `test 목록`: 반드시 실행하거나 not_verified로 기록해야 하는 테스트
- `criterion`: green 판정 기준
- `gate`: 참조해야 하는 gate id
- `reuse`: 재발명 금지 canonical input
- `next-atom`: 다음 atom pointer

각 atom은 구현 세션과 검증 세션을 분리할 수 있다. 구현 세션은 scope lock, task list, code diff, command manifest를 만든다. 검증 세션은 동일 scope를 다시 읽고 test, static analysis, red-team, review, sidecar completeness를 검증한다.

## 6. AtomDietRecord

각 atom은 `ops/training/{phase_or_stage}/atom_###/` 아래에 학습 식단 sidecar를 남긴다.

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

이 21개 파일은 Naite 학습의 원재료다. 특히 `review_5pack.json`은 perf/security/chain/agent-token/devex 리뷰를 강제하고, `deny_audit.json`은 dependency/license/advisory/source check를 기록한다. 성능이 좋아도 보안, gas, chain invariant, privacy, secret policy를 위반하면 reward는 0 또는 deny label이 된다.

중요한 점은 **모든 로그가 학습 데이터가 아니라는 것**이다. secret, private memory, provider body, sponsor key, payment secret, 권리 불명 웹 본문은 Naite 공용 학습 후보가 아니다. 데이터셋 빌더는 "훈련할 데이터를 모으는 장치"인 동시에 "훈련하면 안 되는 데이터를 제거하는 검증 파이프라인"이다.

## 7. 기억 소유권

Sinabro의 기억은 모델의 hidden state나 중앙 서버 계정에 묶이지 않는다.

- 메시지, tool result, skill artifact, system memory는 typed chunk로 직렬화된다.
- Walrus에 저장된 blob은 로컬 digest와 blob-id verify를 통과해야 한다.
- Sui `memory_root`와 `audit_log`는 owner invariant와 replay anchor를 제공한다.
- replay는 Sui event와 Walrus blob에서 같은 transcript hash를 재현해야 한다.
- delete/export/import/compact는 user-visible memory command와 evidence를 남긴다.

이 설계에서 모델은 기억의 주인이 아니다. 모델은 사용자가 소유한 기억 위를 지나가는 가속기다. Naite가 14B에서 40B로 바뀌거나 외부 API를 쓰더라도, memory root와 audit trail은 유지된다.

## 8. Skills

Sinabro의 스킬 시스템은 초기에는 유료 마켓이 아니다. 초기 릴리스 범위에서 `skill buy`, checkout, paid license, refund, revenue, royalty payout 실행 경로는 금지된다. 초기 목표는 시장화가 아니라 사용성 확보와 스킬 생태계 형성이다.

지원되는 흐름은 다음과 같다.

- `skill search`: 가벼운 card만 검색한다.
- `skill inspect`: 선택한 skill의 manifest, capability, eval, provenance를 자세히 본다.
- `skill recommend`: 현재 repo, toolchain, chain env, budget, test failure를 보고 후보를 추천한다.
- `skill use/install`: capability diff와 user confirmation 후 실행 또는 설치한다.
- `skill enable/disable/update/remove`: local install state를 조작한다.
- `skill fork/publish/eval/provenance`: community registry와 검증 루프를 연결한다.

검색 결과는 전체 manifest를 매번 읽지 않는다. 먼저 name, description, capability summary, verified installs, eval/security/compatibility, permission diff를 보여주고, 사용자가 선택할 때만 heavy metadata를 로드한다. 10k+ skills 환경에서도 terminal search처럼 느껴지는 것이 목표다.

## 9. 도구와 웹 리서치 경계

Sinabro는 web search/fetch/open/snapshot/cite/save-source capability를 갖는 agent로 계획되어 있다. 하지만 웹 결과는 source evidence 없이는 지식이 되지 않는다.

필수 metadata는 다음과 같다.

- `source_url`
- `retrieved_at`
- `fetch_hash`
- rights/robots/paywall decision
- citation evidence
- browser credential redaction report

웹 본문은 기본적으로 Naite 공용 식단 후보가 아니다. 사용자가 local diet, private adapter, redacted contribution을 켜도 rights gate와 redaction gate를 통과해야 한다.

Tool call도 같은 원칙을 따른다. 모델 출력 JSON이 곧 tool execution이 아니다. 순서는 항상 proposal -> capability diff -> approval/budget/source/gas gate -> execution queue -> evidence다.

단 제어 명령은 일반 작업이 아니다. `/kill`, `budget cap`, pause, lockdown, provider freeze, wallet/gas hard stop은 replay/train/evidence/export/tool/serving batch queue 뒤에서 기다리면 안 된다. 이들은 별도 control-plane express rail로 들어가고, token spend, provider call, tool execution, wallet signing, gas sponsorship, memory write, retry 직전에 최신 control state를 다시 확인한다.

## 10. Provider와 Router

Sinabro는 OpenAI, Anthropic, Gemini, local Naite, vLLM 같은 provider를 같은 router 표면으로 다룬다. 그러나 fallback은 절대 조용히 일어나지 않는다.

Router trace는 다음을 남겨야 한다.

- 어떤 provider/model이 선택됐는가
- 왜 선택됐는가
- fallback이 필요했는가
- fallback 비용, 품질, privacy 차이는 무엇인가
- 사용자가 승인했는가
- request/job/eval evidence는 어디에 있는가

Stage H에서 Naite가 vLLM으로 연결되어도 이 원칙은 유지된다. local FT endpoint가 준비됐다는 사실만으로 production route가 되지 않는다. model card, adapter hash, tokenizer/template lock, eval report, rollback manifest, cost ledger, signed artifact chain이 맞아야 한다.

## 11. Gas Station 불변식

Sinabro는 오픈소스 gasless UX를 지원하되 sponsor key를 repo, client, container image, docs example에 넣지 않는다. 공개 endpoint는 숨길 수 없다고 가정한다. 따라서 보안은 "비밀 URL"이 아니라 "서명 불가능 조건"에서 나온다.

Gas Station의 핵심 invariant는 다음과 같다.

- sponsor key는 서버 KMS/HSM/TEE signer 밖으로 export되지 않는다.
- open-source client는 user transaction intent와 user signature만 만든다.
- Gas Station은 raw opaque transaction bytes에 서명하지 않는다.
- package/function allowlist 없이는 sponsor signature를 만들 수 없다.
- dry-run/dev-inspect가 abort, storage delta, gas budget, object count, command count를 먼저 확인한다.
- per-user, wallet, IP, ASN, package, skill, epoch, global hot-wallet quota가 모두 통과해야 한다.
- sponsor gas coin은 1 transaction lease만 허용한다.
- hot wallet은 소액으로 유지되고 treasury는 multisig/cold path 뒤에 둔다.
- anomaly trigger가 발생하면 hosted gas station은 paused로 전환된다.

Gas sponsorship은 skill payment와 분리된다. 초기 릴리스 범위에는 skill price payment가 없다.

## 12. Naite 학습

Naite의 학습은 Stage E 이후에만 시작된다. Stage G는 A100에서 Strand-14B 계열 QLoRA/LoRA SFT smoke를 수행하는 첫 학습 게이트다.

학습 원칙은 다음과 같다.

- SFT smoke 전에는 GRPO/MURPHY/FGO를 실행하지 않는다.
- loss가 내려가는 것만으로 승급하지 않는다.
- compile, clippy, miri, Kani, Move test, Move Prover, gas, Korean eval, held-out generalization이 회귀하면 promotion 금지다.
- OOM, timeout, infra failure는 모델 잘못으로 reward하지 않는다.
- provider output은 공용 Naite 학습에 넣지 않는다.
- S1 verifiable data와 S2 narrative data를 분리한다.
- Stage H serving handoff는 signed artifact chain 없이는 불가능하다.

한국어는 단순 번역 작업이 아니다. 목표는 한국어로 lifetime, ownership, invariant, gas, exploit, Prover repair, Rust/Move debugging을 지시해도 영어와 동등한 품질을 내는 것이다. 보상 신호는 언어 중립인 compiler/prover/test/gas에 둔다.

## 13. 평가

Sinabro/Naite의 평가는 모델 benchmark 하나로 끝나지 않는다.

- Rust: `cargo fmt`, `cargo clippy`, `cargo test`, `cargo miri`, fuzz/property, criterion, Kani
- Move/Sui: `sui move test`, Move Prover, BCS parity, owner invariant, gas trace
- Walrus: PUT/GET round trip, blob-id local derive, integrity verify
- Memory: replay determinism, transcript hash, delete/export/import semantics
- Skill: malicious fixture, capability diff, signature/provenance, verified install, no-commerce scan
- Web: source URL, retrieved_at, fetch hash, rights/citation evidence, credential redaction
- Router: no silent fallback, route decision evidence, cost/quality scorecard
- Gas: allowlist, dry-run, quota, gas cap, coin lease, hot wallet burn cap
- Dataset: PII0/secret0, S1/S2 split, reward firewall, deny audit
- Korean: Korean prompt eval with English-equivalent technical quality
- Long context: RULER/long-context smoke, packing/OOM guard

가장 강한 평가 기준은 held-out 일반화다. Naite는 학습 trace를 외웠다는 이유만으로 개선됐다고 보지 않는다. 안전성과 비용 gate를 유지한 채, 학습에 쓰지 않은 Rust/Move/gas/security 과제에서 개선을 보여야 한다.

## 14. 오픈소스 사용자 주권

Sinabro/Naite는 오픈소스 배포를 전제로 설계된다. 따라서 기본값은 보수적이어야 한다.

사용자 학습 모드는 다음과 같다.

```toml
mode = "off" # off | evidence_only | local_diet | private_adapter | contribute_redacted
external_model_output_training = "never"
```

사용자는 다음 중 하나를 선택할 수 있다.

- 학습 산출물 없이 Sinabro만 사용
- 로컬 evidence만 생성
- 로컬 Naite 학습 레코드 생성
- private adapter 학습
- redacted trace를 공개 데이터셋 후보로 기여

사용자는 safety kernel을 끌 수 없다. secret redaction, capability diff, no silent fallback, no auto-merge, wallet/gas/mainnet approval gate, source evidence 요구사항은 항상 유지된다.

## 15. 로드맵

로드맵은 각 단계가 독립적으로 검증 가능한 산출물을 남기도록 구성된다.

- **Stage A:** Rust core, Telegram/CLI foundation, trace/measure collector, Phase 0 atom contract.
- **Stage B:** signed chunk schema, Walrus testnet client, Sui testnet `memory_root`/`audit_log`, owner invariant, replay determinism.
- **Stage C:** GA hardening, gas trace harness, mainnet gate, key isolation, hosted/self/none gas policy.
- **Stage D:** skill runtime, open registry, signed packages, provenance, install receipt, progressive disclosure, Memory Intelligence.
- **Stage E:** AtomDietRecord dataset builder, rights/redaction, Rust/Move/Walrus/skill/memory collectors, reward firewall, Stage G unlock packet.
- **Stage F:** CLI Cockpit, provider/tool/web/skill/memory/wallet/gas/chain/dataset/train/eval/measure controls, first 5-minute UX.
- **Stage G:** A100 SFT smoke and first Naite fine-tune with strict eval and GRPO lock.
- **Stage H:** vLLM serving, local FT router, no silent fallback proof, CLI/Telegram state sync, Stage I handoff.
- **Stage I:** read-only mainnet measurement loop for gas/cycle/security telemetry.
- **Stage J:** self-growth v1, public open-source readiness, SDK, docs, review queue.
- **Stage K:** 통제된 자기개선 루프가 gate 안에서 수동 개선 속도를 앞서는지 검증한 뒤에만 더 큰 GPU/model로 승급.

## 16. 강점

Sinabro/Naite가 일반 코딩 챗봇과 다른 점은 개발 루프 전체를 구조화된 상태로 남긴다는 것이다.

- 컨텍스트 창 밖에서도 기억을 유지한다. 기억은 Walrus/Sui 기반 소유 substrate에 남는다.
- prompt engineering을 넘어선 개선 루프를 갖는다. 모든 atom은 학습 가능한 evidence를 만든다.
- green 상태는 command output, artifact hash, proof, gas trace, approval 같은 구체적 증거를 가리켜야 한다.
- capability diff와 approval이 모델 밖에 있으므로 도구 실행 경계가 더 명확하다.
- 초기 adoption을 유료 마켓에 묶지 않고 skill registry를 확장할 수 있다.
- 외부 frontier API를 쓰더라도 provider output은 같은 evidence/privacy gate를 통과한다.
- 추후 Naite를 더 큰 모델로 옮겨도 memory, skill, evidence substrate는 유지된다.

따라서 Sinabro/Naite는 단순한 Web3 도구나 local model wrapper가 아니다. 첫 깊은 전문화 영역은 Rust/Move/Sui/Walrus지만, 같은 atom/evidence/skill 구조를 통해 더 넓은 소프트웨어 엔지니어링으로 확장할 수 있다.

## 17. 한계

현재 한계는 명확히 구분한다.

- 초기 릴리스 범위에는 Solana/Anchor tool execution이 없다. 관련 언급은 향후 확장 또는 데이터셋/참고 자료에 한정된다.
- 초기 릴리스 범위에는 유료 스킬 마켓 실행 경로가 없다.
- Naite가 launch 시점부터 frontier model을 능가한다고 가정하지 않는다.
- Walrus/Sui memory ownership, Gas Station, vLLM serving, mainnet measurement는 공개 주장 전에 단계별 evidence가 필요하다.
- 자기개선은 권한 상승이 아니다. Naite가 더 좋아져도 Sinabro의 권한은 넓어지지 않는다.
- 공개 기여 데이터는 opt-in, redaction, rights check, provenance preservation을 통과해야 한다.

## 18. 결론

Sinabro는 에이전트 계층이고, Naite는 그 에이전트가 만든 검증된 작업 기록으로 개선되는 모델이다. Walrus/Sui 기억은 사용자가 소유한 연속성이고, skill은 재사용 가능한 능력 단위이며, AtomDietRecord는 실제 작업을 다음 학습 신호로 바꾸는 기록 형식이다.

목표는 과장된 데모가 아니라 개발자가 설치하고, 검사하고, 확장하고, 신뢰할 수 있는 조용한 오픈소스 시스템이다. 모든 주장은 trace를 가져야 하고, 모든 trace는 hash를 가져야 하며, 모든 개선은 다음 개선을 위한 학습 기록을 남겨야 한다.

## 참고 문헌

아래 공개 문헌은 백서의 형식, 평가, 안전성 서술 방식을 참고하기 위해 사용했다. Sinabro/Naite의 구조와 로드맵은 프로젝트 고유 설계다.

- Ryan Teknium, Jeffrey Quesnelle, Chen Guang. "Hermes 3 Technical Report." arXiv:2408.11857, 2024. https://arxiv.org/abs/2408.11857
- Nous Research. "Hermes 3." https://nousresearch.com/hermes3/
- OpenAI. "GPT-4 Technical Report." arXiv:2303.08774, 2023; revised 2024. https://arxiv.org/abs/2303.08774
- OpenAI. "GPT-4o System Card." 2024. https://openai.com/index/gpt-4o-system-card/
