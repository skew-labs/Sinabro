//! `sinabro daemon` — Stage G operational daemon + task/session control rail
//! (G-WP-03 · #509-#514).
//!
//! Stage F minted the control spine reused here: the canonical
//! [`crate::tui::job_rail`] (the no-zombie job rail), the
//! [`crate::commands::kill`] express kill, the [`crate::commands::budget`] cap
//! gate, and the [`crate::commands::platform_telegram::ExpressControl`] rail.
//! Stage G composes them into the operational daemon and never redefines them:
//!
//! - [`supervisor`] (#509): the daemon supervisor view — background watcher
//!   lifecycle that owns no wallet/provider secret.
//! - [`task_session`] (#510): the shared task/session inbox — provider / audit /
//!   memory / evidence / notification / handoff jobs share one id space.
//! - [`control_express`] (#511): the express bypass — STOP/freeze/pause controls
//!   preempt the saturated background queues (no live action).
//! - [`budget_kill`] (#512): budget/kill integration — the cap is re-checked
//!   before each side effect and a killed task can never write evidence.
//! - [`reconnect`] (#513): reconnect/resume — CLI and Telegram see one shared
//!   state hash; a stale view is refused.
//! - [`approval_sync`] (#514): approval event sync — each approval is recorded
//!   once with its source channel and hash; a replay is refused.
//! - [`runtime`] (ENDGAME E3): the REAL bounded background runner that turns the
//!   above SCAFFOLD into a live autonomous-while-away job — a pure step-machine
//!   ([`runtime::AutonomyRuntime`]) + a thin `std::thread` pump
//!   ([`runtime::RuntimeHandle`]). It holds ONLY READ + an OPTIONAL owner-armed
//!   egress grant, re-derives the per-turn capability from the grant, re-checks the
//!   budget cap before every side effect, and is killable with no zombie. It owns
//!   no wallet/provider secret and adds no socket (every outbound byte still passes
//!   the SI-2 redact choke inside the agent loop).
//! - [`remote_approval`] (ENDGAME E4): the "away → ping → reply → proceed"
//!   orchestration. When the runner hits a gated action it cannot fire (no grant),
//!   the owner is PINGED (SI-2-redacted, SI-6-deduped); the owner's untrusted phone
//!   reply is INGESTED (sender-pinned, action-bound, replay-refused via the now
//!   load-bearing [`approval_sync`]); on approval a NARROW single-shot grant
//!   (unforgeable SI-3) ARMS the runner ([`runtime::AutonomyRuntime::install_egress_grant`])
//!   so the one denied action proceeds — and nothing wider.
//!
//! No module here loads a wallet/provider secret or trains a model (Stage G
//! `G-G-NO-TRAINING-IN-G`). [`runtime`] is the ONE module that drives a live
//! bounded job (the agent loop), but it opens no socket itself and mints no
//! authority (the per-turn egress capability comes only from the owner-armed grant).

pub mod approval_sync;
pub mod budget_kill;
pub mod control_express;
pub mod reconnect;
pub mod remote_approval;
pub mod runtime;
pub mod supervisor;
pub mod task_session;
