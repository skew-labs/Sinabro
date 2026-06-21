//! `mnemos-cli` — the Hermes-style local CLI cockpit (Phase 0).
//!
//! Boot wiring per ATOM_PLAN atom #6 (A.0.6 graceful shutdown 배선) — the same
//! boundary-aware boot/shutdown chain as `mnemos-agent`, differing only in the
//! [`mnemos_a_core::LogService`] discriminant stamped onto every event line.
//! Atom #45 (J.0.5) lands [`repl::CliRepl`] / [`repl::run_repl`] as the
//! Hermes-style local REPL surface; this bin keeps the canonical boot
//! sequence in [`main`] and exposes the REPL module as a sibling so a
//! future Stage F/H atom can thread the live `LlmClient` into the loop
//! without disturbing the boot chain.
#![deny(missing_docs)]

mod repl;

use std::ffi::OsString;
use std::io::Write as _;
use std::process::ExitCode;
use std::time::{Duration, Instant};

use mnemos_a_core::{
    ErrorOp, LogService, LogShutdownEvent, MnemosError, RuntimeEnv, RuntimeShutdownState,
    RuntimeSupervisor, StateRejectReason, config_error_report, config_path_from_args,
    current_effective_uid_u32, emit_config_failure_log, emit_shutdown_log, emit_startup_log,
    init_json_logging, load_runtime_config_from_path, validate_runtime_env,
};

const SERVICE: LogService = LogService::Cli;
const SUPERVISOR_CAPACITY: usize = 8;
const SHUTDOWN_TIMEOUT_MS_U64: u64 = 5_000;
const SHUTDOWN_TIMEOUT_MS_U32: u32 = 5_000;
const DRAIN_POLL_INTERVAL_MS: u64 = 50;

const HELP_TEXT: &str = concat!(
    "mnemos-cli — MNEMOS Phase 0 local CLI cockpit\n",
    "\n",
    "USAGE:\n",
    "    mnemos-cli --config <PATH>\n",
    "    mnemos-cli --repl\n",
    "    mnemos-cli --help\n",
    "\n",
    "OPTIONS:\n",
    "    --config <PATH>    Path to a TOML runtime config (required for service mode).\n",
    "    --repl             Launch the Hermes-style local REPL (atom #45 · J.0.5).\n",
    "    -h, --help         Print this help and exit.\n",
);

fn main() -> ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if args.iter().any(|a| a == "--help" || a == "-h") {
        write_to_stderr(HELP_TEXT.as_bytes());
        return ExitCode::SUCCESS;
    }

    let env = RuntimeEnv::default_phase0();
    if let Err(e) = validate_runtime_env(env, current_effective_uid_u32()) {
        emit_config_failure_log(SERVICE, config_error_report(e));
        return ExitCode::FAILURE;
    }

    if args.iter().any(|a| a == "--repl") {
        let _init = init_json_logging();
        emit_startup_log(SERVICE);
        let cfg = repl::CliRepl::default();
        return match repl::run_repl(&cfg) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                emit_config_failure_log(SERVICE, config_error_report(e));
                ExitCode::FAILURE
            }
        };
    }

    let config_path = match config_path_from_args(args.iter().cloned()) {
        Ok(Some(p)) => p,
        Ok(None) => {
            let err = MnemosError::state_rejected(ErrorOp::Config, StateRejectReason::PhaseGate);
            emit_config_failure_log(SERVICE, config_error_report(err));
            return ExitCode::FAILURE;
        }
        Err(e) => {
            emit_config_failure_log(SERVICE, config_error_report(e));
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = load_runtime_config_from_path(&config_path, env) {
        emit_config_failure_log(SERVICE, config_error_report(e));
        return ExitCode::FAILURE;
    }

    let _init = init_json_logging();
    emit_startup_log(SERVICE);

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let err = MnemosError::source_redacted_from_error(ErrorOp::Bootstrap, &e);
            emit_config_failure_log(SERVICE, config_error_report(err));
            return ExitCode::FAILURE;
        }
    };

    let supervisor: RuntimeSupervisor<SUPERVISOR_CAPACITY> = RuntimeSupervisor::new();
    rt.block_on(supervise_until_shutdown(&supervisor))
}

async fn supervise_until_shutdown<const CAP: usize>(
    supervisor: &RuntimeSupervisor<CAP>,
) -> ExitCode {
    wait_for_terminal_signal().await;
    let _accepted = supervisor.request_shutdown(SHUTDOWN_TIMEOUT_MS_U64);
    emit_shutdown_log(
        SERVICE,
        LogShutdownEvent::Requested,
        SHUTDOWN_TIMEOUT_MS_U32,
        0,
        0,
        0,
        0,
    );
    let started = Instant::now();
    emit_shutdown_log(
        SERVICE,
        LogShutdownEvent::DrainStarted,
        SHUTDOWN_TIMEOUT_MS_U32,
        0,
        0,
        0,
        0,
    );
    loop {
        let elapsed_ms_u64: u64 = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let elapsed_ms_u32: u32 = u32::try_from(elapsed_ms_u64).unwrap_or(u32::MAX);
        if elapsed_ms_u64 >= SHUTDOWN_TIMEOUT_MS_U64 {
            let report = supervisor.record_drain_timeout(elapsed_ms_u64);
            emit_shutdown_log(
                SERVICE,
                LogShutdownEvent::DrainTimeout,
                SHUTDOWN_TIMEOUT_MS_U32,
                elapsed_ms_u32,
                report.active_count_u16,
                report.timed_out_count_u16,
                report.unknown_after_boundary_count_u16,
            );
            return ExitCode::SUCCESS;
        }
        let report = supervisor.drain_snapshot(elapsed_ms_u64);
        if report.shutdown_state == RuntimeShutdownState::Exited {
            emit_shutdown_log(
                SERVICE,
                LogShutdownEvent::Completed,
                SHUTDOWN_TIMEOUT_MS_U32,
                elapsed_ms_u32,
                report.active_count_u16,
                report.timed_out_count_u16,
                report.unknown_after_boundary_count_u16,
            );
            return ExitCode::SUCCESS;
        }
        tokio::time::sleep(Duration::from_millis(DRAIN_POLL_INTERVAL_MS)).await;
    }
}

#[cfg(unix)]
async fn wait_for_terminal_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    match (
        signal(SignalKind::terminate()),
        signal(SignalKind::interrupt()),
    ) {
        (Ok(mut term), Ok(mut intr)) => {
            tokio::select! {
                _ = term.recv() => {}
                _ = intr.recv() => {}
            }
        }
        _ => {
            let _ = tokio::signal::ctrl_c().await;
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_terminal_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

fn write_to_stderr(bytes: &[u8]) {
    let stderr = std::io::stderr();
    let mut h = stderr.lock();
    let _ = h.write_all(bytes);
}
