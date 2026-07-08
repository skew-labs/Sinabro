//! `sinabro` / `mnemos` binary entry.
//!
//! Dispatch (5-mode): `--version` / `--help` / `doctor` are handled
//! here; the default (no args) and `repl` enter the interactive REPL read-eval
//! loop ([`sinabro::repl::run`]); `tui` enters the full-screen cockpit event loop
//! ([`sinabro::tui::run`]); `run` is the non-interactive single command; and every
//! other operational top-level command or closed [`sinabro::grammar`] namespace
//! routes to [`sinabro::dispatch::run`], which
//! classifies the command through [`sinabro::command::CommandEnvelope`] and
//! renders the handler status / approval-locked surface (no side effect runs at
//! this stage). The binary writes to
//! explicit stdout/stderr handles (never the `print!`/`println!` macros, which
//! the workspace clippy gate denies) and returns an [`ExitCode`]; there is no
//! `unwrap`/`expect`/`panic` path. argv[0] selects only the banner name so the
//! `mnemos` alias and `sinabro` behave identically.
#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::process::ExitCode;

use sinabro::dispatch;
use sinabro::doctor::{self, DoctorProbe};
use sinabro::grammar;
use sinabro::repl;
use sinabro::tui;

fn invoked_name() -> &'static str {
    // argv[0] basename ending in "mnemos" => legacy alias banner; else sinabro.
    match std::env::args().next() {
        Some(arg0)
            if arg0
                .rsplit(['/', '\\'])
                .next()
                .is_some_and(|b| b.ends_with("mnemos")) =>
        {
            "mnemos"
        }
        _ => "sinabro",
    }
}

/// Whether an executable named `name` exists on `PATH` (local fs only; no spawn,
/// no network).
fn on_path(name: &str) -> bool {
    let Some(path) = std::env::var_os("PATH") else {
        return false;
    };
    std::env::split_paths(&path).any(|dir| dir.join(name).is_file())
}

fn provider_env_present() -> bool {
    // Presence only; the value is never read.
    ["ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"]
        .iter()
        .any(|k| std::env::var_os(k).is_some())
}

fn write_help(out: &mut impl Write, invoked: &str) -> io::Result<()> {
    writeln!(out, "{invoked} — Mnemos / Sinabro CLI Cockpit (Stage F)")?;
    writeln!(out)?;
    writeln!(out, "USAGE:")?;
    writeln!(out, "    sinabro [--version|--help]")?;
    writeln!(out, "    sinabro doctor")?;
    writeln!(out, "    sinabro <namespace> [verb] ...")?;
    writeln!(out)?;
    writeln!(
        out,
        "NAMESPACES (closed surface, {} total):",
        grammar::COUNT
    )?;
    let mut line = String::from("    ");
    for ns in grammar::ALL {
        line.push_str(ns.canonical_name());
        line.push(' ');
        if line.len() > 64 {
            writeln!(out, "{}", line.trim_end())?;
            line = String::from("    ");
        }
    }
    if line.trim().is_empty() {
        Ok(())
    } else {
        writeln!(out, "{}", line.trim_end())
    }
}

/// Gather the doctor-visible secret-scan surfaces: the user-controlled
/// PLAINTEXT config the binary can see — `$HOME/.mnemos/config.toml` and a project
/// `./sinabro.toml` when present. The encrypted memory key/store and the hash-only
/// otel/audit dirs are NEVER read (no plaintext secret lives there). Best-effort:
/// an unreadable / absent file contributes no surface (an empty surface set is
/// vacuously secret-zero — a clean fresh install).
fn gather_secret_surfaces() -> Vec<String> {
    let mut surfaces = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        let cfg = std::path::Path::new(&home)
            .join(".mnemos")
            .join("config.toml");
        if let Ok(text) = std::fs::read_to_string(&cfg) {
            surfaces.push(text);
        }
    }
    if let Ok(text) = std::fs::read_to_string("sinabro.toml") {
        surfaces.push(text);
    }
    surfaces
}

fn run_doctor(out: &mut impl Write, invoked: &str) -> io::Result<()> {
    // The security verdicts are MEASURED, never hardcoded `true`.
    let surfaces = gather_secret_surfaces();
    let surface_refs: Vec<&str> = surfaces.iter().map(String::as_str).collect();
    let probe = DoctorProbe {
        rust_ok: on_path("rustc") || on_path("cargo"),
        sui_ok: on_path("sui"),
        walrus_ok: on_path("walrus"),
        provider_ok: provider_env_present(),
        secret_zero: doctor::measure_secret_zero(&surface_refs),
        safety_kernel_intact: doctor::measure_safety_kernel_intact(),
    };
    let report = doctor::build_report(&probe);
    let trust = doctor::safety_kernel_trust(probe.safety_kernel_intact, false, false);
    writeln!(out, "{invoked} doctor")?;
    writeln!(out, "  rust:     {}", yn(report.rust_ok))?;
    writeln!(out, "  sui:      {}", yn(report.sui_ok))?;
    writeln!(out, "  walrus:   {}", yn(report.walrus_ok))?;
    writeln!(out, "  provider: {}", yn(report.provider_ok))?;
    writeln!(out, "  secret-zero: {}", yn(report.secret_zero))?;
    writeln!(out, "  safety-kernel: {trust:?}")?;
    writeln!(out, "  learning: off (default)")?;
    writeln!(out, "  next: {}", doctor::next_action(&probe))?;
    Ok(())
}

const fn yn(ok: bool) -> &'static str {
    if ok { "ok" } else { "missing" }
}

fn main() -> ExitCode {
    let invoked = invoked_name();
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = io::stdout().lock();
    let mut err = io::stderr().lock();

    let result: io::Result<ExitCode> = match args.first().map(String::as_str) {
        Some("--version" | "-V") => {
            writeln!(out, "{invoked} {}", env!("CARGO_PKG_VERSION")).map(|()| ExitCode::SUCCESS)
        }
        Some("--help" | "-h") => write_help(&mut out, invoked).map(|()| ExitCode::SUCCESS),
        Some("doctor") => run_doctor(&mut out, invoked).map(|()| ExitCode::SUCCESS),
        // 5-mode dispatch. The default (no args) and `repl` enter the
        // interactive REPL read-eval loop; `tui` enters the full-screen cockpit
        // event loop. Both are render/dispatch only — every side-effect verb stays
        // approval-gated and disabled at this stage (no side effect runs). In a non-TTY
        // pipe each loop exits cleanly at EOF (never hangs).
        None | Some("repl") => repl::run::launch().map(|()| ExitCode::SUCCESS),
        Some("tui") => tui::run::launch().map(|()| ExitCode::SUCCESS),
        // `run` is the non-interactive single command for CI / automation.
        Some("run") => dispatch::run(&args[1..], &mut out, &mut err),
        // `admin` is the operator console (sponsor quota / balance / release /
        // federation / incident), rendered through the closed admin namespace
        // surface — operator-gated, render-only at this stage.
        Some("admin") => dispatch::run(&args, &mut out, &mut err),
        // Every other token (operational top-level command or closed namespace)
        // routes to the operational dispatch. The safety gate lives in
        // `CommandEnvelope::classify`; dispatch renders status / locked surfaces
        // only and never executes a side effect at this stage.
        Some(_) => dispatch::run(&args, &mut out, &mut err),
    };

    match result {
        Ok(code) => code,
        // A broken stdout/stderr pipe is the only failure path here; exit non-zero
        // without panicking.
        Err(_) => ExitCode::FAILURE,
    }
}
