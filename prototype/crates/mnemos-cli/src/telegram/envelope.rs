//! Operational Telegram → CommandEnvelope bridge (atom #507 · G.2.1).
//!
//! The CLI and the Telegram bridge see the *same* command semantics: a control
//! verb (`/status`, `/kill`, `/budget`, `/task`, `/session`, `/notify`, `/audit`)
//! classifies to a byte-identical [`crate::command::CommandEnvelope`] regardless
//! of the channel it entered through, so a command can never diverge by transport
//! (the channel-parity invariant, `G-G-CONTROL-EXPRESS`). Only the
//! [`crate::commands::platform_telegram::PlatformOrigin`] differs. A verb outside
//! the closed control set is refused fail-closed (a hidden side-effect command is
//! impossible).
//!
//! Reuse (no reinvention): the classified command is the crate
//! [`crate::command::CommandEnvelope`] built through its closed
//! [`crate::command::CommandEnvelope::classify`] risk→approval mapping; the
//! transport wrapper is the F [`crate::commands::platform_telegram::MessageEnvelope`];
//! the namespace is the closed [`crate::grammar::CliNamespace`]. This module
//! performs no live action.

use crate::command::{CliMode, CommandEnvelope, CommandRisk};
use crate::commands::platform_telegram::{MessageEnvelope, PlatformOrigin};
use crate::grammar::CliNamespace;

/// The closed set of control verbs reachable from Telegram (and the CLI). A verb
/// outside this set is forbidden on the bridge.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlVerb {
    /// `/status` — read operational status.
    Status = 1,
    /// `/kill` — express hard stop.
    Kill = 2,
    /// `/budget` — budget cap control.
    Budget = 3,
    /// `/task` — task inbox control.
    Task = 4,
    /// `/session` — session control.
    Session = 5,
    /// `/notify` — notification rule control.
    Notify = 6,
    /// `/audit` — audit trail view.
    Audit = 7,
}

impl ControlVerb {
    /// Every control verb, in discriminant order.
    pub const ALL: [ControlVerb; 7] = [
        ControlVerb::Status,
        ControlVerb::Kill,
        ControlVerb::Budget,
        ControlVerb::Task,
        ControlVerb::Session,
        ControlVerb::Notify,
        ControlVerb::Audit,
    ];

    /// The stable `u8` discriminant.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// The canonical (lower-case) verb string.
    #[must_use]
    pub const fn canonical(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Kill => "kill",
            Self::Budget => "budget",
            Self::Task => "task",
            Self::Session => "session",
            Self::Notify => "notify",
            Self::Audit => "audit",
        }
    }

    /// The closed command namespace this verb belongs to. `/status`, `/kill` and
    /// `/budget` are agent-turn controls; the rest map to their own namespace.
    #[must_use]
    pub const fn namespace(self) -> CliNamespace {
        match self {
            Self::Status | Self::Kill | Self::Budget => CliNamespace::Agent,
            Self::Task => CliNamespace::Task,
            Self::Session => CliNamespace::Session,
            Self::Notify => CliNamespace::Notify,
            Self::Audit => CliNamespace::Audit,
        }
    }

    /// The risk class of this control verb. Read-only views need no approval;
    /// `/kill`, `/budget` and `/notify` mutate local control/config state.
    #[must_use]
    pub const fn risk(self) -> CommandRisk {
        match self {
            Self::Status | Self::Task | Self::Session | Self::Audit => CommandRisk::ReadOnly,
            Self::Kill | Self::Budget | Self::Notify => CommandRisk::LocalWrite,
        }
    }

    /// Parse a raw token (optionally a `/`-prefixed slash command) into a control
    /// verb. An unknown token returns `None` (the caller refuses it).
    #[must_use]
    pub fn parse(token: &str) -> Option<ControlVerb> {
        let t = token.trim().trim_start_matches('/').to_ascii_lowercase();
        ControlVerb::ALL.into_iter().find(|v| v.canonical() == t)
    }
}

/// Why a Telegram → command bridge was refused (fail-closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TelegramBridgeReject {
    /// The verb is not a recognized control verb — forbidden on the bridge.
    #[error("forbidden telegram command verb")]
    ForbiddenVerb,
}

/// Classify a control verb into a [`CommandEnvelope`]. The envelope is
/// origin-independent: the same verb always produces the same command.
#[must_use]
pub fn classify_verb(verb: ControlVerb) -> CommandEnvelope {
    CommandEnvelope::classify(
        verb.namespace(),
        verb.canonical(),
        CliMode::Run,
        verb.risk(),
        verb.canonical().as_bytes(),
    )
}

/// Bridge a raw Telegram command token into a [`MessageEnvelope`]. A non-control
/// verb is refused. The resulting [`CommandEnvelope`] is byte-identical to the
/// CLI's for the same verb — only the [`PlatformOrigin`] differs.
pub fn bridge(
    origin: PlatformOrigin,
    token: &str,
) -> Result<MessageEnvelope, TelegramBridgeReject> {
    let verb = ControlVerb::parse(token).ok_or(TelegramBridgeReject::ForbiddenVerb)?;
    Ok(MessageEnvelope::new(origin, classify_verb(verb)))
}

/// Whether the same verb yields the SAME command from the CLI and from Telegram
/// (the channel-parity invariant): the commands are equal and only the origin
/// differs.
#[must_use]
pub fn same_command_across_channels(verb: ControlVerb) -> bool {
    let cli = MessageEnvelope::new(PlatformOrigin::Cli, classify_verb(verb));
    let tg = MessageEnvelope::new(PlatformOrigin::Telegram, classify_verb(verb));
    cli.origin != tg.origin && cli.same_command(&tg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repl::latency::p95_ms;

    fn bridged_command(verb: &str) -> Option<CommandEnvelope> {
        bridge(PlatformOrigin::Telegram, verb)
            .ok()
            .map(|m| m.command())
    }

    #[test]
    fn status_bridges_to_agent_read_only() {
        let m = bridge(PlatformOrigin::Telegram, "/status");
        assert!(m.is_ok());
        if let Ok(env) = m {
            assert_eq!(env.origin, PlatformOrigin::Telegram);
            assert_eq!(env.command().id.namespace, CliNamespace::Agent);
            assert_eq!(env.command().risk, CommandRisk::ReadOnly);
        }
    }

    #[test]
    fn kill_and_budget_bridge_to_agent_namespace() {
        for verb in ["/kill", "budget"] {
            let m = bridge(PlatformOrigin::Telegram, verb);
            assert!(m.is_ok(), "{verb} must bridge");
            if let Ok(env) = m {
                assert_eq!(env.command().id.namespace, CliNamespace::Agent);
            }
        }
    }

    #[test]
    fn task_session_notify_audit_bridge_to_own_namespace() {
        let cases = [
            ("task", CliNamespace::Task),
            ("session", CliNamespace::Session),
            ("notify", CliNamespace::Notify),
            ("audit", CliNamespace::Audit),
        ];
        for (verb, ns) in cases {
            let c = bridged_command(verb);
            assert!(c.is_some(), "{verb} must bridge");
            if let Some(cmd) = c {
                assert_eq!(cmd.id.namespace, ns);
            }
        }
    }

    #[test]
    fn forbidden_command_is_refused() {
        for verb in [
            "train",
            "sign",
            "publish",
            "buy",
            "definitely-not-a-control",
        ] {
            assert_eq!(
                bridge(PlatformOrigin::Telegram, verb),
                Err(TelegramBridgeReject::ForbiddenVerb),
                "{verb} must be forbidden on the bridge"
            );
        }
    }

    #[test]
    fn envelope_equality_cli_and_telegram_same_command() {
        // Every control verb is the same command across channels.
        for verb in ControlVerb::ALL {
            assert!(
                same_command_across_channels(verb),
                "{verb:?} must be channel-identical"
            );
        }
        // A CLI command and a Telegram command for the SAME verb are equal.
        let cli = bridge(PlatformOrigin::Cli, "kill");
        let tg = bridge(PlatformOrigin::Telegram, "kill");
        assert!(cli.is_ok() && tg.is_ok());
        if let (Ok(c), Ok(t)) = (cli, tg) {
            assert_ne!(c.origin, t.origin);
            assert!(c.same_command(&t));
        }
        // Different verbs are NOT the same command.
        let kill = bridged_command("kill");
        let budget = bridged_command("budget");
        assert!(kill.is_some() && budget.is_some());
        assert_ne!(kill, budget);
    }

    #[test]
    fn bridge_p95_within_20ms() {
        let mut samples = Vec::with_capacity(256);
        for _ in 0..256 {
            let t = std::time::Instant::now();
            let m = bridge(PlatformOrigin::Telegram, "status");
            std::hint::black_box(&m);
            samples.push(t.elapsed().as_nanos() as u64);
        }
        let p95 = p95_ms(&samples) / 1_000_000;
        assert!(p95 <= 20, "telegram bridge p95 {p95}ms exceeds 20ms");
    }
}
