//! `command_manifest.json` parser → typed command results (atom #338 · E.0.7,
//! §4.2 `CommandResult`).
//!
//! The exact command, exit code, and (when present) wall time are parsed into a
//! `Copy` value; the shell text itself is reduced to a `sha256` so it is replay-
//! addressable but never carries free text into reward. Legacy manifests record
//! only an `exit` integer (no duration); `wall_ms` then defaults to `0`.
use crate::diet_kind::DietFileKind;
use crate::error::{DietError, DietResult};
use crate::{as_object, opt_i64, opt_str, opt_u64, parse_json, req_array, req_str};

const KIND: DietFileKind = DietFileKind::CommandManifest;

/// How a command terminated (§4.2 `CommandExitClass`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[repr(u8)]
pub enum CommandExitClass {
    /// Exit code 0 / explicit pass.
    Pass = 1,
    /// Non-zero exit / explicit fail.
    Fail = 2,
    /// Failure masked by infrastructure (tool/host), not the model.
    InfraMasked = 3,
    /// The command was not run.
    NotRun = 4,
}

impl CommandExitClass {
    /// Numeric discriminant.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse from a discriminant; `None` if not `1..=4`.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Pass),
            2 => Some(Self::Fail),
            3 => Some(Self::InfraMasked),
            4 => Some(Self::NotRun),
            _ => None,
        }
    }

    /// Parse an explicit status label; `None` if unrecognized.
    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "Pass" | "pass" | "PASS" => Some(Self::Pass),
            "Fail" | "fail" | "FAIL" => Some(Self::Fail),
            "InfraMasked" | "infra_masked" | "infra" => Some(Self::InfraMasked),
            "NotRun" | "not_run" | "notrun" => Some(Self::NotRun),
            _ => None,
        }
    }

    /// Classify by exit code: `0` is [`Self::Pass`], anything else [`Self::Fail`].
    pub const fn from_exit_code(code: i64) -> Self {
        if code == 0 { Self::Pass } else { Self::Fail }
    }
}

/// One parsed command invocation (§4.2 `CommandResult`).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CommandResult {
    /// `sha256` of the exact command string (replay-addressable, text-free).
    pub command_hash_32: [u8; 32],
    /// How the command terminated.
    pub exit_class: CommandExitClass,
    /// The raw exit code (or `0` for a not-run/infra-masked command).
    pub exit_code_i32: i32,
    /// Wall time in milliseconds (`0` when the manifest did not record it).
    pub wall_ms_u64: u64,
}

impl CommandResult {
    /// Construct a command result from its components.
    pub const fn new(
        command_hash_32: [u8; 32],
        exit_class: CommandExitClass,
        exit_code_i32: i32,
        wall_ms_u64: u64,
    ) -> Self {
        Self {
            command_hash_32,
            exit_class,
            exit_code_i32,
            wall_ms_u64,
        }
    }
}

/// Parse every command in a `command_manifest.json` document.
pub fn parse(text: &str) -> DietResult<Vec<CommandResult>> {
    let v = parse_json(KIND, text)?;
    let obj = as_object(&v, KIND, "$root")?;
    let commands = req_array(obj, KIND, "commands")?;
    let mut out = Vec::with_capacity(commands.len());
    for c in commands {
        let co = as_object(c, KIND, "commands[]")?;
        let cmd = req_str(co, KIND, "cmd")?;
        let command_hash_32 = crate::sha256(cmd.as_bytes());
        let label = opt_str(co, "status")
            .or_else(|| opt_str(co, "exit_class"))
            .and_then(CommandExitClass::from_label);
        let exit = opt_i64(co, "exit");
        let (exit_class, exit_code_i32) = match (label, exit) {
            (Some(s), e) => (s, e.unwrap_or(0) as i32),
            (None, Some(e)) => (CommandExitClass::from_exit_code(e), e as i32),
            (None, None) => {
                return Err(DietError::MissingField {
                    kind: KIND,
                    field: "exit",
                });
            }
        };
        let wall_ms_u64 = opt_u64(co, "wall_ms")
            .or_else(|| opt_u64(co, "duration_ms"))
            .unwrap_or(0);
        out.push(CommandResult::new(
            command_hash_32,
            exit_class,
            exit_code_i32,
            wall_ms_u64,
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pass_and_fail_classify_by_exit() -> DietResult<()> {
        let r = parse(
            r#"{"commands":[{"cmd":"cargo build","exit":0},{"cmd":"cargo test","exit":101}]}"#,
        )?;
        assert_eq!(r.len(), 2);
        assert_eq!(r[0].exit_class, CommandExitClass::Pass);
        assert_eq!(r[0].command_hash_32, crate::sha256(b"cargo build"));
        assert_eq!(r[1].exit_class, CommandExitClass::Fail);
        assert_eq!(r[1].exit_code_i32, 101);
        Ok(())
    }

    #[test]
    fn explicit_infra_and_not_run_status() -> DietResult<()> {
        let r = parse(
            r#"{"commands":[{"cmd":"sui move test","exit":1,"status":"InfraMasked"},{"cmd":"miri","status":"NotRun"}]}"#,
        )?;
        assert_eq!(r[0].exit_class, CommandExitClass::InfraMasked);
        assert_eq!(r[0].exit_code_i32, 1);
        assert_eq!(r[1].exit_class, CommandExitClass::NotRun);
        assert_eq!(r[1].exit_code_i32, 0);
        Ok(())
    }

    #[test]
    fn missing_exit_without_status_rejects() {
        assert!(matches!(
            parse(r#"{"commands":[{"cmd":"x"}]}"#),
            Err(DietError::MissingField {
                kind: DietFileKind::CommandManifest,
                field: "exit"
            })
        ));
    }

    #[test]
    fn command_hash_is_stable() -> DietResult<()> {
        let a = parse(r#"{"commands":[{"cmd":"echo hi","exit":0}]}"#)?;
        let b = parse(r#"{"commands":[{"cmd":"echo hi","exit":0}]}"#)?;
        assert_eq!(a[0].command_hash_32, b[0].command_hash_32);
        Ok(())
    }

    #[test]
    fn malformed_json_rejects_without_leak() {
        assert!(matches!(
            parse("{not json"),
            Err(DietError::MalformedJson {
                kind: DietFileKind::CommandManifest,
                ..
            })
        ));
    }

    #[test]
    fn template_note_is_tolerated() -> DietResult<()> {
        // legacy manifests carry a `_template_note`; it must be ignored, not rejected.
        let r = parse(r#"{"_template_note":"x","commands":[{"cmd":"ls","exit":0}]}"#)?;
        assert_eq!(r.len(), 1);
        Ok(())
    }
}
