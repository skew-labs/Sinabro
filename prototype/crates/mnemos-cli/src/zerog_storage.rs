//! `zerog_storage` — 0G Storage round-trip via the `0g-storage-client` Go sidecar (W2-C).
//!
//! 0G Storage has NO Rust SDK; the documented client is the Go binary
//! `0g-storage-client` (`github.com/0gfoundation/0g-storage-client`, Go ≥ 1.23). This
//! module drives it as a sidecar to round-trip the agent's ENCRYPTED memory (opaque
//! AES-256-GCM-SIV ciphertext; 0G's own encryption is OFF) through 0G Storage testnet.
//!
//! ## funds-safe posture (the agent NEVER holds a signing key)
//! Unlike Walrus testnet (keyless publisher), a 0G Storage **upload** costs an a0gi fee
//! and needs an EVM **signer private key** — that is FUNDS. So this module splits the
//! round-trip:
//! - **upload (FUNDS)** — the agent only CONSTRUCTS the exact command ([`upload_command`])
//!   with the signer key as the OWNER's env reference (`$ZEROG_STORAGE_SIGNER_KEY`, value
//!   never read/held by the agent). The OWNER runs it.
//! - **download + verify (KEYLESS)** — [`download_argv`] carries NO `--key`; the proof-
//!   verified download + byte-match ([`download_and_verify`]) is fully agent-runnable.
//!
//! The actual subprocess execution is gated behind the off-by-default `zerog-storage`
//! cargo feature (honest-degrade when off). The pure helpers + the verify classifier are
//! always-compiled and unit-tested via an INJECTED runner (no Go, no network in tests).
//! Closed endpoints only — no arbitrary URL (mirrors the `ProviderHost` closed allowlist).

/// 0G Galileo testnet EVM RPC (chain 16602) — the upload's `--url` (chain interaction).
pub const ZEROG_TESTNET_EVM_RPC: &str = "https://evmrpc-testnet.0g.ai";
/// 0G Storage testnet Turbo indexer — the `--indexer` for upload + download.
pub const ZEROG_TESTNET_INDEXER: &str = "https://indexer-storage-testnet-turbo.0g.ai";
/// Env var naming the OWNER-built `0g-storage-client` binary path (download path only).
pub const ZEROG_STORAGE_BINARY_ENV: &str = "ZEROG_STORAGE_CLIENT";
/// Env var the OWNER sets with the TESTNET signer key for the upload. NEVER read by the
/// agent — it appears ONLY as a `$`-reference inside the emitted owner command string.
pub const ZEROG_STORAGE_SIGNER_KEY_ENV: &str = "ZEROG_STORAGE_SIGNER_KEY";
/// Wall-clock cap for the download subprocess.
pub const ZEROG_DOWNLOAD_TIMEOUT_MS: u64 = 120_000;
/// Captured-stream cap for the download subprocess (logs only; the payload is a file).
pub const ZEROG_DOWNLOAD_STREAM_CAP_BYTES: usize = 64 * 1024;
/// Max bytes read back for the byte-match (a memory `.mc` ciphertext is KB; a large
/// adapter is a follow-on flow). A file larger than this is not our small record ⇒ reject.
pub const ZEROG_VERIFY_MAX_BYTES: usize = 16 * 1024 * 1024;

/// The exact OWNER-RUN upload command. The agent CONSTRUCTS but NEVER runs this: the signer
/// key is the owner's env (`$ZEROG_STORAGE_SIGNER_KEY`) and its value is never held by the
/// agent; the binary is the owner's env (`$ZEROG_STORAGE_CLIENT`). Encryption stays OFF
/// (no `--encrypt`/`--encryption-key`) so our AES ciphertext uploads opaque.
#[must_use]
pub fn upload_command(ciphertext_path: &str) -> String {
    format!(
        "\"${bin}\" upload --url {rpc} --indexer {idx} --key \"${key}\" --file \"{file}\"",
        bin = ZEROG_STORAGE_BINARY_ENV,
        rpc = ZEROG_TESTNET_EVM_RPC,
        idx = ZEROG_TESTNET_INDEXER,
        key = ZEROG_STORAGE_SIGNER_KEY_ENV,
        file = ciphertext_path,
    )
}

/// The KEYLESS proof-verified download argv (each element is ONE argument — never a shell
/// string). There is deliberately NO `--key`: download needs no signer. `--proof` makes the
/// client validate each segment's Merkle proof (failure ⇒ non-zero exit, gated below).
#[must_use]
pub fn download_argv(binary: &str, root_hash: &str, out_path: &str) -> Vec<String> {
    vec![
        binary.to_string(),
        "download".to_string(),
        "--indexer".to_string(),
        ZEROG_TESTNET_INDEXER.to_string(),
        "--root".to_string(),
        root_hash.to_string(),
        "--file".to_string(),
        out_path.to_string(),
        "--proof".to_string(),
    ]
}

/// A 0G Storage Merkle rootHash: `0x` + exactly 64 lowercase/uppercase hex chars (32 bytes).
/// Validated before it is ever placed in a subprocess argv (no injection surface).
#[must_use]
pub fn is_valid_root_hash(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 66
        && b[0] == b'0'
        && (b[1] == b'x' || b[1] == b'X')
        && b[2..].iter().all(u8::is_ascii_hexdigit)
}

/// Parse the Merkle rootHash from the client's STDERR. The Go client logs (logrus, to
/// stderr) `file uploaded, root = 0x<64hex>`, wrapped in a level/timestamp prefix and
/// (by default) ANSI color. Robust contract: the LAST standalone `0x` + exactly-64-hex
/// token (not preceded/followed by another hex digit), normalized to lowercase `0x…`.
#[must_use]
pub fn parse_root_hash(stderr: &str) -> Option<String> {
    let b = stderr.as_bytes();
    let mut found: Option<String> = None;
    let mut i = 0usize;
    while i + 66 <= b.len() {
        let is_prefix = b[i] == b'0' && (b[i + 1] == b'x' || b[i + 1] == b'X');
        let prev_ok = i == 0 || !b[i - 1].is_ascii_hexdigit();
        if is_prefix && prev_ok {
            let hex = &b[i + 2..i + 66];
            let after_ok = i + 66 >= b.len() || !b[i + 66].is_ascii_hexdigit();
            if after_ok && hex.iter().all(u8::is_ascii_hexdigit) {
                let mut s = String::with_capacity(66);
                s.push_str("0x");
                for &c in hex {
                    s.push((c as char).to_ascii_lowercase());
                }
                found = Some(s);
            }
        }
        i += 1;
    }
    found
}

/// The verdict of a proof-verified download + byte-match.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZerogVerify {
    /// `--proof` download succeeded (exit 0) AND the bytes match the original ciphertext.
    ByteMatch,
    /// The supplied rootHash was not a valid `0x`+64-hex token (rejected pre-spawn).
    InvalidRoot,
    /// The download subprocess could not be spawned / produced no file.
    SpawnFailed,
    /// The client exited non-zero — a proof/integrity failure (`os.Exit(1)`).
    ExitNonZero(Option<i32>),
    /// Download succeeded but the bytes differ from the original ciphertext.
    Mismatch,
}

/// The result of a KEYLESS proof-verified download that RETURNS the bytes (the
/// Walrus→0G fallback fetch; W4 Slice 2). Unlike [`ZerogVerify`] there is no
/// `expected` to byte-match against — the caller AEAD-decodes the bytes, and the
/// decrypt tag IS the integrity gate (a tampered blob fails to open, fail-closed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZerogFetch {
    /// `--proof` download succeeded (exit 0) — the raw downloaded bytes (the caller
    /// AEAD-decodes them; an empty vec ⇒ over-cap / unreadable, decode fails closed).
    Bytes(Vec<u8>),
    /// The supplied rootHash was not a valid `0x`+64-hex token (rejected pre-spawn).
    InvalidRoot,
    /// The download subprocess could not be spawned / produced no file.
    SpawnFailed,
    /// The client exited non-zero — a proof/integrity failure (`os.Exit(1)`).
    ExitNonZero(Option<i32>),
}

/// Run the KEYLESS proof-verified download via an INJECTED `runner` and byte-match the
/// downloaded bytes against `expected` (the original AES ciphertext). The runner returns
/// `(exit_code, downloaded_bytes)` or `None` on spawn failure. Tests script the runner;
/// the prod path ([`run_download`], `zerog-storage`-gated) backs it with the bounded
/// `exec_local` subprocess runner + a capped file read. Two independent gates:
/// `--proof` (exit code) AND our byte-match.
pub fn download_and_verify<R>(
    binary: &str,
    root_hash: &str,
    out_path: &str,
    expected: &[u8],
    runner: R,
) -> ZerogVerify
where
    R: FnOnce(Vec<String>) -> Option<(Option<i32>, Vec<u8>)>,
{
    if !is_valid_root_hash(root_hash) {
        return ZerogVerify::InvalidRoot;
    }
    let argv = download_argv(binary, root_hash, out_path);
    match runner(argv) {
        None => ZerogVerify::SpawnFailed,
        Some((code, _)) if code != Some(0) => ZerogVerify::ExitNonZero(code),
        Some((_, bytes)) if bytes.as_slice() == expected => ZerogVerify::ByteMatch,
        Some(_) => ZerogVerify::Mismatch,
    }
}

/// Run the KEYLESS proof-verified download via an INJECTED `runner` and RETURN the
/// downloaded bytes (the Walrus→0G fallback fetch). The `--proof` exit code is the
/// first gate (a proof/integrity failure ⇒ `ExitNonZero`); the caller's AEAD decrypt
/// is the second (a tampered blob fails to open). Tests script the runner; the prod
/// path [`run_download_to_bytes`] (`zerog-storage`-gated) backs it with the bounded
/// `exec_local` subprocess runner + a capped file read.
pub fn download_to_bytes<R>(binary: &str, root_hash: &str, out_path: &str, runner: R) -> ZerogFetch
where
    R: FnOnce(Vec<String>) -> Option<(Option<i32>, Vec<u8>)>,
{
    if !is_valid_root_hash(root_hash) {
        return ZerogFetch::InvalidRoot;
    }
    let argv = download_argv(binary, root_hash, out_path);
    match runner(argv) {
        None => ZerogFetch::SpawnFailed,
        Some((code, _)) if code != Some(0) => ZerogFetch::ExitNonZero(code),
        Some((_, bytes)) => ZerogFetch::Bytes(bytes),
    }
}

/// PROD runner (`zerog-storage`-gated): run the keyless download via the bounded
/// `exec_local` argv runner (env-scrubbed, timeout+reap — the SAME discipline as the
/// remote-shell ssh leg), then read back the proof-validated file (capped). NOTE: this is
/// a NETWORKED subprocess (the Go client dials the 0G indexer); it is keyless + bounded
/// to fixed args + the closed testnet indexer. SBPL sandbox-confinement = follow-on.
#[cfg(feature = "zerog-storage")]
#[must_use]
pub fn run_download(binary: &str, root_hash: &str, out_path: &str, expected: &[u8]) -> ZerogVerify {
    download_and_verify(binary, root_hash, out_path, expected, |argv| {
        let outcome = crate::exec_local::run_argv_command_with_env(
            argv,
            ZEROG_DOWNLOAD_TIMEOUT_MS,
            ZEROG_DOWNLOAD_STREAM_CAP_BYTES,
            &[],
        )
        .ok()?;
        let meta = std::fs::metadata(out_path).ok()?;
        if meta.len() > ZEROG_VERIFY_MAX_BYTES as u64 {
            // Too large to be our small record — surface as a non-match (exit kept).
            return Some((outcome.exit_code, Vec::new()));
        }
        let bytes = std::fs::read(out_path).ok()?;
        Some((outcome.exit_code, bytes))
    })
}

/// PROD runner (`zerog-storage`-gated) for the Walrus→0G fallback FETCH: run the
/// keyless proof-verified download via the bounded `exec_local` argv runner
/// (env-scrubbed, timeout+reap), then read back the proof-validated file (capped) and
/// RETURN the bytes. NETWORKED subprocess (the Go client dials the 0G indexer); keyless
/// + bounded to fixed args + the closed testnet indexer. The caller AEAD-decodes.
#[cfg(feature = "zerog-storage")]
#[must_use]
pub fn run_download_to_bytes(binary: &str, root_hash: &str, out_path: &str) -> ZerogFetch {
    download_to_bytes(binary, root_hash, out_path, |argv| {
        let outcome = crate::exec_local::run_argv_command_with_env(
            argv,
            ZEROG_DOWNLOAD_TIMEOUT_MS,
            ZEROG_DOWNLOAD_STREAM_CAP_BYTES,
            &[],
        )
        .ok()?;
        let meta = std::fs::metadata(out_path).ok()?;
        if meta.len() > ZEROG_VERIFY_MAX_BYTES as u64 {
            // Too large to be our small record — surface as empty (decode fails closed).
            return Some((outcome.exit_code, Vec::new()));
        }
        let bytes = std::fs::read(out_path).ok()?;
        Some((outcome.exit_code, bytes))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upload_command_is_keyed_by_owner_env_never_a_value() {
        let cmd = upload_command("/tmp/zerog_backup_0.mc");
        // exact owner-run shape; key + binary are ENV references (no value held by the agent)
        assert!(cmd.contains("\"$ZEROG_STORAGE_CLIENT\" upload"));
        assert!(cmd.contains("--url https://evmrpc-testnet.0g.ai"));
        assert!(cmd.contains("--indexer https://indexer-storage-testnet-turbo.0g.ai"));
        assert!(cmd.contains("--key \"$ZEROG_STORAGE_SIGNER_KEY\""));
        assert!(cmd.contains("--file \"/tmp/zerog_backup_0.mc\""));
        // encryption OFF: never emits the 0G-side encryption flags
        assert!(!cmd.contains("--encrypt"));
        assert!(!cmd.contains("--encryption-key"));
    }

    #[test]
    fn download_argv_is_keyless_and_proof_verified() {
        let argv = download_argv("/opt/0g-storage-client", "0xabc", "/tmp/out.mc");
        assert_eq!(argv[0], "/opt/0g-storage-client");
        assert_eq!(argv[1], "download");
        assert!(argv.contains(&"--proof".to_string()), "proof-verified");
        assert!(argv.contains(&"--indexer".to_string()));
        // KEYLESS: download never carries a signer key
        assert!(!argv.iter().any(|a| a == "--key"));
        assert!(!argv.iter().any(|a| a == "--url"));
    }

    #[test]
    fn root_hash_validator() {
        let good = "0x".to_string() + &"a1".repeat(32); // 0x + 64 hex
        assert!(is_valid_root_hash(&good));
        assert!(is_valid_root_hash(
            &("0xABCD".to_string() + &"0".repeat(60))
        ));
        assert!(!is_valid_root_hash("0xabc")); // too short
        assert!(!is_valid_root_hash(&("0x".to_string() + &"a".repeat(65)))); // too long
        assert!(!is_valid_root_hash(&("0x".to_string() + &"g".repeat(64)))); // non-hex
        assert!(!is_valid_root_hash(&"a".repeat(66))); // no 0x
        // an injection attempt is structurally rejected (not 0x+64hex)
        assert!(!is_valid_root_hash("0xdeadbeef; rm -rf /"));
    }

    #[test]
    fn parse_root_hash_survives_logrus_prefix_and_ansi() {
        let root = "0x".to_string() + &"c5".repeat(32);
        let line = format!("\x1b[36mINFO\x1b[0m[0000] file uploaded, root = {root}\n");
        assert_eq!(parse_root_hash(&line).as_deref(), Some(root.as_str()));
        // uppercase normalizes to lowercase
        let up = format!("root = 0x{}", "AB".repeat(32));
        assert_eq!(
            parse_root_hash(&up).as_deref(),
            Some(("0x".to_string() + &"ab".repeat(32)).as_str())
        );
        // no hash present
        assert_eq!(parse_root_hash("INFO no upload happened"), None);
        // a 0x token that is NOT exactly 64 hex is not mistaken for a root
        assert_eq!(parse_root_hash("addr 0xdeadbeef done"), None);
    }

    #[test]
    fn download_and_verify_byte_match_via_scripted_runner() {
        let root = "0x".to_string() + &"11".repeat(32);
        let v = download_and_verify("bin", &root, "/tmp/out.mc", b"CIPHERTEXT", |argv| {
            // the runner sees a KEYLESS proof-verified argv
            assert!(argv.contains(&"--proof".to_string()));
            assert!(!argv.iter().any(|a| a == "--key"));
            Some((Some(0), b"CIPHERTEXT".to_vec()))
        });
        assert_eq!(v, ZerogVerify::ByteMatch);
    }

    #[test]
    fn download_and_verify_classifies_failures() {
        let root = "0x".to_string() + &"22".repeat(32);
        // proof/integrity failure ⇒ exit 1 ⇒ ExitNonZero (byte-match never reached)
        let v = download_and_verify("bin", &root, "/o", b"X", |_| Some((Some(1), Vec::new())));
        assert_eq!(v, ZerogVerify::ExitNonZero(Some(1)));
        // exit 0 but tampered bytes ⇒ Mismatch
        let v = download_and_verify("bin", &root, "/o", b"ORIG", |_| {
            Some((Some(0), b"TAMPERED".to_vec()))
        });
        assert_eq!(v, ZerogVerify::Mismatch);
        // spawn failure ⇒ SpawnFailed
        let v = download_and_verify("bin", &root, "/o", b"X", |_| None);
        assert_eq!(v, ZerogVerify::SpawnFailed);
        // invalid root ⇒ rejected pre-spawn (runner never invoked)
        let v = download_and_verify("bin", "0xnothex", "/o", b"X", |_| {
            panic!("runner must NOT run on an invalid root");
        });
        assert_eq!(v, ZerogVerify::InvalidRoot);
    }

    #[test]
    fn download_to_bytes_returns_proof_verified_bytes() {
        let root = "0x".to_string() + &"33".repeat(32);
        let f = download_to_bytes("bin", &root, "/tmp/o.mc", |argv| {
            // the fallback fetch sees the SAME keyless proof-verified argv
            assert!(argv.contains(&"--proof".to_string()));
            assert!(!argv.iter().any(|a| a == "--key"));
            Some((Some(0), b"CIPHERTEXT".to_vec()))
        });
        assert_eq!(f, ZerogFetch::Bytes(b"CIPHERTEXT".to_vec()));
    }

    #[test]
    fn download_to_bytes_classifies_failures() {
        let root = "0x".to_string() + &"44".repeat(32);
        // proof/integrity failure ⇒ ExitNonZero (bytes never returned)
        assert_eq!(
            download_to_bytes("bin", &root, "/o", |_| Some((Some(1), Vec::new()))),
            ZerogFetch::ExitNonZero(Some(1))
        );
        // spawn failure ⇒ SpawnFailed
        assert_eq!(
            download_to_bytes("bin", &root, "/o", |_| None),
            ZerogFetch::SpawnFailed
        );
        // invalid root ⇒ rejected pre-spawn (runner never invoked)
        assert_eq!(
            download_to_bytes("bin", "0xnothex", "/o", |_| panic!("must not run")),
            ZerogFetch::InvalidRoot
        );
    }
}
