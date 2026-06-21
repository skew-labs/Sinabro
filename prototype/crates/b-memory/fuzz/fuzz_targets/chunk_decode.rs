#![no_main]
//! `cargo-fuzz` target for the Stage B canonical decoder (atom #97 · B.1.16).
//!
//! Coverage-guided libFuzzer mirror of the `tests/chunk_prop.rs`
//! `prop_arbitrary_bytes_never_panic` property. For ANY input bytes the
//! invariant is:
//!
//!   * [`decode_stage_b_chunk`](mnemos_b_memory::decode_stage_b_chunk) (the #92
//!     thin wrapper over Stage A `decode_chunk_v1`) returns `Ok | Err` and never
//!     panics / aborts; and
//!   * any **accepted** (canonical) bytes re-encode to themselves — Stage A's
//!     non-canonical / trailing-byte reject means the accepted set is exactly the
//!     canonical set, so `encode_stage_b_chunk(decode(b)) == b`.
//!
//! RUN STATUS: deferred (see `fuzz/Cargo.toml` header) — `cargo-fuzz` +
//! `libfuzzer-sys` are absent in this offline env; the run is a K.0.1 CI nightly
//! follow-on. The harness is structurally complete so that environment can run
//! `cargo +nightly fuzz run chunk_decode` with no further wiring.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(env) = mnemos_b_memory::decode_stage_b_chunk(data) {
        if let Ok(re) = mnemos_b_memory::encode_stage_b_chunk(&env) {
            assert_eq!(re.as_slice(), data, "decoded bytes must be canonical");
        }
    }
});
