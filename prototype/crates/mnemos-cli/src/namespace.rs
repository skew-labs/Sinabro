//! Nous IR — the NAMESPACE: name↔cid mappings as VERSIONED FIRST-CLASS DATA
//! ("names are data").
//!
//! The node identity codec made the definition node's identity its CONTENT
//! ([`crate::defn_node::node_cid`])
//! and demoted the name to data. This module gives that data a home: an append-only log of
//! binding EVENTS (`Bind name → cid` / `Unbind name`), where
//!
//! * the namespace STATE is a deterministic FOLD of the log (replayable at any
//!   version — `state at version k` = fold of the first `k` events);
//! * a RENAME is two mapping events (unbind old ‖ bind new) — the NODE is never
//!   touched (this module cannot even reach node derivation: it stores raw 32-byte
//!   cids and never constructs a node);
//! * one cid may carry MANY names (aliases) — the map is name-keyed.
//!
//! ## Wire codec (fail-closed, the `AGRX`/`WMIX` sibling; magic `NSPX`)
//!
//! ```text
//! log    = "NSPX" ‖ u8 version(=1) ‖ le32 event_count ‖ event…
//! Bind   = u8 1 ‖ le16 |name| ‖ name ‖ cid_raw[32] ‖ le16 |author| ‖ author
//! Unbind = u8 2 ‖ le16 |name| ‖ name ‖ le16 |author| ‖ author
//! ```
//!
//! Decode is fail-closed (truncated / bad magic / unknown version / unknown kind /
//! bad name / trailing bytes ⇒ typed error, never partial trust). A NAME is 1..=256
//! bytes of ASCII-graphic (0x21..=0x7E) and may NOT be 64 lowercase hex — so a name
//! can never be confused with a node cid (the resolve surface dispatches on shape
//! with zero ambiguity, by construction).
//!
//! ## Authority model (honest v1 STUB)
//!
//! Every event carries an `author` string (data, not proof). The WRITE surface is
//! the owner's dispatch verbs (`context ns-bind/ns-unbind/ns-rename`, LocalWrite
//! tier — the blast-radius law: ledger-touching ⇒ owner surface); reads are
//! free. Signed, verifiable authorship is the ledger seam, NOT claimed here.
//!
//! PURITY: the codec + fold are PURE. Persistence goes through the SHARED
//! [`crate::memory_store::atomic_write`] under the data dir (the shared-write idiom — no
//! raw `fs::write`, no second write path). No network, no exec, no custody surface
//! (funds stay hard-locked behind the uninhabited custody type).

use std::collections::BTreeMap;
use std::path::PathBuf;

/// The namespace-log magic (4 bytes) — `NSPX` = Nous nameSPace indeX.
pub const NAMESPACE_MAGIC: [u8; 4] = *b"NSPX";

/// The log wire version this codec WRITES.
pub const NAMESPACE_VERSION: u8 = 1;

/// Max bytes of one name (fail-closed: longer is refused, never truncated).
pub const NAME_CAP_BYTES: usize = 256;

/// Max bytes of one author tag (a data stub, not proof — see module docs).
pub const AUTHOR_CAP_BYTES: usize = 96;

/// The log file under `<data_dir>/nous/` (the owner's local namespace).
pub const NAMESPACE_LOG_FILE: &str = "namespace.nsl";

/// One binding event — the namespace's unit of change. A rename is two events;
/// the referenced NODE is untouched by construction (only a raw cid is stored).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum NsEvent {
    /// Bind (or re-bind) `name` to a definition-node cid.
    Bind {
        /// The human name (validated by [`valid_name`]).
        name: String,
        /// The raw 32-byte node cid (hex form = [`crate::defn_node::node_cid`] output).
        cid: [u8; 32],
        /// Who recorded the event (data stub; see module docs).
        author: String,
    },
    /// Remove `name` from the namespace (the cid keeps existing — names are data).
    Unbind {
        /// The name to remove.
        name: String,
        /// Who recorded the event.
        author: String,
    },
}

impl NsEvent {
    /// The event's name field (every event kind has one).
    #[must_use]
    pub fn name(&self) -> &str {
        match self {
            NsEvent::Bind { name, .. } | NsEvent::Unbind { name, .. } => name,
        }
    }
}

/// Typed codec/validation failures (fail-closed; no partial trust).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
#[non_exhaustive]
pub enum NamespaceError {
    /// The bytes were shorter than a field demanded.
    Truncated,
    /// The 4-byte magic was not [`NAMESPACE_MAGIC`].
    BadMagic,
    /// The version byte was not [`NAMESPACE_VERSION`].
    UnknownVersion,
    /// An event's kind byte was not a known event.
    UnknownKind,
    /// A name failed [`valid_name`] (empty / over-cap / non-graphic / cid-shaped).
    BadName,
    /// An author tag was over [`AUTHOR_CAP_BYTES`] or not UTF-8.
    BadAuthor,
    /// A string field was not valid UTF-8.
    NotUtf8,
    /// Trailing garbage followed the last event.
    TrailingBytes,
}

impl NamespaceError {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            NamespaceError::Truncated => "truncated namespace log",
            NamespaceError::BadMagic => "bad namespace magic",
            NamespaceError::UnknownVersion => "unknown namespace log version",
            NamespaceError::UnknownKind => "unknown namespace event kind",
            NamespaceError::BadName => "bad name (1..=256 ASCII-graphic bytes; must not be 64-hex)",
            NamespaceError::BadAuthor => "bad author tag",
            NamespaceError::NotUtf8 => "not valid UTF-8",
            NamespaceError::TrailingBytes => "trailing bytes after the last event",
        }
    }
}

/// True iff `s` is exactly 64 lowercase-hex chars (a node-cid shape).
#[must_use]
pub fn is_cid_shaped(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// Validate a namespace name: 1..=[`NAME_CAP_BYTES`] bytes, ASCII-graphic
/// (0x21..=0x7E) only, and NOT cid-shaped — so names and cids are structurally
/// disjoint alphabets (the resolve overload can never mis-route).
#[must_use]
pub fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= NAME_CAP_BYTES
        && name.bytes().all(|b| (0x21..=0x7E).contains(&b))
        && !is_cid_shaped(name)
}

fn valid_author(author: &str) -> bool {
    author.len() <= AUTHOR_CAP_BYTES
}

/// Encode an event log to its canonical bytes. `None` iff any event carries an
/// invalid name/author (fail-closed at the WRITE side too — a bad event is never
/// serialized into the owner's log).
#[must_use]
pub fn encode_log(events: &[NsEvent]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(5 + 4 + events.len() * 48);
    out.extend_from_slice(&NAMESPACE_MAGIC);
    out.push(NAMESPACE_VERSION);
    out.extend_from_slice(&u32::try_from(events.len()).ok()?.to_le_bytes());
    for ev in events {
        match ev {
            NsEvent::Bind { name, cid, author } => {
                if !valid_name(name) || !valid_author(author) {
                    return None;
                }
                out.push(1);
                push_str(&mut out, name)?;
                out.extend_from_slice(cid);
                push_str(&mut out, author)?;
            }
            NsEvent::Unbind { name, author } => {
                if !valid_name(name) || !valid_author(author) {
                    return None;
                }
                out.push(2);
                push_str(&mut out, name)?;
                push_str(&mut out, author)?;
            }
        }
    }
    Some(out)
}

fn push_str(out: &mut Vec<u8>, s: &str) -> Option<()> {
    out.extend_from_slice(&u16::try_from(s.len()).ok()?.to_le_bytes());
    out.extend_from_slice(s.as_bytes());
    Some(())
}

fn take<'a>(bytes: &'a [u8], at: &mut usize, n: usize) -> Result<&'a [u8], NamespaceError> {
    let end = at.checked_add(n).ok_or(NamespaceError::Truncated)?;
    if end > bytes.len() {
        return Err(NamespaceError::Truncated);
    }
    let s = &bytes[*at..end];
    *at = end;
    Ok(s)
}

fn take_str(bytes: &[u8], at: &mut usize) -> Result<String, NamespaceError> {
    let mut l = [0u8; 2];
    l.copy_from_slice(take(bytes, at, 2)?);
    let n = u16::from_le_bytes(l) as usize;
    let s = core::str::from_utf8(take(bytes, at, n)?).map_err(|_| NamespaceError::NotUtf8)?;
    Ok(s.to_string())
}

/// Decode an event log (fail-closed: any malformation ⇒ typed error, zero events
/// trusted). The inverse of [`encode_log`] (byte round-trip proven in tests).
pub fn decode_log(bytes: &[u8]) -> Result<Vec<NsEvent>, NamespaceError> {
    let mut at = 0usize;
    if take(bytes, &mut at, 4)? != NAMESPACE_MAGIC {
        return Err(NamespaceError::BadMagic);
    }
    if take(bytes, &mut at, 1)?[0] != NAMESPACE_VERSION {
        return Err(NamespaceError::UnknownVersion);
    }
    let mut c = [0u8; 4];
    c.copy_from_slice(take(bytes, &mut at, 4)?);
    let count = u32::from_le_bytes(c) as usize;
    let mut events = Vec::with_capacity(count.min(4096));
    for _ in 0..count {
        let kind = take(bytes, &mut at, 1)?[0];
        match kind {
            1 => {
                let name = take_str(bytes, &mut at)?;
                let mut cid = [0u8; 32];
                cid.copy_from_slice(take(bytes, &mut at, 32)?);
                let author = take_str(bytes, &mut at)?;
                if !valid_name(&name) {
                    return Err(NamespaceError::BadName);
                }
                if !valid_author(&author) {
                    return Err(NamespaceError::BadAuthor);
                }
                events.push(NsEvent::Bind { name, cid, author });
            }
            2 => {
                let name = take_str(bytes, &mut at)?;
                let author = take_str(bytes, &mut at)?;
                if !valid_name(&name) {
                    return Err(NamespaceError::BadName);
                }
                if !valid_author(&author) {
                    return Err(NamespaceError::BadAuthor);
                }
                events.push(NsEvent::Unbind { name, author });
            }
            _ => return Err(NamespaceError::UnknownKind),
        }
    }
    if at != bytes.len() {
        return Err(NamespaceError::TrailingBytes);
    }
    Ok(events)
}

/// The folded namespace state: `name → cid` plus honest anomaly accounting.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NamespaceState {
    /// The current bindings (name-keyed; many names may point at one cid).
    pub bindings: BTreeMap<String, [u8; 32]>,
    /// Unbinds of absent names seen during the fold (deterministic no-ops,
    /// surfaced honestly rather than hidden).
    pub anomalies: u32,
}

/// Fold the FIRST `upto` events into a state (the whole log: `upto = len`).
/// Deterministic replay — "state at version k" is a pure function of the log
/// prefix (-3). A re-bind overwrites (the map holds the CURRENT cid; the
/// history stays in the log).
#[must_use]
pub fn fold_at(events: &[NsEvent], upto: usize) -> NamespaceState {
    let mut st = NamespaceState::default();
    for ev in events.get(..upto.min(events.len())).unwrap_or_default() {
        match ev {
            NsEvent::Bind { name, cid, .. } => {
                st.bindings.insert(name.clone(), *cid);
            }
            NsEvent::Unbind { name, .. } => {
                if st.bindings.remove(name).is_none() {
                    st.anomalies = st.anomalies.saturating_add(1);
                }
            }
        }
    }
    st
}

/// Fold the whole log.
#[must_use]
pub fn fold(events: &[NsEvent]) -> NamespaceState {
    fold_at(events, events.len())
}

/// Every name currently bound to `cid` (the alias set, -2), in name order.
#[must_use]
pub fn names_of(state: &NamespaceState, cid: &[u8; 32]) -> Vec<String> {
    state
        .bindings
        .iter()
        .filter(|(_, c)| *c == cid)
        .map(|(n, _)| n.clone())
        .collect()
}

/// Parse a 64-hex node cid into its raw 32 bytes (`None` = not cid-shaped).
#[must_use]
pub fn cid_from_hex(hex: &str) -> Option<[u8; 32]> {
    if !is_cid_shaped(hex) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let hi = (chunk[0] as char).to_digit(16)?;
        let lo = (chunk[1] as char).to_digit(16)?;
        out[i] = u8::try_from(hi * 16 + lo).ok()?;
    }
    Some(out)
}

/// The namespace log path: `<data_dir>/nous/namespace.nsl` (created on demand).
/// `None` = no data dir / io (honest-degrade at the caller).
#[must_use]
pub fn namespace_log_path() -> Option<PathBuf> {
    let dir = crate::memory_store::data_dir().ok()?.join("nous");
    std::fs::create_dir_all(&dir).ok()?;
    Some(dir.join(NAMESPACE_LOG_FILE))
}

/// Load the owner's namespace log (absent file = empty log, honest zero).
pub fn load_log(path: &std::path::Path) -> Result<Vec<NsEvent>, NamespaceError> {
    match std::fs::read(path) {
        Ok(bytes) => decode_log(&bytes),
        Err(_) => Ok(Vec::new()),
    }
}

/// Append `new_events` to the log at `path` ATOMICALLY (read → validate → encode
/// full log → shared `atomic_write`). Fail-closed: an invalid event, a corrupt
/// existing log, or an io failure writes NOTHING. Returns the new event count.
pub fn append_events(
    path: &std::path::Path,
    new_events: &[NsEvent],
) -> Result<usize, NamespaceError> {
    let mut events = load_log(path)?;
    events.extend_from_slice(new_events);
    let bytes = encode_log(&events).ok_or(NamespaceError::BadName)?;
    crate::memory_store::atomic_write(path, &bytes).map_err(|_| NamespaceError::Truncated)?;
    Ok(events.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cid_seq() -> [u8; 32] {
        let mut c = [0u8; 32];
        for (i, b) in c.iter_mut().enumerate() {
            *b = u8::try_from(i).expect("0..32");
        }
        c
    }

    /// Cross-language lock: the 2-event golden log encodes to
    /// EXACTLY the Python-derived 79 bytes / sha256.
    #[test]
    fn encode_log_matches_python_golden_vector() {
        let events = vec![
            NsEvent::Bind {
                name: "squads/fk".to_string(),
                cid: cid_seq(),
                author: "owner".to_string(),
            },
            NsEvent::Unbind {
                name: "squads/fk".to_string(),
                author: "owner".to_string(),
            },
        ];
        let bytes = encode_log(&events).expect("encodes");
        assert_eq!(bytes.len(), 79, "bind=51 + unbind=19 + header=9");
        assert_eq!(
            crate::hex32(&crate::sha256_32(&bytes)),
            "42b06e3bcc7d03c87e8b0adcc2c46a83222468756abc0a4f7dc07fab85eef974"
        );
        // byte round-trip
        assert_eq!(decode_log(&bytes).expect("decodes"), events);
    }

    /// -1 — a RENAME is mapping events ONLY: the cid bytes are bit-identical
    /// before/after, and this module has no path to node derivation at all.
    #[test]
    fn rename_is_mapping_events_only_node_untouched() {
        let cid = cid_seq();
        let log = vec![
            NsEvent::Bind {
                name: "old/name".to_string(),
                cid,
                author: "owner".to_string(),
            },
            // rename = unbind old ‖ bind new — SAME cid value, no node contact.
            NsEvent::Unbind {
                name: "old/name".to_string(),
                author: "owner".to_string(),
            },
            NsEvent::Bind {
                name: "new/name".to_string(),
                cid,
                author: "owner".to_string(),
            },
        ];
        let st = fold(&log);
        assert_eq!(st.bindings.get("new/name"), Some(&cid));
        assert_eq!(st.bindings.get("old/name"), None);
        assert_eq!(st.anomalies, 0);
        // the cid VALUE survived the rename bit-for-bit.
        assert_eq!(st.bindings.get("new/name"), Some(&cid_seq()));
    }

    /// -2 — aliases: many names, one cid; reverse lookup returns them all.
    #[test]
    fn aliases_many_names_one_cid() {
        let cid = cid_seq();
        let log = vec![
            NsEvent::Bind {
                name: "a".to_string(),
                cid,
                author: "owner".to_string(),
            },
            NsEvent::Bind {
                name: "b/alias".to_string(),
                cid,
                author: "owner".to_string(),
            },
        ];
        let st = fold(&log);
        assert_eq!(
            names_of(&st, &cid),
            vec!["a".to_string(), "b/alias".to_string()]
        );
    }

    /// -3 — versioned replay: state-at-k is a pure function of the prefix;
    /// a re-bind overwrites while history stays replayable.
    #[test]
    fn versioned_replay_resolves_at_any_prefix() {
        let c1 = cid_seq();
        let mut c2 = cid_seq();
        c2[0] = 0xAA;
        let log = vec![
            NsEvent::Bind {
                name: "n".to_string(),
                cid: c1,
                author: "owner".to_string(),
            },
            NsEvent::Bind {
                name: "n".to_string(),
                cid: c2,
                author: "owner".to_string(),
            },
        ];
        assert_eq!(fold_at(&log, 0).bindings.get("n"), None);
        assert_eq!(fold_at(&log, 1).bindings.get("n"), Some(&c1));
        assert_eq!(fold_at(&log, 2).bindings.get("n"), Some(&c2));
        // determinism: same prefix, same state.
        assert_eq!(fold_at(&log, 1), fold_at(&log, 1));
    }

    /// Fail-closed decode: every malformation is a typed refusal.
    #[test]
    fn decode_fails_closed() {
        let good = encode_log(&[NsEvent::Bind {
            name: "n".to_string(),
            cid: cid_seq(),
            author: "o".to_string(),
        }])
        .expect("encodes");
        assert_eq!(decode_log(&good[..3]), Err(NamespaceError::Truncated));
        let mut bad_magic = good.clone();
        bad_magic[0] = b'X';
        assert_eq!(decode_log(&bad_magic), Err(NamespaceError::BadMagic));
        let mut bad_ver = good.clone();
        bad_ver[4] = 9;
        assert_eq!(decode_log(&bad_ver), Err(NamespaceError::UnknownVersion));
        let mut bad_kind = good.clone();
        bad_kind[9] = 7;
        assert_eq!(decode_log(&bad_kind), Err(NamespaceError::UnknownKind));
        let mut trailing = good.clone();
        trailing.push(0);
        assert_eq!(decode_log(&trailing), Err(NamespaceError::TrailingBytes));
        assert_eq!(decode_log(b""), Err(NamespaceError::Truncated));
    }

    /// Name gates: empty / over-cap / non-graphic / cid-shaped all refused, at
    /// BOTH the encode side and the decode side.
    #[test]
    fn name_gates_are_disjoint_from_cids() {
        assert!(valid_name("squads/mintFundedSigner"));
        assert!(valid_name("a"));
        assert!(!valid_name(""));
        assert!(!valid_name(&"x".repeat(NAME_CAP_BYTES + 1)));
        assert!(!valid_name("has space"));
        assert!(!valid_name("한글이름"));
        // a 64-lowercase-hex name is REFUSED — names and cids stay disjoint.
        assert!(!valid_name(&"a".repeat(64)));
        // …but 64 chars that are not pure hex are fine.
        assert!(valid_name(&format!("{}z", "a".repeat(63))));
        assert_eq!(
            encode_log(&[NsEvent::Bind {
                name: "a".repeat(64),
                cid: cid_seq(),
                author: String::new(),
            }]),
            None,
            "encode refuses a cid-shaped name"
        );
    }

    /// cid_from_hex: total inverse of hex32 on the cid alphabet; refuses others.
    #[test]
    fn cid_hex_round_trips() {
        let cid = cid_seq();
        let hex = crate::hex32(&cid);
        assert_eq!(cid_from_hex(&hex), Some(cid));
        assert_eq!(cid_from_hex("nope"), None);
        assert_eq!(cid_from_hex(&"A".repeat(64)), None, "uppercase refused");
    }

    /// Deterministic mini-space (LCG): fold(decode(encode(log))) == fold(log) and
    /// alias/unbind invariants hold across generated event sequences.
    #[test]
    fn property_minispace_fold_determinism() {
        const NAMES: &[&str] = &["a", "b", "lib/util", "pkg/mod#f", "x1"];
        let mut seed: u64 = 0x0BAD_5EED_0BAD_5EED;
        let mut lcg = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 33) as usize
        };
        for _ in 0..32 {
            let mut log = Vec::new();
            for _ in 0..(lcg() % 12) {
                let name = NAMES[lcg() % NAMES.len()].to_string();
                if lcg() % 3 == 0 {
                    log.push(NsEvent::Unbind {
                        name,
                        author: "owner".to_string(),
                    });
                } else {
                    let mut cid = [0u8; 32];
                    cid[0] = u8::try_from(lcg() % 256).unwrap_or(0);
                    log.push(NsEvent::Bind {
                        name,
                        cid,
                        author: "owner".to_string(),
                    });
                }
            }
            let bytes = encode_log(&log).expect("valid events encode");
            let decoded = decode_log(&bytes).expect("round-trip");
            assert_eq!(decoded, log);
            assert_eq!(fold(&decoded), fold(&log), "codec never changes the fold");
            // every bound name resolves to the LAST bind not followed by an unbind.
            let st = fold(&log);
            for (name, cid) in &st.bindings {
                let last = log
                    .iter()
                    .rev()
                    .find(|e| e.name() == name)
                    .expect("bound name has an event");
                match last {
                    NsEvent::Bind { cid: c, .. } => assert_eq!(c, cid),
                    NsEvent::Unbind { .. } => panic!("unbound name still in state"),
                }
            }
        }
    }

    /// Persistence: append → reload round-trips through the SHARED atomic path;
    /// appending an invalid event writes NOTHING (fail-closed).
    #[test]
    fn append_and_reload_round_trips_atomically() {
        let dir = std::env::temp_dir().join(format!("sinabro_ns_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let path = dir.join(NAMESPACE_LOG_FILE);
        let bind = NsEvent::Bind {
            name: "n".to_string(),
            cid: cid_seq(),
            author: "owner".to_string(),
        };
        assert_eq!(
            append_events(&path, std::slice::from_ref(&bind)).expect("append"),
            1
        );
        assert_eq!(load_log(&path).expect("load"), vec![bind.clone()]);
        // fail-closed append: a bad name writes nothing.
        let before = std::fs::read(&path).expect("read");
        assert!(
            append_events(
                &path,
                &[NsEvent::Bind {
                    name: String::new(),
                    cid: cid_seq(),
                    author: "owner".to_string(),
                }]
            )
            .is_err()
        );
        assert_eq!(
            std::fs::read(&path).expect("read"),
            before,
            "log byte-unchanged"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
