//! Private REPL history + redaction (atom #412 F.1.3).
//!
//! The history is a bounded ring of command lines. The hard law: secrets,
//! provider keys, wallet material, raw tx bytes, and install-approval phrases
//! never persist in history *as raw text*. Detection reuses the a-core
//! [`looks_like_secret`] scanner plus a single-token key/tx shape check; when a
//! line is sensitive only its redaction class is kept (the raw value is dropped
//! at the [`redact_for_log`] call site and cannot cross any later boundary).

use std::collections::VecDeque;

use mnemos_a_core::{LogRedactionKind, RedactedLogValue, looks_like_secret, redact_for_log};

/// History store schema version (bumped only when the entry shape changes).
pub const HISTORY_SCHEMA_VERSION_U16: u16 = 1;

/// One history entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HistoryEntry {
    /// A non-sensitive command line, stored verbatim.
    Plain(String),
    /// A sensitive line: the raw value was dropped; only the redaction class is
    /// retained.
    Redacted(RedactedLogValue),
}

impl HistoryEntry {
    /// Whether this entry is redacted (raw value not present).
    #[must_use]
    pub const fn is_redacted(&self) -> bool {
        matches!(self, Self::Redacted(_))
    }
}

const fn is_keyish_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-')
}

fn is_single_token(s: &str) -> bool {
    !s.is_empty() && !s.bytes().any(|b| b.is_ascii_whitespace())
}

/// Classify a line; `Some(kind)` means it must be redacted, `None` means it is
/// safe to store verbatim. Fail-closed: an ambiguous high-entropy single token
/// is treated as a key (over-redaction is safe; leaking is not).
#[must_use]
pub fn classify(line: &str) -> Option<LogRedactionKind> {
    let t = line.trim();
    if t.is_empty() {
        return None;
    }
    if looks_like_secret(t) {
        return Some(LogRedactionKind::ApiToken);
    }
    if is_single_token(t) {
        let n = t.len();
        if n >= 128 && t.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(LogRedactionKind::SuiTxBytes);
        }
        if n >= 32 && t.bytes().all(is_keyish_byte) {
            return Some(LogRedactionKind::ApiToken);
        }
    }
    None
}

/// Bounded, redacting command history.
#[derive(Clone, Debug)]
pub struct HistoryStore {
    entries: VecDeque<HistoryEntry>,
    cap: usize,
    schema_version_u16: u16,
}

impl HistoryStore {
    /// A history store holding at most `cap` entries (a zero cap stores nothing).
    #[must_use]
    pub fn new(cap: usize) -> Self {
        Self {
            entries: VecDeque::new(),
            cap,
            schema_version_u16: HISTORY_SCHEMA_VERSION_U16,
        }
    }

    fn push_entry(&mut self, entry: HistoryEntry) {
        if self.cap == 0 {
            return;
        }
        self.entries.push_back(entry);
        while self.entries.len() > self.cap {
            self.entries.pop_front();
        }
    }

    /// Push a command line, auto-redacting if it is sensitive.
    pub fn push(&mut self, line: &str) {
        match classify(line) {
            Some(kind) => self.push_entry(HistoryEntry::Redacted(redact_for_log(line, kind))),
            None => self.push_entry(HistoryEntry::Plain(line.to_string())),
        }
    }

    /// Push a line the caller *knows* is sensitive (e.g. an install-approval
    /// phrase or wallet material the REPL was collecting), always redacting it
    /// under `kind` regardless of its shape.
    pub fn push_sensitive(&mut self, line: &str, kind: LogRedactionKind) {
        self.push_entry(HistoryEntry::Redacted(redact_for_log(line, kind)));
    }

    /// The entries, oldest first.
    pub fn entries(&self) -> impl Iterator<Item = &HistoryEntry> {
        self.entries.iter()
    }

    /// Number of stored entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The recallable command lines (the `Plain` entries only, oldest first) for the
    /// interactive editor's up/down history. A `Redacted` entry is SKIPPED — its raw
    /// text was already dropped at push time, so it can never be reconstructed for
    /// recall and the secret never crosses the editor boundary. Returns owned
    /// `String`s so the editor can hold a stable snapshot while the store keeps
    /// mutating (a line submitted now is recallable on the next prompt).
    #[must_use]
    pub fn recall_lines(&self) -> Vec<String> {
        self.entries
            .iter()
            .filter_map(|e| match e {
                HistoryEntry::Plain(text) => Some(text.clone()),
                HistoryEntry::Redacted(_) => None,
            })
            .collect()
    }

    /// The current schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u16 {
        self.schema_version_u16
    }

    /// Migrate to `new_version`: re-scan every `Plain` entry and redact any that
    /// now classifies as sensitive (e.g. detection improved across versions),
    /// then bump the schema version. Returns the number of entries newly
    /// redacted. Already-redacted entries are never un-redacted.
    pub fn migrate(&mut self, new_version: u16) -> usize {
        let mut migrated = 0usize;
        for entry in &mut self.entries {
            if let HistoryEntry::Plain(text) = entry {
                if let Some(kind) = classify(text) {
                    *entry = HistoryEntry::Redacted(redact_for_log(text, kind));
                    migrated += 1;
                }
            }
        }
        self.schema_version_u16 = new_version;
        migrated
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_command_is_stored_verbatim() {
        let mut h = HistoryStore::new(8);
        h.push("skill search redact");
        assert_eq!(h.len(), 1);
        let first = h.entries().next();
        assert_eq!(
            first,
            Some(&HistoryEntry::Plain("skill search redact".to_string()))
        );
    }

    #[test]
    fn hex_key_shaped_input_is_redacted() {
        let mut h = HistoryStore::new(8);
        // 64 hex chars (single token) -> key-shaped -> redacted, raw dropped.
        let key = "a".repeat(64);
        h.push(&key);
        let only = h.entries().next();
        assert!(only.is_some_and(HistoryEntry::is_redacted));
        // the raw text is provably absent: no Plain entry holds it
        assert!(
            !h.entries()
                .any(|e| matches!(e, HistoryEntry::Plain(p) if p == &key))
        );
    }

    #[test]
    fn base64_key_fixture_is_redacted() {
        let mut h = HistoryStore::new(8);
        h.push("c2VjcmV0LWFwaS1rZXktZml4dHVyZS1iYXNlNjQtbG9uZw==");
        assert!(h.entries().next().is_some_and(HistoryEntry::is_redacted));
    }

    #[test]
    fn install_approval_phrase_is_redacted_by_caller() {
        let mut h = HistoryStore::new(8);
        h.push_sensitive(
            "approve install skill weather-now",
            LogRedactionKind::ToolIo,
        );
        let only = h.entries().next();
        assert!(only.is_some_and(HistoryEntry::is_redacted));
        assert!(!h.entries().any(|e| matches!(e, HistoryEntry::Plain(_))));
    }

    #[test]
    fn empty_and_short_lines_are_not_falsely_redacted() {
        assert_eq!(classify("   "), None);
        assert_eq!(classify("skill list"), None);
        assert_eq!(classify("short"), None);
    }

    #[test]
    fn ring_is_bounded() {
        let mut h = HistoryStore::new(2);
        h.push("trace list");
        h.push("memory status");
        h.push("context map");
        assert_eq!(h.len(), 2);
        // oldest ("trace list") evicted
        assert_eq!(
            h.entries().next(),
            Some(&HistoryEntry::Plain("memory status".to_string()))
        );
    }

    #[test]
    fn migration_preserves_redaction_and_bumps_version() {
        let mut h = HistoryStore::new(8);
        h.push("trace list");
        h.push(&"f".repeat(64)); // redacted
        assert_eq!(h.schema_version(), HISTORY_SCHEMA_VERSION_U16);
        let migrated = h.migrate(HISTORY_SCHEMA_VERSION_U16 + 1);
        assert_eq!(migrated, 0, "nothing was wrongly stored plain");
        assert_eq!(h.schema_version(), HISTORY_SCHEMA_VERSION_U16 + 1);
        assert_eq!(h.len(), 2);
        // the redacted one is still redacted
        assert!(h.entries().any(HistoryEntry::is_redacted));
    }

    #[test]
    fn zero_cap_stores_nothing() {
        let mut h = HistoryStore::new(0);
        h.push("trace list");
        h.push_sensitive("secret", LogRedactionKind::ApiToken);
        assert!(h.is_empty());
    }

    #[test]
    fn recall_lines_are_plain_only_oldest_first() {
        let mut h = HistoryStore::new(8);
        h.push("trace list");
        h.push("memory status");
        assert_eq!(
            h.recall_lines(),
            vec!["trace list".to_string(), "memory status".to_string()]
        );
    }

    #[test]
    fn recall_lines_skips_redacted_so_no_secret_is_recalled() {
        let mut h = HistoryStore::new(8);
        h.push("provider status");
        h.push(&"a".repeat(64)); // key-shaped single token -> redacted, raw dropped
        h.push("memory status");
        let recall = h.recall_lines();
        // only the two Plain commands remain; the redacted secret is absent.
        assert_eq!(
            recall,
            vec!["provider status".to_string(), "memory status".to_string()]
        );
        assert!(!recall.iter().any(|l| l.contains(&"a".repeat(64))));
    }
}
