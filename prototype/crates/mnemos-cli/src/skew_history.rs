//! `skew_history` — MNEMOS × SKEW K-3: the PURE, byte-locked time-series WINDOW codec + the
//! deterministic OHLC / volume / funding analyzers for the history accumulator.
//!
//! ## PURE (no Solana / serde / net / clock / float / RNG dependency)
//! Skew stores only the LATEST `ReferenceSnapshot` (no time-series). Sinabro polls the chain's
//! singleton PDAs over time and accumulates each `(slot, value)` sample into a bounded, append-only,
//! slot-sorted WINDOW. The dispatch glue seals these plaintext window bytes into the agent's OWN
//! AEAD-encrypted memory (local storage-of-record + a 2-tier Walrus ciphertext publish — E14-W2).
//! This module is the plaintext codec + the analysis ONLY: it never touches the network, a key, or a
//! chain-write path.
//!
//! ## Deterministic-no-LLM analysis
//! The OHLC / volume / funding analyzers are pure integer math — no float, no clock, no RNG. Re-runs
//! over the same window are byte-identical. The model never fabricates a candle / volume bar /
//! funding step; it can only READ the rendered series. This is the §2 "LLM off the hot path" + the
//! §14 "deterministic-no-LLM-judge oracle" discipline applied to analytics.

use std::fmt::Write as _;

/// The kind of series a window holds — one per Skew time-bearing account source. The wire tag.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeriesKind {
    /// `ReferenceSnapshot.composite_atoms` → OHLC price candles (the chart).
    ReferencePrice = 1,
    /// `SettlementReceipt.paid_amount` / `settlement_price` → volume + realized-price series.
    SettlementVolume = 2,
    /// `FundingState.cumulative_funding_index` (signed) → funding-rate deltas.
    FundingRate = 3,
}

impl SeriesKind {
    /// Map the wire tag byte back to a kind (fail-closed: `None` on an unknown byte).
    #[must_use]
    pub const fn from_u8(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::ReferencePrice),
            2 => Some(Self::SettlementVolume),
            3 => Some(Self::FundingRate),
            _ => None,
        }
    }

    /// The wire tag byte.
    #[must_use]
    pub const fn tag(self) -> u8 {
        self as u8
    }

    /// A stable display / topic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReferencePrice => "price",
            Self::SettlementVolume => "volume",
            Self::FundingRate => "funding",
        }
    }
}

/// One time-series sample. A SUPERSET over the three kinds (a window holds ONE kind, so only the
/// kind-relevant fields carry meaning). All integer — no float anywhere.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HistorySample {
    /// The time axis: `observed_slot` (price) / `created_slot` (volume) / `last_snapshot_slot` (funding).
    pub slot: u64,
    /// `composite_atoms` (price) / `settlement_price` (volume) / 0 (funding).
    pub price_atoms: u128,
    /// 0 (price) / `paid_amount` (volume) / `max_rate` (funding clamp bound).
    pub amount_atoms: u128,
    /// 0 (price) / `signed_payoff_amount` (volume) / `cumulative_funding_index` (funding; SIGNED).
    pub signed_atoms: i128,
    /// `confidence_bps` (price) / 0 (volume) / `status` (funding).
    pub aux_u32: u32,
    /// Price decimal exponent (price) / 0 (volume / funding). The display scale `10^exponent`.
    pub exponent: u8,
}

/// The per-sample on-wire width: `slot(8) + price(16) + amount(16) + signed(16) + aux(4) + exp(1)`.
const SAMPLE_BYTES: usize = 8 + 16 + 16 + 16 + 4 + 1;

/// The window codec magic (Skew History) — disambiguates a window blob from a memory record / index.
const HISTORY_MAGIC: &[u8; 4] = b"SKWH";
/// The window codec version.
const HISTORY_VERSION: u8 = 1;
/// The header width: `magic(4) + version(1) + kind(1) + series_id(32) + count(u32 = 4)`.
const HISTORY_HEADER_BYTES: usize = 4 + 1 + 1 + 32 + 4;

/// The bounded cap on samples in ONE window (ring: the oldest is dropped past this). Caps both the
/// in-memory growth AND the codec `from_bytes` (an untrusted blob can never allocate past this).
pub const SKEW_HISTORY_MAX_SAMPLES: usize = 4096;

/// The AEAD associated-data binding a SEALED history window — DISTINCT from the memory-record,
/// walrus-index, and settings AADs (so a window ciphertext can never be opened as another payload).
/// `PersistedStore::seal_skew_history` / `open_skew_history` bind to this; the storage-of-record + the
/// Walrus sub-blob are both sealed with it (secret-zero: only a LOCAL open reveals the plaintext).
pub const SKEW_HISTORY_AAD: &[u8] = b"sinabro.skew.history.v1";

/// A bounded, append-only, slot-sorted time-series window = one Walrus sub-blob. `series_id` is the
/// on-chain account pubkey (the per-market singleton PDA). Samples are kept sorted by `slot` and
/// deduped by `slot` (a re-poll of an unchanged snapshot is idempotent); past [`SKEW_HISTORY_MAX_SAMPLES`]
/// the OLDEST is dropped (a bounded ring — never an unbounded grow).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HistoryWindow {
    /// Which series this window holds.
    pub kind: SeriesKind,
    /// The on-chain account pubkey (the per-market singleton PDA) this series tracks.
    pub series_id: [u8; 32],
    /// The samples, sorted by `slot`, deduped by `slot`, bounded by [`SKEW_HISTORY_MAX_SAMPLES`].
    pub samples: Vec<HistorySample>,
}

/// Fail-closed window-codec errors (a malformed / hostile blob never decodes to a partial window).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HistoryCodecError {
    /// Fewer bytes than the declared structure requires.
    Truncated,
    /// The leading 4 bytes are not [`HISTORY_MAGIC`].
    BadMagic,
    /// The version byte is not [`HISTORY_VERSION`].
    UnknownVersion,
    /// The kind byte is not a declared [`SeriesKind`].
    UnknownKind,
    /// The declared sample count exceeds [`SKEW_HISTORY_MAX_SAMPLES`] (DoS bound).
    TooManySamples,
    /// Trailing bytes after the last declared sample.
    TrailingBytes,
}

impl HistoryWindow {
    /// A fresh empty window for `kind` tracking `series_id`.
    #[must_use]
    pub const fn new(kind: SeriesKind, series_id: [u8; 32]) -> Self {
        Self {
            kind,
            series_id,
            samples: Vec::new(),
        }
    }

    /// Append a sample, keeping the window slot-sorted + deduped-by-slot + bounded. Returns `true`
    /// iff the window CHANGED (a new slot, or a replaced value at an existing slot). A re-poll of an
    /// unchanged snapshot (same slot + same fields) is idempotent and returns `false` — the
    /// deterministic accumulation property. Past the cap the OLDEST sample is dropped (bounded ring).
    pub fn append_sample(&mut self, s: HistorySample) -> bool {
        match self.samples.binary_search_by(|e| e.slot.cmp(&s.slot)) {
            Ok(i) => {
                if self.samples[i] == s {
                    false // idempotent re-poll
                } else {
                    self.samples[i] = s; // a re-validation at the same slot ⇒ newest value wins
                    true
                }
            }
            Err(i) => {
                self.samples.insert(i, s);
                // Bounded ring: drop the oldest (lowest slot) past the cap.
                while self.samples.len() > SKEW_HISTORY_MAX_SAMPLES {
                    self.samples.remove(0);
                }
                true
            }
        }
    }

    /// Append an EVENT sample (use for event series like settlements, where multiple distinct events
    /// can share a slot — unlike `append_sample`, this does NOT dedup by slot). Idempotent on a
    /// re-poll: a sample with IDENTICAL fields is skipped (returns `false`); a distinct event at the
    /// same slot is kept. Keeps the window slot-sorted + bounded (ring-drop oldest past the cap).
    pub fn push_event(&mut self, s: HistorySample) -> bool {
        if self.samples.contains(&s) {
            return false; // idempotent re-poll of the same settlement event
        }
        let i = self.samples.partition_point(|e| e.slot <= s.slot);
        self.samples.insert(i, s);
        while self.samples.len() > SKEW_HISTORY_MAX_SAMPLES {
            self.samples.remove(0);
        }
        true
    }

    /// The number of samples currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Whether the window holds no samples.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// A short topic label for the Walrus manifest entry (`skew:<kind>:<series-hex8>`).
    #[must_use]
    pub fn topic(&self) -> String {
        format!("skew:{}:{}", self.kind.as_str(), short_hex(&self.series_id))
    }

    /// Encode the window to canonical plaintext bytes (the dispatch glue seals these into AEAD
    /// ciphertext). Format: `magic(4) ‖ version(1) ‖ kind(1) ‖ series_id(32) ‖ count(u32 LE) ‖
    /// [slot(u64) price(u128) amount(u128) signed(i128) aux(u32) exp(u8)]*`. Deterministic.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let n = self.samples.len().min(SKEW_HISTORY_MAX_SAMPLES);
        let mut out = Vec::with_capacity(HISTORY_HEADER_BYTES + n * SAMPLE_BYTES);
        out.extend_from_slice(HISTORY_MAGIC);
        out.push(HISTORY_VERSION);
        out.push(self.kind.tag());
        out.extend_from_slice(&self.series_id);
        out.extend_from_slice(&(n as u32).to_le_bytes());
        for s in self.samples.iter().take(n) {
            out.extend_from_slice(&s.slot.to_le_bytes());
            out.extend_from_slice(&s.price_atoms.to_le_bytes());
            out.extend_from_slice(&s.amount_atoms.to_le_bytes());
            out.extend_from_slice(&s.signed_atoms.to_le_bytes());
            out.extend_from_slice(&s.aux_u32.to_le_bytes());
            out.push(s.exponent);
        }
        out
    }

    /// Decode a window from plaintext bytes (after the AEAD open). Fail-closed: every length is
    /// checked before consumed; the magic / version / kind are validated; the count is capped at
    /// [`SKEW_HISTORY_MAX_SAMPLES`]; trailing bytes are rejected. Never a partial window.
    ///
    /// # Errors
    /// Returns [`HistoryCodecError`] on truncation, bad magic / version / kind, an over-cap count, or
    /// trailing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HistoryCodecError> {
        let mut pos = 0usize;
        let magic = take(bytes, &mut pos, 4).ok_or(HistoryCodecError::Truncated)?;
        if magic != HISTORY_MAGIC {
            return Err(HistoryCodecError::BadMagic);
        }
        let version = take(bytes, &mut pos, 1).ok_or(HistoryCodecError::Truncated)?[0];
        if version != HISTORY_VERSION {
            return Err(HistoryCodecError::UnknownVersion);
        }
        let kind_byte = take(bytes, &mut pos, 1).ok_or(HistoryCodecError::Truncated)?[0];
        let kind = SeriesKind::from_u8(kind_byte).ok_or(HistoryCodecError::UnknownKind)?;
        let mut series_id = [0u8; 32];
        series_id.copy_from_slice(take(bytes, &mut pos, 32).ok_or(HistoryCodecError::Truncated)?);
        let count_bytes = take(bytes, &mut pos, 4).ok_or(HistoryCodecError::Truncated)?;
        let mut cb = [0u8; 4];
        cb.copy_from_slice(count_bytes);
        let count = u32::from_le_bytes(cb) as usize;
        if count > SKEW_HISTORY_MAX_SAMPLES {
            return Err(HistoryCodecError::TooManySamples);
        }
        let mut samples = Vec::with_capacity(count);
        for _ in 0..count {
            let slot = read_u64(bytes, &mut pos)?;
            let price_atoms = read_u128(bytes, &mut pos)?;
            let amount_atoms = read_u128(bytes, &mut pos)?;
            let signed_atoms = read_i128(bytes, &mut pos)?;
            let aux_u32 = read_u32(bytes, &mut pos)?;
            let exponent = take(bytes, &mut pos, 1).ok_or(HistoryCodecError::Truncated)?[0];
            samples.push(HistorySample {
                slot,
                price_atoms,
                amount_atoms,
                signed_atoms,
                aux_u32,
                exponent,
            });
        }
        if pos != bytes.len() {
            return Err(HistoryCodecError::TrailingBytes);
        }
        Ok(Self {
            kind,
            series_id,
            samples,
        })
    }
}

// ── cursor readers (fail-closed; no panic) ─────────────────────────────────────────────────────

fn take<'a>(buf: &'a [u8], pos: &mut usize, n: usize) -> Option<&'a [u8]> {
    let end = pos.checked_add(n)?;
    if end > buf.len() {
        return None;
    }
    let s = &buf[*pos..end];
    *pos = end;
    Some(s)
}
fn read_u32(buf: &[u8], pos: &mut usize) -> Result<u32, HistoryCodecError> {
    let s = take(buf, pos, 4).ok_or(HistoryCodecError::Truncated)?;
    let mut t = [0u8; 4];
    t.copy_from_slice(s);
    Ok(u32::from_le_bytes(t))
}
fn read_u64(buf: &[u8], pos: &mut usize) -> Result<u64, HistoryCodecError> {
    let s = take(buf, pos, 8).ok_or(HistoryCodecError::Truncated)?;
    let mut t = [0u8; 8];
    t.copy_from_slice(s);
    Ok(u64::from_le_bytes(t))
}
fn read_u128(buf: &[u8], pos: &mut usize) -> Result<u128, HistoryCodecError> {
    let s = take(buf, pos, 16).ok_or(HistoryCodecError::Truncated)?;
    let mut t = [0u8; 16];
    t.copy_from_slice(s);
    Ok(u128::from_le_bytes(t))
}
fn read_i128(buf: &[u8], pos: &mut usize) -> Result<i128, HistoryCodecError> {
    let s = take(buf, pos, 16).ok_or(HistoryCodecError::Truncated)?;
    let mut t = [0u8; 16];
    t.copy_from_slice(s);
    Ok(i128::from_le_bytes(t))
}

/// First 8 bytes of a 32-byte id, lowercase hex (16 chars) — for topics / filenames / display.
#[must_use]
pub fn short_hex(id: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &id[..8] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ── deterministic analyzers (pure integer math; no float, no clock) ────────────────────────────

/// One OHLC candle over a slot bucket. Price = `composite_atoms` (price series) or `settlement_price`
/// (volume series) — integer atoms at the series' decimal scale. Open = price at the LOWEST slot in
/// the bucket; Close = price at the HIGHEST slot; High / Low = the extrema.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Candle {
    /// The bucket index = `start_slot / bucket_slots`.
    pub bucket: u64,
    /// The bucket's first slot (`bucket * bucket_slots`).
    pub start_slot: u64,
    /// Price at the lowest slot in the bucket.
    pub open_atoms: u128,
    /// Highest price in the bucket.
    pub high_atoms: u128,
    /// Lowest price in the bucket.
    pub low_atoms: u128,
    /// Price at the highest slot in the bucket.
    pub close_atoms: u128,
    /// Samples in the bucket.
    pub count: u32,
}

/// Bucket slot-sorted samples into OHLC candles by `price_atoms`. `bucket_slots` is the slot width of
/// one candle (clamped to ≥1). Pure integer math; the input is assumed slot-sorted (the window
/// invariant). Deterministic — byte-identical re-runs.
#[must_use]
pub fn ohlc(samples: &[HistorySample], bucket_slots: u64) -> Vec<Candle> {
    let width = bucket_slots.max(1);
    let mut out: Vec<Candle> = Vec::new();
    for s in samples {
        let bucket = s.slot / width;
        match out.last_mut() {
            Some(c) if c.bucket == bucket => {
                // samples are slot-sorted ⇒ this is a later-or-equal slot ⇒ it is the new close.
                c.close_atoms = s.price_atoms;
                c.high_atoms = c.high_atoms.max(s.price_atoms);
                c.low_atoms = c.low_atoms.min(s.price_atoms);
                c.count = c.count.saturating_add(1);
            }
            _ => out.push(Candle {
                bucket,
                start_slot: bucket.saturating_mul(width),
                open_atoms: s.price_atoms,
                high_atoms: s.price_atoms,
                low_atoms: s.price_atoms,
                close_atoms: s.price_atoms,
                count: 1,
            }),
        }
    }
    out
}

/// One volume bar over a slot bucket: the summed settlement `paid_amount` (the volume), the count,
/// and the realized `settlement_price` OHLC.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeBar {
    /// The bucket index.
    pub bucket: u64,
    /// The bucket's first slot.
    pub start_slot: u64,
    /// Summed `paid_amount` over the bucket (saturating — deterministic, never panics).
    pub volume_atoms: u128,
    /// Settlements in the bucket.
    pub count: u32,
    /// Realized `settlement_price` at the lowest slot.
    pub price_open: u128,
    /// Highest realized price.
    pub price_high: u128,
    /// Lowest realized price.
    pub price_low: u128,
    /// Realized price at the highest slot.
    pub price_close: u128,
}

/// Bucket settlement samples into volume bars: `volume_atoms = Σ amount_atoms` (saturating) + the
/// realized `price_atoms` OHLC. Pure integer math; slot-sorted input assumed.
#[must_use]
pub fn volume(samples: &[HistorySample], bucket_slots: u64) -> Vec<VolumeBar> {
    let width = bucket_slots.max(1);
    let mut out: Vec<VolumeBar> = Vec::new();
    for s in samples {
        let bucket = s.slot / width;
        match out.last_mut() {
            Some(v) if v.bucket == bucket => {
                v.volume_atoms = v.volume_atoms.saturating_add(s.amount_atoms);
                v.count = v.count.saturating_add(1);
                v.price_close = s.price_atoms;
                v.price_high = v.price_high.max(s.price_atoms);
                v.price_low = v.price_low.min(s.price_atoms);
            }
            _ => out.push(VolumeBar {
                bucket,
                start_slot: bucket.saturating_mul(width),
                volume_atoms: s.amount_atoms,
                count: 1,
                price_open: s.price_atoms,
                price_high: s.price_atoms,
                price_low: s.price_atoms,
                price_close: s.price_atoms,
            }),
        }
    }
    out
}

/// One funding point: the cumulative funding index at a slot + the per-interval STEP (the delta from
/// the previous point — the realized funding move for that interval) + the clamp bound.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FundingPoint {
    /// The slot of this funding snapshot.
    pub slot: u64,
    /// The cumulative funding index (SIGNED).
    pub cumulative: i128,
    /// The delta from the previous point's cumulative (this interval's funding step; 0 at the first).
    pub step: i128,
    /// The per-step clamp bound `Fmax` at this slot.
    pub max_rate: u128,
}

/// Turn a funding window into the per-interval funding series: each point's `step` is the SIGNED
/// delta `cumulative[t] − cumulative[t-1]` (saturating; the first point's step is 0). Pure integer.
#[must_use]
pub fn funding_series(samples: &[HistorySample]) -> Vec<FundingPoint> {
    let mut out: Vec<FundingPoint> = Vec::with_capacity(samples.len());
    let mut prev: Option<i128> = None;
    for s in samples {
        let cumulative = s.signed_atoms;
        let step = prev.map_or(0i128, |p| cumulative.saturating_sub(p));
        out.push(FundingPoint {
            slot: s.slot,
            cumulative,
            step,
            max_rate: s.amount_atoms,
        });
        prev = Some(cumulative);
    }
    out
}

/// The max number of analysis rows rendered (bounded output; a window can hold up to the cap).
const RENDER_ROW_CAP: usize = 64;

/// Render a window's analysis by kind (OHLC / volume / funding). `bucket_slots` is the candle / bar
/// slot width (ignored for funding). Output is bounded to [`RENDER_ROW_CAP`] rows.
#[must_use]
pub fn render_window(window: &HistoryWindow, bucket_slots: u64) -> String {
    let mut out = String::new();
    let _ = writeln!(
        out,
        "skew history [{}] series={} samples={} (deterministic integer analysis; no LLM; chart data is REAL)",
        window.kind.as_str(),
        short_hex(&window.series_id),
        window.samples.len()
    );
    if window.is_empty() {
        let _ = writeln!(
            out,
            "  (no samples yet — run `skew accumulate` to poll the chain)"
        );
        return out;
    }
    match window.kind {
        SeriesKind::ReferencePrice => {
            let exp = window.samples.first().map_or(0, |s| s.exponent);
            let _ = writeln!(
                out,
                "  OHLC (bucket={bucket_slots} slots; price atoms @ 10^{exp}):"
            );
            let candles = ohlc(&window.samples, bucket_slots);
            for c in candles.iter().take(RENDER_ROW_CAP) {
                let _ = writeln!(
                    out,
                    "    slot~{} O={} H={} L={} C={} n={}",
                    c.start_slot, c.open_atoms, c.high_atoms, c.low_atoms, c.close_atoms, c.count
                );
            }
            row_cap_note(&mut out, candles.len());
        }
        SeriesKind::SettlementVolume => {
            let _ = writeln!(
                out,
                "  VOLUME (bucket={bucket_slots} slots; Σpaid_amount + realized price OHLC):"
            );
            let bars = volume(&window.samples, bucket_slots);
            for v in bars.iter().take(RENDER_ROW_CAP) {
                let _ = writeln!(
                    out,
                    "    slot~{} vol={} n={} priceO={} H={} L={} C={}",
                    v.start_slot,
                    v.volume_atoms,
                    v.count,
                    v.price_open,
                    v.price_high,
                    v.price_low,
                    v.price_close
                );
            }
            row_cap_note(&mut out, bars.len());
        }
        SeriesKind::FundingRate => {
            let _ = writeln!(
                out,
                "  FUNDING (cumulative index + per-interval step; signed atoms):"
            );
            let pts = funding_series(&window.samples);
            for p in pts.iter().take(RENDER_ROW_CAP) {
                let _ = writeln!(
                    out,
                    "    slot={} cumulative={} step={} max_rate={}",
                    p.slot, p.cumulative, p.step, p.max_rate
                );
            }
            row_cap_note(&mut out, pts.len());
        }
    }
    out
}

fn row_cap_note(out: &mut String, total: usize) {
    if total > RENDER_ROW_CAP {
        let _ = writeln!(
            out,
            "    … ({} more rows; bounded render)",
            total - RENDER_ROW_CAP
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(slot: u64, price: u128) -> HistorySample {
        HistorySample {
            slot,
            price_atoms: price,
            amount_atoms: 0,
            signed_atoms: 0,
            aux_u32: 0,
            exponent: 6,
        }
    }

    #[test]
    fn codec_round_trips_byte_identical() {
        let mut w = HistoryWindow::new(SeriesKind::ReferencePrice, [0xAB; 32]);
        w.append_sample(sample(100, 433_000_000));
        w.append_sample(sample(200, 434_500_000));
        w.append_sample(sample(150, 433_900_000));
        let bytes = w.to_bytes();
        let back = HistoryWindow::from_bytes(&bytes).expect("decodes");
        assert_eq!(back, w);
        // deterministic: re-encode is byte-identical.
        assert_eq!(back.to_bytes(), bytes);
    }

    #[test]
    fn append_is_slot_sorted_deduped_idempotent_and_bounded() {
        let mut w = HistoryWindow::new(SeriesKind::ReferencePrice, [1; 32]);
        assert!(w.append_sample(sample(200, 10)));
        assert!(w.append_sample(sample(100, 20))); // inserts BEFORE 200
        assert!(w.append_sample(sample(150, 30)));
        // slot-sorted:
        let slots: Vec<u64> = w.samples.iter().map(|s| s.slot).collect();
        assert_eq!(slots, vec![100, 150, 200]);
        // idempotent re-poll of an unchanged slot ⇒ no change:
        assert!(!w.append_sample(sample(150, 30)));
        // a re-validation at the same slot with a NEW value ⇒ replace + changed:
        assert!(w.append_sample(sample(150, 99)));
        assert_eq!(
            w.samples
                .iter()
                .find(|s| s.slot == 150)
                .map(|s| s.price_atoms),
            Some(99)
        );
        assert_eq!(w.len(), 3);
    }

    #[test]
    fn push_event_keeps_distinct_same_slot_events_but_dedups_identical() {
        let mut w = HistoryWindow::new(SeriesKind::SettlementVolume, [9; 32]);
        let mk = |slot: u64, price: u128, amount: u128| HistorySample {
            slot,
            price_atoms: price,
            amount_atoms: amount,
            signed_atoms: 0,
            aux_u32: 0,
            exponent: 0,
        };
        assert!(w.push_event(mk(100, 50, 5)));
        // a DISTINCT settlement at the SAME slot is kept (events, not a singleton):
        assert!(w.push_event(mk(100, 60, 7)));
        assert_eq!(w.len(), 2);
        // an IDENTICAL re-poll is idempotent (skipped):
        assert!(!w.push_event(mk(100, 50, 5)));
        assert_eq!(w.len(), 2);
        // volume sums BOTH same-slot events into the bucket:
        let bars = volume(&w.samples, 100);
        assert_eq!(bars.len(), 1);
        assert_eq!(bars[0].volume_atoms, 12); // 5 + 7
        assert_eq!(bars[0].count, 2);
    }

    #[test]
    fn append_drops_oldest_past_the_cap() {
        let mut w = HistoryWindow::new(SeriesKind::ReferencePrice, [2; 32]);
        for i in 0..(SKEW_HISTORY_MAX_SAMPLES as u64 + 10) {
            w.append_sample(sample(i, i as u128));
        }
        assert_eq!(w.len(), SKEW_HISTORY_MAX_SAMPLES);
        // the oldest 10 slots were dropped (bounded ring); the newest is kept.
        assert_eq!(w.samples.first().map(|s| s.slot), Some(10));
        assert_eq!(
            w.samples.last().map(|s| s.slot),
            Some(SKEW_HISTORY_MAX_SAMPLES as u64 + 9)
        );
    }

    #[test]
    fn from_bytes_is_fail_closed() {
        let mut w = HistoryWindow::new(SeriesKind::FundingRate, [3; 32]);
        w.append_sample(sample(1, 0));
        let good = w.to_bytes();
        // bad magic
        let mut bad = good.clone();
        bad[0] ^= 0xff;
        assert_eq!(
            HistoryWindow::from_bytes(&bad),
            Err(HistoryCodecError::BadMagic)
        );
        // bad version
        let mut bad = good.clone();
        bad[4] = 99;
        assert_eq!(
            HistoryWindow::from_bytes(&bad),
            Err(HistoryCodecError::UnknownVersion)
        );
        // bad kind
        let mut bad = good.clone();
        bad[5] = 0; // 0 is not a declared SeriesKind
        assert_eq!(
            HistoryWindow::from_bytes(&bad),
            Err(HistoryCodecError::UnknownKind)
        );
        // truncated
        assert_eq!(
            HistoryWindow::from_bytes(&good[..good.len() - 1]),
            Err(HistoryCodecError::Truncated)
        );
        // trailing bytes
        let mut trailing = good.clone();
        trailing.push(0u8);
        assert_eq!(
            HistoryWindow::from_bytes(&trailing),
            Err(HistoryCodecError::TrailingBytes)
        );
        // an over-cap declared count is rejected (DoS bound): forge count = MAX+1.
        let mut over = good.clone();
        let over_count = (SKEW_HISTORY_MAX_SAMPLES as u32 + 1).to_le_bytes();
        over[38..42].copy_from_slice(&over_count); // count field @ header offset 38
        assert_eq!(
            HistoryWindow::from_bytes(&over),
            Err(HistoryCodecError::TooManySamples)
        );
    }

    #[test]
    fn ohlc_buckets_open_high_low_close_pure_integer() {
        let samples = vec![
            sample(10, 100),  // bucket 0 (width 100): open
            sample(20, 150),  // high
            sample(30, 90),   // low
            sample(40, 120),  // close
            sample(110, 200), // bucket 1: single ⇒ O=H=L=C=200
        ];
        let candles = ohlc(&samples, 100);
        assert_eq!(candles.len(), 2);
        assert_eq!(candles[0].bucket, 0);
        assert_eq!(candles[0].open_atoms, 100);
        assert_eq!(candles[0].high_atoms, 150);
        assert_eq!(candles[0].low_atoms, 90);
        assert_eq!(candles[0].close_atoms, 120);
        assert_eq!(candles[0].count, 4);
        assert_eq!(candles[1].open_atoms, 200);
        assert_eq!(candles[1].close_atoms, 200);
        assert_eq!(candles[1].count, 1);
        // determinism: re-run identical.
        assert_eq!(ohlc(&samples, 100), candles);
    }

    #[test]
    fn volume_sums_amount_and_tracks_realized_price() {
        let mk = |slot: u64, price: u128, amount: u128| HistorySample {
            slot,
            price_atoms: price,
            amount_atoms: amount,
            signed_atoms: 0,
            aux_u32: 0,
            exponent: 6,
        };
        let samples = vec![mk(10, 100, 5), mk(20, 110, 7), mk(110, 120, 3)];
        let bars = volume(&samples, 100);
        assert_eq!(bars.len(), 2);
        assert_eq!(bars[0].volume_atoms, 12); // 5 + 7
        assert_eq!(bars[0].count, 2);
        assert_eq!(bars[0].price_open, 100);
        assert_eq!(bars[0].price_close, 110);
        assert_eq!(bars[1].volume_atoms, 3);
    }

    #[test]
    fn funding_series_computes_signed_deltas() {
        let mk = |slot: u64, cum: i128| HistorySample {
            slot,
            price_atoms: 0,
            amount_atoms: 50,
            signed_atoms: cum,
            aux_u32: 1,
            exponent: 0,
        };
        let samples = vec![mk(10, 100), mk(20, 130), mk(30, 90)];
        let pts = funding_series(&samples);
        assert_eq!(pts.len(), 3);
        assert_eq!(pts[0].step, 0); // first has no prior
        assert_eq!(pts[0].cumulative, 100);
        assert_eq!(pts[1].step, 30); // 130 - 100
        assert_eq!(pts[2].step, -40); // 90 - 130 (signed)
        assert_eq!(pts[2].max_rate, 50);
    }

    #[test]
    fn render_is_bounded_and_kind_dispatched() {
        let mut w = HistoryWindow::new(SeriesKind::ReferencePrice, [0xCD; 32]);
        w.append_sample(sample(10, 100));
        w.append_sample(sample(20, 200));
        let r = render_window(&w, 100);
        assert!(r.contains("OHLC"));
        assert!(r.contains("series="));
        assert!(r.contains("no LLM"));
        // funding kind renders the funding analyzer:
        let mut f = HistoryWindow::new(SeriesKind::FundingRate, [0xEF; 32]);
        f.append_sample(HistorySample {
            slot: 1,
            price_atoms: 0,
            amount_atoms: 7,
            signed_atoms: -5,
            aux_u32: 1,
            exponent: 0,
        });
        assert!(render_window(&f, 1).contains("FUNDING"));
    }
}
