/* ============================================================================
   sinabro desktop — frontend logic (vanilla, withGlobalTauri)
   Easy chat/prompt surface; ALL power lives behind shortcuts (/ and ⌘K palette).
   Every line is dispatched through the Rust core (dispatch::run) via `dispatch_line`.
   No command semantics re-implemented here — the closed grammar lists below are
   completion HINTS only; the core validates & renders. funds/egress stay gated.
   ============================================================================ */

"use strict";

/* ── real command surface (closed grammar — hints only) ──────────────────── */
const TOP_LEVEL = ["status", "setup", "evidence", "budget", "kill", "tui", "repl", "daemon"];

// [name, desc] — DISPLAY HINTS ONLY. The capability GATE (free / gated / locked)
// is NOT hardcoded here: it is read from the CORE via `permission tier` into GATES
// (the single source of truth), so the palette's lock badges cannot drift from the
// core's real risk model. See OFFLINE_HARDLOCK + loadGates() below.
const NAMESPACES = [
  ["agent", "agent turns · budget · kill"],
  ["provider", "LLM provider routing (egress gated)"],
  ["model", "model routing · cache"],
  ["tool", "tool surface"],
  ["sandbox", "sandbox tier"],
  ["skill", "skills (sandbox + approval)"],
  ["registry", "skill registry (inspect-only)"],
  ["memory", "memory (user-owned · tombstone)"],
  ["wallet", "wallet (secret-zero · sign gated)"],
  ["identity", "identity (pubkey binding)"],
  ["key", "keys (rotation · zero plaintext)"],
  ["gas", "gas (no sponsor)"],
  ["chain", "chain (testnet · mainnet LOCKED)"],
  ["package", "Move package (publish = chain-write)"],
  ["multisig", "multisig"],
  ["dataset", "dataset"],
  ["trace", "trace"],
  ["train", "training (Stage F = forbidden)"],
  ["eval", "eval"],
  ["measure", "measure (TTFT/TPOT)"],
  ["platform", "platform · telegram (send = network)"],
  ["release", "release (publish = chain-write)"],
  ["federation", "federation"],
  ["admin", "admin (gated)"],
  ["approval", "approval gate"],
  ["audit", "audit (candidate ≠ finding)"],
  ["privacy", "privacy (egress 0)"],
  ["feature", "feature toggle"],
  ["learning", "self-learning (candidate-only)"],
  ["task", "tasks · automation"],
  ["session", "session"],
  ["context", "context"],
  ["checkpoint", "checkpoint"],
  ["permission", "permission"],
  ["notify", "notify"],
];

// GUI-side grouping for palette discovery (presentation metadata only — NOT
// command semantics; the core still validates every dispatched line).
const NS_CATEGORIES = [
  ["Agent", ["agent", "provider", "model", "tool", "sandbox", "skill", "registry"]],
  ["Memory & data", ["memory", "dataset", "trace", "eval", "measure", "context", "learning", "train"]],
  ["Chain & keys", ["wallet", "identity", "key", "gas", "chain", "package", "multisig", "release"]],
  ["Comms", ["platform", "notify", "federation"]],
  ["Safety & ops", ["admin", "approval", "audit", "privacy", "feature", "task", "session", "checkpoint", "permission"]],
];

/* ── capability gate (CORE is the single source of truth) ─────────────────── */
// The palette's lock badges come from the core's `permission tier` (which projects
// risk_for + the PD-6 custody/funds/chain-write hard-lock), NOT a hardcoded list —
// so the lock state cannot drift from what the core actually enforces.
// OFFLINE_HARDLOCK is the degraded-mode floor: if the Tauri bridge is absent or the
// fetch fails, these custody/funds/chain-write namespaces still render LOCKED (they
// can NEVER appear unlocked); everything else renders neutral until the core answers.
const OFFLINE_HARDLOCK = new Set(["wallet", "key", "gas", "chain", "package", "multisig", "release"]);
const GATES = {}; // { namespace: "free" | "gated" | "locked" } — filled from the core
async function loadGates() {
  try {
    const raw = await invoke("dispatch_line", { line: "permission tier" });
    const text = typeof raw === "string" ? raw : String(raw == null ? "" : raw);
    let n = 0;
    for (const line of text.split("\n")) {
      const m = /^([a-z_]+)=(free|gated|locked)$/.exec(line.trim());
      if (m) { GATES[m[1]] = m[2]; n += 1; }
    }
    return n;
  } catch (_) {
    return 0; // bridge absent / core unreachable → OFFLINE_HARDLOCK floor applies
  }
}
// The honest gate for a namespace: the core truth when loaded, else the custody
// floor. Never less-locked than the floor for a custody/funds/chain-write surface.
function gateFor(name) {
  if (Object.prototype.hasOwnProperty.call(GATES, name)) return GATES[name];
  return OFFLINE_HARDLOCK.has(name) ? "locked" : "free";
}
// Badge: 🔒 ONLY for genuine hard-locks (custody/funds/chain-write); a live dot for
// gated (available behind approval); nothing extra for free (autonomous READ).
function gateBadge(gate) {
  return gate === "locked" ? "🔒 namespace" : gate === "gated" ? "● namespace" : "namespace";
}

/* ── tiny state ──────────────────────────────────────────────────────────── */
const state = {
  projects: [{ id: "mnemos", name: "mnemos", icon: "▸", sessions: [] }],
  currentProject: "mnemos",
  currentSession: null,
  seq: 0,
};

/* ── helpers ─────────────────────────────────────────────────────────────── */
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}
function nowLabel() {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}
function hasTauri() {
  return typeof window !== "undefined" && window.__TAURI__ && window.__TAURI__.core;
}
async function invoke(cmd, args) {
  if (!hasTauri()) throw new Error("Tauri bridge missing — run with `cargo tauri dev` or the built app.");
  return window.__TAURI__.core.invoke(cmd, args);
}

/* ── session persistence (GUI-owned, secret-zero on-disk store) ───────────── */
// The persisted payload is safe at rest: input lines are redacted via the core
// (see dispatch -> redact_input) and response cards are the core's secret-zero
// render. Best-effort: persistence failures never block the UI.
async function persist() {
  if (!hasTauri()) return;
  try {
    const payload = JSON.stringify({
      v: 1,
      projects: state.projects,
      currentProject: state.currentProject,
      currentSession: state.currentSession,
      seq: state.seq,
    });
    await invoke("save_sessions", { json: payload });
  } catch (_) {}
}
async function restore() {
  if (!hasTauri()) return false;
  try {
    const raw = await invoke("load_sessions");
    if (!raw) return false;
    const data = JSON.parse(raw);
    if (!data || !Array.isArray(data.projects) || !data.projects.length) return false;
    state.projects = data.projects;
    state.currentProject = data.currentProject || data.projects[0].id;
    state.currentSession = data.currentSession || null;
    state.seq = typeof data.seq === "number" ? data.seq : 0;
    return true;
  } catch (_) {
    return false;
  }
}

/* ── response parsing (emit() fixed header order) ────────────────────────── */
function parseResponse(raw) {
  const out = { command: "", envelope: "", risk: "", approval: "", state: "", truth: "", body: [], error: false };
  for (const line of String(raw).split("\n")) {
    if (line.startsWith("command=")) out.command = line.slice(8);
    else if (line.startsWith("envelope=")) out.envelope = line.slice(9);
    else if (line.startsWith("risk=")) {
      const m = line.match(/^risk=(\S+)\s+approval=(\S+)/);
      if (m) { out.risk = m[1]; out.approval = m[2]; } else out.risk = line.slice(5);
    } else if (line.startsWith("state=")) out.state = line.slice(6);
    else if (line.startsWith("truth=")) out.truth = line.slice(6);
    else {
      if (line.includes("[stderr]") || /unknown command/i.test(line)) out.error = true;
      if (line.trim() !== "" || out.body.length) out.body.push(line);
    }
  }
  while (out.body.length && out.body[out.body.length - 1].trim() === "") out.body.pop();
  return out;
}
// Closed-set class maps (threat model M2): these header values come from
// dispatch output, which with the VM lane can originate on a REMOTE host —
// never interpolate them raw into class attributes. Unknown values fall back
// to the safe default class; the pill TEXT still shows the esc()'d original.
const RISK_SET = ["read-only", "local-write", "network", "wallet-sign", "chain-write", "training", "admin"];
const TRUTH_SET = ["pass", "degraded", "red", "unknown"];
const riskClass = (r) => "r-" + (RISK_SET.includes(r) ? r : "read-only");
const stateClass = (s) => (s === "LOCKED" ? "s-locked" : s === "NO-TRAINING" ? "s-no-training" : "s-local");
const truthClass = (t) => {
  const v = String(t || "UNKNOWN").toLowerCase();
  return "t-" + (TRUTH_SET.includes(v) ? v : "unknown");
};

function bodyLineHTML(line) {
  const locked = /LOCKED|locked|denied|gated|forbidden/.test(line) ? " locked" : "";
  const m = line.match(/^([A-Za-z][\w.-]*)=(.*)$/);
  if (m) return `<div class="body-line${locked}"><span class="kv-key">${esc(m[1])}</span>=${esc(m[2])}</div>`;
  return `<div class="body-line${locked}">${esc(line) || "&nbsp;"}</div>`;
}

// The core emits actionable hints like "next: sinabro setup". Extract a runnable
// command from such a line — but ONLY when its first token is a real command
// (guards against turning prose into a button). Returns null otherwise.
function nextHint(line) {
  const m = String(line).match(/next:\s*(.+)$/i);
  if (!m) return null;
  const cmd = m[1].trim().replace(/^sinabro\s+/i, "").replace(/[.;,\s]+$/, "");
  if (!cmd) return null;
  const first = cmd.split(/\s+/)[0];
  const known = TOP_LEVEL.includes(first) || NAMESPACES.some((e) => e[0] === first);
  return known ? cmd : null;
}

/* ── R11 loading/answer UX (D-3 NN/G "less chat, more answer"; D-2 layout-stable) ──
   HONEST BY CONSTRUCTION: the core consult loop is SYNCHRONOUS (spawn_blocking)
   with NO streaming channel — the GUI receives ONE final string. A determinate
   %-bar would be FAKE, so the loading card is INDETERMINATE (an animation + a
   context label + the loop's REAL bound). The answer card SPLITS the core's own
   emitted body (probed from dispatch.rs) into ANSWER (big, first) + a folded
   receipt block — PURE VISUAL grouping, zero command-semantics re-implementation
   (dispatch_line → dispatch::run stays the single truth source). */
/* ── FACELIFT — icon system: one consistent stroke SVG set replaces the mixed
   unicode/emoji glyphs (the last "toy" tell). Static markup declares `data-icon="name"`
   (filled by fillIcons on init); dynamic templates call icon(name) inline. Sized by
   1em (CSS .ic) so each icon scales with its button's font-size. */
const ICONS = {
  folder:   '<path d="M3.5 7.3A1.6 1.6 0 0 1 5.1 5.7h3l1.6 1.9H19a1.6 1.6 0 0 1 1.6 1.6v8A1.6 1.6 0 0 1 19 18.8H5.1A1.6 1.6 0 0 1 3.5 17.2z"/>',
  chevron:  '<path d="m6.5 9.5 5.5 5.5 5.5-5.5"/>',
  chevronR: '<path d="m9.5 6 6 6-6 6"/>',
  help:     '<circle cx="12" cy="12" r="8.6"/><path d="M9.7 9.4a2.4 2.4 0 1 1 3.4 2.2c-.8.4-1.1.9-1.1 1.7"/><path d="M12 16.6h.01"/>',
  settings: '<path d="M4 7h16M4 12h16M4 17h16"/><circle cx="9" cy="7" r="2"/><circle cx="15.5" cy="12" r="2"/><circle cx="8" cy="17" r="2"/>',
  theme:    '<circle cx="12" cy="12" r="8.2"/><path d="M12 3.8a8.2 8.2 0 0 0 0 16.4z" fill="currentColor" stroke="none"/>',
  clock:    '<circle cx="12" cy="12" r="8.4"/><path d="M12 7.6V12l3 1.8"/>',
  shield:   '<path d="M12 3.4 5.6 6v5c0 3.7 2.8 6.5 6.4 7.5 3.6-1 6.4-3.8 6.4-7.5V6z"/><path d="m9.3 11.7 1.9 1.9 3.6-3.8"/>',
  database: '<ellipse cx="12" cy="5.7" rx="6.6" ry="2.7"/><path d="M5.4 5.7v12.6c0 1.5 3 2.7 6.6 2.7s6.6-1.2 6.6-2.7V5.7"/><path d="M5.4 12c0 1.5 3 2.7 6.6 2.7s6.6-1.2 6.6-2.7"/>',
  zap:      '<path d="M13 2.6 4.8 13.4H11l-1 8 8.2-10.8H12z"/>',
  sparkles: '<path d="M12 3.6 13.5 8 18 9.5 13.5 11 12 15.4 10.5 11 6 9.5 10.5 8z"/><path d="m18.5 15.5.8 2.2 2.2.8-2.2.8-.8 2.2-.8-2.2-2.2-.8 2.2-.8z"/>',
  undo:     '<path d="M3.6 11.6a8.4 8.4 0 1 1 2.2 6"/><path d="M3.1 6.6v5.1h5.1"/>',
  list:     '<path d="M8.4 6.6H20M8.4 12H20M8.4 17.4H20"/><path d="M4.4 6.6h.01M4.4 12h.01M4.4 17.4h.01"/>',
  bell:     '<path d="M6.3 9.3a5.7 5.7 0 0 1 11.4 0c0 5.4 2 6.6 2 6.6H4.3s2-1.2 2-6.6"/><path d="M10.2 19.3a2 2 0 0 0 3.6 0"/>',
  edit:     '<path d="M12.5 19.7H20"/><path d="M16.3 4.2a1.9 1.9 0 0 1 2.6 2.6L8.4 17.3l-3.4.9.9-3.4z"/>',
  command:  '<rect x="4.3" y="4.3" width="6.1" height="6.1" rx="1.2"/><rect x="13.6" y="4.3" width="6.1" height="6.1" rx="1.2"/><rect x="4.3" y="13.6" width="6.1" height="6.1" rx="1.2"/><rect x="13.6" y="13.6" width="6.1" height="6.1" rx="1.2"/>',
  refresh:  '<path d="M20.4 11.4a8.4 8.4 0 1 1-2.2-6"/><path d="M20.9 5.2v5.1h-5.1"/>',
  plus:     '<path d="M12 5.6v12.8M5.6 12h12.8"/>',
  arrowUp:  '<path d="M12 18.4V6M6.2 11.8 12 6l5.8 5.8"/>',
  code:     '<path d="m9 8.5-4 3.5 4 3.5"/><path d="m15 8.5 4 3.5-4 3.5"/>',
  panelLeft:  '<rect x="3.4" y="5" width="17.2" height="14" rx="2"/><path d="M9.2 5.2v13.6"/>',
  panelRight: '<rect x="3.4" y="5" width="17.2" height="14" rx="2"/><path d="M14.8 5.2v13.6"/>',
};
function icon(name) {
  const p = ICONS[name]; if (!p) return "";
  return `<svg class="ic" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${p}</svg>`;
}
function fillIcons(root) {
  (root || document).querySelectorAll("[data-icon]:not([data-icon-done])").forEach((el) => {
    el.innerHTML = icon(el.dataset.icon);
    el.setAttribute("data-icon-done", "1");
  });
}

/* brand marks for the connector chips (functional identification of each integration).
   Telegram = its paper-plane; Walrus = a teal wave (decentralized storage); LLM provider
   = an indigo orbit. Filled/colored (not the monochrome stroke set). */
const CONNECTOR_LOGOS = {
  telegram: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="12" fill="#2AABEE"/><path d="M17.6 7.3 15.7 17c-.14.62-.52.77-1.05.48l-2.9-2.13-1.4 1.35c-.15.15-.28.28-.58.28l.2-2.95 5.34-4.83c.23-.2-.05-.32-.36-.12l-6.6 4.15-2.84-.89c-.62-.2-.63-.62.13-.92l11.1-4.28c.51-.19.96.12.79.8z" fill="#fff"/></svg>`,
  walrus: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="12" fill="#0FB5A6"/><path d="M5 13.2c1.25 0 1.25 1.5 2.5 1.5s1.25-1.5 2.5-1.5 1.25 1.5 2.5 1.5 1.25-1.5 2.5-1.5 1.25 1.5 2.5 1.5M5 9.6c1.25 0 1.25 1.5 2.5 1.5s1.25-1.5 2.5-1.5 1.25 1.5 2.5 1.5 1.25-1.5 2.5-1.5 1.25 1.5 2.5 1.5" stroke="#fff" stroke-width="1.5" fill="none" stroke-linecap="round"/></svg>`,
  provider: `<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="12" fill="#5E6AD2"/><circle cx="12" cy="12" r="2.5" fill="#fff"/><path d="M12 5.4a6.6 6.6 0 0 1 5.7 9.9" stroke="#fff" stroke-width="1.6" fill="none" stroke-linecap="round"/></svg>`,
};

function loadingCardHTML(m) {
  const ld = m.loading || { kind: "consult", cmd: "" };
  // S-C/C2: a REAL progressive token feed — the core streams REDACTED deltas through a
  // tauri Channel AS the model generates (never a fake %); Esc truly cancels mid-stream.
  // `m.streaming` is set the instant the stream starts, so the feed node exists from the
  // FIRST frame — subsequent deltas update it IN PLACE (no full re-render ⇒ no flicker).
  const streaming = m.streaming === true || (typeof m.streamText === "string" && m.streamText.length > 0);
  const label = streaming
    ? "streaming…  (Esc to cancel)"
    : ld.kind === "consult"
      ? "consulting the provider…"
      : `running ${esc(ld.cmd || "command")}…`;
  // The bound is shown ONLY for a live consult, where the agent loop's caps
  // actually apply (a plain command has no 5-turn loop — faking one would lie).
  const bound = ld.kind === "consult"
    ? `<div class="loading-bound">bounded · ≤5 turns · 60s · fail-closed budget</div>`
    : "";
  // STABLE id ⇒ runChatStream appends each delta to this one node (textContent), never
  // rebuilding #messages — the 144hz-smooth path.
  const feed = streaming
    ? `<div class="loading-feed answer-line" id="live-stream-feed" data-shown="${(m.streamText || "").length}">${esc(m.streamText || "")}</div>`
    : "";
  return `
    <div class="card loading-card" aria-busy="true">
      <div class="loading-row">
        <span class="loading-spin" aria-hidden="true"></span>
        <span class="loading-label">${label}</span>
      </div>
      ${feed}
      <div class="loading-track" aria-hidden="true"><span class="loading-bar"></span></div>
      ${bound}
    </div>`;
}

// A consult answer card = [lede] + <answer> + a FIXED trailing receipt block
// (loop:/usage:/cache:/cost:/guard:/sha/otel/advisory — the exact dispatch.rs
// emit order). Detect by the receipt block's presence (self-gating: an error /
// key-missing / fan / non-consult card lacks loop:+guard: ⇒ flat render). Split
// positionally at the first `loop: turns=` ⇒ robust to ANY answer content.
function splitConsult(p) {
  const body = p.body || [];
  const start = body.findIndex((l) => /^loop: turns=/.test(l));
  if (start < 0 || !body.some((l) => /^guard: action=/.test(l))) return null;
  const hasLede = /^(LIVE|LOCAL) provider (consult|fan): /.test(body[0] || "");
  return {
    lede: hasLede ? body[0] : "",
    answer: body.slice(hasLede ? 1 : 0, start),
    receipts: body.slice(start),
  };
}

// P2 — Agent Activity Timeline: lift the loop's AUTONOMOUS tool trail OUT of the folded
// receipts into a 1st-class strip, so the agent's tool use is VISIBLE (it ran
// walrus-index → walrus-fetch …), not buried. PURE parse of the core's own `loop:`
// receipt line — zero new command semantics, single-truth-source preserved.
function parseAgentTrail(receipts) {
  const loop = (receipts || []).find((l) => /^loop: turns=/.test(l));
  if (!loop) return null;
  const m = loop.match(/trail=\[([^\]]*)\]/);
  const steps = m && m[1].trim() ? m[1].split(",").map((s) => s.trim()).filter(Boolean) : [];
  if (!steps.length) return null;
  const num = (k) => { const r = loop.match(new RegExp("\\b" + k + "=(\\d+)")); return r ? r[1] : null; };
  return { steps, turns: num("turns"), reads: num("reads") };
}
// E — friendly verbs for the reasoning trace: the real tool name → a readable step.
const TRAIL_VERB = {
  "walrus-index": "recalled the memory index", "walrus-fetch": "fetched a memory from Walrus",
  "memory": "recalled memory", "file": "read a file", "search": "searched the code",
  "codebase": "searched the codebase semantically", "web": "fetched the web",
  "web-fetch": "fetched the web", "web-search": "searched the web",
  "audit": "scanned for security leads", "context": "indexed the project",
  "lsp": "checked diagnostics", "git": "read git", "test": "ran tests", "mcp": "called an MCP tool",
};
// The agent activity = a compact strip (summary) that EXPANDS into a step-by-step trace
// ("how it got here"): friendly labels over the REAL tool trail (no fabricated thinking).
function agentTrailHTML(tr) {
  const parsed = tr.steps.map((s) => {
    const sp = s.indexOf(" ");
    return { raw: s, kind: sp > 0 ? s.slice(0, sp) : s, detail: sp > 0 ? s.slice(sp + 1) : "" };
  });
  const strip = parsed.map((p, i) => `<span class="trail-step" style="--reveal-i:${i}" title="${esc(p.raw)}"><span class="trail-dot" aria-hidden="true"></span>${esc(p.kind)}${p.detail ? `<span class="trail-detail">${esc(p.detail)}</span>` : ""}</span>`).join(`<span class="trail-arrow" aria-hidden="true">→</span>`);
  const plural = (n, w) => (n ? `${n} ${w}${n === "1" ? "" : "s"}` : null);
  const sum = [plural(tr.reads, "read"), plural(tr.turns, "turn")].filter(Boolean).join(" · ");
  const verb = (k) => TRAIL_VERB[k] || ("used " + k);
  const rows = parsed.map((p, i) => `<div class="trace-step"><span class="trace-n mono">${i + 1}</span><span class="trace-verb">${esc(verb(p.kind))}</span>${p.detail ? `<span class="trace-arg mono">${esc(p.detail)}</span>` : ""}</div>`).join("");
  return `<details class="agent-trace">`
    + `<summary class="agent-trail trail-fan" aria-label="agent activity — expand for the step-by-step trace">`
    + `<span class="trail-lead">acted</span>${strip}`
    + (sum ? `<span class="trail-sum">${sum}</span>` : "")
    + `<span class="trace-chev" aria-hidden="true">${icon("chevron")}</span>`
    + `</summary>`
    + `<div class="trace-steps">${rows}<div class="trace-step done"><span class="trace-n" aria-hidden="true">→</span><span class="trace-verb">answered</span></div></div>`
    + `</details>`;
}

// D — two-brain route ribbon: the README thesis on screen. A frontier model REASONS,
// a local model EXECUTES; each consult routes to one — parse the core's own lede
// (LIVE ⇒ frontier · LOCAL ⇒ local) and highlight the brain that produced THIS answer.
function routeRibbonHTML(lede) {
  if (!lede) return "";
  const live = /^LIVE /.test(lede);
  const m = lede.match(/:\s*([^:]+)\s*$/);
  const model = m ? m[1].trim() : "";
  return `<div class="route-ribbon" title="two-brain route — a frontier model reasons, a local model executes">`
    + `<span class="rr-node rr-frontier${live ? " on" : ""}">${icon("sparkles")}frontier</span>`
    + `<span class="rr-arrow" aria-hidden="true">→</span>`
    + `<span class="rr-node rr-local${live ? "" : " on"}">${icon("zap")}local</span>`
    + (model ? `<span class="rr-model mono">${esc(model)}</span>` : "")
    + `</div>`;
}

// The answer is the deliverable (model prose, or a sealed PROPOSE-EDIT render).
// Render it plainly — NO key=value / locked-word tinting (that styling is for
// receipts & status lines, never the model's own text).
function answerLineHTML(line) {
  return `<div class="answer-line">${esc(line) || "&nbsp;"}</div>`;
}

/* ── E13-2 (⑱): inbound Telegram remote-control card ──────────────────────────
   A surfaced OWNER message (the core owner-pinned + redacted it before it reached
   the GUI: a non-owner update never arrives; a secret-shaped one arrives only as a
   "withheld" marker). Option A: the GUI SURFACES the inbound (a card); the reply
   loop is the CLI `daemon serve-chat` (the armed session), so the badge is honest —
   "card only · arm via CLI to reply", never a faked "sent". */
function inboundTelegramCardHTML(p) {
  const tag = p.tgKind === "withheld" ? "WITHHELD"
    : p.tgKind === "approval" ? "APPROVAL REPLY" : "OWNER CHAT";
  return `
    <div class="card card-inbound-tg">
      <div class="card-head">
        <span class="card-env"><b>inbound</b> telegram</span>
        <div class="card-chips">
          <span class="pill pill-risk ${riskClass("read-only")}">from owner</span>
          <span class="pill pill-truth ${truthClass("UNKNOWN")}">${esc(tag)}</span>
          <span class="pill pill-state ${stateClass("LOCKED")}">card only · arm via CLI to reply</span>
        </div>
      </div>
      <div class="card-body"><div class="body-line">${esc(p.text || "")}</div></div>
    </div>`;
}

// The collapsed meta under a chat answer: ONE quiet line — the route (frontier/local ·
// model) + the tool count — that expands into the full route ribbon + the step-by-step
// agent trace + the verification/cost receipts. Nothing is removed (the honest render is
// intact, one click away); it's just no longer shouting around a one-line reply.
function consultMetaHTML(sc) {
  const lede = sc.lede || "";
  const live = /^LIVE /.test(lede);
  const mm = lede.match(/:\s*([^:]+)\s*$/);
  const model = mm ? mm[1].trim() : "";
  const routeTxt = (live ? "frontier" : "local") + (model ? " · " + model : "");
  const tr = parseAgentTrail(sc.receipts);
  const toolTxt = tr ? `${tr.steps.length} tool${tr.steps.length === 1 ? "" : "s"}` : "";
  const bits = [routeTxt, toolTxt].filter(Boolean).join("  ·  ");
  const ribbon = sc.lede ? routeRibbonHTML(sc.lede) : "";
  const trail = tr ? agentTrailHTML(tr) : "";
  const receipts = `<div class="receipts-body">${sc.receipts.map(bodyLineHTML).join("")}</div>`;
  return `<details class="answer-meta">`
    + `<summary class="answer-meta-sum"><span class="am-bits">${esc(bits) || "verification"}</span><span class="am-toggle">details</span></summary>`
    + `<div class="answer-meta-body">${ribbon}${trail}${receipts}</div>`
    + `</details>`;
}

function cardHTML(p) {
  if (p && p.kind === "inbound-telegram") return inboundTelegramCardHTML(p);
  const sc = splitConsult(p);
  // ── chat answer: answer-FIRST and clean (the owner asked for "just the answer").
  // No pills, no route wall, no "ACTED" strip, no hint button — the answer is the card;
  // route/trail/receipts fold into one quiet line underneath. ──
  if (sc) {
    const answer = sc.answer.length
      ? `<div class="card-answer">${sc.answer.map(answerLineHTML).join("")}</div>`
      : `<div class="card-answer"><div class="answer-line answer-empty">(no answer text)</div></div>`;
    return `
    <div class="card card-consult">
      <div class="card-body">${answer}${consultMetaHTML(sc)}</div>
    </div>`;
  }
  // ── command output — CLEAN, like an agent tool result (owner 2026-07-01: "커서/코덱스/
  // 클루드 어디에도 이런 seal/PD-6 없다"). Just the result; the audit chrome (seal · risk ·
  // state · truth) folds into ONE quiet `details` line — available for the security-minded,
  // never a receipt wall. A LOCKED gated preview still routes to the clean Continue flow
  // (intentConfirmHTML, rendered by the message view). ──
  const body = p.body.length
    ? p.body.map(bodyLineHTML).join("")
    : `<div class="body-line${p.error ? " card-error" : ""}">${esc(p.error ? "(no output)" : "ok")}</div>`;
  let hint = "";
  for (const l of p.body) { const h = nextHint(l); if (h) { hint = h; break; } }
  const hintRow = hint
    ? `<div class="card-hint"><button class="suggest" data-card-run="${esc(hint)}"><span class="sg-glyph">›</span>run ${esc(hint)}</button></div>`
    : "";
  const locked = String(p.state || "").toUpperCase() === "LOCKED";
  const metaBits = `${esc((p.command || "").split(/\s+/)[0] || "command")} · ${esc(p.risk || "read-only")}${locked ? " · needs approval" : ""}`;
  const meta = `<details class="answer-meta">`
    + `<summary class="answer-meta-sum"><span class="am-bits">${metaBits}</span><span class="am-toggle">details</span></summary>`
    + `<div class="answer-meta-body mono">seal ${esc(p.envelope || "—")} · ${esc(p.state || "")} · ${esc(p.truth || "")}</div>`
    + `</details>`;
  return `
    <div class="card${p.error ? " card-error" : ""}">
      <div class="card-body${p.error ? " card-error" : ""}">${body}</div>
      ${meta}${hintRow}
    </div>`;
}

/* ── R7: Intent Preview → single approval ─────────────────────────────────────
   Research D-2/D-3: ONE clear approval gate, never scattered Accepts. A
   side-effect command typed WITHOUT its ceremony phrase comes back LOCKED +
   approval=typed-phrase — the core's OWN gated preview (probed 2026-06-11: state=
   LOCKED, risk=admin|network, a `usage: <ns> <verb> <PHRASE> …` line, "denied: no
   live call without the exact phrase"). We read the exact phrase from THAT line
   (the single source of truth — never a 2nd hardcoded phrase list) and offer one
   Approve that re-dispatches the same line with the phrase injected. The core is
   still the sole verifier (phrase + redaction + bounds); the GUI only carries the
   consent. Read-only cards (approval=none) never gate — they already ran. */
function gatedIntent(card) {
  if (!card || card.state !== "LOCKED" || !/typed-phrase/.test(card.approval || "")) return null;
  for (const line of card.body || []) {
    const m = String(line).match(/^usage:\s+(\S+)\s+(\S+)\s+(\S+)/);
    if (m) return { ns: m[1], verb: m[2], phrase: m[3], risk: card.risk || "network" };
  }
  return null;
}

// S2 inline approve (owner screenshot SS1, 2026-06-14): a soft "Confirm" on the SAME turn
// — a Cancel + a Continue, NOT a conversation-breaking modal/new turn. Continue runs the
// action IN PLACE (approveIntent → the answer continues below); Cancel dismisses it without
// running (cancelIntent). The core is still the sole verifier (the phrase + redaction +
// bounds live in the core; the GUI only carries consent). "Nothing has run yet" is honest:
// this is the gated PREVIEW the core returned — no side effect has fired.
function intentConfirmHTML(m, intent) {
  const action = `${intent.ns} ${intent.verb}`;
  const rc = RISK_SET.includes(intent.risk) ? intent.risk : "network";
  return `<div class="intent-confirm r-${esc(rc)}">
      <div class="ic-row">
        <span class="ic-badge">confirm</span>
        <span class="ic-action mono">${esc(action)}</span>
        <span class="pill pill-risk ${riskClass(intent.risk)}">${esc(intent.risk)}</span>
      </div>
      <div class="ic-desc">a live <b>${esc(intent.risk)}</b> action — the core verifies the phrase, redacts &amp; bounds it before anything runs. <b>Nothing has run yet.</b></div>
      <div class="ic-actions">
        <button class="ic-cancel" data-cancel-intent="${esc(m.intentKey)}">Cancel</button>
        <button class="ic-continue" data-approve-intent="${esc(m.intentKey)}">Continue <span class="ic-ret">↵</span></button>
      </div>
    </div>`;
}

/* ── sessions / sidebar ──────────────────────────────────────────────────── */
function currentSession() {
  const proj = state.projects.find((p) => p.id === state.currentProject);
  return proj ? proj.sessions.find((s) => s.id === state.currentSession) || null : null;
}
function newSession(activate = true) {
  const proj = state.projects.find((p) => p.id === state.currentProject) || state.projects[0];
  const s = { id: "s" + ++state.seq, title: "New session", messages: [], time: nowLabel() };
  proj.sessions.unshift(s);
  if (activate) { state.currentSession = s.id; renderView(); }
  renderSidebar(); persist();
  return s;
}
// D#7: keyboard quick-switch — ⌘1..⌘9 jumps to the Nth session of the current project
// (newest first = the sidebar order). Resume (last active session) is already restored on load.
function switchSessionByIndex(i) {
  const proj = state.projects.find((p) => p.id === state.currentProject) || state.projects[0];
  const s = proj && proj.sessions[i];
  if (!s) return;
  state.currentSession = s.id;
  renderView(); renderSidebar(); persist();
}
function ensureSession() {
  let s = currentSession();
  if (!s) { s = newSession(false); state.currentSession = s.id; }
  return s;
}
function renderSidebar() {
  const root = $("#projects");
  if (!root) return;
  const filter = ($("#session-filter")?.value || "").toLowerCase();
  root.innerHTML = state.projects
    .map((proj) => {
      const sessions = proj.sessions.filter((s) => !filter || s.title.toLowerCase().includes(filter));
      const items = sessions.length
        ? sessions
            .map(
              (s) => `
          <div class="session${s.id === state.currentSession ? " active" : ""}" data-session="${s.id}">
            <span class="session-title">${esc(s.title)}</span>
            <span class="session-time">${esc(s.time)}</span>
          </div>`
            )
            .join("")
        : `<div class="session-empty">No sessions yet</div>`;
      return `
        <div class="project">
          <button class="project-head" data-project="${proj.id}">
            <span class="project-ico">${proj.icon}</span>
            <span class="project-name">${esc(proj.name)}</span>
            <span class="project-count">${proj.sessions.length}</span>
          </button>
          ${items}
        </div>`;
    })
    .join("");
  $$(".session", root).forEach((el) =>
    el.addEventListener("click", () => { state.currentSession = el.dataset.session; renderView(); renderSidebar(); persist(); })
  );
}

/* ── composer (clean; power is behind / and ⌘K) ─────────────────────────── */
// TIER-1 (#1): session autonomy preset — Ask-first (per-action, default) · Auto-read (reads
// autonomous, already free) · Bold (arm a BOUNDED, revocable edit+run session). The preset is
// a GUI affordance over the EXISTING core grants (the run IS the owner's arm gesture); custody
// / funds stay 🔒 in EVERY mode (the bold grant cannot touch them — CustodyCapability uninhabited).
const AUTONOMY_MODES = ["Ask-first", "Auto-read", "Bold"];
function currentMode() { try { return localStorage.getItem("sinabro.mode") || "Ask-first"; } catch (_) { return "Ask-first"; } }
function setAutonomyMode(m) {
  try { localStorage.setItem("sinabro.mode", m); } catch (_) {}
  const el = $("#mode-mini"); if (el) el.textContent = m;
  if (m === "Bold") {
    dispatch("daemon bold arm-bold-session-edit-run-bounded-revocable"); // arm the bounded, revocable session
    toast("⚡ Bold — armed a bounded, revocable edit+run session; custody / funds stay 🔒");
  } else if (m === "Auto-read") {
    toast("Auto-read — reads run autonomously (already free); egress / mutate still ask per-action");
  } else {
    toast("Ask-first — every gated action asks per-action (the safe default)");
  }
}
function cycleAutonomyMode() {
  const i = AUTONOMY_MODES.indexOf(currentMode());
  setAutonomyMode(AUTONOMY_MODES[(i + 1) % AUTONOMY_MODES.length]);
}

function composerTemplate() {
  return `
    <div class="composer">
      <div class="composer-box reveal d2">
        <textarea id="composer-input" class="composer-input" rows="1"
          placeholder="Type a command —  /  or  ⌘K  for everything" spellcheck="false"></textarea>
        <div class="composer-toolbar">
          <div class="tool-left">
            <button class="iconbtn" data-act="attach" title="Attach a file (drag one onto the window)">${icon("plus")}</button>
            <button class="accesschip" data-act="access" title="Current access"><span class="led"></span>LOCAL-ONLY</button>
            <button class="accesschip" data-act="mode" title="Autonomy preset — Ask-first (per-action) · Auto-read · Bold (armed, bounded, revocable). Custody/funds 🔒 in every mode."><span class="dot"></span><span id="mode-mini">${esc(currentMode())}</span></button>
          </div>
          <div class="tool-right">
            <button class="modelchip" data-act="model"><span class="dot"></span><span id="model-mini">local · executor</span></button>
            <button id="send-btn" class="sendbtn" data-act="send" title="Run (↵)" disabled>${icon("arrowUp")}</button>
          </div>
        </div>
      </div>
      <div id="ac" class="ac" hidden></div>
    </div>`;
}

function suggestChip(cmd, label) {
  return `<button class="suggest" data-suggest="${esc(cmd)}"><span class="sg-glyph">›</span>${esc(label)}</button>`;
}

// A#13: LLM key presence (null=unknown, true/false=known). Fetched on load (+ after the
// owner sets/clears a key) from the core's secret_status — the VALUE is never read, only
// presence. Drives the empty-screen onboarding nudge.
let keyPresent = null;
async function refreshKeyPresence() {
  if (!hasTauri()) return; // web build: leave unknown (no nag)
  try {
    const st = await invoke("secret_status");
    keyPresent = Array.isArray(st) && !!(st.find((s) => s && s.name === "OPENROUTER_API_KEY") || {}).present;
  } catch (_) { return; }
  // Re-render ONLY the welcome screen (never clobber an active conversation).
  const s = currentSession();
  if (!s || s.messages.length === 0) renderView();
}

function emptyTemplate() {
  // A#13: a KEY-CONDITIONAL onboarding nudge — shown ONLY when we KNOW there is no LLM key
  // (keyPresent===false; null=unknown ⇒ no premature nag). Click → Settings → Secrets.
  const keyNudge = keyPresent === false
    ? `<div class="empty-keynudge reveal d2" style="margin:12px 0;padding:10px 14px;border:1px solid var(--danger,#e0564f);border-radius:8px;display:flex;gap:10px;align-items:center;justify-content:center;flex-wrap:wrap;font-size:13px;">
        <span>No LLM key yet — chat needs <span class="mono">OPENROUTER_API_KEY</span>.</span>
        <button class="suggest" data-action="settings"><span class="sg-glyph">›</span>Set your key</button>
      </div>`
    : "";
  return `
    <div class="empty">
      <div class="empty-inner">
        <div class="empty-head reveal d1">
          <img class="empty-logo" src="sinabro_logo.png" alt="sinabro" />
          <div class="empty-wordmark">sinabro</div>
        </div>
        ${keyNudge}
        ${composerTemplate()}
        <div class="suggests reveal d3">
          ${suggestChip("status", "Status now")}
          ${suggestChip("provider status", "Providers")}
          ${suggestChip("memory status", "Memory")}
          ${suggestChip("audit status", "Audit")}
          <button class="suggest more" data-suggest="__palette__">⌘K  All commands</button>
        </div>
        <div class="connectors reveal d4">
          ${connectorHTML("provider", "P", "LLM provider", "Routing · egress gated", "gated")}
          ${connectorHTML("telegram", "T", "Telegram", "Notify · gated live send", "gated")}
          ${connectorHTML("walrus", "W", "Walrus testnet", "Memory · gated PUT", "testnet")}
        </div>
      </div>
    </div>`;
}

function connectorHTML(id, glyph, title, desc, state) {
  const logo = CONNECTOR_LOGOS[id];
  return `
    <button class="connector" data-connector="${id}">
      <div class="connector-top">
        <span class="connector-ico${logo ? " has-logo" : ""}">${logo || esc(glyph)}</span>
        <span class="connector-state state-gated">${esc(state)}</span>
      </div>
      <div class="connector-title">${esc(title)}</div>
      <div class="connector-desc">${esc(desc)}</div>
    </button>`;
}

function conversationTemplate(session) {
  const msgs = session.messages
    .map((m) => {
      if (m.role === "user")
        return `<div class="msg-wrap"><div class="cmd-line"><span class="cmd-glyph">›</span><span class="cmd-text">${esc(m.text)}</span></div></div>`;
      if (m.pending) return `<div class="msg-wrap">${loadingCardHTML(m)}</div>`;
      // E13-2: a surfaced inbound owner message renders as a card only (no rerun /
      // copy — it was received, not run); just the card + its arrival time.
      if (m.card && m.card.kind === "inbound-telegram")
        return `<div class="msg-wrap">${cardHTML(m.card)}<div class="msg-actions"><span class="msg-time">${esc(m.time || "")}</span></div></div>`;
      const intent = gatedIntent(m.card);
      const live = intent && m.intentKey != null && intentSrc.has(m.intentKey);
      // SS1: the gated card stays put; Continue runs it in place (no new turn). While it
      // runs, an inline marker; a declined intent leaves an honest "nothing ran" note.
      const confirmBar = live ? intentConfirmHTML(m, intent) : "";
      const runningBar = m.approving
        ? `<div class="intent-running"><span class="loading-spin" aria-hidden="true"></span><span>running… the conversation stays put</span></div>`
        : "";
      const cancelledBar = m.cancelled
        ? `<div class="intent-cancelled">declined — nothing ran. Re-type it, or ask a follow-up below.</div>`
        : "";
      return `
        <div class="msg-wrap">
          ${cardHTML(m.card)}
          ${confirmBar}${runningBar}${cancelledBar}
          <div class="msg-actions">
            <button class="actbtn" data-act="copy" title="Copy">⧉</button>
            <button class="actbtn" data-act="rerun" data-cmd="${esc(m.card.command || "")}" title="Re-run">↻</button>
            <span class="msg-time">${esc(m.time || "")}</span>
          </div>
        </div>`;
    })
    .join("");
  return `
    <div class="conversation">
      <div class="messages" id="messages">${msgs}</div>
      <div class="composer-dock"><div class="msg-wrap">${composerTemplate()}</div></div>
    </div>`;
}

function renderView() {
  const view = $("#view");
  const s = currentSession();
  const title = $("#conv-title");
  const bodyEl = $("#body");
  if (!s || s.messages.length === 0) {
    if (title) title.textContent = s ? s.title : "sinabro";
    if (bodyEl) bodyEl.classList.add("hero-mode");    // full-window welcome hero
    view.innerHTML = emptyTemplate();
  } else {
    if (bodyEl) bodyEl.classList.remove("hero-mode");  // back to the 3-pane IDE
    if (title) title.textContent = s.title;
    view.innerHTML = conversationTemplate(s);
    const m = $("#messages");
    if (m) {
      // R11 (D-2 / NN/G): never auto-yank to the bottom. Pin the NEWEST user
      // turn to the top so the answer fills in BELOW it (answer-first reading).
      // scrollTop clamps on a short conversation ⇒ layout-stable, no jump.
      const cmds = m.querySelectorAll(".cmd-line");
      const last = cmds.length ? cmds[cmds.length - 1].closest(".msg-wrap") : null;
      if (last) {
        const top = last.getBoundingClientRect().top - m.getBoundingClientRect().top + m.scrollTop;
        m.scrollTop = Math.max(0, top - 8);
      } else {
        m.scrollTop = 0;
      }
    }
  }
  bindComposer();
}

/* ── composer behaviour + autocomplete ───────────────────────────────────── */
let ac = { open: false, items: [], active: -1, mode: "cmd", atSrc: null };
// P5: @-mention fuzzy file search over the indexed project tree (tree.files). A simple,
// deterministic scorer (basename substring > path substring > subsequence; shorter wins) —
// no fuzzy lib, raw-byte discipline. Returns up to 8 {name=relpath} items.
function isSubsequence(q, s) { let i = 0; for (const c of s) { if (c === q[i]) i += 1; if (i === q.length) return true; } return q.length === 0; }
function fuzzyFiles(query) {
  const files = tree.files || [];
  if (!files.length) return [];
  const q = String(query).toLowerCase();
  if (!q) return files.slice(0, 8).map((p) => ({ name: p }));
  const scored = [];
  for (const p of files) {
    const lp = p.toLowerCase();
    const base = lp.split("/").pop();
    const bi = base.indexOf(q), pi = lp.indexOf(q);
    let score = -1;
    if (bi >= 0) score = 1000 - bi - p.length * 0.1;        // basename hit = best
    else if (pi >= 0) score = 500 - pi - p.length * 0.1;    // path hit
    else if (isSubsequence(q, lp)) score = 100 - p.length * 0.1; // loose subsequence
    if (score > -1) scored.push({ p, score });
  }
  scored.sort((a, b) => b.score - a.score);
  return scored.slice(0, 8).map((s) => ({ name: s.p }));
}
// ── B⑩ @-unify: capability-typed @-source router ──────────────────────────────
// Each @-source resolves to an ALREADY-LIVE READ capability — NO new core, NO new
// IPC, NO new dispatch verb (namespace COUNT 35 kept). Two resolve kinds (owner-locked
// T1 = "C hybrid"): "token" = insert a mention token, the agent reads it on send (the
// legacy @file path — the GUI never touches content); "fetch" = inline-resolve NOW via
// the EXISTING `runLine`/dispatch_line bridge over a live `context …`/`audit …`/`memory …`
// verb and append the core-REDACTED `card.body` as a quoted context block (the SAME
// pure-GUI pattern as the ⌘⇧F find-in-files panel). Every byte is redacted by the core
// before it reaches the GUI (secret-zero preserved); custody is never reachable. A
// feature-gated source (web/memory) on a build without it honest-degrades via the core.
const AT_SOURCES = [
  { key: "file",   tier: "READ",  kind: "token", arg: "path" },
  { key: "git",    tier: "READ",  kind: "fetch", arg: "enum", enumv: ["status", "diff", "log", "show", "blame"], verb: (a) => `context git ${a}` },
  { key: "search", tier: "READ",  kind: "fetch", arg: "text", verb: (a) => `context search ${a}` },
  { key: "symbol", tier: "READ",  kind: "fetch", arg: "path", verb: (a) => `context lsp-diagnostics ${a}` },
  { key: "index",  tier: "READ",  kind: "fetch", arg: "pathopt", verb: (a) => (a ? `context index ${a}` : "context index") },
  { key: "audit",  tier: "READ",  kind: "fetch", arg: "path", verb: (a) => `audit detect ${a}` },
  { key: "web",    tier: "READ*", kind: "fetch", arg: "text", verb: (a) => (/^https?:\/\//i.test(a) ? `context web-fetch ${a}` : `context web-search ${a}`) },
  { key: "memory", tier: "READ*", kind: "fetch", arg: "idopt", verb: (a) => (a ? `memory walrus-fetch ${a}` : "memory walrus-index") },
];
function atSourceByKey(k) { return AT_SOURCES.find((s) => s.key === String(k).toLowerCase()); }
function atFileItems(query) { return fuzzyFiles(query).map((it) => ({ kind: "file", name: it.name.split("/").pop(), hint: it.name, path: it.name })); }
// Render the current ac.items into the overlay (shared by every mode; `ta` is threaded so a
// mouse pick routes back through acceptAC with the right textarea).
function renderAC(ta, acEl) {
  if (!acEl) return;
  acEl.hidden = false;
  acEl.innerHTML = ac.items
    .map((it, i) => `
      <div class="ac-item${i === ac.active ? " active" : ""}" data-i="${i}">
        <span class="ac-kind">${esc(it.kind)}</span><span class="ac-name">${esc(it.name)}</span><span class="ac-hint">${esc(it.hint || "")}</span>
      </div>`)
    .join("");
  $$(".ac-item", acEl).forEach((el) =>
    el.addEventListener("mousedown", (e) => { e.preventDefault(); acceptAC(ta, acEl, parseInt(el.dataset.i, 10)); })
  );
}
// The P5 file-fuzzy overlay (VERBATIM) — `@<query>` lists indexed project files; a pick inserts the
// relpath as a mention TOKEN (the agent reads it on send via its lane-A-walled file-read tool; the
// GUI never reads bytes). Shared by a bare `@foo` and the `@file:` source — zero P5 regression.
function renderFileFuzzy(ta, acEl, query) {
  const items = fuzzyFiles(query);
  if (!items.length) return closeAC(acEl);
  ac.open = true; ac.mode = "file"; ac.items = items; ac.active = 0; acEl.hidden = false;
  acEl.innerHTML = items
    .map((it, i) => `
      <div class="ac-item${i === 0 ? " active" : ""}" data-i="${i}">
        <span class="ac-kind">file</span><span class="ac-name">${esc(it.name.split("/").pop())}</span><span class="ac-hint">${esc(it.name)}</span>
      </div>`)
    .join("");
  $$(".ac-item", acEl).forEach((el) =>
    el.addEventListener("mousedown", (e) => { e.preventDefault(); acceptAC(ta, acEl, parseInt(el.dataset.i, 10)); })
  );
}
// `@…` routing. `@src:arg` for a known FETCH source → its arg stage; `@file:arg` (the TOKEN source)
// → file fuzzy; a bare `@` → the capability-typed source MENU; `@<query>` → file fuzzy (P5, verbatim).
function updateAtMention(ta, acEl, raw) {
  const colon = raw.indexOf(":");
  if (colon >= 0) {
    const src = atSourceByKey(raw.slice(0, colon));
    if (src && src.kind === "fetch") return renderAtArg(ta, acEl, src, raw.slice(colon + 1));
    if (src && src.kind === "token") return renderFileFuzzy(ta, acEl, raw.slice(colon + 1));
  }
  if (raw === "") {
    ac.open = true; ac.mode = "atmenu"; ac.active = 0;
    ac.items = AT_SOURCES.map((s) => ({ kind: "@src", name: s.key, hint: s.tier, src: s.key }));
    return renderAC(ta, acEl);
  }
  return renderFileFuzzy(ta, acEl, raw);
}
// The arg stage for a chosen source. `path`/`pathopt` → file fuzzy candidates; `enum` → the
// fixed candidate list (git subcommands); `text`/`idopt`/empty → a single "↵ fetch" row. Each
// item's `run` is the EXACT live wire; `label` is the human tag for the quoted block head.
function renderAtArg(ta, acEl, src, arg) {
  let items = [];
  if (src.arg === "enum") {
    items = (src.enumv || []).filter((s) => s.startsWith(arg.toLowerCase())).map((s) => ({ kind: "@" + src.key, name: s, hint: src.tier, run: src.verb(s), label: s }));
  } else if (src.arg === "path" || (src.arg === "pathopt" && arg)) {
    items = atFileItems(arg).map((it) => ({ kind: "@" + src.key, name: it.name, hint: it.hint, run: src.verb(it.path), label: it.path }));
  }
  if (!items.length) {
    const shown = arg || (src.arg === "pathopt" ? "(whole project)" : src.arg === "idopt" ? "(main index)" : "(type, then ↵)");
    items = [{ kind: "@" + src.key, name: shown, hint: src.tier + " · ↵ fetch", run: src.verb(arg), label: arg }];
  }
  ac.open = true; ac.mode = "atarg"; ac.atSrc = src; ac.items = items; ac.active = 0;
  renderAC(ta, acEl);
}
// Inline-resolve a fetch source NOW: strip the @token, run the live verb through the core, and
// append the REDACTED card.body as a quoted context block the agent will see on send. Pure GUI
// over the existing dispatch_line bridge (ZERO new core / IPC). Errors render as an honest line
// (runLine returns a RED card, never throws).
async function atInlineResolve(ta, acEl, src, verb, label) {
  closeAC(acEl);
  const upto = ta.value.slice(0, ta.selectionStart);
  const rest = ta.value.slice(ta.selectionStart);
  const stripped = upto.replace(/@\S*$/, "").replace(/\s+$/, "");
  const card = await runLine(verb, verb);
  const head = "@" + src.key + (label && !label.startsWith("(") ? " " + label : "");
  const block = atQuoteBlock(head, card.body || []);
  ta.value = (stripped ? stripped + "\n" : "") + block + (rest ? "\n" + rest : "");
  ta.focus();
  const caret = ta.value.length - (rest ? rest.length + 1 : 0);
  try { ta.setSelectionRange(caret, caret); } catch (_) {}
  ta.dispatchEvent(new Event("input"));
}
// A bounded, PLAIN-TEXT quoted block for the composer (the body is ALREADY core-redacted).
function atQuoteBlock(head, lines) {
  const CAP = 40;
  const shown = lines.slice(0, CAP);
  const more = lines.length > CAP ? `\n> … (${lines.length - CAP} more line(s); the agent can re-run the tool for the rest)` : "";
  return `> [${head}]\n` + (shown.length ? shown.map((l) => "> " + l).join("\n") : "> (no result)") + more;
}
function bindComposer() {
  const ta = $("#composer-input");
  if (!ta) return;
  const send = $("#send-btn");
  const acEl = $("#ac");
  const autosize = () => { ta.style.height = "auto"; ta.style.height = Math.min(ta.scrollHeight, 220) + "px"; };
  const refreshSend = () => { if (send) send.disabled = ta.value.trim() === ""; };

  ta.addEventListener("input", () => {
    if (ta.value === "/") { ta.value = ""; refreshSend(); openOverlay("palette"); return; } // "/" = all features
    if (histSuppress) { autosize(); refreshSend(); return; } // S-A: a history step — keep nav alive, no AC pop
    resetHistoryNav(); // S-A: a real keystroke exits ↑/↓ history navigation
    autosize(); refreshSend(); updateAC(ta, acEl);
  });
  ta.addEventListener("keydown", (e) => onComposerKey(e, ta, acEl));
  ta.focus(); autosize(); refreshSend();

  $$("[data-act]", ta.closest(".composer")).forEach((btn) =>
    btn.addEventListener("click", () => onComposerAct(btn.dataset.act, ta))
  );
}
function onComposerAct(act, ta) {
  if (act === "send") return dispatch(ta.value);
  if (act === "attach") return pickFolder();
  if (act === "palette") return openOverlay("palette");
  if (act === "model") return openPanel("model");
  if (act === "mode") return cycleAutonomyMode();
  if (act === "access") return toast("Access = LOCAL-ONLY. egress · funds are gated. read-only=none · local/net=confirm · sign/admin=typed · chain=multisig. Risky commands are flagged on the card.");
}

/* ── file-picker: the "+" button opens a NATIVE folder dialog (P4-3 ②) ────────
   The owner clicks "+" and chooses a folder in the OS dialog (a gesture the
   model cannot script). The backend `pick_folder` command opens it on a worker
   thread (no UI freeze), registers the chosen folder as a read root (R-F1 — the
   same owner-explicit grant as a drag), and returns the PATH. The composer
   pre-fills `context index <path>` so ↵ shows the bounded, denylist-pruned tree
   (multi-repo loop closed). No file BYTES ever cross — only the path; the gated
   core re-walls every later access. Threat model: FILE_CONTEXT §P4-3. */
async function pickFolder() {
  if (!window.__TAURI__ || !window.__TAURI__.core) {
    return toast("File picker needs the desktop app (dragging a file works in any build).");
  }
  try {
    const path = await window.__TAURI__.core.invoke("pick_folder");
    if (!path) return; // owner cancelled
    const ta = document.querySelector("#composer-input");
    if (ta) {
      const quoted = /\s/.test(path) ? `"${path}"` : path;
      ta.value = `context index ${quoted}`;
      ta.dispatchEvent(new Event("input", { bubbles: true }));
      ta.focus();
    }
    toast("📁 folder added as a read root — press ↵ to index it, or ask about it.");
  } catch (e) {
    toast("folder pick failed: " + (e && e.message ? e.message : e));
  }
}

/* ── file attach: Tauri native drag-drop → path into the composer ─────────────
   The OWNER drags a local file onto the window; Tauri's native drag-drop event
   gives the absolute PATH (unlike a WebView HTML5 drop, which hides it). We
   insert the path text into the composer — the core decides everything else
   (the agent's read-only `file read` tool gates allowlist + denylist + size +
   redaction; the path is just text until the owner sends a question with it).
   No file BYTES are read here — the GUI never reads files; only the gated core
   does, on send. */
async function insertPaths(paths) {
  const ta = document.querySelector("#composer-input");
  if (!ta || !paths || !paths.length) return;
  // Drag = capability grant: register each file's PARENT DIR as a read root so
  // the gated core may read it (denylist + redaction + size still apply). The
  // GUI sends only PATHS — never file bytes; the core reads, on send.
  if (window.__TAURI__ && window.__TAURI__.core) {
    const dirs = [...new Set(paths.map((p) => p.replace(/[\\/][^\\/]*$/, "")).filter(Boolean))];
    try { await window.__TAURI__.core.invoke("register_file_roots", { dirs }); } catch (_) {}
  }
  const joined = paths.map((p) => (/\s/.test(p) ? `"${p}"` : p)).join(" ");
  const base = ta.value.trim();
  ta.value = base ? `${base} ${joined}` : joined;
  ta.dispatchEvent(new Event("input", { bubbles: true }));
  ta.focus();
  toast("📎 " + paths.length + " file(s) attached — ask a question about them, then send (↵).");
}
function setDropActive(on) {
  const box = document.querySelector(".composer-box");
  if (box) box.classList.toggle("drop-active", !!on);
}
async function initFileDrop() {
  // Tauri 2.x emits these native window events when files are dragged in.
  if (typeof window === "undefined" || !window.__TAURI__ || !window.__TAURI__.event) return;
  const { listen } = window.__TAURI__.event;
  try {
    await listen("tauri://drag-enter", () => setDropActive(true));
    await listen("tauri://drag-over", () => setDropActive(true));
    await listen("tauri://drag-leave", () => setDropActive(false));
    await listen("tauri://drag-drop", (e) => {
      setDropActive(false);
      const paths = (e && e.payload && e.payload.paths) || [];
      insertPaths(paths);
    });
  } catch (_) { /* event API absent in this build — drag-drop simply inactive */ }
}
function buildCompletions(token) {
  const t = token.toLowerCase();
  const items = [];
  for (const c of TOP_LEVEL) if (c.startsWith(t)) items.push({ kind: "command", name: c, hint: "" });
  for (const [n, d] of NAMESPACES) if (n.startsWith(t)) items.push({ kind: "namespace", name: n, hint: d });
  return items.slice(0, 7);
}
function updateAC(ta, acEl) {
  const upto = ta.value.slice(0, ta.selectionStart);
  // P5 + B⑩ @-unify: an `@` that starts a token routes to the capability-typed source
  // picker (`updateAtMention`); a bare `@foo` still finds files (zero P5 regression).
  const at = upto.match(/(?:^|\s)@(\S*)$/);
  if (at) return updateAtMention(ta, acEl, at[1]);
  if (/\s/.test(upto) || upto.startsWith("/") || upto.trim() === "") return closeAC(acEl);
  const items = buildCompletions(upto.trim());
  if (!items.length) return closeAC(acEl);
  ac.open = true; ac.mode = "cmd"; ac.items = items; ac.active = 0;
  renderAC(ta, acEl);
}
function closeAC(acEl) { ac.open = false; ac.items = []; ac.active = -1; ac.atSrc = null; if (acEl) { acEl.hidden = true; acEl.innerHTML = ""; } }
function moveAC(acEl, dir) {
  if (!ac.open) return;
  ac.active = (ac.active + dir + ac.items.length) % ac.items.length;
  $$(".ac-item", acEl).forEach((el, i) => el.classList.toggle("active", i === ac.active));
}
function acceptAC(ta, acEl, idx) {
  const it = ac.items[idx >= 0 ? idx : ac.active];
  if (!it) return;
  if (ac.mode === "atmenu") {
    // a SOURCE picked → drop "@src:" so the next keystroke enters its arg/fuzzy stage.
    const upto = ta.value.slice(0, ta.selectionStart);
    const rest = ta.value.slice(ta.selectionStart);
    const newUpto = upto.replace(/@\S*$/, "@" + it.src + ":");
    ta.value = newUpto + rest;
    ta.focus();
    try { ta.setSelectionRange(newUpto.length, newUpto.length); } catch (_) {}
    ta.dispatchEvent(new Event("input"));   // re-evaluates the line → renderAtArg / renderFileFuzzy
    return;
  }
  if (ac.mode === "atarg") return atInlineResolve(ta, acEl, ac.atSrc, it.run, it.label != null ? it.label : it.name);
  if (ac.mode === "file") {
    // P5 (verbatim): replace the trailing `@<query>` with the picked file's relpath (the agent reads
    // it via its lane-A-walled file-read tool; the GUI never reads bytes). Keeps the rest + caret.
    const upto = ta.value.slice(0, ta.selectionStart);
    const rest = ta.value.slice(ta.selectionStart);
    const newUpto = upto.replace(/@\S*$/, it.name + " ");
    ta.value = newUpto + rest;
    closeAC(acEl); ta.focus();
    try { ta.setSelectionRange(newUpto.length, newUpto.length); } catch (_) {}
    ta.dispatchEvent(new Event("input"));
    return;
  }
  ta.value = it.kind === "namespace" ? it.name + " status" : it.name + " ";
  closeAC(acEl); ta.focus(); ta.dispatchEvent(new Event("input"));
}
function onComposerKey(e, ta, acEl) {
  if (ac.open) {
    if (e.key === "ArrowDown") { e.preventDefault(); return moveAC(acEl, 1); }
    if (e.key === "ArrowUp") { e.preventDefault(); return moveAC(acEl, -1); }
    if (e.key === "Tab") { e.preventDefault(); return acceptAC(ta, acEl, ac.active); }
    if (e.key === "Escape") { e.preventDefault(); return closeAC(acEl); }
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); return acceptAC(ta, acEl, ac.active); }
  }
  // S-A: ↑/↓ on an EMPTY composer (autocomplete closed) walks recent input history.
  if (!ac.open && (e.key === "ArrowUp" || e.key === "ArrowDown")) {
    if (walkHistory(ta, e.key === "ArrowUp" ? -1 : 1)) { e.preventDefault(); return; }
  }
  if (e.key === "Enter" && !e.shiftKey) {
    e.preventDefault();
    // S-A: an empty composer + a pending gated Confirm ⇒ Enter = Continue (the ↵ the card shows).
    if (ta.value.trim() === "") { const k = latestLiveIntentKey(); if (k != null) { approveIntent(k); return; } }
    dispatch(ta.value);
  }
}

/* ── dispatch ────────────────────────────────────────────────────────────── */
// Live-consult arm state — IN-MEMORY ONLY, deliberately outside `state` so it
// can never land in sessions.json. The GUI never verifies the phrase (the core
// is the sole verifier — no second truth source); arming just auto-prepends
// what the user typed to each chat line. Disarmed chat still routes to the
// core and renders the honest gated preview (which teaches the exact phrase).
// The public confirmation phrase the GUI auto-injects for chat-as-consult. It is
// NOT a secret (zero entropy, a fixed confirmation gesture); the core still
// verifies it on every call (that gate protects the terminal + automation), so
// injecting it here just removes a redundant manual "Arm" step in the GUI.
const CONSULT_PHRASE = "consult-frontier-provider-live";

// The egress env values the Settings panel can set (memory-only, never
// persisted). Mirrors the backend ALLOWED_SECRET_ENVS allowlist. The 3rd tuple
// element marks a true secret (password input) vs a plain value (text input).
// SOT: OpenRouter, OpenAI-compatible (MNEMOS_ATOM_PLAN.md:310/1024). Threat
// model: ops/evidence/stage_g/gui_desktop/SECRET_INPUT_THREAT_MODEL.md.
const SECRET_DEFS = [
  ["OPENROUTER_API_KEY", "OpenRouter API key (sk-or-v1-...)", true],
  ["OPENROUTER_MODEL", "model id (optional, default deepseek/deepseek-chat)", false],
  ["TELEGRAM_BOT_TOKEN", "Telegram bot token (123456789:AA...)", true],
  ["TELEGRAM_CHAT_ID", "Telegram chat id (numeric)", false],
  ["WALRUS_PUBLISHER_TOKEN", "Walrus self-host publisher bearer (sent as Authorization: Bearer; NEVER a Sui key)", true],
];

// A line is a COMMAND when its first token is a real top-level command or
// namespace (the same closed vocabulary the palette uses); anything else is
// CHAT and routes through the gated `provider consult` verb. Known limitation:
// prose that STARTS with a namespace word (e.g. "provider 가 뭐야") is treated
// as a command and renders an unknown-verb card.
function isCommandLine(line) {
  const first = line.split(/\s+/)[0].toLowerCase();
  return TOP_LEVEL.includes(first) || NAMESPACES.some((e) => e[0] === first);
}

// The raw owner line behind an Intent Preview is kept IN MEMORY ONLY, keyed by a
// transient id; it is NEVER persisted (it may hold the message/argv the owner
// typed, which can be secret-shaped — secret-zero at rest). The persisted message
// carries only the numeric key + the core's already-redacted card. After a reload
// the map is empty ⇒ no one-click approve (honest: re-type the command); the card
// still persists, so nothing is lost, only the frictionless re-fire.
const intentSrc = new Map();
let intentSeq = 0;

// Run ONE wire line through the core and return a parsed card (no message mutation).
// The SINGLE place the GUI talks to dispatch_line for a chat / consult / approve — the
// core stays the sole verifier (phrase + redaction + bounds); the GUI re-implements no
// command semantics. An error becomes an honest RED card (never a crash, never a silent drop).
async function runLine(wire, displayFallback) {
  try {
    const raw = await invoke("dispatch_line", { line: wire });
    const card = parseResponse(raw);
    if (!card.command) card.command = displayFallback;
    return card;
  } catch (err) {
    return { command: displayFallback, envelope: "", risk: "read-only", approval: "none", state: "LOCAL-ONLY", truth: "RED", body: [String(err && err.message ? err.message : err)], error: true };
  }
}

// S-C/C2: a STREAMING chat consult. The core (`consult_stream`) pushes each REDACTED delta
// through a tauri Channel AS the model generates; we append it to the pending card's live
// feed and re-render. Returns the final card (the core's full rendered receipt — the truth
// source, NOT the assembled deltas). Honest-degrade: no Tauri / no Channel ⇒ the
// non-streaming runLine path (e.g. the web build), so chat still works everywhere.
async function runChatStream(wire, displayFallback, pending) {
  const Chan = hasTauri() && window.__TAURI__.core.Channel;
  if (!Chan) return runLine(wire, displayFallback);
  try {
    // SMOOTH STREAMING (144hz / macOS feel): render the loading card ONCE so the
    // #live-stream-feed node exists, then append each delta to THAT node's textContent —
    // never re-rendering #messages (the old per-delta renderView() caused the flicker +
    // scroll-jump). Writes are coalesced to ONE per animation frame (rAF), so a burst of
    // tokens paints once per frame, not once per token.
    if (pending) { pending.streaming = true; pending.streamText = ""; renderView(); }
    const ch = new Chan();
    let raf = 0;
    ch.onmessage = (delta) => {
      if (!pending) return;
      pending.streamText = (pending.streamText || "") + String(delta);
      if (raf) return; // a frame is already scheduled — this delta rides it (coalesced)
      raf = requestAnimationFrame(() => {
        raf = 0;
        const el = document.getElementById("live-stream-feed");
        if (!el) { renderView(); return; } // node gone (view switched) — one fallback render
        const full = pending.streamText;
        const shown = el.dataset.shown ? +el.dataset.shown : 0;
        if (full.length > shown) {
          // G — append ONLY this frame's NEW text as a fade-in span (compositor opacity,
          // 144hz-smooth); never re-render the whole feed ⇒ no per-token layout thrash.
          const span = document.createElement("span");
          span.className = "sc";
          span.textContent = full.slice(shown);
          el.appendChild(span);
          el.dataset.shown = String(full.length);
        } else if (full.length < shown) {
          el.textContent = full; el.dataset.shown = String(full.length); // redaction shrank it — resync
        }
      });
    };
    const raw = await invoke("consult_stream_line", { line: wire, onDelta: ch });
    const card = parseResponse(raw);
    if (!card.command) card.command = displayFallback;
    return card;
  } catch (err) {
    return { command: displayFallback, envelope: "", risk: "read-only", approval: "none", state: "LOCAL-ONLY", truth: "RED", body: [String(err && err.message ? err.message : err)], error: true };
  }
}

/* ── TIER-4 one-key REWIND (the Codex-gap differentiator) ──────────────────────────────
   Undo the LAST applied file-edit AND step the conversation back. The CODE rewind REUSES
   the LIVE core verb `tool rewind` through the SAME dispatch_line bridge (the GUI run IS the
   owner approval — phrase auto-injected, like orchestrate/adapter-connect; the CORE is the
   sole validator: confined + IV-W3 staleness-locked + atomic owner-save, the engine in
   revert_blob.rs). The CHAT rewind is a pure GUI-local transcript trim (the chat is a local
   JSON array the core never parses). custody/funds untouched (rewind is local-file-only). */
async function rewindLastEdit() {
  const s = currentSession();
  if (!s) return;
  const card = await runLine("tool rewind rewind-last-owner-live", "tool rewind");
  const ok = String(card.truth || "").toUpperCase() === "GREEN"
    || (card.body || []).some((l) => String(l).includes("rewound:"));
  if (ok) {
    trimLastExchange(s); // step the conversation back one completed exchange (GUI-local)
    toast("↶ rewound the last applied edit + stepped the conversation back");
  } else {
    const why = (card.body && card.body[card.body.length - 1]) || "nothing to undo";
    toast("rewind: " + why);
  }
  // Surface the core's receipt card in the transcript (the truth source — never a fake).
  s.messages.push({ role: "system", card, time: nowLabel() });
  renderView(); renderSidebar(); persist();
}

// ── S-B multi-level rewind: a history panel over the LIVE `tool rewind list` core verb
// (read-only metadata). Each row's "undo" runs `tool rewind <phrase> to <id>` through the
// SAME runLine bridge — the CORE stays the sole validator (confined + IV-W3 staleness-locked
// + atomic owner-save, the revert_blob engine). ⌘⇧Z (rewindLastEdit) stays pop-most-recent;
// this panel browses + targets a SPECIFIC point. custody/funds untouched (local-file-only). ──
let rhOpen = false;
function ensureRewindHistory() {
  let p = document.getElementById("rewind-history");
  if (p) return p;
  p = document.createElement("div");
  p.id = "rewind-history";
  p.setAttribute("style", "position:fixed;right:20px;top:64px;width:min(560px,46vw);max-height:70vh;display:none;flex-direction:column;z-index:9998;background:var(--panel,#1b1d23);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.45);overflow:hidden;");
  p.innerHTML = '<div style="display:flex;gap:8px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--border,#3a3d44);">'
    + '<span style="font-size:12px;opacity:.7;white-space:nowrap;flex:1;">rewind history</span>'
    + '<button data-rh-close title="Close (esc)" style="background:none;border:none;color:var(--fg,#e6e6e6);opacity:.6;cursor:pointer;font-size:14px;">✕</button>'
    + '</div>'
    + '<div id="rh-results" style="overflow:auto;padding:6px 8px;font-size:12px;"></div>';
  document.body.appendChild(p);
  p.addEventListener("click", (e) => {
    if (e.target.closest("[data-rh-close]")) { closeRewindHistory(); return; }
    const undo = e.target.closest("[data-rh-id]");
    if (undo) rewindToId(undo.dataset.rhId);
  });
  return p;
}
async function openRewindHistory() {
  const p = ensureRewindHistory();
  p.style.display = "flex";
  rhOpen = true;
  await refreshRewindHistory();
}
function closeRewindHistory() {
  if (!rhOpen) return false;
  const p = document.getElementById("rewind-history");
  if (p) p.style.display = "none";
  rhOpen = false;
  return true;
}
async function refreshRewindHistory() {
  const p = document.getElementById("rewind-history");
  if (!p) return;
  const out = p.querySelector("#rh-results");
  if (out) out.innerHTML = `<div style="opacity:.6;padding:4px;">loading…</div>`;
  const card = await runLine("tool rewind list", "tool rewind list"); // the LIVE core verb (read-only)
  renderRewindHistory(out, card.body || []);
}
function renderRewindHistory(out, lines) {
  if (!out) return;
  const rows = [];
  for (const l of lines) {
    // parse the core's `[id] path · NB · was sha` metadata rows (single truth source)
    const m = String(l).match(/^\s*\[(\d+)\]\s+(.+?)\s+·\s+(\d+)B\s+·\s+was\s+([0-9a-f]+)/);
    if (m) {
      const name = m[2].split(/[\\/]/).pop();
      rows.push(`<div class="rh-row" style="display:flex;gap:8px;align-items:center;padding:4px 6px;border-radius:4px;"><span class="mono" style="opacity:.55;">[${esc(m[1])}]</span><span class="mono" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="${esc(m[2])}">${esc(name)} <span style="opacity:.5;">· ${esc(m[3])}B</span></span><button data-rh-id="${esc(m[1])}" title="Undo this committed edit (staleness-locked)" style="background:var(--accent,#3b82f6);color:#fff;border:none;border-radius:5px;padding:3px 9px;font-size:11px;cursor:pointer;">undo</button></div>`);
    } else if (/^rewind history:|^no revert/.test(String(l).trim())) {
      rows.push(`<div style="opacity:.7;padding:3px 4px;font-size:11px;">${esc(l)}</div>`);
    }
  }
  out.innerHTML = rows.length ? rows.join("") : `<div style="opacity:.6;padding:4px;">no revert points — apply an edit first</div>`;
}
// Undo a SPECIFIC revert point by id (reuses the live core verb + the SAME honest
// receipt / verdict-gated chat trim as rewindLastEdit). The core consumes the point on success.
async function rewindToId(id) {
  const s = currentSession();
  const card = await runLine("tool rewind rewind-last-owner-live to " + id, "tool rewind to " + id);
  const ok = String(card.truth || "").toUpperCase() === "GREEN"
    || (card.body || []).some((l) => String(l).includes("rewound:"));
  if (ok) {
    if (s) trimLastExchange(s); // step the conversation back (GUI-local, gated on the core verdict)
    toast("↶ rewound to point [" + id + "] + stepped the conversation back");
  } else {
    toast("rewind: " + ((card.body && card.body[card.body.length - 1]) || "could not undo"));
  }
  if (s) s.messages.push({ role: "system", card, time: nowLabel() }); // surface the core receipt (truth source)
  renderView(); renderSidebar(); persist();
  if (rhOpen) refreshRewindHistory(); // the point was consumed — refresh the list
}
// Drop the trailing assistant/system turn(s) + the preceding user turn (one step back).
// Pure GUI over the local `messages` array; persist() saves it. The core sees nothing.
function trimLastExchange(s) {
  let i = s.messages.length - 1;
  while (i >= 0 && s.messages[i].role !== "user") i--; // skip trailing system/assistant turns
  if (i >= 0) s.messages.splice(i); // remove the last user turn + its responses
}

// ── S-A TIER-0 keyboard/feel: shell-style ↑/↓ input history ───────────────────
// An EMPTY composer + ↑ walks recent user inputs (newest first); ↓ walks back to a
// blank draft. Source = recentCommands (the SAME deduped, redaction-skipping recent
// list the ⌘K palette uses — single truth source; a redacted line is never re-offered).
// histSuppress guards the synthetic input event walkHistory fires (so stepping does not
// reset the cursor or pop the autocomplete); a REAL keystroke resets nav (the owner
// edited the recalled line).
let histList = null, histIdx = -1, histSuppress = false;
function resetHistoryNav() { histList = null; histIdx = -1; }
function walkHistory(ta, dir) {
  if (ta.value.trim() !== "" && histIdx < 0) return false; // only an empty composer enters history
  if (histList === null) histList = recentCommands(50).map((r) => r.name);
  if (!histList.length) return false;
  if (dir < 0) histIdx = Math.min(histIdx + 1, histList.length - 1); // ↑ older
  else histIdx = Math.max(histIdx - 1, -1);                          // ↓ newer (−1 ⇒ blank draft)
  ta.value = histIdx < 0 ? "" : histList[histIdx];
  histSuppress = true; ta.dispatchEvent(new Event("input", { bubbles: true })); histSuppress = false;
  try { ta.setSelectionRange(ta.value.length, ta.value.length); } catch (_) {}
  return true;
}

// The newest still-live gated Confirm in this session — Enter = Continue, Esc = Cancel
// when one is pending. The core stays the sole verifier; this only carries the consent
// keystroke into the EXISTING approveIntent / cancelIntent (no 2nd truth source).
function latestLiveIntentKey() {
  const s = currentSession();
  if (!s) return null;
  for (let i = s.messages.length - 1; i >= 0; i--) {
    const m = s.messages[i];
    if (m && m.intentKey != null && intentSrc.has(m.intentKey)) return m.intentKey;
  }
  return null;
}

// ── S-A GUI-abandon of an in-flight turn (honest mid-turn "cancel") ───────────
// The core chat call is synchronous + non-interruptible (a blocking reqwest whole-body
// read; TRUE mid-turn cancel is S-C). Honest v1 = STOP WAITING: drop the loading card +
// free the composer. The worker finishes in the background; its late result still lands
// as a card (never silently dropped, never faked). Labeled "stopped waiting", not "killed".
let inFlight = null; // { pending, sid } — the latest dispatched turn still awaiting the core
function abandonInFlight() {
  if (!inFlight) return false;
  const pending = inFlight.pending, sid = inFlight.sid;
  inFlight = null;
  pending.abandoned = true; // dispatch() sees this when the core finally returns
  for (const proj of state.projects) {
    const s = proj.sessions.find((x) => x.id === sid);
    if (s) { const i = s.messages.indexOf(pending); if (i >= 0) s.messages.splice(i, 1); break; }
  }
  // S-C/C2: a streaming chat is TRULY cancelled mid-turn (the core stops between SSE
  // frames + turns). A blocking/non-streaming turn has nothing to abort here — it finishes
  // in the background (cancel_consult is a no-op when no stream is registered).
  if (hasTauri()) { try { window.__TAURI__.core.invoke("cancel_consult"); } catch (_) {} }
  renderView(); renderSidebar(); persist();
  toast("⏹ stopped — cancelled the turn (a live stream aborts mid-token; a blocking turn finishes in the background)");
  return true;
}

// Approve a gated intent IN PLACE (SS1 — the approve must NOT break the conversation):
// inject the core's phrase after `<ns> <verb>` and run it, then replace the SAME turn's
// LOCKED preview with the real result — NO new user-echo line, NO scroll yank, the composer
// stays alive (the answer continues below). The core verifies the phrase — this is the consent
// gesture, not a 2nd truth source. A re-gate (wrong phrase) re-LOCKS in the same slot.
async function approveIntent(key) {
  const rec = intentSrc.get(Number(key));
  if (!rec) return toast("this approval expired (session reloaded) — re-type the command to run it.");
  const s = currentSession();
  if (!s) return;
  const idx = s.messages.findIndex((x) => x.intentKey === Number(key));
  if (idx < 0) return;
  const tokens = String(rec.line).trim().split(/\s+/);
  if (tokens.length < 2 || !rec.phrase) return;
  const injected = tokens[2] === rec.phrase ? rec.line : [tokens[0], tokens[1], rec.phrase, ...tokens.slice(2)].join(" ");
  const m = s.messages[idx];
  m.approving = true;            // inline running marker on the SAME card slot
  m.cancelled = false;
  m.intentKey = null;            // consume the gate (the consent gesture is spent)
  intentSrc.delete(Number(key));
  renderView();                  // no new user turn ⇒ the scroll pin holds (no yank)
  const card = await runLine(injected, m.card.command || rec.line);
  m.approving = false;
  m.card = card;                 // replace the LOCKED preview with the real result, IN PLACE
  const reIntent = gatedIntent(card);   // a wrong/again-gated phrase re-LOCKS in the same slot
  if (reIntent) { const k2 = ++intentSeq; intentSrc.set(k2, { line: rec.line, phrase: reIntent.phrase }); m.intentKey = k2; }
  renderView(); persist();
}

// Cancel a gated intent: dismiss it WITHOUT running anything (nothing reached the core).
// The card stays, marked declined; the composer invites a re-type or a follow-up.
function cancelIntent(key) {
  const s = currentSession();
  if (s) {
    const idx = s.messages.findIndex((x) => x.intentKey === Number(key));
    if (idx >= 0) { s.messages[idx].intentKey = null; s.messages[idx].cancelled = true; }
  }
  intentSrc.delete(Number(key));
  renderView(); persist();
}

async function dispatch(line) {
  const trimmed = (line || "").trim();
  if (!trimmed) return;
  resetHistoryNav(); // S-A: a sent line resets ↑/↓ history navigation
  const s = ensureSession();
  // Chat routing: single truth source — the GUI never re-implements consult
  // semantics; it only rewrites the line onto the real gated verb. The typed
  // phrase rides in argv and is verified by the core's ApprovalPrompt.
  const isChat = !isCommandLine(trimmed);
  // Chat = live consult: auto-inject the phrase so the user just types a
  // question — no "Arm" step. A missing OPENROUTER_API_KEY simply returns a
  // typed KeyMissing card (no spend, no crash). A line that starts with a real
  // command word runs as that command instead (isCommandLine).
  const wire = isChat ? `provider consult ${CONSULT_PHRASE} ${trimmed}` : trimmed;
  // Show/persist the line through the core's own redactor (single truth source).
  // The RAW line still executes (the core is secret-zero); only the redacted
  // projection is ever rendered or written to the on-disk session store, so a
  // pasted key/token never lands at rest.
  let display = trimmed;
  try {
    const r = await invoke("redact_input", { line: trimmed });
    if (r && typeof r.display === "string") display = r.display;
  } catch (_) {}
  if (s.title === "New session") s.title = display.slice(0, 40);
  s.time = nowLabel();
  s.messages.push({ role: "user", text: display });
  renderView(); renderSidebar(); persist();

  // R11 loading UX: an HONEST, transient placeholder while the (synchronous,
  // non-streaming) core call runs — never persisted, never a fake %. The kind
  // (consult vs command) + first token feed loadingCardHTML's indeterminate
  // animation + context label + the live consult's real bound; replaced in
  // place by the real card when dispatch_line returns.
  const pending = {
    role: "system",
    pending: true,
    time: nowLabel(),
    loading: { kind: isChat ? "consult" : "command", cmd: display.split(/\s+/)[0] || "" },
  };
  s.messages.push(pending);
  renderView();
  inFlight = { pending, sid: s.id }; // S-A: track the awaiting turn so Esc can GUI-abandon it

  // S-C/C2: a chat line STREAMS (real token deltas via a tauri Channel); a command runs
  // whole-body. Both replace the pending card with the core's final receipt on completion.
  const card = isChat ? await runChatStream(wire, display, pending) : await runLine(wire, display);
  if (inFlight && inFlight.pending === pending) inFlight = null; // this turn resolved (not abandoned)
  const idx = s.messages.indexOf(pending);
  const final = { role: "system", card, time: nowLabel() };
  // R7: a LOCKED/typed-phrase card is a gated INTENT — stash the raw line in the
  // in-memory map (never persisted) and tag the message with its key so the view
  // can offer ONE Approve. card itself is the core's redacted render (safe to persist).
  const intent = gatedIntent(card);
  if (intent) {
    const key = ++intentSeq;
    intentSrc.set(key, { line: trimmed, phrase: intent.phrase });
    final.intentKey = key;
  }
  if (idx >= 0) s.messages[idx] = final;
  else s.messages.push(final);
  renderView(); persist();
}

/* ── command palette / search overlay (the "all features" shortcut) ──────── */
let ov = { items: [], active: 0, _filtered: [], scoped: false };
function paletteEntries() {
  const e = [];
  for (const c of TOP_LEVEL) e.push({ kind: "command", name: c, desc: "top-level command", fill: c });
  for (const [n, d] of NAMESPACES) {
    const gate = gateFor(n);
    e.push({ kind: gateBadge(gate), name: n, desc: d, fill: n + " status", gate });
  }
  return e;
}
function openOverlay(mode, subset) {
  let items = paletteEntries();
  if (subset && subset.length) items = items.filter((it) => subset.includes(it.name));
  ov.items = items;
  ov._filtered = items.slice();
  ov.active = 0;
  ov.scoped = !!(subset && subset.length);
  const o = $("#overlay");
  if (!o) return;
  o.hidden = false;
  const input = $("#overlay-input");
  if (input) {
    input.value = "";
    input.placeholder = mode === "automation" ? "Automation commands…" : "Search commands…  (e.g. provider, memory, chain)";
  }
  renderOverlay("");
  // If the core gate fetch hasn't landed yet, load it now and rebuild the badges.
  if (!Object.keys(GATES).length) {
    loadGates().then((n) => {
      if (!n || o.hidden) return;
      let rebuilt = paletteEntries();
      if (subset && subset.length) rebuilt = rebuilt.filter((it) => subset.includes(it.name));
      ov.items = rebuilt;
      renderOverlay(input ? input.value : "");
    });
  }
  if (input) setTimeout(() => { try { input.focus(); } catch (_) {} }, 0);
}
function closeOverlay() { const o = $("#overlay"); if (o) o.hidden = true; }
// Recent commands across persisted sessions (newest first, deduped). Redacted
// entries are skipped — never offer to re-run a secret.
function recentCommands(limit) {
  const seen = new Set(), out = [];
  for (const proj of state.projects) {
    for (const s of proj.sessions) {
      for (let i = s.messages.length - 1; i >= 0; i--) {
        const m = s.messages[i];
        if (!m || m.role !== "user") continue;
        const t = (m.text || "").trim();
        if (!t || t.indexOf("<redacted") === 0 || seen.has(t)) continue;
        seen.add(t); out.push({ kind: "recent", name: t, desc: "recent", fill: t });
        if (out.length >= limit) return out;
      }
    }
  }
  return out;
}
// Empty query → Recent + domain-grouped sections; typing → flat filtered list
// (byte-identical to the prior behavior). Scoped views (automation) stay flat.
function overlayGroups(q) {
  const ql = q.toLowerCase();
  // S-A fuzzy palette: substring on name/desc OR a SUBSEQUENCE on the name (reuse the same
  // isSubsequence scorer the @-mention file fuzzy uses) so "prv" → "provider". Additive
  // (a superset of the prior substring match) ⇒ no entry that matched before stops matching.
  const match = (it) => !ql || it.name.toLowerCase().includes(ql) || it.desc.toLowerCase().includes(ql) || isSubsequence(ql, it.name.toLowerCase());
  if (ql || ov.scoped) {
    return [{ label: ov.scoped && !ql ? "Automation" : "", items: ov.items.filter(match) }];
  }
  const groups = [];
  const recents = recentCommands(5);
  if (recents.length) groups.push({ label: "Recent", items: recents });
  const tops = ov.items.filter((it) => TOP_LEVEL.includes(it.name));
  if (tops.length) groups.push({ label: "Top-level", items: tops });
  for (const [label, list] of NS_CATEGORIES) {
    const items = list.map((n) => ov.items.find((it) => it.name === n)).filter(Boolean);
    if (items.length) groups.push({ label, items });
  }
  const placed = new Set([...TOP_LEVEL, ...NS_CATEGORIES.flatMap((e) => e[1])]);
  const rest = ov.items.filter((it) => !placed.has(it.name));
  if (rest.length) groups.push({ label: "Other", items: rest });
  return groups;
}
function renderOverlay(q) {
  const groups = overlayGroups(q);
  const flat = [];
  groups.forEach((g) => g.items.forEach((it) => flat.push(it)));
  ov._filtered = flat;
  ov.active = Math.min(ov.active, Math.max(0, flat.length - 1));
  const list = $("#overlay-list");
  if (!list) return;
  if (!flat.length) { list.innerHTML = `<div class="overlay-empty">No matching commands</div>`; return; }
  let idx = -1;
  list.innerHTML = groups
    .map((g) => {
      const header = g.label ? `<div class="section-label">${esc(g.label)}</div>` : "";
      const rows = g.items
        .map((it) => {
          idx += 1;
          const i = idx;
          return `
        <div class="overlay-item${i === ov.active ? " active" : ""}" data-i="${i}">
          <span class="oi-kind">${esc(it.kind)}</span><span class="oi-name">${esc(it.name)}</span><span class="oi-desc">${esc(it.desc)}</span>
        </div>`;
        })
        .join("");
      return header + rows;
    })
    .join("");
  $$(".overlay-item", list).forEach((el) => el.addEventListener("click", () => chooseOverlay(parseInt(el.dataset.i, 10))));
}
function chooseOverlay(i) {
  const it = (ov._filtered || [])[i >= 0 ? i : ov.active];
  if (!it) return;
  closeOverlay();
  dispatch(it.fill); // Enter / click = run immediately (easy)
}

/* ── settings / model panel (read-only; reuses the .overlay shell) ───────── */
// Every section is built from REAL dispatch output (single truth source) or
// GUI-owned facts. No egress fires here; funds stay HARD-LOCKED.
let panelOpen = false;
async function runCardHTML(line) {
  try {
    const parsed = parseResponse(await invoke("dispatch_line", { line }));
    if (!parsed.command) parsed.command = line;
    return cardHTML(parsed);
  } catch (e) {
    return `<div class="card"><div class="card-body card-error"><div class="body-line">${esc(String(e && e.message ? e.message : e))}</div></div></div>`;
  }
}
function infoCardHTML(lines) {
  return `<div class="card"><div class="card-body">${lines.map(bodyLineHTML).join("")}</div></div>`;
}
function sectionHTML(label, inner) {
  return `<div class="panel-sec"><div class="section-label">${esc(label)}</div>${inner}</div>`;
}
// Secrets section — memory-only key entry (single truth source: presence comes
// from the backend secret_status; the VALUE is never read back). Each input is
// a password field cleared after Set; the value goes straight to the backend
// process env and is never rendered, logged, or persisted.
// TIER-1 (A#4): a curated known-model list for the OPENROUTER_MODEL dropdown (OpenRouter
// ids). GUI-owned; the core validates + falls back to the default for anything unset.
const KNOWN_MODELS = [
  // BYO-model (Slice 1+2): GLM-5.2 executor via OpenRouter (z-ai/glm-5.2 — cheaper than
  // Z.ai direct); Fugu Ultra is the model id when the provider = sakana.
  "z-ai/glm-5.2",
  "z-ai/glm-4.7",
  "fugu-ultra",
  "deepseek/deepseek-chat",
  "deepseek/deepseek-r1",
  "anthropic/claude-sonnet-4",
  "anthropic/claude-opus-4.1",
  "openai/gpt-4o",
  "openai/gpt-4o-mini",
  "google/gemini-2.0-flash-001",
  "meta-llama/llama-3.3-70b-instruct",
];

// TIER-2 (B#4): config.toml GUI editor — the CLOSED key set the core's `setup persist`
// verb accepts (RawCliConfig; NO wallet/funds/chain keys by construction). The GUI form
// builds `setup persist <phrase> key=value …` from the non-empty fields ⇒ the SAME gated,
// validated, secret-screened, atomic core WRITE (no new IPC).
const CONFIG_KEYS = [
  ["profile", "profile (e.g. default)"],
  ["learning_mode", "learning_mode (on / off)"],
  ["data_egress", "data_egress (gated / off)"],
  ["sponsor_mode", "sponsor_mode (on / off)"],
  ["web3_rpc_endpoint", "web3_rpc_endpoint (https URL, read-only)"],
  ["remote_ssh_host", "remote_ssh_host (user@host)"],
  // walrus_publisher_endpoint / walrus_aggregator_endpoint moved to the dedicated
  // "Walrus (mainnet self-host)" section (S4) — still `data-config-key` inputs persisted
  // by the SAME gated config-save handler, just grouped with the token + status.
];
function configEditorHTML() {
  // Each config key = a kit row (icon + key label + the live input in the control slot);
  // a Save row drives the SAME gated setup-persist ceremony, then an honest note.
  const rows = CONFIG_KEYS.map(([k, ph]) =>
    kRow(icon("command"), esc(k), "", `<input class="panel-input" data-config-key="${esc(k)}" placeholder="${esc(ph)}" autocomplete="off" spellcheck="false" />`)
  );
  rows.push(kRow(icon("refresh"), "Save config", "Only non-empty fields are written, via the gated setup-persist ceremony — validated · secret-screened · atomic; no wallet / funds / chain keys.", kBtn("Save → config.toml", "data-config-save")));
  return kCard(rows);
}
function secretsSectionHTML(statuses) {
  // WALRUS_PUBLISHER_TOKEN renders in the dedicated "Walrus (mainnet self-host)" section
  // (S4), not here — one input per env (the set/clear handler resolves by first match).
  const rows = SECRET_DEFS.filter(([env]) => env !== "WALRUS_PUBLISHER_TOKEN").map(([env, label, secret]) => {
    const st = statuses.find((s) => s.name === env);
    const present = !!(st && st.present);
    // TIER-1 (A#4): OPENROUTER_MODEL is a known-model DROPDOWN, not a raw env string. The
    // <select> sets via the SAME data-secret-input / set_secret path (the core validates +
    // falls back to the default); "" ⇒ the deepseek default. The control slot carries the
    // input/select + Set + Clear; the presence pill rides at the end (set/default · not set).
    if (env === "OPENROUTER_MODEL") {
      const opts = KNOWN_MODELS.map((mdl) => `<option value="${esc(mdl)}">${esc(mdl)}</option>`).join("");
      const ctl = `<select class="panel-input" data-secret-input="${esc(env)}"><option value="">— pick a model (default deepseek/deepseek-chat) —</option>${opts}</select>`
        + kBtn("Set", `data-secret-set="${esc(env)}"`) + (present ? kBtn("Clear", `data-secret-clear="${esc(env)}"`, true) : "") + kPill(present ? "set (memory)" : "default", present ? "ok" : "");
      return kRow(icon("sparkles"), "Frontier model", "OPENROUTER_MODEL — sets via the same gated path; unset falls back to the deepseek default.", ctl);
    }
    const ctl = `<input class="panel-input" type="${secret ? "password" : "text"}" data-secret-input="${esc(env)}" placeholder="${esc(label)}" autocomplete="off" spellcheck="false" />`
      + kBtn("Set", `data-secret-set="${esc(env)}"`) + (present ? kBtn("Clear", `data-secret-clear="${esc(env)}"`, true) : "") + kPill(present ? "set (memory)" : "not set", present ? "ok" : "");
    return kRow(icon(secret ? "shield" : "command"), esc(label), `${esc(env)} — memory-only; the value is sent to the process env and never read back.`, ctl);
  });
  return kCard(rows)
    + byoModelCardHTML(statuses)
    + kCard(kRow(icon("clock"), "Memory-only", "Secrets are cleared when the app closes; raw secrets are never written to disk.", kPill("ephemeral", "ok")));
}

// SLICE 1+2 (BYO-MODEL, owner 2026-06-23) — the routing controls: WHICH frontier provider
// the consult egresses to, and whether the two-model loop's IMPLEMENT brain ("executor") is
// the LOCAL loopback (default · zero-egress · first-class) or a REMOTE provider (egress ·
// redaction-walled · owner-armed). REAL controls: each <select>/<input> rides the SAME
// data-secret-input / data-secret-set → set_secret(process env) path the model dropdown uses
// (the core reads the env; no config file). The provider is a CLOSED set (openrouter/sakana)
// — there is NO arbitrary-URL form, so funds-egress stays structurally impossible.
function byoModelCardHTML(statuses) {
  const present = (n) => !!((statuses || []).find((s) => s.name === n) || {}).present;
  const setClear = (env) => kBtn("Set", `data-secret-set="${esc(env)}"`)
    + (present(env) ? kBtn("Clear", `data-secret-clear="${esc(env)}"`, true) : "")
    + kPill(present(env) ? "set (memory)" : "default", present(env) ? "ok" : "");
  const provSelect = (env) => `<select class="panel-input" data-secret-input="${esc(env)}">`
    + `<option value="">— OpenRouter (default) —</option>`
    + `<option value="openrouter">OpenRouter</option>`
    + `<option value="sakana">Sakana Fugu</option></select>` + setClear(env);
  const modelOpts = KNOWN_MODELS.map((m) => `<option value="${esc(m)}">${esc(m)}</option>`).join("");
  return kGroup("Routing · BYO model")
    + kCard([
        kRow(icon("sparkles"), "Frontier provider",
          "SINABRO_FRONTIER_PROVIDER — which provider the frontier consult egresses to (closed set; egress · redaction-walled · owner-armed). Unset = OpenRouter. Pick Sakana to use Fugu (then set the model to fugu-ultra).",
          provSelect("SINABRO_FRONTIER_PROVIDER")),
      ])
    + kCard([
        kRow(icon("zap"), "Executor mode",
          "SINABRO_EXECUTOR_MODE — the two-model loop's implement brain. local = loopback · zero-egress · free (default · first-class · air-gappable); remote = a provider via egress · redaction-walled · owner-armed.",
          `<select class="panel-input" data-secret-input="SINABRO_EXECUTOR_MODE"><option value="">— local (loopback) · default —</option><option value="local">Local (loopback · zero-egress)</option><option value="remote">Remote (provider · egress)</option></select>` + setClear("SINABRO_EXECUTOR_MODE")),
        kRow(icon("sparkles"), "Executor provider",
          "SINABRO_EXECUTOR_PROVIDER — used only when the mode is remote (closed set). GLM-5.2 = the OpenRouter model id z-ai/glm-5.2.",
          provSelect("SINABRO_EXECUTOR_PROVIDER")),
        kRow(icon("command"), "Executor model",
          "SINABRO_EXECUTOR_MODEL — used only when the mode is remote. TYPE ANY model id (free-text — e.g. a per-domain LoRA adapter id), or pick a known one; unset = the provider default.",
          `<input class="panel-input" list="byo-known-models" data-secret-input="SINABRO_EXECUTOR_MODEL" placeholder="type a model id (or pick) — unset = provider default" autocomplete="off" spellcheck="false" /><datalist id="byo-known-models">${modelOpts}</datalist>` + setClear("SINABRO_EXECUTOR_MODEL")),
      ])
    + kCard(kRow(icon("shield"), "Both brains — your choice",
        "LOCAL stays first-class (zero-egress, air-gappable, free). REMOTE routes through the SAME redaction wall + same-message owner-arm as the frontier; the host is a closed allowlist (no provider can be a funds host), so funds / chain / wallet stay HARD-LOCKED.",
        kPill("custody hard-locked", "lock")));
}

// S4 (WALRUS_MAINNET_SELFHOST) — the dedicated self-host Walrus section: the two endpoint
// URL inputs (the SAME `data-config-key` mechanism the config editor uses, persisted by the
// gated config-save), the WALRUS_PUBLISHER_TOKEN secret row, and a presence-only
// "● connected (memory)" status from `walrus_status` (booleans only; never a URL/token).
function walrusSettingsSectionHTML(statuses, wstat) {
  const tokSt = statuses.find((s) => s.name === "WALRUS_PUBLISHER_TOKEN");
  const tokPresent = !!(tokSt && tokSt.present);
  const pubOk = !!(wstat && wstat.publisher_configured);
  const aggOk = !!(wstat && wstat.aggregator_configured);
  const active = pubOk && aggOk; // token optional — some publishers are open
  const L = CONNECTOR_LOGOS;
  const tokClear = tokPresent ? kBtn("Clear", 'data-secret-clear="WALRUS_PUBLISHER_TOKEN"', true) : "";
  const intro = kRow(`<span class="set-ico plain">${L.walrus}</span>`, "Your OWN Walrus (mainnet)", "Enter your self-host publisher + aggregator https URLs (and a bearer token if your publisher needs one); your encrypted memory then lives on YOUR Walrus. The app holds no Sui key and never signs — your publisher pays.", kPill(active ? "active" : "set urls", active ? "ok" : ""));
  const pubInput = kRow(icon("database"), "Publisher URL", "https only — no IP / localhost.", `<input class="panel-input" data-config-key="walrus_publisher_endpoint" placeholder="https://publisher.your-walrus…" autocomplete="off" spellcheck="false" />`);
  const aggInput = kRow(icon("database"), "Aggregator URL", "The GET / read side.", `<input class="panel-input" data-config-key="walrus_aggregator_endpoint" placeholder="https://aggregator.your-walrus…" autocomplete="off" spellcheck="false" />`);
  const saveBtn = kRow(icon("refresh"), "Save endpoints", "Persisted via the gated config-save to ~/.mnemos/config.toml.", kBtn("Save → config.toml", "data-config-save"));
  const tokCtl = `<input class="panel-input" type="password" data-secret-input="WALRUS_PUBLISHER_TOKEN" placeholder="bearer token (Authorization: Bearer; NEVER a Sui key)" autocomplete="off" spellcheck="false" />`
    + kBtn("Set", 'data-secret-set="WALRUS_PUBLISHER_TOKEN"') + tokClear + kPill(tokPresent ? "token set" : "token optional", tokPresent ? "ok" : "");
  const tokRow = kRow(icon("shield"), "Publisher token", "WALRUS_PUBLISHER_TOKEN — sent only as a bearer header; memory-only.", tokCtl);
  const status = kCard([
    kFact("Publisher", `${pubOk ? "● connected" : "○ not configured"}`),
    kFact("Aggregator", `${aggOk ? "● connected" : "○ not configured"}`),
    kFact("Token", `${tokPresent ? "● memory" : "○ none"}`),
    kRow(icon("zap"), "Self-host status", active ? "MAINNET self-host ACTIVE — reads auto-use it; a fresh write is the owner ceremony." : "Set BOTH https URLs to activate.", kPill(active ? "active" : "inactive", active ? "ok" : "")),
  ]);
  const note = kCard(kRow(icon("shield"), "Safety", "https-only + SSRF-walled at use; the token is memory-only (cleared on close, never written to disk). The app holds no Sui key and never signs.", kPill("no key · never signs", "ok")));
  return kCard([intro, pubInput, aggInput, saveBtn, tokRow]) + status + note;
}

async function settingsPanelHTML() {
  // FACELIFT: General is the keys + config + self-host HUB. The System/Providers/Sandbox/
  // Privacy status dumps are intentionally dropped here — each has a dedicated section in the
  // rail (no duplicate text wall). Only the real state the rendered controls need is loaded.
  const [secrets, walrusStat] = await Promise.all([
    invoke("secret_status").catch(() => []),
    invoke("walrus_status").catch(() => ({})),
  ]);
  const sessions = state.projects.reduce((n, p) => n + p.sessions.length, 0);
  const theme = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  return `
    <div class="set-title">General</div>
    <div class="set-lede">Your keys, config and self-host storage — memory-only secrets, gated writes.</div>
    ${kGroup("Secrets (memory-only)")}
    ${secretsSectionHTML(secrets)}
    ${kGroup("Walrus — mainnet self-host")}
    ${walrusSettingsSectionHTML(secrets, walrusStat)}
    ${kGroup("Config — config.toml")}
    ${configEditorHTML()}
    ${kGroup("Appearance")}
    ${kCard(kRow(icon("theme"), "Theme", "Local to this machine.", kSeg(theme, [["dark", "Dark"], ["light", "Light"]], "data-theme-set")))}
    ${kGroup("Session storage & safety")}
    ${kCard([
      kFact("Sessions", esc(String(sessions))),
      kFact("Store", "~/Library/Application Support/com.sinabro.desktop"),
      kRow(icon("shield"), "Redaction", "Core secret-zero — raw secrets are never written.", kPill("on", "ok")),
      kRow(icon("shield"), "Funds &amp; keys", "Wallet · signing · mainnet — HARD-LOCKED in 1.0.", kPill("hard-locked", "lock")),
    ])}`;
}
async function modelPanelHTML() {
  const keyOk = keyPresent === true;
  // A#1 (owner "모델 설정 아예 안됨"): show the model the core will ACTUALLY use (from the
  // backend resolver), not a hardcoded "deepseek-chat" that lied about an explicit selection.
  let activeModel = "deepseek/deepseek-chat (default)";
  try { activeModel = await invoke("frontier_model_view"); } catch (_) {}
  return `
    <div class="set-title">Models &amp; provider</div>
    <div class="set-lede">A frontier model reasons; an executor model implements — each can be a LOCAL loopback (zero-egress) or a REMOTE provider (egress · gated). Routing lives in Settings.</div>
    ${kGroup("Frontier")}
    ${kCard([
      kRow(icon("sparkles"), `Provider key ${keyOk ? '<span class="sdot ok"></span>' : '<span class="sdot off"></span>'}`, keyOk ? "OPENROUTER_API_KEY set — read only at the TLS boundary, never shown." : "Set OPENROUTER_API_KEY to consult the frontier.", kBtn(keyOk ? "Change key" : "Set key", 'data-ov-nav="general"', true)),
      kRow(icon("zap"), "Active model", "OPENROUTER_MODEL · your Settings pick is now authoritative (an explicit choice is never downgraded). Pick below.", `<span class="set-val mono">${esc(activeModel)}</span>`),
      kRow(icon("shield"), "Egress", "One-shot, bounded, phrase auto-injected; no silent fallback (core-enforced).", kPill("gated", "ok")),
      kRow(icon("zap"), "Routing · BYO model", "Pick the frontier provider (OpenRouter / Sakana Fugu) and the executor brain (local loopback or a remote provider). Local stays first-class.", kBtn("Configure", 'data-ov-nav="general"', true)),
    ])}
    ${kGroup("Live consult")}
    ${kCard(kRow(icon("list"), "Provider status", "", kBtn("Run", 'data-panel-run="provider status"', true)))}`;
}
/* ── R7b: privacy · safety panel (all REAL backing; no fake claim) ─────────────
   Privacy is a product selling point (research D-4: no-account · opt-in telemetry ·
   file-over-app · zero off-box). Every line below is a real dispatch output or a
   real on-disk fact — NEVER an advertised feature sinabro lacks (the E-connector
   lesson). Telemetry is a REAL opt-in toggle (set_telemetry → SINABRO_OTEL_EXPORT,
   memory-only). Stop/Pause is HONEST: the loop is bounded-by-construction + the
   express kill rail is surfaced read-only (probed: phase-0 = no live job to signal),
   never a fake interrupt button. */
async function privacyPanelHTML() {
  const tele = await invoke("telemetry_status").catch(() => false);
  return `
    <div class="set-title">Privacy &amp; safety</div>
    <div class="set-lede">No account, no cloud. Your data is local files you own; nothing leaves unredacted.</div>
    ${kGroup("Identity")}
    ${kCard(kRow(icon("shield"), "Account", "None · no login · no cloud sync. sinabro never asks who you are.", kPill("local", "ok")))}
    ${kGroup("What leaves the machine")}
    ${kCard([
      kRow(icon("zap"), "Egress", "", kPill("provider · telegram · walrus", "") + " " + kPill("gated · off by default", "ok")),
      kRow(icon("shield"), "Redaction wall", "", kPill("on", "ok")),
      kRow(icon("clock"), "Telemetry", tele ? "On — one local OTLP span per consult in ~/.mnemos/otel; not pushed off-box." : "Off — no spans written. (Opt-in.)", kToggle(tele, `data-telemetry-set="${tele ? "off" : "on"}"`)),
    ])}
    ${kGroup("On-device — file-over-app")}
    ${kCard([
      kFact("Memory store", "~/.mnemos/store · AES-256-GCM-SIV"),
      kFact("Memory key", "~/.mnemos/memory.key · 0600 local"),
      kFact("Proposals", "~/.mnemos/proposals · sealed"),
    ])}
    ${kGroup("Agent safety")}
    ${kCard([
      kRow(icon("shield"), "Bounded loop", "≤5 turns · 20k tokens · 60s — cannot run away. Side-effects need one Approve.", kPill("bounded", "ok")),
      kRow(icon("shield"), "Funds &amp; keys", "Wallet · signing · chain-write are unrepresentable.", kPill("hard-locked", "lock")),
    ])}`;
}
/* ── R7c: Action Audit — chronological cross-session activity feed ─────────────
   Research D-3: a timestamped activity feed + session grouping. Real NOW from the
   persisted store — each record is the CORE's own verdict for one dispatched action
   (verb · risk · truth · time; an action that went through the single-Approve gate
   is marked). The richer per-consult OTel spans (loop · cost · guard) live in
   ~/.mnemos/otel when opt-in telemetry is ON; their parser is PROBE-DEFERRED until a
   real span exists to read — no blind parser (the R4.5/R6 rule). Undo = honest
   scope: decline a pending edit (pre-commit) is real; an applied edit has no
   journal/undo-blob in v1 (P3-2) — surface the boundary, never a fake Undo. */
function auditRowHTML(r) {
  return `<div class="audit-row">
    <span class="audit-verb">${esc(r.cmd)}</span>
    <span class="pill pill-risk ${riskClass(r.risk)}">${esc(r.risk)}</span>
    <span class="pill pill-truth ${truthClass(r.truth)}">${esc(r.truth)}</span>
    ${r.gated ? `<span class="audit-gate">approved</span>` : ""}
    <span class="audit-time">${esc(r.time)}</span>
  </div>`;
}
async function auditPanelHTML() {
  const recs = [];
  for (const proj of state.projects) {
    for (const sess of proj.sessions) {           // newest session first (unshift order)
      for (let i = sess.messages.length - 1; i >= 0; i--) {
        const m = sess.messages[i];
        if (!m || m.role !== "system" || !m.card) continue;
        recs.push({ cmd: m.card.command || "—", risk: m.card.risk || "read-only", truth: m.card.truth || "UNKNOWN", time: m.time || sess.time || "", gated: m.intentKey != null });
      }
    }
  }
  const tele = await invoke("telemetry_status").catch(() => false);
  const total = recs.length;
  const attention = recs.filter((r) => /red|degraded/i.test(r.truth)).length;
  const summary = kCard([
    kFact("Actions", esc(String(total))),
    kFact("Attention", `${esc(String(attention))} (truth=red/degraded)`),
    kRow(icon("shield"), "Source", "Persisted sessions on this machine — redacted, secret-zero.", kPill("local", "ok")),
  ]);
  // The feed itself keeps its audit-row markup; the surrounding chrome becomes the kit.
  const feed = total
    ? `<div class="set-card"><div class="audit-feed">${recs.slice(0, 250).map(auditRowHTML).join("")}</div></div>${total > 250 ? kCard(kFact("Showing", `the 250 most recent of ${esc(String(total))}`)) : ""}`
    : kCard(kRow(icon("clock"), "No actions yet", "Run a command and it lands here.", ""));
  const otel = kCard(kRow(icon("clock"), "Telemetry trail", "Richer per-consult spans (loop · cost · guard) record to ~/.mnemos/otel when ON (enable in Privacy).", kPill(tele ? "on" : "off", tele ? "ok" : "")));
  return `
    <div class="set-title">Activity &amp; audit</div>
    <div class="set-lede">Every dispatched action, newest first — the core's own verdict, redacted on this machine.</div>
    ${kGroup("Summary")}
    ${summary}
    ${kGroup("Activity (newest first)")}
    ${feed}
    ${kGroup("Telemetry")}
    ${otel}
    ${kCard(kRow(icon("shield"), "Edits reversible before commit · staleness refused", "", kPill("fail-closed", "ok")))}`;
}
/* ── E14-W2: the two-tier Walrus long-term memory panel ───────────────────────
   The agent's "메인 저장소" (MAIN INDEX) + per-memory "서브 저장소" (detail), surfaced
   for the owner. Reuses the STRUCTURED backend commands (never emit-text parsing —
   the R4.5 lesson): `walrus_memory_index` decrypts the MAIN INDEX locally (pointer
   → testnet aggregator GET → AEAD open → decode) and lists every memory's id +
   topic + sub-store blob-id; a row click calls `walrus_memory_fetch` to enter that
   SUB-STORE, fetch + decrypt its detail (redact-belted). This is the SAME two-tier
   navigation the agent does AUTONOMOUSLY mid-loop (`TOOL: memory walrus-index` /
   `walrus-fetch <id>`). READ-only · ciphertext-only on the wire · no funds ·
   custody/wallet/mainnet structurally unreachable (PD-6). No pointer yet ⇒ an
   honest "run backup-walrus" hint, never a fabricated "synced" index. */
function walrusRowHTML(e, i = 0) {
  // S5: `--reveal-i` drives the staggered fan-out (CSS `.walrus-fan .walrus-row`),
  // capped so a long index never stalls the cascade.
  const ri = Math.min(i, 16);
  return `<div class="walrus-row" style="--reveal-i:${ri}">
      <button class="suggest" data-walrus-fetch="${esc(String(e.id))}" title="Enter this memory's sub-store — fetch + decrypt its detail from Walrus">
        <span class="sg-glyph">›</span>id=${esc(String(e.id))}
      </button>
      <span class="walrus-topic">${esc(e.topic)}</span>
      <span class="lockchip mono">${esc(e.sub_blob)}…</span>
    </div>`;
}
async function walrusPanelHTML() {
  let view;
  try { view = await invoke("walrus_memory_index"); }
  catch (e) { view = { kind: "unavailable", reason: String(e && e.message ? e.message : e) }; }
  // S5: the READ routes to the configured self-host aggregator (mainnet) when set, else
  // testnet — label the MAIN INDEX node with which store the owner is looking at.
  let wstat = {}, secrets = [];
  try { wstat = await invoke("walrus_status"); } catch (_) { wstat = {}; }
  try { secrets = await invoke("secret_status"); } catch (_) { secrets = []; }
  const L = CONNECTOR_LOGOS;
  const title = `<div class="set-title">Memory · Walrus</div><div class="set-lede">Encrypted two-tier memory the agent roams on its own — ciphertext on the wire, decrypted only here.</div>`;
  // Owner "월러스 붙여넣기 어디간데": the paste-and-set (publisher/aggregator URL + token) lives
  // HERE now, at the top of the Walrus section — paste your URLs, Save, done.
  const connect = kGroup("Connect your Walrus — paste + save") + walrusSettingsSectionHTML(secrets, wstat);
  const intro = kCard(kRow(`<span class="set-ico plain">${L.walrus}</span>`, "Encrypted · decrypted only here", "", kPill("encrypted", "ok")));
  const detailSlot = `<div id="walrus-detail">${kCard(kRow(icon("folder"), "Sub-store detail", "Select a memory above to fetch + decrypt its detail.", ""))}</div>`;
  if (!view || view.kind !== "index") {
    const reason = (view && view.reason) || "no main index";
    const empty = kCard([
      kRow(icon("database"), "No main index yet", esc(reason), kPill("empty", "")),
      kRow(icon("refresh"), "Publish the encrypted index to Walrus testnet", "One touch — publishes your encrypted memory + round-trip verifies (no phrase to type).", kBtn("Publish now", 'data-panel-run="memory backup-walrus backup-encrypted-memory-to-walrus-testnet"')),
    ]);
    return `${title}${connect}${kGroup("Two-tier Walrus memory")}${intro}${kGroup("Main index")}${empty}`;
  }
  const entries = view.entries || [];
  const net = wstat && wstat.aggregator_configured ? "MAINNET self-host" : "testnet";
  // S5: the MAIN INDEX node "쫙" — it pops in, then the SUB-STORE rows below fan out from
  // it with a staggered, GPU-composited reveal (CSS `.walrus-main-node` + `.walrus-fan`).
  const mainNode = `<div class="walrus-main-node">
      <span class="walrus-main-glyph">⛁</span>
      <span class="walrus-main-label">MAIN INDEX</span>
      <span class="walrus-main-sub">${entries.length} sub-store${entries.length === 1 ? "" : "s"} · ${esc(net)} · decrypted locally</span>
    </div>`;
  const rows = entries.length
    ? `<div class="walrus-feed walrus-fan">${entries.map((e, i) => walrusRowHTML(e, i)).join("")}</div>`
    : kCard(kRow(icon("database"), "Index is empty", "No memories published yet.", kPill("empty", "")));
  const indexCard = `<div class="set-card">${mainNode}${rows}</div>`;
  return `${title}${connect}${kGroup("Two-tier Walrus memory")}${intro}${kGroup("Main index")}${indexCard}${kGroup("Sub-store detail")}${detailSlot}`;
}
/* ── R10: first-run capability disclosure + progressive disclosure ─────────────
   Research D-3 (NN/G — declare the capability range on first entry) + D-5 #5
   (progressive disclosure: essentials first, specifics behind a fold; layout-stable,
   dismissible, remembered) + D-2 (never forced — 1x on first run + a "?" recall, never
   re-popped) + 2-3 (being honest about LIMITS builds trust — 46% of devs actively
   distrust agent autonomy). NO-FAKE: every line is a REAL, already-shipped + gated core
   surface (probed 2026-06-11: budget/privacy/memory/wallet/chain + the R3-R9 GUI slices)
   — sinabro never advertises a capability it lacks (the E-connector lesson). STATIC by
   design (capabilities are structural, not live numbers — the R6 status bar carries
   metrics); command semantics are NOT re-implemented (the buttons reuse real data-action
   wiring). The 3 tiers carry the AUDIT SOUL: each gets the same trust pill the receipt
   cards use (autonomous=t-pass · gated=s-locked · off-limits=r-admin). */
function discCapHTML(tier, tierCls, title, desc) {
  return `<div class="disc-cap">
      <span class="pill ${tierCls}">${esc(tier)}</span>
      <div class="disc-cap-text">
        <div class="disc-cap-title">${esc(title)}</div>
        <div class="disc-cap-desc">${esc(desc)}</div>
      </div>
    </div>`;
}
function disclosurePanelHTML() {
  const intro = `<div class="disc-intro">
      <div class="disc-mark">▌</div>
      <div class="disc-lede">sinabro is a <b>local</b> coding &amp; audit agent. Your code and keys stay on this machine — nothing leaves it until you approve a specific action.</div>
    </div>`;
  const caps = [
    discCapHTML("autonomous", "pill-truth t-pass", "Reads on its own — read-only",
      "Opens your files, memory and project tree by itself, behind allowlist · denylist · size · redaction walls. No approval needed: nothing changes."),
    discCapHTML("asks first", "pill-state s-locked", "Side-effects need ONE approval",
      "Consult a provider · run a command · edit a file · send a message — each returns an Intent Preview with a single Approve. The core verifies, redacts and bounds it; the GUI never acts on its own."),
    discCapHTML("off-limits", "pill-risk r-admin", "Funds are hard-locked",
      "Wallet · funds · mainnet · chain-writes are structurally impossible — for you AND the model. No seed phrase is ever accepted; signing is preview-only in 1.0."),
  ].join("");
  const safety = infoCardHTML([
    "loop=bounded by construction: <=5 turns · 20k tokens · 60s deadline (it cannot run away)",
    "budget=pre-dispatch gate, fail-closed — an over-budget call is never sent",
    "guard=every turn is health-checked in-core; a secret-touch stops the loop",
  ]);
  const privacy = infoCardHTML([
    "account=none · no login · no cloud — sinabro never asks who you are",
    "at-rest=local files you own; memories sealed AES-256-GCM-SIV; no plaintext on disk",
    "egress=none by default; redaction scans every outbound fragment (secret-shaped ⇒ refused)",
    "telemetry=opt-in, off by default (a LOCAL span file, never pushed off-box in v1)",
  ]);
  const start = `<div class="disc-steps">
      <div class="disc-step"><span class="disc-num">1</span><span>Open a folder — its tree indexes on the right, read-only.</span></div>
      <div class="disc-step"><span class="disc-num">2</span><span>Set your key — Settings → Secrets, <span class="mono">OPENROUTER_API_KEY</span> (memory-only).</span></div>
      <div class="disc-step"><span class="disc-num">3</span><span>Type a question in the agent pane — it fires one gated consult.</span></div>
    </div>
    <div class="disc-actions">
      <button class="suggest" data-action="open-root"><span class="sg-glyph">›</span>Open a folder</button>
      <button class="suggest" data-action="settings"><span class="sg-glyph">›</span>Set your key</button>
      <button class="suggest" data-action="privacy"><span class="sg-glyph">›</span>Privacy &amp; safety</button>
    </div>`;
  const deep = `<details class="disc-details">
      <summary>Show the exact gates &amp; walls</summary>
      ${infoCardHTML([
        "read-only (autonomous)=memory index/read · file read · project index",
        "gated (single Approve, typed-phrase)=provider consult · provider orchestrate (two-model) · daemon evolve (autonomous R-E-W) · tool run (exec) · tool apply (edit) · platform send · memory backup-walrus",
        "verify gate=a Code result is judged by a real sui move build (network-DENIED sandbox); only an oracle-Verified, cross-memory-consistent pattern ever persists — the model never self-certifies",
        "exec wall=Admin · env-scrubbed (PATH/HOME/LANG/TERM only) · no shell · argv-split · 10s timeout",
        "edit wall=staleness-locked (refuses a since-changed file) · atomic · mode-preserved",
        "hard-lock=no wallet or chain host exists in the egress allowlist (impossible by construction)",
      ])}
    </details>`;
  return [
    `<div class="panel-sec">${intro}</div>`,
    sectionHTML("What it can do", `<div class="disc-caps">${caps}</div>`),
    sectionHTML("Bounded & honest", safety),
    sectionHTML("Privacy — yours, local", privacy),
    sectionHTML("Start here", start),
    `<div class="panel-sec">${deep}</div>`,
  ].join("");
}
/* ── P1-6: Agent flows panel — orchestrate · evolve · autonomy · dynamic-LoRA routing.
   Every line is a REAL, already-shipped + gated core surface reached through the same
   `dispatch_line` bridge the chat uses (no fake capability). orchestrate/evolve need a
   LOCAL model server (local-mlx/local-vllm) on the loopback for the EXECUTE brain; without
   one the run honest-degrades. The owner-armed phrase is auto-injected (the GUI run IS the
   owner's approval, like the chat consult); the CORE stays the sole verifier (redaction,
   bounds, the class-typed ORACLE gate). custody/funds HARD-LOCKED throughout. */
function flowsPanelHTML() {
  const orchestrate = kCard(kRow(icon("zap"), "Orchestrate a task", "frontier plans · local executes · oracle-verified",
    `<input class="panel-input" data-flow-input="orchestrate" placeholder="e.g. build a Sui counter module" autocomplete="off" spellcheck="false" />` + kBtn("Run", 'data-flow-run="orchestrate"')));
  const planmode = kCard(kRow(icon("list"), "Plan Mode", "review sub-tasks before running",
    `<input class="panel-input" data-flow-input="planmode" placeholder="task to PLAN" autocomplete="off" spellcheck="false" />` + kBtn("Plan", "data-planmode-plan")))
    + `<div id="planmode-result" class="planmode-result"></div>`;
  const evolve = kCard(kRow(icon("refresh"), "Evolve a goal", "verified patterns persist to Walrus",
    `<input class="panel-input" data-flow-input="evolve" placeholder="goal to autonomously evolve" autocomplete="off" spellcheck="false" />` + kBtn("Run", 'data-flow-run="evolve"')));
  const daemon = kCard([
    kRow(icon("zap"), "Status & surfaces", "",
      kBtn("daemon status", 'data-panel-run="daemon status"', true) + kBtn("daemon serve", 'data-panel-run="daemon serve"', true) + kBtn("autonomy surfaces", 'data-panel-run="daemon"', true)),
    kRow(icon("edit"), "Armed sessions", "bounded · revocable",
      kBtn("Bold session (edit+run)", 'data-panel-run="daemon bold arm-bold-session-edit-run-bounded-revocable"') + kBtn("Run-mutate (local)", 'data-panel-run="daemon run-mutate arm-mutate-local-autonomy-bounded-revocable"') + kBtn("Apply exec proposal", 'data-panel-run="tool exec-apply exec-apply-owner-live"')),
    kRow(icon("command"), "Needs an arg", "",
      kBtn("Serve-chat (needs session)", 'data-panel-run="daemon serve-chat"', true) + kBtn("Run-frontier (needs task)", 'data-panel-run="daemon run-frontier"', true)),
  ]);
  const routing = kCard([
    kFact("Routing config", "~/.mnemos/routing_table.txt"),
    kRow(icon("list"), "Edit adapter map", "", kBtn("Open LoRA / routing", 'data-ov-nav="routing"')),
  ]);
  return `
    <div class="set-title">Agent · autonomy</div>
    <div class="set-lede">A frontier model plans, a local model executes — every result oracle-verified before it persists.</div>
    ${kGroup("Orchestrate — two-model loop")}
    ${orchestrate}
    ${kGroup("Plan Mode — review, approve, run")}
    ${planmode}
    ${kGroup("Evolve — autonomous Read-Execute-Write")}
    ${evolve}
    ${kGroup("Autonomy (daemon)")}
    ${daemon}
    ${kGroup("Dynamic-LoRA routing")}
    ${routing}
    ${kCard(kRow(icon("shield"), "Wallet · mainnet · chain-write", "", kPill("hard-locked", "lock")))}`;
}

// ── MEGA "BUILD FOR REAL" capabilities panel (web3 read · settings-sync · codebase ·
//    image · remote-shell). PURE GUI: every control dispatches an ALREADY-LIVE core verb
//    through the SAME `dispatch` bridge the chat + palette use (NO new Rust, NO new IPC).
//    Owner-armed actions auto-inject their arm phrase (the GUI run IS the owner's approval,
//    like the flows panel); the CORE stays the sole verifier (arm ceremony + redaction +
//    gates). custody/funds/mainnet/chain-write stay HARD-LOCKED. ──
function megaPanelHTML() {
  const intro = infoCardHTML([
    "These wire the new MEGA-lane capabilities to the SAME core verbs the CLI + agent use — the GUI run IS your approval; the CORE stays the sole verifier (arm ceremony + redaction + gates).",
    "READS are free; owner-armed actions auto-inject their arm phrase here. funds / wallet / mainnet / chain-write stay HARD-LOCKED.",
  ]);
  const codebase = `<div class="panel-row">
      <button class="suggest" data-panel-run="context codebase build"><span class="sg-glyph">›</span>Build index</button>
    </div>
    <div class="panel-row">
      <input class="panel-input" data-mega-input="codebase" placeholder="@codebase query (semantic + lexical retrieval; local embeddings)" autocomplete="off" spellcheck="false" />
      <button class="suggest" data-mega-run="codebase"><span class="sg-glyph">›</span>Search</button>
    </div>`;
  const image = `<div class="panel-row">
      <input class="panel-input" data-mega-input="image" placeholder="image path — local-vision describe (bytes never leave the box)" autocomplete="off" spellcheck="false" />
      <button class="suggest" data-mega-run="image"><span class="sg-glyph">›</span>Describe</button>
    </div>`;
  const web3 = `<div class="panel-row">
      <select class="panel-input" data-mega-select="web3">
        <option value="sol_balance">sol_balance</option>
        <option value="sol_account">sol_account</option>
        <option value="sol_sig_status">sol_sig_status</option>
        <option value="sol_slot">sol_slot</option>
        <option value="sol_health">sol_health</option>
        <option value="sol_block_height">sol_block_height</option>
        <option value="sui_balance">sui_balance</option>
        <option value="sui_object">sui_object</option>
        <option value="sui_tx">sui_tx</option>
        <option value="sui_checkpoint">sui_checkpoint</option>
      </select>
      <input class="panel-input" data-mega-input="web3" placeholder='params JSON (optional) e.g. ["&lt;address&gt;"]' autocomplete="off" spellcheck="false" />
      <button class="suggest" data-mega-run="web3"><span class="sg-glyph">›</span>Read (armed)</button>
    </div>`;
  const sync = `<div class="panel-row">
      <button class="suggest" data-panel-run="setup sync-push settings-sync-push-owner-live"><span class="sg-glyph">›</span>Push config → Walrus (armed)</button>
    </div>
    <div class="panel-row">
      <input class="panel-input" data-mega-input="syncpull" placeholder="blob_id to pull + decrypt + apply" autocomplete="off" spellcheck="false" />
      <button class="suggest" data-mega-run="syncpull"><span class="sg-glyph">›</span>Pull + apply (armed)</button>
    </div>`;
  const remote = `<div class="panel-row">
      <select class="panel-input" data-mega-select="remote">
        <option value="whoami">whoami</option>
        <option value="uname">uname</option>
        <option value="df">df</option>
        <option value="git-status">git-status</option>
        <option value="git-head">git-head</option>
      </select>
      <button class="suggest" data-mega-run="remote"><span class="sg-glyph">›</span>Run on remote box (armed)</button>
    </div>`;
  const imagefrontier = `<div class="panel-row">
      <input class="panel-input" data-mega-input="imagefrontier" placeholder="image path → frontier (⚠ an image CANNOT be auto-redacted)" autocomplete="off" spellcheck="false" />
      <button class="suggest" data-mega-run="imagefrontier"><span class="sg-glyph">›</span>Prepare frontier image (armed)</button>
    </div>`;
  const lock = `<div class="panel-row"><span class="lockchip">⬤ funds / wallet / mainnet / chain-write — HARD-LOCKED; chain reads are READ-only (no WRITE); an image to the frontier cannot be auto-redacted (you are warned before it leaves)</span></div>`;
  return [
    sectionHTML("New capabilities", intro),
    sectionHTML("Semantic codebase index — @codebase (READ)", codebase),
    sectionHTML("Image — local-vision describe (READ)", image),
    sectionHTML("Web3 RPC read — owner-armed, READ-only, config endpoint", web3),
    sectionHTML("Settings sync — config ⇄ encrypted Walrus (owner-armed)", sync),
    sectionHTML("Remote diagnostic over SSH — owner-armed, READ-only", remote),
    sectionHTML("Image → frontier — owner-armed, unredactable warning", imagefrontier),
    sectionHTML("Safety", lock),
  ].join("");
}

// Build the wire for a MEGA panel control (auto-injecting the owner-armed phrase). Returns
// `null` when a required input is empty (the caller toasts + skips — no empty dispatch).
function megaWire(key, root) {
  const inp = root.querySelector(`[data-mega-input="${key}"]`);
  const sel = root.querySelector(`[data-mega-select="${key}"]`);
  const val = inp && inp.value ? inp.value.trim() : "";
  const sv = sel && sel.value ? sel.value.trim() : "";
  switch (key) {
    case "codebase": return val ? `context codebase ${val}` : null;
    case "image": return val ? `context image ${val}` : null;
    case "web3": return sv ? `daemon web3-read arm-web3-rpc-read-bounded-revocable ${sv}${val ? " " + val : ""}` : null;
    case "syncpull": return val ? `setup sync-pull settings-sync-pull-owner-live ${val}` : null;
    case "remote": return sv ? `daemon remote-run arm-remote-shell-read-diagnostic-bounded ${sv}` : null;
    case "imagefrontier": return val ? `daemon image-frontier arm-frontier-image-egress-unredactable ${val}` : null;
    default: return null;
  }
}

// ── B⑬ Plan Mode rendering: PLAN → editable checklist → Approve & Run the approved subset ──
// `orchestrate_plan` returns the canonical SUBTASK lines (INERT — no implement/synthesis yet); the
// owner unchecks any to skip; `orchestrate_run` IMPLEMENTS+SYNTHESIZES the approved subset (the core
// re-validates the approved lines through the SAME grammar parser). The plan is inert until approved.
let planmodeTask = "";
let planmodeLines = [];
function renderPlanmodeChecklist(out) {
  if (!out) return;
  if (!planmodeLines.length) { out.innerHTML = `<div class="viewer-msg">no sub-tasks (the planner produced none)</div>`; return; }
  const items = planmodeLines
    .map((line, i) => `<label class="pm-item" style="display:block;margin:2px 0;"><input type="checkbox" data-pm-idx="${i}" checked /> <span class="mono">${esc(line)}</span></label>`)
    .join("");
  out.innerHTML = `<div class="pm-head" style="opacity:.7;margin:6px 0;">Review the plan — uncheck any sub-task to skip it, then approve.</div>`
    + `<div class="pm-list">${items}</div>`
    + `<button class="suggest" data-planmode-run><span class="sg-glyph">▶</span>Approve &amp; Run</button>`;
  const run = out.querySelector("[data-planmode-run]");
  if (run) run.addEventListener("click", () => submitPlanmodeRun(out));
}
async function submitPlanmodeRun(out) {
  const approved = planmodeLines.filter((_, i) => {
    const cb = out.querySelector(`[data-pm-idx="${i}"]`);
    return cb && cb.checked;
  });
  if (!approved.length) { toast("approve at least one sub-task"); return; }
  out.innerHTML = `<div class="viewer-msg">running ${approved.length} sub-task(s) — implement + synthesize…</div>`;
  let res;
  try { res = await invoke("orchestrate_run", { payload: { phrase: "orchestrate-two-model-live", task: planmodeTask, approved } }); }
  catch (e) { out.innerHTML = `<div class="viewer-msg">run failed: ${esc(e && e.message ? e.message : e)}</div>`; return; }
  // Render the REAL per-worker fleet the backend returns (id/kind/model/port/verdict/admits/
  // preview). Fixes the owner's "I can't tell if the worker loop even runs" — it was reading a
  // dead `res.subtasks` field (orchestrate_run returns `workers`), so the fleet was discarded.
  const workers = Array.isArray(res.workers) ? res.workers : [];
  const rows = workers.map((w) => {
    const ok = w.admits ? '<span class="pm-ok">✓ admits</span>' : '<span class="pm-no">✗ rejected</span>';
    const prev = w.preview ? `<div class="pm-preview mono">${esc(w.preview)}</div>` : "";
    return `<div class="pm-worker"><div class="mono pm-verdict"><b>#${w.id} ${esc(w.kind)}</b> · ${esc(w.model_id)} · :${w.port} · ${ok} · ${esc(w.verdict)}</div>${prev}</div>`;
  }).join("");
  const fleet = rows || `<div class="viewer-msg">no workers ran</div>`;
  const synth = res.synthesis ? `<div class="pm-synth mono">${esc(res.synthesis)}</div>` : `<div class="viewer-msg">no synthesis</div>`;
  out.innerHTML = `<div class="pm-head" style="opacity:.7;margin:6px 0;">stop=${esc(res.stop)} · ${workers.length} worker(s)</div>${fleet}`
    + `<div class="pm-head" style="opacity:.7;margin:8px 0 4px;">synthesis</div>${synth}`;
}
/* ── P2-S3: Settings as a CENTER tab (SS2 — left icon rail + sectioned content) ──
   The ⚙ opens Settings as a CENTER tab next to the file tabs (Cursor-style), NOT a
   modal overlay. A left rail switches sections; the first 7 sections REUSE the existing
   async builders (settingsPanelHTML / modelPanelHTML / privacyPanelHTML / walrusPanelHTML
   / flowsPanelHTML / auditPanelHTML) as their body — no duplication, single truth source —
   plus a NEW Editor section (GUI-owned localStorage prefs; no core, no egress). The modal
   (#panel) survives ONLY for the first-run disclosure + the quick-access agent-pane buttons
   (▤/⛁/⚡) and the model chip (owner-locked default: leave + also-in-rail). custody/funds stay
   HARD-LOCKED — these are read/preference surfaces, never a custody unlock. */
let settingsSection = "overview";
// [key, label, glyph] — the rail. The first 7 reuse the live builders; the last 3 are
// honest S4 placeholders (LoRA routing editor · skills · evidence) wired in later slices.
const SETTINGS_SECTIONS = [
  ["overview", "Overview", "command"],
  ["models", "Models · provider", "sparkles"],
  ["walrus", "Memory · Walrus", "database"],
  ["flows", "Agent · autonomy", "zap"],
  ["routing", "LoRA / routing", "list"],
  ["privacy", "Privacy · safety", "shield"],
  ["editor", "Editor", "edit"],
  ["general", "General", "settings"],
  ["host", "Host / Remote", "refresh"],
  ["audit", "Activity · audit", "clock"],
  ["skills", "Skills", "help"],
  ["evolution", "Evolution · perf", "undo"],
  ["evidence", "Evidence", "folder"],
  ["websetup", "Web / Setup", "plus"],
];

// GUI-owned preferences (LOCAL to this machine; localStorage; no core, no egress).
function getPref(key, dflt) { try { const v = localStorage.getItem(key); return v == null ? dflt : v; } catch (_) { return dflt; } }
function setPref(key, val) { try { localStorage.setItem(key, val); } catch (_) {} }
// Apply the persisted UI/code font sizes (called on init + after a change). The code
// font drives the viewer via the --code-font CSS var; the UI font is the body size.
function applyUiPrefs() {
  document.body.style.fontSize = getPref("sinabro.uiFont", "13px");
  document.documentElement.style.setProperty("--code-font", getPref("sinabro.codeFont", "12px"));
}

// NEW Editor section — REAL GUI-owned controls (localStorage only; no dispatch, no core).
function editorSettingsHTML() {
  const uiFont = getPref("sinabro.uiFont", "13px");
  const codeFont = getPref("sinabro.codeFont", "12px");
  const theme = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  return `
    <div class="set-title">Editor</div>
    <div class="set-lede">Appearance &amp; layout — local to this machine (localStorage), never off-box.</div>
    ${kGroup("Text")}
    ${kCard([
      kRow(icon("edit"), "UI font size", "Interface text.", kSeg(uiFont, [["12px", "Compact"], ["13px", "Default"], ["14px", "Comfortable"]], "data-ui-font")),
      kRow(icon("code"), "Code font size", "Viewer &amp; editor.", kSeg(codeFont, [["12px", "12"], ["13px", "13"], ["14px", "14"], ["15px", "15"]], "data-code-font")),
      kRow(icon("list"), "Soft wrap", "Wrap long lines in the code viewer.", kToggle(viewWrap, 'data-action="wrap-toggle"')),
    ])}
    ${kGroup("Appearance & layout")}
    ${kCard([
      kRow(icon("theme"), "Theme", "", kSeg(theme, [["dark", "Dark"], ["light", "Light"]], "data-theme-set")),
      kRow(icon("refresh"), "Pane widths", "Restore the default agent / files columns.", kBtn("Reset", 'data-layout-reset="1"', true)),
    ])}`;
}
// Honest placeholder for an S4 rail section not yet wired (never a fake control).
function s4PlaceholderHTML(title, slice) {
  return infoCardHTML([
    `${title} — dedicated surface lands in ${slice}`,
    "the core capability is already LIVE behind the dispatch bridge; this editor/view is the remaining GUI slice",
  ]);
}
/* ── P2-S4a: the dynamic-LoRA routing EDITOR (Settings → LoRA / Routing) ───────────────
   Reads + edits + SAVES the routing table the orchestrate verb + the autonomous evolve loop
   consume. ★ The GUI NEVER re-parses the config in JS ★ — it calls the CORE: read_routing_table
   (the SAME load the loops use) and write_routing_table (core builds → re-parse-validates →
   atomic-writes, fail-closed). NOT custody: a binding is a loopback port + a request-body
   model_id; no funds / wallet / chain (PD-6). The owner's Save click IS the authorization. */
function routingRowHTML(kind, port, model) {
  return `<div class="routing-row" data-routing-row>
      <input class="panel-input rt-kind" data-routing-kind value="${esc(kind)}" placeholder="kind (e.g. sui_move)" autocomplete="off" spellcheck="false" />
      <input class="panel-input rt-port" data-routing-port value="${esc(String(port))}" placeholder="port" inputmode="numeric" autocomplete="off" spellcheck="false" />
      <input class="panel-input rt-model" data-routing-model value="${esc(model)}" placeholder="model_id / adapter" autocomplete="off" spellcheck="false" />
      <button class="rt-del" data-routing-remove title="Remove this binding">✕</button>
    </div>`;
}
async function routingPanelHTML() {
  let view;
  try { view = await invoke("read_routing_table"); }
  catch (e) { view = { error: String(e && e.message ? e.message : e) }; }
  const title = `<div class="set-title">LoRA / routing</div><div class="set-lede">Map each expert kind to a (port · model_id) — a multi-LoRA server hot-swaps the adapter per sub-task.</div>`;
  if (!view || view.error) {
    return `${title}${kGroup("Dynamic-LoRA routing")}${kCard(kRow(icon("list"), "Routing unavailable", esc((view && view.error) || "no response"), kPill("error", "")))}`;
  }
  const intro = kCard(kFact("Config", esc(view.path || "routing_table.txt")));
  // Binding rows keep the routing-row primitive (data-routing-* inputs); the card wraps them.
  const rows = (view.entries || []).map((e) => routingRowHTML(e.kind, e.port, e.model_id)).join("");
  const bindings = `<div class="set-card"><div id="routing-rows">${rows}</div></div>`
    + kCard(kRow(icon("plus"), "Add a binding", "", kBtn("Add binding", "data-routing-add")));
  const d = view.default || { port: "", model_id: "" };
  const dflt = `<div class="set-card"><div class="routing-row routing-default" data-routing-default>
      <span class="rt-deflabel">default</span>
      <input class="panel-input rt-port" data-routing-default-port value="${esc(String(d.port))}" placeholder="port" inputmode="numeric" autocomplete="off" spellcheck="false" />
      <input class="panel-input rt-model" data-routing-default-model value="${esc(d.model_id)}" placeholder="default model_id" autocomplete="off" spellcheck="false" />
    </div></div>`;
  const save = kCard([
    kRow(icon("refresh"), "Save routing table", "core-validated · atomic", `<button class="set-btn rt-save" data-routing-save>Save</button>`),
    kRow(icon("shield"), "port = worker · model_id = adapter", "", kPill("hard-locked", "lock")),
  ]);
  // P2-S4f: ONE-CLICK "Connect an adapter" — pick a PEFT/LoRA folder, auto-read adapter_config.json,
  // check the expert kinds, Connect → builds the rows + SAVES through the SAME core write_routing_table.
  const adapterKinds = [
    ["audit", true], ["sui_move", false], ["solana_anchor", false],
    ["web3_frontend", false], ["nl_bridge", false],
  ].map(([k, on]) =>
    `<label class="adapter-kind" style="display:inline-flex;align-items:center;gap:4px;margin-right:10px"><input type="checkbox" data-adapter-kind value="${k}"${on ? " checked" : ""}/> ${esc(k)}</label>`
  ).join("");
  const connectCard = kCard([
    kRow(icon("folder"), "Choose an adapter folder", "PEFT/LoRA folder · base auto-detected", kBtn("Choose folder…", "data-adapter-pick")),
    `<div class="set-row" id="adapter-status"><div class="set-main"><div class="set-desc">no adapter picked yet</div></div></div>`,
    kRow(icon("code"), "Served model + port", "",
      `<input class="panel-input rt-model" data-adapter-model placeholder="served model id (e.g. naite-foundations)" autocomplete="off" spellcheck="false" /><input class="panel-input rt-port" data-adapter-port value="11434" placeholder="port" inputmode="numeric" autocomplete="off" spellcheck="false" />`),
    kRow(icon("list"), "Route these kinds", "",
      `<div style="display:flex;flex-wrap:wrap;gap:4px">${adapterKinds}<label class="adapter-kind" style="display:inline-flex;align-items:center;gap:4px"><input type="checkbox" data-adapter-default/> also set as default</label></div>`),
    kRow(icon("refresh"), "Connect adapter", "writes config · then serve it locally", kBtn("Connect adapter", "data-adapter-connect")),
  ]);
  return `${title}
    ${kGroup("Connect an adapter (one-click)")}
    ${connectCard}
    ${kGroup("Dynamic-LoRA routing")}
    ${intro}
    ${kGroup("Kind → (port · model_id) bindings")}
    ${bindings}
    ${kGroup("Default target (required)")}
    ${dflt}
    ${kGroup("Save")}
    ${save}`;
}
// Append a blank editable binding row (transient until Save; the core is the validator).
function addRoutingRow() {
  const rows = document.querySelector("#routing-rows");
  if (!rows) return;
  const wrap = document.createElement("div");
  wrap.innerHTML = routingRowHTML("", 11434, "");
  const row = wrap.firstElementChild;
  if (row) rows.appendChild(row);
}
// Collect the edited rows + default and SAVE through the core (write_routing_table). The JS
// port range check is UX-only (a clean message); the CORE is the sole validator (kind charset,
// non-empty model, build-then-reparse) — the GUI re-implements no config parsing.
async function saveRoutingTable() {
  const entries = [];
  for (const r of document.querySelectorAll("#routing-rows [data-routing-row]")) {
    const kind = (r.querySelector("[data-routing-kind]")?.value || "").trim();
    const portRaw = (r.querySelector("[data-routing-port]")?.value || "").trim();
    const model = (r.querySelector("[data-routing-model]")?.value || "").trim();
    if (!kind && !model && !portRaw) continue; // skip a fully-blank row
    const port = parseInt(portRaw, 10);
    if (!Number.isInteger(port) || port < 0 || port > 65535) { toast(`invalid port for "${kind || "(unnamed)"}" — 0..65535`); return; }
    entries.push({ kind, port, model_id: model });
  }
  const dPortRaw = (document.querySelector("[data-routing-default-port]")?.value || "").trim();
  const dModel = (document.querySelector("[data-routing-default-model]")?.value || "").trim();
  const dPort = parseInt(dPortRaw, 10);
  if (!Number.isInteger(dPort) || dPort < 0 || dPort > 65535) { toast("invalid default port — 0..65535"); return; }
  try {
    await invoke("write_routing_table", { payload: { entries, default_port: dPort, default_model: dModel } });
    toast("✓ routing table saved (core-validated + atomic)");
    if (editor.activePanel === "settings") fillCenterPanel();
  } catch (e) {
    toast("routing save refused: " + (e && e.message ? e.message : e));
  }
}
/* ── P2-S4f: ONE-CLICK adapter connect (the "어댑터 연결" delta on top of the S4a editor) ──
   pickAdapterFolder REUSES pick_folder (registers a read root) + read_file_view (lane-A walls +
   redaction; NO new Rust) to auto-detect the adapter's base model; connectAdapter MERGES the picked
   adapter onto the EXISTING table (never wipes other bindings) and SAVES through the SAME core
   write_routing_table (the sole fail-closed validator). HONEST: it writes config only — a local
   server must serve the model id on that port; sinabro never fakes a running adapter. */
async function pickAdapterFolder() {
  if (!window.__TAURI__ || !window.__TAURI__.core) { return toast("Adapter picker needs the desktop app."); }
  let path;
  try { path = await invoke("pick_folder"); }
  catch (e) { return toast("folder pick failed: " + (e && e.message ? e.message : e)); }
  if (!path) return; // owner cancelled
  // Best-effort metadata read (the folder is now a read root) — honest-degrade if absent.
  let base = "", peft = "";
  try {
    const view = await invoke("read_file_view", { path: path + "/adapter_config.json" });
    if (view && view.content) {
      const cfg = JSON.parse(view.content);
      base = String(cfg.base_model_name_or_path || "").trim();
      peft = String(cfg.peft_type || "").trim();
    }
  } catch (_) { /* no adapter_config.json here — never fabricate a base model */ }
  // Suggest a served model id from the folder basename (editable; must match the local server).
  const baseName = path.split("/").filter(Boolean).pop() || "adapter";
  const suggest = baseName.toLowerCase().replace(/[^a-z0-9_-]/g, "-").replace(/_/g, "-");
  const modelEl = document.querySelector("[data-adapter-model]");
  if (modelEl && !modelEl.value.trim()) modelEl.value = suggest;
  const statusEl = document.querySelector("#adapter-status");
  if (statusEl) {
    const detail = base ? `${esc(peft || "adapter")} · base ${esc(base)}` : "no adapter_config.json found here — type the served model id manually";
    statusEl.innerHTML = `<span class="mono">${esc(path)}</span><br><span class="lockchip">${detail}</span>`;
  }
  toast(base ? `📦 adapter read — base ${base}` : "📁 folder picked (no adapter_config.json — set the model id manually)");
}
async function connectAdapter() {
  const model = (document.querySelector("[data-adapter-model]")?.value || "").trim();
  const portRaw = (document.querySelector("[data-adapter-port]")?.value || "").trim();
  if (!model) { return toast("type a served model id (must match your local server)"); }
  const port = parseInt(portRaw, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) { return toast("invalid port — 0..65535"); }
  const kinds = [];
  for (const c of document.querySelectorAll("[data-adapter-kind]")) { if (c.checked) kinds.push(c.value); }
  if (!kinds.length) { return toast("check at least one expert kind to route to this adapter"); }
  // Merge onto the EXISTING table so connecting one adapter never drops the owner's other bindings.
  let view;
  try { view = await invoke("read_routing_table"); } catch (e) { view = { entries: [], default: null }; }
  const map = new Map();
  for (const en of (view.entries || [])) map.set(en.kind, { kind: en.kind, port: en.port, model_id: en.model_id });
  for (const k of kinds) map.set(k, { kind: k, port, model_id: model });
  const entries = [...map.values()];
  const setDefault = !!document.querySelector("[data-adapter-default]")?.checked;
  const curDefPort = view.default && Number.isInteger(view.default.port) ? view.default.port : port;
  const curDefModel = (view.default && view.default.model_id) || model;
  const default_port = setDefault ? port : curDefPort;
  const default_model = setDefault ? model : curDefModel;
  try {
    await invoke("write_routing_table", { payload: { entries, default_port, default_model } });
    toast(`✓ wired ${kinds.length} kind(s) → ${model} @ :${port} — now run a local server (ollama/mlx/vLLM) serving "${model}" on :${port}`);
    if (editor.activePanel === "settings") fillCenterPanel();
  } catch (e) {
    toast("connect refused: " + (e && e.message ? e.message : e));
  }
}
/* ── P2-S4b: the SKILLS section (Settings → Skills) ────────────────────────────────────
   Surfaces the LIVE skill/registry verbs (read-only) + `skill eval` (REAL Seatbelt sandbox,
   owner-gated, PROPOSE-only). RECONCILED on the real binary: `registry`/`skill` (bare) →
   a read-only status card (no `list`/`search` verb exists — never fake a skill enumeration);
   `skill eval <cmd>` WITHOUT the phrase → the core's gated LOCKED preview (state=LOCKED,
   approval=typed-phrase, `usage: skill eval skill-eval-owner-live <cmd>`) which gatedIntent
   recognizes ⇒ the S2 inline Confirm in the agent pane carries the consent (Continue injects
   the phrase + runs in the network-DENIED LocalWrite sandbox). NO new gate code — it reuses
   the S2 machinery. The model has no self-eval path. custody/funds untouched (PD-6). */
async function skillsPanelHTML() {
  const reg = await runCardHTML("registry");
  return `
    <div class="set-title">Skills</div>
    <div class="set-lede">Reproducible command bundles — run in a network-denied sandbox, owner-gated.</div>
    ${kGroup("Eval a command")}
    ${kCard(kRow(icon("command"), "Run in sandbox", "",
      `<input class="panel-input" data-skill-eval-input placeholder="/bin/echo ok  ·  cargo test" autocomplete="off" spellcheck="false" />` + kBtn("Eval", "data-skill-eval")))}
    ${kGroup("Registry")}
    ${`<div class="set-card">${reg}</div>`}
    ${kCard(kRow(icon("shield"), "Sandbox", "", kPill("network denied", "ok") + " " + kPill("hard-locked", "lock")))}`;
}
/* ── P2-S4c: the DGM-H PERF-LEDGER view (Settings → Evolution, read-only) ───────────────
   Surfaces the autonomy evolve loop's performance ledger — <data_dir>/evolution_ledger.txt
   (`key\treinforced\tdemoted`, written by the evolve loop). RECONCILED: the codec
   (the core's pure ledger parser + EVOLUTION_LEDGER_FILE) + verification::PerfScore + data_dir
   are ALL already pub ⇒ the GUI reads it via a thin Tauri command read_perf_ledger (NO prototype
   core change; the GUI never re-parses the ledger format in JS). DGM-H: reinforced = verified-good
   downstream, demoted = failed; a pattern is "confirmed" only after ≥1 verified-good AND never
   demoted (the model can never confirm itself — P-HALL). HONEST-EMPTY when nothing has evolved
   (NEVER a fabricated ledger). The pattern CONTENT lives in encrypted #sinabro-pattern memories
   (⛁ Walrus). READ-only; custody/funds untouched (PD-6). */
async function perfLedgerPanelHTML() {
  let view;
  try { view = await invoke("read_perf_ledger"); }
  catch (e) { view = { error: String(e && e.message ? e.message : e) }; }
  const title = `<div class="set-title">Evolution · perf</div><div class="set-lede">Each autonomously-evolved pattern carries a perf score — confirmed only after independent verification.</div>`;
  if (!view || view.error) {
    return `${title}${kGroup("Perf-ledger")}${kCard(kRow(icon("undo"), "Perf-ledger unavailable", esc((view && view.error) || "no response"), kPill("error", "")))}`;
  }
  const entries = view.entries || [];
  let table;
  if (!entries.length) {
    table = kCard(kRow(icon("undo"), "No patterns evolved yet", "Run an Evolve goal in Agent · autonomy.", kPill("empty", "")));
  } else {
    const rows = entries.map((e) => {
      const r = e.reinforced || 0, d = e.demoted || 0, net = r - d;
      const confirmed = r >= 1 && d === 0;
      return `<div class="perf-row">
          <span class="perf-key mono">${esc(String(e.key).slice(0, 12))}…</span>
          <span class="pill pill-truth ${confirmed ? "t-pass" : "t-unknown"}">${confirmed ? "confirmed" : "advisory"}</span>
          <span class="perf-stat">↑${esc(String(r))} ↓${esc(String(d))} · net ${esc(String(net))}</span>
        </div>`;
    }).join("");
    table = `<div class="set-card"><div class="perf-feed">${rows}</div></div>`;
  }
  return `${title}
    ${kGroup(`Tracked patterns${entries.length ? ` · ${entries.length}` : ""}`)}
    ${table}
    ${kCard(kRow(icon("shield"), "Oracle-gated · read-only", "", kPill("hard-locked", "lock")))}`;
}
/* ── P2-S4d: the AUDIT-DETECT runner (Settings → Evidence) ──────────────────────────────
   Surfaces the LIVE `audit detect <path>` verb (E11-2 ⑮). RECONCILED on the real binary:
   read-only (risk=read-only approval=none) — it RUNS immediately + renders an impact-ranked
   CANDIDATE report ("candidates=N files_scanned=M … direct_finding_count=0 … candidate !=
   finding: promotion needs a reproduced LOCAL repro receipt"). The GUI dispatches the verb;
   the report lands in the agent pane. A candidate is a LEAD, NEVER a finding — promotion goes
   through the owner-gated, kernel-sandboxed repro chokepoint, never the GUI, never auto. The
   model reaches detect only as a gated READ tool. custody/funds untouched (PD-6). */
async function evidencePanelHTML() {
  return `
    <div class="set-title">Evidence</div>
    <div class="set-lede">Scan a local tree for candidate leads — promotion stays owner-gated.</div>
    ${kGroup("Audit detect")}
    ${kCard(kRow(icon("folder"), "Scan a path", "",
      `<input class="panel-input" data-audit-detect-input placeholder="crates/  ·  src  ·  .  for cwd" autocomplete="off" spellcheck="false" />` + kBtn("Detect", "data-audit-detect")))}
    ${kGroup("Audit chain")}
    ${kCard(kRow(icon("shield"), "Inspect tamper-evident chain", "",
      kBtn("audit", 'data-panel-run="audit"') + " " + kBtn("evidence pack", 'data-panel-run="evidence pack"')))}
    ${kCard(kRow(icon("shield"), "Candidate ≠ finding", "", kPill("leads only", "ok") + " " + kPill("hard-locked", "lock")))}`;
}
/* ── P2-S4e: the WEB / ENV-SETUP guided chain (Settings → Web / Setup; owner Q2=A) ───────
   A guided, PER-STEP-APPROVED chain over LIVE verbs (RECONCILED on the real desktop-feature
   binary): `context web-search <q>` + `context web-fetch <url>` (E11-1, read-only approval=none,
   live source-linked advisory) → `daemon fetch <ARM_PHRASE> <url>` (E13-3 ⑲ owner-armed bounded
   GET to /tmp, SSRF-walled + 8-host allowlist; HONEST-DEGRADES to "transport not compiled" unless
   built with download-egress — NEVER a fake "done") → `tool run <cmd>` (no phrase ⇒ the gated
   LOCKED preview ⇒ the S2 inline Confirm carries the consent for the install exec). Each step is a
   SEPARATE owner action; the GUI dispatches the LIVE verb (no fake bypass, no fake automation). The
   download click is the owner ARM gesture (like the flows phrases); downloaded bytes are NEVER
   executed — only an explicit, gated install step runs. custody/funds HARD-LOCKED (PD-6). */
function webSetupPanelHTML() {
  return `
    <div class="set-title">Web / setup</div>
    <div class="set-lede">Search, fetch, download, install — each step a separate one-click action.</div>
    ${kGroup("Web — read-only")}
    ${kCard([
      kRow(icon("plus"), "Search the web", "",
        `<input class="panel-input" data-web-search-input placeholder="install ripgrep macos" autocomplete="off" spellcheck="false" />` + kBtn("Search", "data-web-search")),
      kRow(icon("folder"), "Fetch a page", "",
        `<input class="panel-input" data-web-fetch-input placeholder="https://…" autocomplete="off" spellcheck="false" />` + kBtn("Fetch", "data-web-fetch")),
    ])}
    ${kGroup("Setup — owner-gated")}
    ${kCard([
      kRow(icon("database"), "Download to /tmp", "armed · 8-host allowlist",
        `<input class="panel-input" data-download-input placeholder="https://allowlisted-host/…" autocomplete="off" spellcheck="false" />` + kBtn("Download", "data-download")),
      kRow(icon("command"), "Install step", "gated local exec",
        `<input class="panel-input" data-toolrun-input placeholder="brew install ripgrep" autocomplete="off" spellcheck="false" />` + kBtn("Propose", "data-toolrun")),
    ])}
    ${kCard(kRow(icon("shield"), "Downloaded bytes are never executed", "", kPill("per-step approval", "ok") + " " + kPill("hard-locked", "lock")))}`;
}
/* ── P4: Host / Remote (SSH) — the VM-lane picker (Cursor / VS Code / Zed Remote-SSH analog) ──
   sinabro runs its core LOCALLY or on a REMOTE SSH host (the VM lane): host=vm + an ssh_target ⇒
   the SAME dispatched argv is forwarded to `sinabro` on the remote box — the GUI "drives", the
   agent + its LOOPBACK model/LoRA server live on the remote. RESEARCH (VS Code/Cursor/Zed all
   split local-UI ↔ remote-server over SSH): ours is the argv-forwarding variant — `sinabro` is
   PRE-INSTALLED on the remote (no auto-uploaded server; simpler, honest). The backend is already
   hardened (charset-gated + POSIX-quoted argv [no CVE-2023-51385 injection] · destination validated
   so it can't be read as an ssh option · known_hosts TOFU-pin then fail-closed · BatchMode keys/
   agent only · NEVER a silent local fallback). Reuses the LIVE get_host/set_host commands; the model/
   LoRA transport stays loopback-only on whichever host runs sinabro. custody/funds/chain HARD-LOCKED
   on ANY host. */
async function hostPanelHTML() {
  let cfg;
  try { cfg = await invoke("get_host"); }
  catch (e) { cfg = { error: String(e && e.message ? e.message : e) }; }
  const title = `<div class="set-title">Host / remote</div><div class="set-lede">Run sinabro on THIS machine or forward to a remote SSH box — the GUI drives, the agent lives on the host.</div>`;
  if (!cfg || cfg.error) {
    return `${title}${kGroup("Host")}${kCard(kRow(icon("refresh"), "Host config unavailable", esc((cfg && cfg.error) || "no response"), kPill("error", "")))}`;
  }
  const isVm = cfg.mode === "vm";
  const target = cfg.ssh_target || "";
  const intro = kCard(kFact("Mode", `${esc(cfg.mode || "local")}${isVm && target ? " → " + esc(target) : ""}`));
  const modeRow = kCard(kRow(icon("zap"), "Current mode", "",
    kPill(isVm ? "remote" : "local", "ok") + (isVm ? kBtn("Switch to Local", "data-host-local", true) : "")));
  const remoteRow = kCard(kRow(icon("refresh"), "Remote SSH target", "",
    `<input class="panel-input" data-host-target placeholder="user@host[:port] (e.g. me@gpu-box:22)" value="${esc(target)}" autocomplete="off" spellcheck="false" />` + kBtn("Connect (SSH)", "data-host-save-vm") + kBtn("Test", "data-host-test", true)));
  const sec = kCard(kRow(icon("shield"), "Connection security", "", kPill("keys only", "ok") + " " + kPill("host-key pinned", "ok") + " " + kPill("no silent fallback", "ok")));
  const lock = kCard(kRow(icon("shield"), "Custody hard-locked on any host", "", kPill("hard-locked", "lock")));
  return `${title}
    ${kGroup("Where sinabro runs")}
    ${intro}
    ${kGroup("Mode")}
    ${modeRow}
    ${kGroup("Remote SSH target")}
    ${remoteRow}
    ${kGroup("Connection security")}
    ${sec}
    ${kGroup("Safety")}
    ${lock}`;
}
// Build ONE rail section's body. The first 7 REUSE the live builders (single truth
// source); editor is GUI-owned; the last ones are honest S4 placeholders.
// FACELIFT C — settings KIT helpers: build the visual cards/rows/controls concisely so
// EVERY section is a control panel, not a text dump. (label/desc/ctl are raw HTML so callers
// can pass pills/icons; callers esc() any user/text content.)
function kGroup(l) { return `<div class="set-group">${esc(l)}</div>`; }
function kCard(rows) { return `<div class="set-card">${(Array.isArray(rows) ? rows : [rows]).join("")}</div>`; }
function kRow(ico, label, desc, ctl) { return `<div class="set-row"><span class="set-ico">${ico || ""}</span><div class="set-main"><div class="set-label">${label}</div>${desc ? `<div class="set-desc">${desc}</div>` : ""}</div>${ctl ? `<div class="set-ctl">${ctl}</div>` : ""}</div>`; }
function kFact(label, value) { return `<div class="set-row set-fact"><div class="set-main"><div class="set-label">${label}</div></div>${value ? `<div class="set-ctl"><span class="set-val mono">${value}</span></div>` : ""}</div>`; }
function kSeg(cur, opts, attr) { return `<div class="seg">${opts.map(([v, l]) => `<button class="${v === cur ? "on" : ""}" ${attr}="${esc(v)}">${esc(l)}</button>`).join("")}</div>`; }
function kBtn(label, attr, ghost) { return `<button class="set-btn${ghost ? " ghost" : ""}" ${attr}>${esc(label)}</button>`; }
function kToggle(on, attr) { return `<div class="sw${on ? " on" : ""}" ${attr || ""}></div>`; }
function kPill(text, cls) { return `<span class="spill ${cls || ""}">${esc(text)}</span>`; }
// Split a "key=value · rest" core/info line into a readable fact row (label + mono value).
function kFactLine(line) {
  const s = String(line);
  const eq = s.indexOf("=");
  if (eq > 0 && eq < 28) return kFact(esc(s.slice(0, eq)), esc(s.slice(eq + 1)));
  return `<div class="set-row set-fact"><div class="set-main"><div class="set-desc">${esc(s)}</div></div></div>`;
}

// FACELIFT C — the Overview hub: a visual control panel (logo cards · toggles ·
// segmented controls · one-touch buttons) reflecting real state, wired to the core /
// prefs / rail navigation. Replaces the text-dump first impression.
function overviewSettingsHTML() {
  const theme = document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
  const mode = currentMode();
  const keyOk = keyPresent === true;
  const provDot = keyOk ? '<span class="sdot ok"></span>' : '<span class="sdot off"></span>';
  const provDesc = keyOk ? "OpenRouter key set · egress-gated" : "No key yet — set one to consult the frontier";
  const seg = (cur, opts, attr) => `<div class="seg">${opts.map(([v, l]) => `<button class="${v === cur ? "on" : ""}" ${attr}="${esc(v)}">${esc(l)}</button>`).join("")}</div>`;
  const L = CONNECTOR_LOGOS;
  return `
    <div class="set-title">Overview</div>
    <div class="set-lede">Everything sinabro can do — at a glance, one touch to change.</div>
    <div class="set-group">Brains</div>
    <div class="set-card">
      <div class="set-row">
        <span class="set-ico plain">${L.provider}</span>
        <div class="set-main"><div class="set-label">Frontier provider ${provDot}</div><div class="set-desc">${provDesc}</div></div>
        <div class="set-ctl"><button class="set-btn ghost" data-ov-nav="models">${keyOk ? "Change key" : "Set key"}</button></div>
      </div>
      <div class="set-row">
        <span class="set-ico">${icon("zap")}</span>
        <div class="set-main"><div class="set-label">Autonomy</div><div class="set-desc">How far it acts before asking. Funds &amp; keys stay locked in every mode.</div></div>
        <div class="set-ctl">${seg(mode, [["Ask-first", "Ask-first"], ["Auto-read", "Auto-read"], ["Bold", "Bold"]], "data-ov-mode")}</div>
      </div>
    </div>
    <div class="set-group">Memory</div>
    <div class="set-card">
      <div class="set-row">
        <span class="set-ico plain">${L.walrus}</span>
        <div class="set-main"><div class="set-label">Walrus memory <span class="spill ok">testnet</span></div><div class="set-desc">Encrypted two-tier memory — yours, on decentralized storage.</div></div>
        <div class="set-ctl"><button class="set-btn" data-ov-nav="walrus">Open</button></div>
      </div>
      <div class="set-row">
        <span class="set-ico">${icon("database")}</span>
        <div class="set-main"><div class="set-label">Encrypt every memory</div><div class="set-desc">Ciphertext leaves the machine; topics stay opaque on the network.</div></div>
        <div class="set-ctl"><div class="sw on" title="always on — secret-zero"></div></div>
      </div>
    </div>
    <div class="set-group">Connect</div>
    <div class="set-card">
      <div class="set-row">
        <span class="set-ico plain">${L.telegram}</span>
        <div class="set-main"><div class="set-label">Telegram</div><div class="set-desc">Approve &amp; drive the agent from your phone, redaction-walled.</div></div>
        <div class="set-ctl"><button class="set-btn ghost" data-ov-nav="general">Connect</button></div>
      </div>
    </div>
    <div class="set-group">Appearance &amp; safety</div>
    <div class="set-card">
      <div class="set-row">
        <span class="set-ico">${icon("theme")}</span>
        <div class="set-main"><div class="set-label">Theme</div></div>
        <div class="set-ctl">${seg(theme, [["dark", "Dark"], ["light", "Light"]], "data-theme-set")}</div>
      </div>
      <div class="set-row">
        <span class="set-ico">${icon("shield")}</span>
        <div class="set-main"><div class="set-label">Funds &amp; keys <span class="spill lock">hard-locked</span></div><div class="set-desc">Wallet · signing · chain-write are unrepresentable — not a toggle.</div></div>
        <div class="set-ctl"><div class="sw" style="opacity:.4;pointer-events:none"></div></div>
      </div>
    </div>`;
}
async function settingsSectionHTMLFor(section) {
  switch (section) {
    case "overview": return overviewSettingsHTML();
    case "general": return await settingsPanelHTML();
    case "editor": return editorSettingsHTML();
    case "host": return await hostPanelHTML();
    case "models": return await modelPanelHTML();
    case "privacy": return await privacyPanelHTML();
    case "walrus": return await walrusPanelHTML();
    case "flows": return flowsPanelHTML();
    case "mega": return megaPanelHTML();
    case "audit": return await auditPanelHTML();
    case "routing": return await routingPanelHTML();
    case "skills": return await skillsPanelHTML();
    case "evolution": return await perfLedgerPanelHTML();
    case "evidence": return await evidencePanelHTML();
    case "websetup": return webSetupPanelHTML();
    default: return overviewSettingsHTML();
  }
}
// The center Settings shell: a LEFT rail + a RIGHT content column (filled async).
function settingsCenterHTML() {
  const rail = SETTINGS_SECTIONS
    .map(([key, label, glyph]) => `<button class="settings-rail-item${key === settingsSection ? " on" : ""}" data-settings-section="${esc(key)}">
        <span class="sri-glyph">${icon(glyph)}</span><span class="sri-label">${esc(label)}</span>
      </button>`)
    .join("");
  return `<div class="settings-center">
      <div class="settings-rail">${rail}</div>
      <div class="settings-content" id="settings-content"><div class="panel-loading">loading…</div></div>
    </div>`;
}
// The synchronous shell for a center panel (extensible; S3 ships "settings").
function centerPanelShellHTML(kind) {
  return kind === "settings" ? settingsCenterHTML() : infoCardHTML([`panel=${esc(kind)} (no shell)`]);
}
// Fill the active center panel's content column asynchronously (mirrors how openPanel did
// loading… → await). Re-checks activePanel after the await so a navigate-away mid-fetch never
// writes into the wrong surface, then wires the section's actions (single truth: bindPanelActions).
async function fillCenterPanel() {
  if (editor.activePanel !== "settings") return;
  let html;
  try { html = await settingsSectionHTMLFor(settingsSection); }
  catch (e) { html = infoCardHTML([`section error=${esc(String(e && e.message ? e.message : e))}`]); }
  if (editor.activePanel !== "settings") return; // user closed / switched while awaiting
  const content = $("#settings-content");
  if (!content) return;
  content.innerHTML = html;
  bindPanelActions(content);
}
// Switch the active rail section (no full editor re-render — just reflect the rail then
// re-fill the content column).
function setSettingsSection(key) {
  settingsSection = key;
  $$(".settings-rail-item").forEach((b) => b.classList.toggle("on", b.dataset.settingsSection === key));
  const content = $("#settings-content");
  if (content) content.innerHTML = `<div class="panel-loading">loading…</div>`;
  fillCenterPanel();
}
// Open a CENTER tab (next to the file tabs). The open file (editor.active) STAYS open —
// just not focused — so closing the panel returns to it.
function openCenterPanel(kind, name, glyph) {
  if (!editor.panels.some((p) => p.panel === kind)) editor.panels.push({ panel: kind, name, glyph });
  editor.activePanel = kind;
  // FIX: a center panel (Settings) renders inside the CODE pane, which hero-mode hides on the
  // empty welcome screen ⇒ the panel would open invisibly. Leave hero-mode for the 3-pane.
  const b = $("#body"); if (b) b.classList.remove("hero-mode");
  renderEditor();
}
// Close a CENTER tab; if it was active, fall back to a file / diff / placeholder.
function closeCenterPanel(kind) {
  const i = editor.panels.findIndex((p) => p.panel === kind);
  if (i >= 0) editor.panels.splice(i, 1);
  if (editor.activePanel === kind) editor.activePanel = null;
  const s = currentSession();
  if ((!s || s.messages.length === 0) && !editor.activePanel && !editor.active && !editor.diffId) {
    const b = $("#body"); if (b) b.classList.add("hero-mode"); // nothing open + empty session ⇒ welcome hero again
  }
  renderEditor(); renderFiles();
}
// After a memory-only change (secret / telemetry) made FROM a settings surface, re-render it
// IN ITS CURRENT HOME: a still-open modal (privacy quick-access) re-renders the modal; otherwise
// the center Settings tab's section re-fills. Never pops the retired settings modal.
function settingsSurfaceRefresh(section) {
  if (panelOpen && section === "privacy") { openPanel("privacy"); return; } // toggled from the privacy quick-access modal
  settingsSection = section;
  if (editor.activePanel === "settings") { fillCenterPanel(); return; }
  openCenterPanel("settings", "Settings", "⚙");
}

function bindPanelActions(root) {
  $$("[data-theme-set]", root).forEach((b) =>
    b.addEventListener("click", () => { setTheme(b.dataset.themeSet); if (editor.activePanel === "settings") fillCenterPanel(); })
  );
  // FACELIFT C — Overview hub controls: one-touch nav to a rail section · set autonomy mode.
  $$("[data-ov-nav]", root).forEach((b) =>
    b.addEventListener("click", () => setSettingsSection(b.dataset.ovNav))
  );
  $$("[data-ov-mode]", root).forEach((b) =>
    b.addEventListener("click", () => { setAutonomyMode(b.dataset.ovMode); if (editor.activePanel === "settings") fillCenterPanel(); })
  );
  // P2-S3: Editor section (GUI-owned prefs; localStorage only). UI / code font apply
  // immediately + re-fill the section so the active choice reflects; layout reset clears the
  // persisted pane widths. No core, no egress.
  $$("[data-ui-font]", root).forEach((b) =>
    b.addEventListener("click", () => { setPref("sinabro.uiFont", b.dataset.uiFont); applyUiPrefs(); if (editor.activePanel === "settings") fillCenterPanel(); })
  );
  $$("[data-code-font]", root).forEach((b) =>
    b.addEventListener("click", () => { setPref("sinabro.codeFont", b.dataset.codeFont); applyUiPrefs(); if (editor.activePanel === "settings") fillCenterPanel(); })
  );
  $$("[data-layout-reset]", root).forEach((b) =>
    b.addEventListener("click", () => {
      try { localStorage.removeItem("sinabro.wAgent"); localStorage.removeItem("sinabro.wFiles"); } catch (_) {}
      const body = $("#body");
      if (body) { body.style.removeProperty("--w-agent"); body.style.removeProperty("--w-files"); }
      toast("layout reset — default pane widths restored");
    })
  );
  // Owner "왼쪽 프롬프트 창에 띄우지말고, 저 버튼 누르면 실제로 실행하고 보여줘": a panel/ceremony
  // button now RUNS its verb and shows the result INLINE in the panel (right below the button),
  // NEVER as a chat-conversation message. The chat pane stays the agent conversation.
  $$("[data-panel-run]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      if (b.disabled) return;
      b.disabled = true; b.classList.add("running");
      let card;
      try { card = await runLine(b.dataset.panelRun, b.dataset.panelRun.split(/\s+/)[0]); }
      finally { b.disabled = false; b.classList.remove("running"); }
      root.querySelectorAll(".panel-run-result").forEach((el) => el.remove());
      const slot = document.createElement("div");
      slot.className = "panel-run-result";
      slot.style.marginTop = "10px";
      (b.closest(".set-card") || b).insertAdjacentElement("afterend", slot);
      slot.innerHTML = cardHTML(card);
      slot.scrollIntoView({ behavior: "smooth", block: "nearest" });
    })
  );
  // TIER-2 (B#4): config.toml editor — collect non-empty fields → the gated setup-persist
  // verb (the CORE validates + secret-screens + atomic-writes; no new IPC, no JS gate).
  $$("[data-config-save]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      const pairs = [];
      $$("[data-config-key]", root).forEach((inp) => { const v = (inp.value || "").trim(); if (v) pairs.push(`${inp.dataset.configKey}=${v}`); });
      if (!pairs.length) { toast("config: nothing to save (all fields empty)"); return; }
      const card = await runLine("setup persist config-persist-owner-live " + pairs.join(" "), "setup persist");
      const ok = String(card.truth || "").toUpperCase() === "GREEN"
        || (card.body || []).some((l) => /truth=PASS|parsed_back=true|bytes=\d/.test(String(l)));
      toast(ok ? "✓ config saved → ~/.mnemos/config.toml" : ("config: " + ((card.body && card.body[card.body.length - 1]) || "not saved")));
    })
  );
  // Secrets: set/clear go straight to the backend process env (memory only).
  // The value is read from the password input, sent once, and the input is
  // cleared immediately — it is never stored in `state` or rendered back.
  $$("[data-secret-set]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      const env = b.dataset.secretSet;
      const input = root.querySelector(`[data-secret-input="${env}"]`);
      const value = input && input.value ? input.value : "";
      if (!value) { toast("empty — not set"); return; }
      try {
        await invoke("set_secret", { name: env, value });
        if (input) input.value = "";
        toast(env + " set (memory only)");
        settingsSurfaceRefresh("general");
        refreshKeyPresence(); // A#13: clear the empty-screen no-key nudge once a key is set
      } catch (e) { toast("set failed: " + (e && e.message ? e.message : e)); }
    })
  );
  $$("[data-secret-clear]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      const env = b.dataset.secretClear;
      try {
        await invoke("clear_secret", { name: env });
        toast(env + " cleared");
        settingsSurfaceRefresh("general");
        refreshKeyPresence(); // A#13: re-show the empty-screen no-key nudge once a key is cleared
      } catch (e) { toast("clear failed: " + (e && e.message ? e.message : e)); }
    })
  );
  // E14-W2: enter a memory's SUB-STORE — fetch + decrypt its detail from Walrus.
  // READ-only (the agent roams freely); the backend applies the canonical redaction
  // belt, so a secret-shaped memory comes back WITHHELD, never rendered.
  $$("[data-walrus-fetch]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      const id = b.dataset.walrusFetch;
      const slot = root.querySelector("#walrus-detail");
      if (slot) slot.innerHTML = `<div class="panel-row"><span class="lockchip">fetching id=${esc(String(id))} from Walrus sub-store + decrypting…</span></div>`;
      let view;
      try { view = await invoke("walrus_memory_fetch", { id: Number(id) }); }
      catch (e) { view = { kind: "unavailable", reason: String(e && e.message ? e.message : e) }; }
      if (!slot) return;
      if (view && view.kind === "detail") {
        slot.innerHTML = infoCardHTML([`id=${esc(String(view.id))} · fetched from sub-store + decrypted locally · ciphertext-only on the wire`])
          + `<pre class="walrus-detail-body">${esc(view.content)}</pre>`;
      } else if (view && view.kind === "withheld") {
        slot.innerHTML = `<div class="panel-row"><span class="lockchip">id=${esc(String(view.id))} withheld — secret-shaped memory (decrypted locally but not rendered)</span></div>`;
      } else {
        const reason = (view && view.reason) || "fetch failed";
        slot.innerHTML = `<div class="panel-row"><span class="lockchip">${esc(reason)}</span></div>`;
      }
    })
  );
  // P1-6: Agent flows — orchestrate (two-model) + evolve (autonomous R-E-W). Reads the
  // task/goal input, auto-injects the owner-armed phrase (the GUI run IS the approval, like
  // the chat consult), and dispatches the REAL core verb; the core stays the sole verifier
  // (redaction + bounds + the class-typed ORACLE gate). Empty input ⇒ no dispatch.
  $$("[data-flow-run]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const kind = b.dataset.flowRun;
      const input = root.querySelector(`[data-flow-input="${kind}"]`);
      const val = input && input.value ? input.value.trim() : "";
      if (!val) { toast(kind === "orchestrate" ? "enter a task first" : "enter a goal first"); return; }
      const line = kind === "orchestrate"
        ? `provider orchestrate orchestrate-two-model-live ${val}`
        : `daemon evolve autonomous-evolve-write-live ${val}`;
      closePanel();
      dispatch(line);
    })
  );
  // MEGA capabilities: each control dispatches an ALREADY-LIVE core verb (auto-injecting the
  // owner-armed phrase where required) through the SAME bridge the chat uses; empty input ⇒ skip.
  $$("[data-mega-run]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const line = megaWire(b.dataset.megaRun, root);
      if (!line) { toast("enter a value first"); return; }
      closePanel();
      dispatch(line);
    })
  );
  // B⑬ Plan Mode: run ONLY the frontier PLAN → render the sub-tasks as a checklist (each
  // disable-able) → on Approve & Run, IMPLEMENT+SYNTHESIZE the APPROVED subset. The plan is INERT
  // until approved; the phrase is auto-injected (egress gate) and the core re-validates the lines.
  $$("[data-planmode-plan]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      const input = root.querySelector('[data-flow-input="planmode"]');
      const task = input && input.value ? input.value.trim() : "";
      if (!task) { toast("enter a task to plan first"); return; }
      const out = root.querySelector("#planmode-result");
      if (out) out.innerHTML = `<div class="viewer-msg">planning…</div>`;
      let res;
      try { res = await invoke("orchestrate_plan", { payload: { phrase: "orchestrate-two-model-live", task } }); }
      catch (e) { if (out) out.innerHTML = `<div class="viewer-msg">plan failed: ${esc(e && e.message ? e.message : e)}</div>`; return; }
      planmodeTask = task;
      planmodeLines = (res && res.subtasks) || [];
      renderPlanmodeChecklist(out);
    })
  );
  // P2-S4b: Skills — `skill eval <cmd>` dispatched WITHOUT the phrase ⇒ the core returns the
  // gated LOCKED preview ⇒ the S2 inline Confirm (in the agent pane) carries the consent
  // (Continue injects skill-eval-owner-live + runs in the network-DENIED sandbox). The GUI
  // re-implements NO gate; the core is the sole verifier. Empty input ⇒ no dispatch.
  $$("[data-skill-eval]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const input = root.querySelector("[data-skill-eval-input]");
      const val = input && input.value ? input.value.trim() : "";
      if (!val) { toast("enter a command to eval first"); return; }
      dispatch("skill eval " + val);
    })
  );
  // P2-S4d: Audit detect — `audit detect <path>` is read-only (approval=none) ⇒ it runs + the
  // ranked candidate report lands in the agent pane (no gate). Empty path ⇒ "." (cwd). The core
  // is the sole engine; the GUI only dispatches the LIVE verb (candidate != finding).
  $$("[data-audit-detect]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const input = root.querySelector("[data-audit-detect-input]");
      const val = input && input.value ? input.value.trim() : ".";
      dispatch("audit detect " + (val || "."));
    })
  );
  // P2-S4e: web/env-setup guided chain — each step dispatches a LIVE verb (the core is the sole
  // gate/verifier). search/fetch = read-only (run immediately) ; download = the owner-armed bounded
  // GET (the Download click is the arm gesture; honest-degrades without download-egress) ; install =
  // `tool run <cmd>` no-phrase ⇒ the gated preview ⇒ S2 inline Confirm carries consent.
  $$("[data-web-search]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const v = (root.querySelector("[data-web-search-input]")?.value || "").trim();
      if (!v) { toast("enter a search query first"); return; }
      dispatch("context web-search " + v);
    })
  );
  $$("[data-web-fetch]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const v = (root.querySelector("[data-web-fetch-input]")?.value || "").trim();
      if (!v) { toast("enter a URL to fetch first"); return; }
      dispatch("context web-fetch " + v);
    })
  );
  $$("[data-download]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const v = (root.querySelector("[data-download-input]")?.value || "").trim();
      if (!v) { toast("enter an https URL to download first"); return; }
      dispatch("daemon fetch arm-download-bounded-revocable " + v);
    })
  );
  $$("[data-toolrun]", root).forEach((b) =>
    b.addEventListener("click", () => {
      const v = (root.querySelector("[data-toolrun-input]")?.value || "").trim();
      if (!v) { toast("enter an install command first"); return; }
      dispatch("tool run " + v);
    })
  );
  // P4: Host / Remote (SSH) — reuse the LIVE get_host/set_host. Local clears the vm target;
  // Connect saves host=vm (the core's parse_target validates user@host[:port], M3); Test
  // dispatches `status` (routes per the saved host → the remote if vm; a typed error if
  // unreachable / sinabro absent — NEVER a silent local fallback). The model has no path here.
  $$("[data-host-local]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      try { await invoke("set_host", { mode: "local", sshTarget: null }); toast("host = local (this machine)"); }
      catch (e) { toast("set host failed: " + (e && e.message ? e.message : e)); }
      if (editor.activePanel === "settings") fillCenterPanel();
    })
  );
  $$("[data-host-save-vm]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      const t = (root.querySelector("[data-host-target]")?.value || "").trim();
      if (!t) { toast("enter an ssh target: user@host[:port]"); return; }
      try {
        await invoke("set_host", { mode: "vm", sshTarget: t });
        toast("host = remote (SSH) → " + t + " · press Test to verify");
      } catch (e) { toast("invalid ssh target: " + (e && e.message ? e.message : e)); }
      if (editor.activePanel === "settings") fillCenterPanel();
    })
  );
  $$("[data-host-test]", root).forEach((b) =>
    b.addEventListener("click", () => { toast("testing host → running status…"); dispatch("status"); })
  );
  // R7b: opt-in telemetry toggle (memory-only env via set_telemetry; never disk).
  $$("[data-telemetry-set]", root).forEach((b) =>
    b.addEventListener("click", async () => {
      const on = b.dataset.telemetrySet === "on";
      try {
        await invoke("set_telemetry", { on });
        toast(on ? "telemetry enabled (opt-in; local spans only)" : "telemetry disabled");
        settingsSurfaceRefresh("privacy");
      } catch (e) { toast("telemetry toggle failed: " + (e && e.message ? e.message : e)); }
    })
  );
}
async function openPanel(kind) {
  const p = $("#panel");
  if (!p) return;
  const titleEl = $("#panel-title");
  const body = $("#panel-body");
  const panelTitles = { model: "Model · provider", privacy: "Privacy · safety", audit: "Activity · audit", walrus: "Memory · Walrus (2-tier)", flows: "Agent flows · orchestrate · evolve", disclosure: "What sinabro can do" };
  if (titleEl) titleEl.textContent = panelTitles[kind] || "Settings";
  if (body) body.innerHTML = `<div class="panel-loading">loading…</div>`;
  p.hidden = false;
  panelOpen = true;
  let html;
  try {
    html = kind === "model" ? await modelPanelHTML() : kind === "privacy" ? await privacyPanelHTML() : kind === "audit" ? await auditPanelHTML() : kind === "walrus" ? await walrusPanelHTML() : kind === "flows" ? flowsPanelHTML() : kind === "mega" ? megaPanelHTML() : kind === "disclosure" ? disclosurePanelHTML() : await settingsPanelHTML();
  } catch (e) {
    html = infoCardHTML([`panel error=${String(e && e.message ? e.message : e)}`]);
  }
  if (!panelOpen) return; // user closed it while awaiting dispatch
  if (body) { body.innerHTML = html; bindPanelActions(body); }
}
function closePanel() { const p = $("#panel"); if (p) p.hidden = true; panelOpen = false; }

/* ── honest model label (fetched once) ───────────────────────────────────── */
async function refreshModelLabel() {
  if (!hasTauri()) return;
  try {
    const p = parseResponse(await invoke("dispatch_line", { line: "provider status" }));
    const cfg = p.body.find((l) => l.startsWith("providers_configured="));
    const n = cfg ? parseInt(cfg.split("=")[1], 10) : 0;
    const label = n > 0 ? `provider · ${n}` : "local · executor";
    const top = $("#model-label"); if (top) top.textContent = label;
    const mini = $("#model-mini"); if (mini) mini.textContent = label;
    const st = $("#status-model"); if (st) st.textContent = label;
  } catch (_) {}
}

/* ── R6 status meter (HW · token budget · TPS) ────────────────────────────────
   The "local signature" status bar. Backed by the STRUCTURED read_status_view
   command (never emit-text parsing — the R4.5 lesson). Honest by construction:
   cores is a real std probe, budget is the real pre-dispatch token gate, tps is
   "—" until a live consult measures throughput (no fake numbers). */
function humanTokens(n) {
  if (n == null) return "—";
  if (n >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (n >= 1e3) return (n / 1e3).toFixed(0) + "k";
  return String(n);
}
async function refreshStatus() {
  if (!hasTauri()) return;
  let s;
  try { s = await invoke("read_status_view"); } catch (_) { return; }
  if (!s) return;
  const hw = $("#st-hw-v");
  if (hw) hw.textContent = s.cores != null ? `${s.cores} cores` : "—";
  const bud = $("#st-budget-v");
  if (bud) bud.textContent = `${humanTokens(s.budget_tokens)} tok`;
  const tps = $("#st-tps-v");
  if (tps) tps.textContent = s.tps != null ? `${s.tps}` : "—";
}

/* ── toast + notifications log (S-D: stacking; important failures no longer vanish) ──── */
// In-memory notifications ring (newest first; TRANSIENT — never persisted to sessions).
// EVERY toast is also logged here, so a failure that scrolled past its 3.8s toast is
// still recoverable in the 🔔 notifications panel. Errors are auto-classified (by text)
// for a distinct border + a longer dwell.
let notifications = [];
const NOTIFICATIONS_CAP = 40;
let notificationsOpen = false;
function toastKind(msg) {
  return /fail|refus|denied|error|❌|✕|could not|cannot|unavailable|secret-shaped|wrong phrase/i.test(String(msg))
    ? "error" : "info";
}
function toast(msg, kind) {
  const text = String(msg);
  const k = kind || toastKind(text);
  notifications.unshift({ msg: text, time: nowLabel(), kind: k });
  if (notifications.length > NOTIFICATIONS_CAP) notifications.length = NOTIFICATIONS_CAP;
  if (notificationsOpen) renderNotifications();
  let stack = document.getElementById("toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.id = "toast-stack";
    stack.setAttribute("style", "position:fixed;left:50%;bottom:24px;transform:translateX(-50%);display:flex;flex-direction:column;gap:8px;align-items:center;z-index:10000;pointer-events:none;max-width:80vw;");
    document.body.appendChild(stack);
  }
  // S-D: each toast STACKS (no longer overwrites a single node) so a burst of failures is
  // all visible at once; the oldest visible drops past a small cap.
  const t = document.createElement("div");
  t.className = "toast-item";
  t.setAttribute("style", "pointer-events:auto;position:static;max-width:520px;padding:9px 13px;border-radius:8px;font-size:13px;line-height:1.35;background:var(--panel,#1b1d23);color:var(--fg,#e6e6e6);border:1px solid " + (k === "error" ? "var(--danger,#e0564f)" : "var(--border,#3a3d44)") + ";box-shadow:0 6px 24px rgba(0,0,0,.4);opacity:0;transition:opacity .25s;");
  t.textContent = text;
  stack.appendChild(t);
  while (stack.children.length > 4) stack.removeChild(stack.firstChild);
  requestAnimationFrame(() => { t.style.opacity = "1"; });
  const ttl = k === "error" ? 6000 : 3800; // failures dwell longer (papercut: vanish in 3.8s)
  setTimeout(() => { t.style.opacity = "0"; setTimeout(() => { if (t.parentNode === stack) stack.removeChild(t); }, 300); }, ttl);
}

// S-D: the notifications panel — a scrollback of recent toasts (mirrors the rewind-history
// panel). Opened from the 🔔 topbar button; Esc / ✕ closes; "clear" empties it. Transient +
// GUI-local (no IPC, never persisted).
function ensureNotifications() {
  let p = document.getElementById("notifications-panel");
  if (p) return p;
  p = document.createElement("div");
  p.id = "notifications-panel";
  p.setAttribute("style", "position:fixed;right:20px;top:64px;width:min(520px,46vw);max-height:70vh;display:none;flex-direction:column;z-index:9998;background:var(--panel,#1b1d23);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.45);overflow:hidden;");
  p.innerHTML = '<div style="display:flex;gap:8px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--border,#3a3d44);">'
    + '<span style="font-size:12px;opacity:.7;white-space:nowrap;flex:1;">notifications</span>'
    + '<button data-notif-clear title="Clear" style="background:none;border:none;color:var(--fg,#e6e6e6);opacity:.6;cursor:pointer;font-size:12px;">clear</button>'
    + '<button data-notif-close title="Close (esc)" style="background:none;border:none;color:var(--fg,#e6e6e6);opacity:.6;cursor:pointer;font-size:14px;">✕</button>'
    + '</div>'
    + '<div id="notif-results" style="overflow:auto;padding:6px 8px;font-size:12px;"></div>';
  document.body.appendChild(p);
  p.addEventListener("click", (e) => {
    if (e.target.closest("[data-notif-close]")) { closeNotifications(); return; }
    if (e.target.closest("[data-notif-clear]")) { notifications = []; renderNotifications(); return; }
  });
  return p;
}
function openNotifications() {
  const p = ensureNotifications();
  p.style.display = "flex";
  notificationsOpen = true;
  renderNotifications();
}
function closeNotifications() {
  if (!notificationsOpen) return false;
  const p = document.getElementById("notifications-panel");
  if (p) p.style.display = "none";
  notificationsOpen = false;
  return true;
}
function renderNotifications() {
  const p = document.getElementById("notifications-panel");
  if (!p) return;
  const out = p.querySelector("#notif-results");
  if (!out) return;
  out.innerHTML = notifications.length
    ? notifications.map((n) => `<div class="notif-row" style="display:flex;gap:8px;padding:4px 6px;border-radius:4px;border-left:2px solid ${n.kind === "error" ? "var(--danger,#e0564f)" : "var(--border,#3a3d44)"};margin-bottom:3px;"><span class="mono" style="opacity:.5;white-space:nowrap;">${esc(n.time)}</span><span style="flex:1;min-width:0;">${esc(n.msg)}</span></div>`).join("")
    : `<div style="opacity:.6;padding:4px;">no notifications yet</div>`;
}

/* ── chrome / global ─────────────────────────────────────────────────────── */
function setTheme(name) {
  // dark (default) / light. Legacy persisted values: crt -> dark, paper -> light.
  const light = name === "light" || name === "paper";
  document.documentElement.setAttribute("data-theme", light ? "light" : "dark");
  applyCmTheme();   // A④: mirror the theme into the live CM6 editor
}
function toggleTheme() {
  const cur = document.documentElement.getAttribute("data-theme");
  setTheme(cur === "light" ? "dark" : "light");
}
function bindChrome() {
  // Action buttons (static AND dynamically rendered — tree placeholders, the
  // "Open folder…" retry, etc.) are handled by delegation in the document click
  // listener below (handleAction). A per-element bind would miss anything
  // rendered after init.
  const f = $("#session-filter");
  if (f) f.addEventListener("input", renderSidebar);

  document.addEventListener("click", (e) => {
    // Outside-click closes the session popover (but not a click on the switcher
    // itself, nor inside the popover).
    const pop = $("#ss-popover");
    if (pop && !pop.hidden && !e.target.closest("#ss-popover") && !e.target.closest('[data-action="session-switcher"]')) closeSessionPopover();
    const actEl = e.target.closest("[data-action]");
    if (actEl) { handleAction(actEl.dataset.action); return; }
    const fmode = e.target.closest("[data-files-mode]");   // R8a: RIGHT-pane Files|Outline toggle
    if (fmode) { setFilesMode(fmode.dataset.filesMode); return; }
    const sg = e.target.closest("[data-suggest]");
    if (sg) { const v = sg.dataset.suggest; if (v === "__palette__") openOverlay("palette"); else dispatch(v); return; }
    const c = e.target.closest("[data-connector]");
    if (c) {
      const id = c.dataset.connector;
      if (id === "provider") openPanel("model");
      // The gated preview card teaches the exact phrase + required envs; the
      // live send itself only fires when the user types the full command.
      else if (id === "telegram") dispatch("platform send");
      else if (id === "walrus") dispatch("memory status");
      return;
    }
    const copy = e.target.closest('[data-act="copy"]');
    if (copy) {
      const card = copy.closest(".msg-wrap").querySelector(".card-body");
      if (card && navigator.clipboard) navigator.clipboard.writeText(card.innerText).then(() => toast("Copied"));
      return;
    }
    const rerun = e.target.closest('[data-act="rerun"]');
    if (rerun && rerun.dataset.cmd) { dispatch(rerun.dataset.cmd); return; }
    const cardRun = e.target.closest("[data-card-run]");
    if (cardRun && cardRun.dataset.cardRun) { dispatch(cardRun.dataset.cardRun); return; }
    // S2 (SS1): inline Cancel / Continue on a gated confirm card — Continue runs the
    // action IN PLACE (no conversation break); Cancel dismisses it without running. The
    // core stays the sole verifier (phrase + redaction + bounds).
    const cancelBtn = e.target.closest("[data-cancel-intent]");
    if (cancelBtn) { cancelIntent(cancelBtn.dataset.cancelIntent); return; }
    const intentBtn = e.target.closest("[data-approve-intent]");
    if (intentBtn) { approveIntent(intentBtn.dataset.approveIntent); return; }
  });

  const oi = $("#overlay-input");
  if (oi) {
    oi.addEventListener("input", () => renderOverlay(oi.value));
    oi.addEventListener("keydown", (e) => {
      const n = (ov._filtered || []).length;
      if (!n) { if (e.key === "Escape") closeOverlay(); return; }
      if (e.key === "ArrowDown") { e.preventDefault(); ov.active = (ov.active + 1) % n; renderOverlay(oi.value); }
      else if (e.key === "ArrowUp") { e.preventDefault(); ov.active = (ov.active - 1 + n) % n; renderOverlay(oi.value); }
      else if (e.key === "Enter") { e.preventDefault(); chooseOverlay(ov.active); }
      else if (e.key === "Escape") { e.preventDefault(); closeOverlay(); }
    });
  }
  $("#overlay")?.addEventListener("click", (e) => { if (e.target.id === "overlay") closeOverlay(); });
  $("#panel")?.addEventListener("click", (e) => { if (e.target.id === "panel") closePanel(); });
  // A session pick inside the popover closes it. Capture runs BEFORE the
  // per-row switch handler (which renderSidebar re-attaches), so e.target is
  // still in the popover subtree; defer the close so the switch completes.
  $("#ss-popover")?.addEventListener("click", (e) => { if (e.target.closest(".session")) setTimeout(closeSessionPopover, 0); }, true);
  // R3: file tree (RIGHT) + editor tabs (CENTER) — delegated on the persistent
  // container elements (their innerHTML is re-rendered; the listener survives).
  $("#files-body")?.addEventListener("click", onFilesClick);
  $("#code-tabs")?.addEventListener("click", onTabsClick);
  $("#code-body")?.addEventListener("click", onCodeBodyClick);
  // P6: inline FIM — delegated on the persistent #code-body (the edit textarea is re-rendered).
  $("#code-body")?.addEventListener("input", (e) => { if (e.target && e.target.id === "viewer-edit-area") onEditInput(e.target); });
  $("#code-body")?.addEventListener("keydown", (e) => { if (e.target && e.target.id === "viewer-edit-area") onEditKeydown(e, e.target); });
  // R8b: terminal dock — Enter routes `tool run <cmd>` through dispatch + the R7a gate.
  $("#term-input")?.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); runTerm(); } });

  document.addEventListener("keydown", (e) => {
    const meta = e.metaKey || e.ctrlKey;
    if (meta && e.key.toLowerCase() === "k") { e.preventDefault(); openOverlay("palette"); }
    else if (meta && e.key.toLowerCase() === "n") { e.preventDefault(); newSession(); }
    else if (meta && !e.shiftKey && /^[1-9]$/.test(e.key)) { e.preventDefault(); switchSessionByIndex(parseInt(e.key, 10) - 1); } // D#7: ⌘1-9 quick-switch
    else if (meta && e.shiftKey && e.key.toLowerCase() === "z") { e.preventDefault(); rewindLastEdit(); }
    // S-A: ⌘S save · ⌘P quick-open · ⌘G go-to-line. ⌘G yields to CM6's find-next when the
    // editor is focused (don't clobber the editor's own ⌘F/⌘G); ⌘F itself is never bound here.
    else if (meta && !e.shiftKey && e.key.toLowerCase() === "s") { e.preventDefault(); saveOwnerFile(); }
    else if (meta && !e.shiftKey && e.key.toLowerCase() === "p") { e.preventDefault(); openQuickOpen(); }
    else if (meta && !e.shiftKey && e.key.toLowerCase() === "g") {
      if (!(HAS_CM && cmView && cmView.hasFocus)) { e.preventDefault(); openGoToLine(); }
    }
    else if (e.key === "Escape") {
      // Most-transient first: popover → overlay → panel → quick-open → go-to-line → find
      // → GUI-abandon an in-flight turn → cancel a pending gated Confirm.
      const pop = $("#ss-popover");
      if (pop && !pop.hidden) { closeSessionPopover(); return; }
      if (!$("#overlay").hidden) { closeOverlay(); return; }
      if ($("#panel") && !$("#panel").hidden) { closePanel(); return; }
      if (closeQuickOpen()) return;
      if (closeGoToLine()) return;
      if (closeRewindHistory()) return;
      if (closeNotifications()) return;
      if (fifOpen) { closeFindPanel(); return; }
      if (abandonInFlight()) return;
      const k = latestLiveIntentKey();
      if (k != null) cancelIntent(k);
    }
  });
}

/* ── R2 IDE shell: session switcher · workspace root · splitters · terminal ── */
let uiRoot = null;
function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }

// Session switcher popover — reuses the persisted project/session store
// (renderSidebar → #projects). OUR model, IDE-integrated into the narrow agent
// pane: not a chat-app sidebar, not a Cursor clone. Opening re-renders the list;
// a pick closes it (see the capture listener in bindChrome).
function toggleSessionPopover() {
  const p = $("#ss-popover");
  if (!p) return;
  if (p.hidden) {
    p.hidden = false;
    renderSidebar();
    const f = $("#session-filter");
    if (f) setTimeout(() => { try { f.focus(); } catch (_) {} }, 0);
  } else {
    p.hidden = true;
  }
}
function closeSessionPopover() { const p = $("#ss-popover"); if (p) p.hidden = true; }

// Workspace root (the folder the file tree will index — R3). Reuses the SAME
// backend `pick_folder` as the composer "+", which registers the chosen folder
// as a read root (an owner-explicit capability grant — real, not fake). R2 only
// sets the label; the tree renders from `context index <root>` in R3.
async function openRoot() {
  closeSessionPopover();
  if (!hasTauri()) { toast("The folder picker needs the desktop app (cargo tauri dev)."); return; }
  try {
    const path = await invoke("pick_folder");
    if (!path) return; // owner cancelled
    setRoot(path);
    loadTree(path); // pick_folder already registered it as a read root
    loadProposals();
    toast("📁 indexing " + (String(path).split(/[\\/]/).pop() || path) + " …");
  } catch (e) {
    toast("folder pick failed: " + (e && e.message ? e.message : e));
  }
}
function setRoot(path) {
  uiRoot = path;
  const base = String(path).replace(/[\\/]+$/, "").split(/[\\/]/).pop() || path;
  const rl = $("#root-label"); if (rl) rl.textContent = base;
  const fr = $("#files-root"); if (fr) fr.textContent = base;
  try { localStorage.setItem("sinabro.root", path); } catch (_) {}
}
async function restoreRoot() {
  let r = null;
  try { r = localStorage.getItem("sinabro.root"); } catch (_) {}
  if (!r) return;
  setRoot(r);
  if (!hasTauri()) return;
  // Reopen-last-workspace: re-establish the read root the owner ALREADY granted
  // (the lane-A denylist / redaction / size walls still gate every access — no
  // silent NEW capability), then index it.
  try { await invoke("register_file_roots", { dirs: [r] }); } catch (_) {}
  loadTree(r);
}

// Resizable 3-pane shell: two splitters drive the grid columns (--w-agent /
// --w-files on #body); CENTER (1fr) absorbs the remainder. Widths persist
// (layout stability — the Cursor-churn lesson, research D-2/D-5).
function initSplitters() {
  const body = $("#body");
  if (!body) return;
  try {
    const wa = localStorage.getItem("sinabro.wAgent");
    const wf = localStorage.getItem("sinabro.wFiles");
    if (wa) body.style.setProperty("--w-agent", wa);
    if (wf) body.style.setProperty("--w-files", wf);
  } catch (_) {}
  $$(".splitter", body).forEach((sp) =>
    sp.addEventListener("mousedown", (e) => startDrag(e, sp, body))
  );
}
function startDrag(e, sp, body) {
  e.preventDefault();
  const which = sp.dataset.split; // "agent" | "files"
  const startX = e.clientX;
  const cs = getComputedStyle(body);
  const startA = parseInt(cs.getPropertyValue("--w-agent"), 10) || 340;
  const startF = parseInt(cs.getPropertyValue("--w-files"), 10) || 264;
  sp.classList.add("dragging");
  document.body.style.cursor = "col-resize";
  document.body.style.userSelect = "none";
  const move = (ev) => {
    const dx = ev.clientX - startX;
    if (which === "agent") body.style.setProperty("--w-agent", clamp(startA + dx, 240, 600) + "px");
    else body.style.setProperty("--w-files", clamp(startF - dx, 180, 560) + "px");
  };
  const up = () => {
    sp.classList.remove("dragging");
    document.body.style.cursor = "";
    document.body.style.userSelect = "";
    window.removeEventListener("mousemove", move);
    window.removeEventListener("mouseup", up);
    try {
      const cs2 = getComputedStyle(body);
      localStorage.setItem("sinabro.wAgent", cs2.getPropertyValue("--w-agent").trim());
      localStorage.setItem("sinabro.wFiles", cs2.getPropertyValue("--w-files").trim());
    } catch (_) {}
  };
  window.addEventListener("mousemove", move);
  window.addEventListener("mouseup", up);
}

// Terminal dock (CENTER, bottom) — structural placeholder; the gated local-exec
// surface (owner-ceremonied, Admin tier) wires in a later slice. No fake shell.
function toggleTerm() {
  const b = $("#term-body");
  const dock = $("#term-dock");
  if (!b) return;
  b.hidden = !b.hidden;
  if (dock) dock.classList.toggle("open", !b.hidden);
  if (!b.hidden) { const inp = $("#term-input"); if (inp) setTimeout(() => { try { inp.focus(); } catch (_) {} }, 0); }
}
// R8b: the terminal dock is a REAL gated-exec launcher (no fake shell). A typed
// command routes through the SAME dispatch + R7a gate: `tool run <cmd>` (no phrase)
// ⇒ a LOCKED intent-preview card in the agent pane ⇒ one Approve injects the
// `exec-local-owner-live` ceremony ⇒ the core runs it (Admin · env-scrubbed PATH/
// HOME/LANG/TERM only · no shell · argv-split · 10s timeout) and renders the exec
// receipt (argv · exit · duration · stdout/stderr, secret-shaped withheld). The GUI
// re-implements NOTHING — it only launches the real ceremony.
function runTerm() {
  const inp = $("#term-input");
  if (!inp) return;
  const cmd = inp.value.trim();
  if (!cmd) return;
  inp.value = "";
  dispatch("tool run " + cmd);
}

/* ── R3: file tree (context index) + click→open viewer (context file) ─────── */
// All backed by the REAL core (dispatch_line → dispatch::run); the GUI reads
// ZERO file bytes — only the gated core does, behind the lane-A walls (allowlist
// + denylist + size + redaction). No fake tree/viewer. Formats probed live
// 2026-06-11 (see G_WP_13). Path note: dispatch_line tokenizes on whitespace,
// so paths containing spaces are a known v1 limitation.
const tree = { project: null, model: null, expanded: new Set(), truncated: false, count: 0, loading: false, error: null, files: [] };
const editor = { open: [], active: null, diffId: null, panels: [], activePanel: null };
let filesMode = "tree"; // R8a: RIGHT pane shows the file tree ("tree") or the open file's outline ("outline")
let proposals = []; // pending model-authored file edits (R5); read-only until owner-approved
let inlineOracle = {}; // B⑧ Cmd-K: advisory Move-build oracle badge by proposal id (id -> label)

function relJoin(project, rel) {
  const base = String(project).replace(/[\\/]+$/, "");
  return rel ? base + "/" + rel : base;
}

// Centralized action handler (delegated, so dynamically rendered buttons work).
// Pane focus toggles — hide/show the left (chat) or right (files) pane so the center
// pane can fill the window (read code · or Settings full-screen). Persisted; the state
// is INDEPENDENT of Settings — opening Settings never re-shows a hidden pane (the owner:
// "full-screen Settings must not snap the side panes back on"). Suppressed under hero-mode.
function paneHidden(side) {
  try { return localStorage.getItem(side === "agent" ? "sinabro.hideAgent" : "sinabro.hideFiles") === "1"; }
  catch (_) { return false; }
}
function applyPaneVisibility() {
  const body = $("#body"); if (!body) return;
  const ha = paneHidden("agent"), hf = paneHidden("files");
  body.classList.toggle("hide-agent", ha);
  body.classList.toggle("hide-files", hf);
  const bl = $('[data-action="toggle-left"]'); if (bl) bl.classList.toggle("on", !ha);
  const br = $('[data-action="toggle-right"]'); if (br) br.classList.toggle("on", !hf);
}
function togglePane(side) {
  const key = side === "agent" ? "sinabro.hideAgent" : "sinabro.hideFiles";
  try { localStorage.setItem(key, paneHidden(side) ? "0" : "1"); } catch (_) {}
  applyPaneVisibility();
}

function handleAction(a) {
  if (a === "new-session") { newSession(); closeSessionPopover(); }
  else if (a === "session-switcher") toggleSessionPopover();
  else if (a === "palette") { closeSessionPopover(); openOverlay("palette"); }
  else if (a === "open-root") openRoot();
  else if (a === "refresh-tree") { if (uiRoot) loadTree(uiRoot); loadProposals(); }
  else if (a === "show-proposals") { if (proposals.length) { editor.activePanel = null; if (!editor.diffId || !proposals.some((x) => x.id === editor.diffId)) editor.diffId = proposals[0].id; renderEditor(); } }
  else if (a === "close-diff") { editor.diffId = null; renderEditor(); }
  else if (a === "wrap-toggle") { viewWrap = !viewWrap; try { localStorage.setItem("sinabro.wrap", viewWrap ? "1" : "0"); } catch (_) {} renderEditor(); }
  else if (a === "term-toggle") toggleTerm();
  else if (a === "settings") { closeSessionPopover(); closePanel(); openCenterPanel("settings", "Settings", "⚙"); }
  else if (a === "model") { closeSessionPopover(); openPanel("model"); }
  else if (a === "privacy") { closeSessionPopover(); openPanel("privacy"); }
  else if (a === "audit") { closeSessionPopover(); openPanel("audit"); }
  else if (a === "walrus") { closeSessionPopover(); openPanel("walrus"); }
  else if (a === "flows") { closeSessionPopover(); openPanel("flows"); }
  else if (a === "mega") { closeSessionPopover(); openPanel("mega"); }
  else if (a === "rewind") rewindLastEdit();
  else if (a === "rewind-history") openRewindHistory();
  else if (a === "notifications") openNotifications();
  else if (a === "disclosure") { closeSessionPopover(); openPanel("disclosure"); }
  else if (a === "theme") toggleTheme();
  else if (a === "toggle-left") togglePane("agent");
  else if (a === "toggle-right") togglePane("files");
  else if (a === "overlay-close") closeOverlay();
  else if (a === "panel-close") closePanel();
}

// (The emit-text `parseIndex` was retired: the tree now uses the backend
// `read_index_view` structured channel — full data, no 80x64 terminal-card cap.)

function buildTreeModel(entries) {
  const root = { name: "", type: "dir", path: "", size: null, children: new Map() };
  for (const e of entries) {
    const parts = e.path.split("/");
    let node = root;
    for (let i = 0; i < parts.length; i++) {
      const part = parts[i];
      const last = i === parts.length - 1;
      if (!node.children.has(part)) node.children.set(part, { name: part, type: last ? e.type : "dir", path: parts.slice(0, i + 1).join("/"), size: last ? e.size : null, children: new Map() });
      node = node.children.get(part);
      if (last) { node.type = e.type; node.size = e.size; }
    }
  }
  return root;
}
function sortedChildren(node) {
  return [...node.children.values()].sort((a, b) => (a.type !== b.type ? (a.type === "dir" ? -1 : 1) : a.name.localeCompare(b.name)));
}
function fmtSize(n) {
  if (n == null) return "";
  if (n < 1024) return n + " B";
  if (n < 1048576) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + " KB";
  return (n / 1048576).toFixed(1) + " MB";
}

async function loadTree(rootPath) {
  if (!rootPath) return;
  editor.open = []; editor.active = null; renderEditor();
  tree.loading = true; tree.error = null; renderFiles();
  // Structured data channel (backend read_index_view) — reuses the SAME core
  // lane-A walls as `context index`, but returns the FULL bounded tree (≤4096),
  // not the emit's ~57-row terminal-card slice.
  let view;
  try { view = await invoke("read_index_view", { path: rootPath }); }
  catch (e) { tree.loading = false; tree.model = null; tree.error = String(e && e.message ? e.message : e); renderFiles(); return; }
  tree.loading = false;
  if (!view || view.kind === "denied") { tree.model = null; tree.error = "index denied — " + ((view && view.reason) || "unknown"); renderFiles(); return; }
  if (view.kind === "withheld") { tree.model = null; tree.error = "index withheld — a name was secret-shaped (redaction)"; renderFiles(); return; }
  tree.project = view.root || rootPath;
  tree.truncated = !!view.truncated;
  const entries = (view.entries || []).map((e) => ({ type: e.dir ? "dir" : "file", path: e.path, size: e.dir ? null : e.size }));
  tree.count = entries.length;
  tree.files = entries.filter((e) => e.type === "file").map((e) => e.path); // P5: @-mention fuzzy search source
  tree.expanded = new Set(); // dirs collapsed by default; root children visible
  tree.model = buildTreeModel(entries);
  renderFiles();
}

function treePlaceholderHTML() {
  return `<div class="tree-placeholder">
      <div class="tph-title">No folder indexed</div>
      <div class="tph-sub">Pick a folder — its tree renders here (bounded, denylist-pruned), and click-to-open feeds the editor.</div>
      <button class="suggest" data-action="open-root"><span class="sg-glyph">›</span>Open folder…</button>
      <div class="tph-tag">tree + click→open · R3</div>
    </div>`;
}
function renderFiles() {
  const el = $("#files-body");
  if (!el) return;
  syncFilesModes();                                       // R8a: reflect the active Files|Outline toggle
  if (filesMode === "outline") { el.innerHTML = renderOutline(); return; }
  if (tree.loading) { el.innerHTML = `<div class="tree-status">indexing…</div>`; return; }
  if (tree.error) {
    el.innerHTML = `<div class="tree-placeholder">
        <div class="tph-title">Index unavailable</div>
        <div class="tph-sub">${esc(tree.error)}</div>
        <button class="suggest" data-action="open-root"><span class="sg-glyph">›</span>Open another folder…</button>
      </div>`;
    return;
  }
  if (!tree.model) { el.innerHTML = treePlaceholderHTML(); return; }
  const rows = renderTreeNodes(tree.model, 0).join("");
  const trunc = tree.truncated ? `<div class="tree-trunc">showing ${tree.count} entries (truncated) — pick a narrower folder for the full tree</div>` : "";
  el.innerHTML = `<div class="tree">${rows || `<div class="tree-status">empty folder</div>`}</div>${trunc}`;
}
function renderTreeNodes(node, depth) {
  const out = [];
  for (const c of sortedChildren(node)) {
    const pad = 8 + depth * 13;
    if (c.type === "dir") {
      const open = tree.expanded.has(c.path);
      out.push(`<div class="tnode tdir${open ? " open" : ""}" data-tdir="${esc(c.path)}" style="padding-left:${pad}px"><span class="tcaret">▸</span><span class="tname">${esc(c.name)}</span></div>`);
      if (open) out.push(...renderTreeNodes(c, depth + 1));
    } else {
      const active = editor.active === c.path ? " active" : "";
      out.push(`<div class="tnode tfile${active}" data-tfile="${esc(c.path)}" style="padding-left:${pad + 13}px" title="${esc(c.path)}"><span class="tname">${esc(c.name)}</span><span class="tsize">${esc(fmtSize(c.size))}</span></div>`);
    }
  }
  return out;
}
function onFilesClick(e) {
  // R8a: outline rows live in the same RIGHT-pane body when filesMode === "outline".
  const ol = e.target.closest("[data-outline-line]");
  if (ol) { jumpToLine(parseInt(ol.dataset.outlineLine, 10)); return; }
  const dir = e.target.closest("[data-tdir]");
  if (dir) { const p = dir.dataset.tdir; if (tree.expanded.has(p)) tree.expanded.delete(p); else tree.expanded.add(p); renderFiles(); return; }
  const file = e.target.closest("[data-tfile]");
  if (file) openFile(file.dataset.tfile);
}

/* ── R8a: code outline (RIGHT-pane Files|Outline toggle) ──────────────────────
   The open file's top-level symbols, extracted from the REAL bytes the gated core
   returned (read_file_view → editor.open[].lines) — never a fake/guessed tree. One
   regex set per language (validated against real source, the R4 discipline); click
   a symbol → proportional smooth-scroll the viewer to its line. Honest empty when a
   language has no rules or no symbols are found. Frontend only; no core change. */
function setFilesMode(m) { filesMode = m === "outline" ? "outline" : "tree"; renderFiles(); }
function syncFilesModes() { $$("[data-files-mode]").forEach((b) => b.classList.toggle("on", b.dataset.filesMode === filesMode)); }
const OUTLINE_RULES = {
  rust: [
    [/^\s*(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:async\s+)?(?:unsafe\s+)?(?:const\s+)?fn\s+([A-Za-z_]\w*)/, "fn"],
    [/^\s*(?:pub(?:\([^)]*\))?\s+)?struct\s+([A-Za-z_]\w*)/, "struct"],
    [/^\s*(?:pub(?:\([^)]*\))?\s+)?enum\s+([A-Za-z_]\w*)/, "enum"],
    [/^\s*(?:pub(?:\([^)]*\))?\s+)?trait\s+([A-Za-z_]\w*)/, "trait"],
    [/^\s*impl(?:\s*<[^>]*>)?\s+([A-Za-z_][\w:]*(?:\s+for\s+[A-Za-z_][\w:]*)?)/, "impl"],
    [/^\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_]\w*)/, "mod"],
    [/^\s*macro_rules!\s+([A-Za-z_]\w*)/, "macro"],
  ],
  js: [
    [/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/, "fn"],
    [/^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/, "class"],
    [/^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/, "fn"],
  ],
  ts: [
    [/^\s*(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s*\*?\s*([A-Za-z_$][\w$]*)/, "fn"],
    [/^\s*(?:export\s+)?(?:default\s+)?(?:abstract\s+)?class\s+([A-Za-z_$][\w$]*)/, "class"],
    [/^\s*(?:export\s+)?interface\s+([A-Za-z_$][\w$]*)/, "interface"],
    [/^\s*(?:export\s+)?type\s+([A-Za-z_$][\w$]*)/, "type"],
    [/^\s*(?:export\s+)?(?:const\s+)?enum\s+([A-Za-z_$][\w$]*)/, "enum"],
    [/^\s*(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)/, "fn"],
  ],
  python: [
    [/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)/, "def"],
    [/^\s*class\s+([A-Za-z_]\w*)/, "class"],
  ],
  shell: [[/^\s*(?:function\s+)?([A-Za-z_]\w*)\s*\(\)\s*\{?/, "fn"]],
  toml: [[/^\s*\[\[?\s*([^\]]+?)\s*\]\]?/, "section"]],
  yaml: [[/^([A-Za-z_][\w-]*):/, "key"]],
  md: [[/^(#{1,6})\s+(.+?)\s*#*\s*$/, "heading", 2]],
};
function extractOutline(lines, lang) {
  const rules = OUTLINE_RULES[lang];
  if (!rules || !lines) return [];
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    for (const r of rules) {
      const m = r[0].exec(lines[i]);
      if (m) { out.push({ kind: r[1], name: (m[r[2] || 1] || "").trim(), line: i + 1 }); break; }
    }
  }
  return out;
}
function outlineGlyph(kind) {
  return { fn: "ƒ", struct: "S", enum: "E", trait: "T", impl: "◇", mod: "M", macro: "!", class: "C", interface: "I", type: "t", def: "ƒ", section: "§", key: "·", heading: "#" }[kind] || "•";
}
function renderOutline() {
  const f = editor.open.find((x) => x.relpath === editor.active);
  if (!f) return `<div class="tree-placeholder"><div class="tph-title">No file open</div><div class="tph-sub">Open a file — its symbols (functions · types · sections) list here for quick jumps.</div></div>`;
  if (!f.lines) return `<div class="tree-status">${esc(f.message || "no content to outline")}</div>`;
  const lang = langOf(f.name);
  const syms = extractOutline(f.lines, lang);
  if (!syms.length) return `<div class="tree-status">no symbols found (${esc(lang)})</div>`;
  const rows = syms
    .map((s) => `<div class="outline-row" data-outline-line="${s.line}" title="line ${s.line}"><span class="ol-kind ol-${esc(s.kind)}">${esc(outlineGlyph(s.kind))}</span><span class="ol-name">${esc(s.name)}</span><span class="ol-line">${s.line}</span></div>`)
    .join("");
  return `<div class="outline">${rows}</div>`;
}
function jumpToLine(n) {
  if (HAS_CM && cmView && cmView._rel === editor.active && n) {
    const doc = cmView.state.doc;
    const line = doc.line(Math.min(Math.max(1, n), doc.lines));
    cmView.dispatch({ selection: { anchor: line.from }, effects: CM.EditorView.scrollIntoView(line.from, { y: "center" }) });
    cmView.focus();
    return;
  }
  const body = $("#code-body");
  const code = body && body.querySelector(".viewer-code");
  if (!body || !code || !n) return;
  const f = editor.open.find((x) => x.relpath === editor.active);
  const total = (f && f.lines && f.lines.length) || 1;
  const lineH = code.scrollHeight / Math.max(1, total);   // uniform line height (one <pre>)
  const top = Math.max(0, (n - 1) * lineH - body.clientHeight * 0.3);
  body.scrollTo({ top, behavior: "smooth" });
}

// (The emit-text `parseFileContent` was retired: the viewer now uses the backend
// `read_file_view` structured channel — full unclamped content, same walls.)
async function openFile(relpath) {
  if (!tree.project) return;
  const abspath = relJoin(tree.project, relpath);
  const name = relpath.split("/").pop();
  editor.active = relpath;
  editor.activePanel = null;   // opening a file focuses it (leaves any Settings center tab open behind)
  let entry = editor.open.find((f) => f.relpath === relpath);
  if (!entry) { entry = { relpath, abspath, name, lines: null, message: "opening…", meta: null, loading: true }; editor.open.push(entry); }
  else { entry.loading = true; }
  renderFiles(); renderEditor();
  // Structured channel (backend read_file_view) — SAME lane-A read + redaction
  // walls as `context file`, but the FULL unclamped content (no 80x64 emit cap).
  let view;
  try { view = await invoke("read_file_view", { path: abspath }); }
  catch (e) { entry.loading = false; entry.lines = null; entry.message = "open failed: " + (e && e.message ? e.message : e); renderEditor(); return; }
  entry.loading = false;
  if (!view) { entry.lines = null; entry.message = "no response"; renderEditor(); return; }
  if (view.kind === "text") {
    const lines = String(view.content).split("\n");
    if (lines.length > 1 && lines[lines.length - 1] === "") lines.pop(); // drop the trailing-newline empty
    entry.lines = lines;
    entry.meta = `${name} · ${fmtSize(view.bytes)} · sha ${view.sha}`;
    entry.shaFull = view.sha_full || null;  // P2-S5: the owner-save staleness baseline
    entry.editing = false;                  // a fresh read leaves edit mode
    entry.message = null;
  } else if (view.kind === "binary") {
    entry.lines = null; entry.meta = `${name} · ${fmtSize(view.bytes)}`;
    entry.message = "binary file — content not shown (utf-8 only)";
  } else if (view.kind === "withheld") {
    entry.lines = null; entry.meta = `${name} · ${fmtSize(view.bytes)}`;
    entry.message = "content withheld — this file looks secret-shaped (redaction). Ask about it in the agent pane instead.";
  } else {
    entry.lines = null; entry.meta = name;
    entry.message = "read denied — " + (view.reason || "outside the allowed roots");
  }
  renderEditor(); renderFiles();   // R8a: refresh the outline once the real content has loaded
}
function editorPlaceholderHTML() {
  return `<div class="editor-placeholder">
      <div class="ph-mark">⌗</div>
      <div class="ph-title">Your code, live</div>
      <div class="ph-sub">Open a file from the tree and it renders here. Agent edits arrive as a diff you approve — never applied silently.</div>
      <div class="ph-tag">read-only viewer · live diff + single approval</div>
    </div>`;
}
/* ── R4: lightweight syntax highlighter (self-authored · offline · no bundler) ─
   Validated against REAL `context file` output (Rust/JSON/JS) 2026-06-11:
   character-preserving (exact round-trip), strings/comments shield keywords, no
   cross-line string bleed, Rust lifetimes ≠ char literals. The core emit clamps
   each line to 80 cols (a core invariant we do NOT touch) — long source lines
   render clamped; honest, not faked. */
let viewWrap = (function () { try { return localStorage.getItem("sinabro.wrap") === "1"; } catch (_) { return false; } })();
const LANGS = {
  rust:   { line: "//", block: true, charlit: true, sq: false, kw: "as async await break const continue crate dyn else enum extern fn for if impl in let loop match mod move mut pub ref return static struct super trait type unsafe use where while".split(" "), lit: "true false None Some Ok Err self Self".split(" "), types: true },
  js:     { line: "//", block: true, tpl: true, kw: "var let const function return if else for while do break continue switch case default new delete typeof instanceof in of class extends super import export from async await yield try catch finally throw void this".split(" "), lit: "null true false undefined NaN".split(" "), types: true },
  ts:     { line: "//", block: true, tpl: true, kw: "var let const function return if else for while do break continue switch case default new delete typeof instanceof in of class extends super import export from async await yield try catch finally throw void this interface type enum implements public private protected readonly namespace declare abstract keyof infer satisfies".split(" "), lit: "null true false undefined NaN".split(" "), types: true },
  python: { line: "#", block: false, kw: "def class return if elif else for while break continue import from as pass lambda yield with try except finally raise global nonlocal in is not and or del assert async await".split(" "), lit: "None True False self".split(" "), types: true },
  shell:  { line: "#", block: false, kw: "if then else elif fi for while until do done case esac in function return export local readonly set unset declare".split(" "), lit: "true false".split(" "), types: false },
  json:   { line: null, block: false, sq: false, kw: [], lit: "true false null".split(" "), types: false },
  toml:   { line: "#", block: false, kw: [], lit: "true false".split(" "), types: false },
  yaml:   { line: "#", block: false, kw: [], lit: "true false null yes no".split(" "), types: false },
  css:    { line: null, block: true, kw: [], lit: [], types: false },
  plain:  { line: null, block: false, kw: [], lit: [], types: false },
};
function buildLexer(cfg) {
  const parts = [], tags = [];
  const add = (p, t) => { parts.push("(" + p + ")"); tags.push(t); };
  if (cfg.block) add("\\/\\*[\\s\\S]*?\\*\\/", "comment");
  if (cfg.line === "//") add("\\/\\/[^\\n]*", "comment");
  else if (cfg.line === "#") add("#[^\\n]*", "comment");
  if (cfg.tpl) add("`(?:\\\\.|[^`\\\\])*`", "string");
  add("\"(?:\\\\.|[^\"\\\\\\n])*\"", "string");
  if (cfg.charlit) add("'(?:\\\\.|[^'\\\\\\n])'", "string");
  else if (cfg.sq !== false) add("'(?:\\\\.|[^'\\\\\\n])*'", "string");
  add("\\b\\d[\\d_]*(?:\\.\\d+)?(?:[eE][+-]?\\d+)?\\b", "number");
  if (cfg.kw && cfg.kw.length) add("\\b(?:" + cfg.kw.join("|") + ")\\b", "keyword");
  if (cfg.lit && cfg.lit.length) add("\\b(?:" + cfg.lit.join("|") + ")\\b", "literal");
  if (cfg.types) add("\\b[A-Z][A-Za-z0-9_]*\\b", "type");
  return { re: new RegExp(parts.join("|"), "g"), tags };
}
function lexerFor(lang) {
  const cfg = LANGS[lang] || LANGS.plain;
  if (!cfg._lex) cfg._lex = buildLexer(cfg);
  return cfg._lex;
}
function highlight(text, lang) {
  if (lang === "plain" || lang === "md") return esc(text);
  const { re, tags } = lexerFor(lang);
  let out = "", last = 0, m;
  re.lastIndex = 0;
  while ((m = re.exec(text))) {
    if (m.index > last) out += esc(text.slice(last, m.index));
    let cls = "plain";
    for (let g = 1; g < m.length; g++) { if (m[g] !== undefined) { cls = tags[g - 1]; break; } }
    out += `<span class="tok-${cls}">${esc(m[0])}</span>`;
    last = m.index + m[0].length;
    if (m[0].length === 0) re.lastIndex++;
  }
  out += esc(text.slice(last));
  return out;
}
function langOf(name) {
  if (name === "Cargo.lock") return "toml";
  const ext = (String(name).split(".").pop() || "").toLowerCase();
  const map = { rs: "rust", js: "js", mjs: "js", cjs: "js", jsx: "js", ts: "ts", tsx: "ts", json: "json", toml: "toml", lock: "toml", py: "python", sh: "shell", bash: "shell", zsh: "shell", css: "css", md: "md", markdown: "md", yml: "yaml", yaml: "yaml" };
  return map[ext] || "plain";
}

/* ── A④ KEYSTONE-2: CodeMirror-6 editor substrate (vendored global `CM`) ───────
   Replaces the vanilla <textarea>/regex-highlight viewer with ONE EditorView,
   readOnly-toggled (read-only VIEWER ⟺ owner EDIT = the same widget). Unifies:
   real syntax highlight (lang-rust/Move/js/json/python), multi-cursor, find/replace
   (⌘F), undo/redo, the A①⨉A④ diagnostics GUTTER (context lsp-diagnostics → markers),
   and the re-homed P6 FIM ghost. The fim_complete / owner_save_file / dispatch_line
   IPCs are UNCHANGED — the core never sees CM6 (this is a pure GUI surface). No new
   runtime egress; custody/funds (PD-6) untouched. HONEST-DEGRADE: if the bundle did
   not load (CM undefined), viewerHTML falls back to the prior textarea/.viewer path. */
const HAS_CM = typeof CM !== "undefined" && !!(CM && CM.EditorView);
let cmView = null;
let cmLang, cmReadOnly, cmWrap, cmThemeC;
let fimEffect, fimField, diagEffect, diagField, diagGutter, fimKeymap, cmHighlightStyle;
let GhostWidget, DiagMarker;
const SEV_GLYPH = { error: "●", warning: "▲", info: "■", hint: "·" };
const SEV_RANK = { hint: 0, info: 1, warning: 2, error: 3 };
// CM6 theme tracks styles.css tokens (CSS vars switch with <html data-theme>).
const CM_THEME_STYLE = {
  "&": { color: "var(--text)", backgroundColor: "transparent", height: "100%" },
  ".cm-content": { fontFamily: "var(--font-mono)", fontSize: "var(--code-font, 12px)", caretColor: "var(--accent)" },
  ".cm-scroller": { fontFamily: "var(--font-mono)", fontSize: "var(--code-font, 12px)", lineHeight: "1.55", overflow: "auto" },
  ".cm-gutters": { backgroundColor: "var(--bg-2, transparent)", color: "var(--faint)", border: "none", borderRight: "1px solid var(--border)" },
  ".cm-activeLineGutter": { backgroundColor: "var(--accent-soft)", color: "var(--muted)" },
  ".cm-activeLine": { backgroundColor: "rgba(127,127,127,0.05)" },
  "&.cm-focused .cm-cursor": { borderLeftColor: "var(--accent)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection": { backgroundColor: "var(--select)" },
  ".cm-fim-ghost": { opacity: "0.5", color: "var(--muted)", fontStyle: "italic" },
  ".cm-panels": { backgroundColor: "var(--surface)", color: "var(--text)", border: "1px solid var(--border)" },
  ".cm-panel.cm-search input, .cm-panel.cm-search button": { fontFamily: "var(--font-mono)", fontSize: "11px" },
  ".cm-searchMatch": { backgroundColor: "var(--warn-soft)", outline: "1px solid var(--warn)" },
  ".cm-searchMatch-selected": { backgroundColor: "var(--accent-soft)" },
  ".cm-selectionMatch": { backgroundColor: "var(--accent-soft)" },
  ".cm-diagnostics-gutter": { minWidth: "16px", textAlign: "center" },
  ".cm-diag-marker": { fontWeight: "700", cursor: "default" },
  ".cm-diag-error": { color: "var(--bad)" },
  ".cm-diag-warning": { color: "var(--warn)" },
  ".cm-diag-info": { color: "var(--info)" },
  ".cm-diag-hint": { color: "var(--muted)" },
};
function initCM6() {
  cmLang = new CM.Compartment(); cmReadOnly = new CM.Compartment();
  cmWrap = new CM.Compartment(); cmThemeC = new CM.Compartment();

  // P6 FIM re-home: a single-suggestion ghost as an inline widget at the cursor.
  GhostWidget = class extends CM.WidgetType {
    constructor(text) { super(); this.text = text; }
    eq(o) { return o.text === this.text; }
    toDOM() { const s = document.createElement("span"); s.className = "cm-fim-ghost"; s.textContent = this.text; return s; }
    ignoreEvent() { return false; }
  };
  fimEffect = CM.StateEffect.define();   // value: {text, from} to set, null to clear
  fimField = CM.StateField.define({
    create() { return { text: null, from: 0 }; },
    update(val, tr) {
      for (const e of tr.effects) if (e.is(fimEffect)) return e.value || { text: null, from: 0 };
      if (tr.docChanged) return { text: null, from: 0 };   // any real edit clears the ghost
      return val;
    },
    provide: (fld) => CM.EditorView.decorations.from(fld, (val) => {
      if (!val.text) return CM.Decoration.none;
      const w = CM.Decoration.widget({ widget: new GhostWidget(val.text), side: 1 });
      return CM.Decoration.set([w.range(val.from)]);
    }),
  });
  fimKeymap = [
    { key: "Tab", run: (view) => {
        const g = view.state.field(fimField);
        if (!g.text) return false;   // no ghost ⇒ let Tab indent
        view.dispatch({ changes: { from: g.from, insert: g.text }, selection: { anchor: g.from + g.text.length }, effects: fimEffect.of(null) });
        return true;
      } },
    { key: "Escape", run: (view) => {
        const g = view.state.field(fimField);
        if (!g.text) return false;   // no ghost ⇒ let Escape close the search panel
        view.dispatch({ effects: fimEffect.of(null) });
        return true;
      } },
  ];

  // A①⨉A④ diagnostics gutter: markers fed by `context lsp-diagnostics`.
  DiagMarker = class extends CM.GutterMarker {
    constructor(sev, msg) { super(); this.sev = sev; this.msg = msg; }
    eq(o) { return o.sev === this.sev && o.msg === this.msg; }
    toDOM() {
      const s = document.createElement("span");
      s.className = "cm-diag-marker cm-diag-" + this.sev;
      s.textContent = SEV_GLYPH[this.sev] || "·";
      s.title = this.sev + ": " + this.msg;
      return s;
    }
  };
  diagEffect = CM.StateEffect.define();   // value: [{line(1-based), col, sev, msg}]
  diagField = CM.StateField.define({
    create() { return []; },
    update(val, tr) {
      for (const e of tr.effects) if (e.is(diagEffect)) return e.value;
      return val;
    },
  });
  diagGutter = CM.gutter({
    class: "cm-diagnostics-gutter",
    markers: (view) => {
      const diags = view.state.field(diagField);
      if (!diags || !diags.length) return CM.RangeSet.empty;
      const doc = view.state.doc;
      const byLine = new Map();   // highest-severity diagnostic per line
      for (const d of diags) {
        const ln = Math.min(Math.max(1, d.line), doc.lines);
        const prev = byLine.get(ln);
        if (!prev || (SEV_RANK[d.sev] || 0) > (SEV_RANK[prev.sev] || 0)) byLine.set(ln, { sev: d.sev, msg: d.msg });
      }
      const builder = new CM.RangeSetBuilder();
      for (const ln of [...byLine.keys()].sort((a, b) => a - b)) {
        const line = doc.line(ln);
        const d = byLine.get(ln);
        builder.add(line.from, line.from, new DiagMarker(d.sev, d.msg));
      }
      return builder.finish();
    },
    lineMarkerChange: (update) => update.transactions.some((tr) => tr.effects.some((e) => e.is(diagEffect))),
  });

  cmHighlightStyle = CM.HighlightStyle.define([
    { tag: [CM.tags.comment, CM.tags.lineComment, CM.tags.blockComment], color: "var(--tok-comment)", fontStyle: "italic" },
    { tag: [CM.tags.keyword, CM.tags.controlKeyword, CM.tags.moduleKeyword, CM.tags.definitionKeyword, CM.tags.operatorKeyword], color: "var(--tok-keyword)" },
    { tag: [CM.tags.string, CM.tags.special(CM.tags.string), CM.tags.regexp], color: "var(--tok-string)" },
    { tag: [CM.tags.number, CM.tags.integer, CM.tags.float], color: "var(--tok-number)" },
    { tag: [CM.tags.bool, CM.tags.atom, CM.tags.null, CM.tags.literal], color: "var(--tok-literal)" },
    { tag: [CM.tags.typeName, CM.tags.className, CM.tags.namespace, CM.tags.standard(CM.tags.typeName)], color: "var(--tok-type)" },
    { tag: [CM.tags.function(CM.tags.variableName), CM.tags.function(CM.tags.propertyName), CM.tags.propertyName, CM.tags.attributeName], color: "var(--tok-type)" },
  ]);
}
if (HAS_CM) { try { initCM6(); } catch (_) { /* a malformed bundle ⇒ honest-degrade to the textarea path */ } }

function cmThemeExt() {
  const dark = document.documentElement.getAttribute("data-theme") !== "light";
  return [CM.EditorView.theme(CM_THEME_STYLE, { dark }), CM.syntaxHighlighting(cmHighlightStyle)];
}
function cmBaseExtensions() {
  return [
    CM.lineNumbers(), diagGutter,
    CM.highlightActiveLine(), CM.highlightActiveLineGutter(),
    CM.history(), CM.drawSelection(), CM.rectangularSelection(), CM.crosshairCursor(),
    CM.bracketMatching(), CM.indentOnInput(), CM.highlightSelectionMatches(),
    CM.search({ top: true }),
    diagField, fimField,
    CM.EditorView.updateListener.of((u) => { if (u.docChanged && !u.state.readOnly) scheduleFim(u.view); }),
    CM.Prec.highest(CM.keymap.of(fimKeymap)),
    CM.Prec.highest(CM.keymap.of([{ key: "Mod-k", preventDefault: true, run: cmdkRun }])),
    CM.Prec.highest(CM.keymap.of([{ key: "Mod-Shift-f", preventDefault: true, run: () => { openFindPanel(); return true; } }])),
    CM.keymap.of([...CM.defaultKeymap, ...CM.historyKeymap, ...CM.searchKeymap, CM.indentWithTab]),
  ];
}
function buildCmState(f) {
  const langSupport = CM.languageFor(f.name);
  return CM.EditorState.create({
    doc: (f.lines || []).join("\n"),
    extensions: [
      cmBaseExtensions(),
      cmReadOnly.of(CM.EditorState.readOnly.of(!f.editing)),
      cmLang.of(langSupport ? langSupport : []),
      cmWrap.of(viewWrap ? CM.EditorView.lineWrapping : []),
      cmThemeC.of(cmThemeExt()),
    ],
  });
}
// Mount/reconcile the single EditorView into the freshly-rendered #cm6-host. The
// view object PERSISTS across renderEditor() innerHTML churn (its state lives in the
// view, not the parent) — re-attached on each render; setState only on a file or
// edit-mode change (so in-flight owner edits are never clobbered).
function mountCM6(f) {
  const host = document.getElementById("cm6-host");
  if (!host) return;
  if (!cmView) {
    cmView = new CM.EditorView({ state: buildCmState(f), parent: host });
  } else {
    if (cmView.dom.parentElement !== host) host.appendChild(cmView.dom);
    if (cmView._rel !== f.relpath || cmView._editing !== f.editing) {
      cmView.setState(buildCmState(f));
    } else {
      cmView.dispatch({ effects: cmWrap.reconfigure(viewWrap ? CM.EditorView.lineWrapping : []) });
    }
  }
  cmView._rel = f.relpath; cmView._editing = f.editing; cmView._abspath = f.abspath;
  if (f.editing) cmView.focus();
  // Refresh diagnostics on a new file or an edit-mode flip (e.g. after a save reopens).
  const diagKey = f.relpath + "|" + (f.editing ? "e" : "v");
  if (cmView._diagKey !== diagKey) { cmView._diagKey = diagKey; refreshDiagnostics(cmView, f.abspath); }
}
function applyCmTheme() {
  if (!HAS_CM || !cmView) return;
  try { cmView.dispatch({ effects: cmThemeC.reconfigure(cmThemeExt()) }); } catch (_) {}
}
// A①⨉A④: parse `context lsp-diagnostics <path>` (compiler truth) → gutter markers.
// HONEST-DEGRADE: no Tauri bridge / an error / a no-verdict line ⇒ NO markers (the
// diagnostic-line regex simply doesn't match the honest-degrade text) — never faked.
function parseDiagnostics(out) {
  const re = /^\s*(\d+):(\d+)\s+\[(error|warning|info|hint)\]\s+(.*)$/;
  const diags = [];
  for (const line of String(out).split("\n")) {
    const m = re.exec(line);
    if (m) diags.push({ line: parseInt(m[1], 10), col: parseInt(m[2], 10), sev: m[3], msg: m[4].trim() });
  }
  return diags;
}
async function refreshDiagnostics(view, abspath) {
  if (!view || !abspath || !hasTauri()) { try { view && view.dispatch({ effects: diagEffect.of([]) }); } catch (_) {} return; }
  let raw;
  try { raw = await invoke("dispatch_line", { line: "context lsp-diagnostics " + abspath }); }
  catch (_) { return; }   // honest-degrade: bridge/core error ⇒ leave markers as-is (no fake)
  if (view._abspath !== abspath) return;   // the file changed under us — drop stale diagnostics
  try { view.dispatch({ effects: diagEffect.of(parseDiagnostics(raw)) }); } catch (_) {}
}
// P6 FIM (re-homed): debounced loopback `fim_complete` → a CM6 ghost at the cursor.
let cmFimTimer = null, cmFimSeq = 0;
function scheduleFim(view) {
  if (cmFimTimer) clearTimeout(cmFimTimer);
  if (!hasTauri()) return;   // honest-degrade: no desktop bridge ⇒ no ghost
  cmFimTimer = setTimeout(() => requestFimCM(view), 450);
}
async function requestFimCM(view) {
  cmFimTimer = null;
  const sel = view.state.selection.main;
  if (!sel.empty) return;                    // a real selection ⇒ not an insertion point
  const cursor = sel.head;
  const value = view.state.doc.toString();
  const prefix = value.slice(0, cursor);
  if (!prefix.trim()) return;                // nothing to continue from
  const seq = ++cmFimSeq;
  let text;
  try { text = await invoke("fim_complete", { payload: { prefix, suffix: value.slice(cursor) } }); }
  catch (_) { return; }                      // honest-degrade: model absent/unreachable ⇒ no ghost
  if (seq !== cmFimSeq || !text || !text.length) return;
  const cur = view.state.selection.main;     // still the same collapsed cursor + same doc?
  if (!cur.empty || cur.head !== cursor || view.state.doc.toString() !== value) return;
  try { view.dispatch({ effects: fimEffect.of({ text, from: cursor }) }); } catch (_) {}
}

function viewerHTML(f) {
  const lang = langOf(f.name);
  // P2-S5: a text file the owner read (has a staleness baseline) is EDITABLE — an Edit toggle,
  // then a Save (owner_save_file) / Cancel. The MODEL has no path here (a GUI IPC command, not a
  // loop tool). Agent edits stay the diff-approve flow; this is a DIRECT owner write.
  const canEdit = !!(f.lines && f.shaFull);
  const editBtns = f.editing
    ? `<button class="viewer-save" data-save-file title="Save (owner write — staleness-locked, atomic)">save</button><button class="viewer-edit-cancel" data-cancel-edit title="Discard edits">cancel</button>`
    : (canEdit ? `<button class="viewer-edit-btn" data-edit-file title="Edit this file directly (owner write)">edit</button>` : "");
  const wrapBtn = f.editing ? "" : `<button class="viewer-wrap${viewWrap ? " on" : ""}" data-action="wrap-toggle" title="Toggle soft wrap">wrap</button>`;
  const tools = `<span class="viewer-tools"><span class="viewer-lang">${esc(lang)}</span>${wrapBtn}${editBtns}</span>`;
  const metaLine = `<div class="viewer-meta"><span class="viewer-metafile mono">${esc(f.meta || f.name)}</span>${tools}</div>`;
  if (f.loading) return `${metaLine}<div class="viewer-msg">opening…</div>`;
  if (f.lines) {
    // UNIFIED CM6 mount: read-only VIEWER and owner EDIT are ONE EditorView,
    // readOnly-toggled in buildCmState (mountCM6 reconciles after this innerHTML).
    if (HAS_CM) return `${metaLine}<div class="cm6-host" id="cm6-host"></div>`;
    // HONEST-DEGRADE fallback (the bundle did not load): the prior textarea/.viewer.
    if (f.editing) return `${metaLine}<textarea class="viewer-edit-area" id="viewer-edit-area" spellcheck="false">${esc(f.lines.join("\n"))}</textarea>`;
    const gutter = f.lines.map((_, i) => i + 1).join("\n");
    const code = highlight(f.lines.join("\n"), lang);
    return `${metaLine}<div class="viewer${viewWrap ? " wrap" : ""}"><pre class="viewer-gutter">${gutter}</pre><pre class="viewer-code">${code || "&nbsp;"}</pre></div>`;
  }
  return `${metaLine}<div class="viewer-msg">${esc(f.message || "no content")}</div>`;
}
// P2-S5: toggle edit mode on the active file (owner-only; the model cannot reach this).
function setEditing(on) {
  const f = editor.open.find((x) => x.relpath === editor.active);
  if (!f || !f.lines) return;
  f.editing = !!on && !!f.shaFull;
  renderEditor();
}
// P2-S5: persist the owner's edits through the core owner_save_file (confinement + staleness +
// atomic replace + verify). On success, reopen to refresh the content + a fresh staleness baseline.
async function saveOwnerFile() {
  const f = editor.open.find((x) => x.relpath === editor.active);
  if (!f || !f.editing) return;
  // Content from the CM6 doc when mounted, else the fallback textarea.
  let content;
  if (HAS_CM && cmView && cmView._rel === f.relpath) content = cmView.state.doc.toString();
  else { const ta = $("#viewer-edit-area"); if (!ta) return; content = ta.value; }
  if (content == null) return;
  if (!hasTauri()) { toast("saving needs the desktop app (cargo tauri dev)."); return; }
  if (!f.shaFull) { toast("cannot save — no read baseline; reopen the file."); return; }
  try {
    const ok = await invoke("owner_save_file", { payload: { path: f.abspath, content, base_sha: f.shaFull } });
    f.editing = false;
    toast("✓ saved " + f.name + (ok && ok.bytes != null ? " · " + ok.bytes + " B" : ""));
    openFile(f.relpath); // reopen → refreshed content + a new staleness baseline + tree refresh
  } catch (e) {
    const msg = String(e && e.message ? e.message : e);
    if (/stale/.test(msg)) toast("the file changed on disk since you opened it — Cancel, reopen, then re-edit.");
    else toast("save refused: " + msg);
  }
}
// ── P6: INLINE FIM (fill-in-the-middle) autocomplete in the center editor ────────────────────
// While EDITING a file, a debounced request asks the LOOPBACK local model (via the `fim_complete`
// IPC command) for the text to insert at the cursor; the suggestion appears as a SELECTED ghost
// (setRangeText "select") — Tab accepts (collapse), Esc/typing rejects (delete). HONEST-DEGRADE: if
// no local model is compiled/reachable the IPC errors and we show NO ghost (never a fabricated one).
// The MODEL has no path here (a GUI IPC command, owner-only, NOT a loop tool); custody/funds (PD-6)
// untouched — this only proposes text into the owner's own textarea.
const fim = { timer: null, seq: 0, active: false, inserting: false, from: 0, to: 0 };
function onEditInput(ta) {
  if (fim.inserting) return;          // our own setRangeText, not a user keystroke
  fim.active = false;                 // a real edit replaced/typed-over any prior ghost
  if (fim.timer) clearTimeout(fim.timer);
  if (!hasTauri()) return;            // honest-degrade: no desktop bridge ⇒ no ghost
  fim.timer = setTimeout(() => requestFim(ta), 450);
}
async function requestFim(ta) {
  fim.timer = null;
  if (!ta || ta.id !== "viewer-edit-area" || document.activeElement !== ta) return;
  if (ta.selectionStart !== ta.selectionEnd) return;   // a real selection ⇒ not an insertion point
  const cursor = ta.selectionStart;
  const value = ta.value;
  const prefix = value.slice(0, cursor);
  const suffix = value.slice(cursor);
  if (!prefix.trim()) return;         // nothing to continue from
  const seq = ++fim.seq;
  let text;
  try {
    text = await invoke("fim_complete", { payload: { prefix, suffix } });
  } catch (_) { return; }             // honest-degrade: model absent/unreachable ⇒ no ghost
  // staleness: apply ONLY if this is still the latest request AND the editor is byte-for-byte
  // where it was (same value, same collapsed cursor, still focused).
  if (seq !== fim.seq) return;
  if (!text || !text.length) return;
  if (ta.value !== value || ta.selectionStart !== cursor || ta.selectionStart !== ta.selectionEnd) return;
  if (document.activeElement !== ta) return;
  fim.inserting = true;
  ta.setRangeText(text, cursor, cursor, "select");     // insert + SELECT the ghost
  fim.inserting = false;
  fim.active = true; fim.from = cursor; fim.to = cursor + text.length;
}
function onEditKeydown(e, ta) {
  if (!fim.active) return;
  if (e.key === "Tab") {              // accept: collapse the selection (cursor after the ghost)
    e.preventDefault(); e.stopPropagation();
    ta.selectionStart = ta.selectionEnd = fim.to;
    fim.active = false;
    return;
  }
  if (e.key === "Escape") {           // reject: delete the inserted ghost, cursor back to start
    e.preventDefault(); e.stopPropagation();
    fim.inserting = true;
    ta.setRangeText("", fim.from, fim.to, "end");
    fim.inserting = false;
    fim.active = false;
    return;
  }
  fim.active = false;                 // any other key: native edit clears the selection
}
function renderEditor() {
  const tabsEl = $("#code-tabs");
  const bodyEl = $("#code-body");
  if (!tabsEl || !bodyEl) return;
  // file tabs (active iff focused — no panel, no diff) + panel tabs (Settings &c).
  const fileTabs = editor.open
    .map((f) => `<div class="tab${(!editor.activePanel && !editor.diffId && f.relpath === editor.active) ? " active" : ""}" data-tab="${esc(f.relpath)}" title="${esc(f.relpath)}"><span class="tab-name">${esc(f.name)}</span><button class="tab-close" data-tabclose="${esc(f.relpath)}" title="Close">✕</button></div>`)
    .join("");
  const panelTabs = editor.panels
    .map((p) => `<div class="tab panel-tab${editor.activePanel === p.panel ? " active" : ""}" data-paneltab="${esc(p.panel)}" title="${esc(p.name)}"><span class="tab-glyph">${esc(p.glyph)}</span><span class="tab-name">${esc(p.name)}</span><button class="tab-close" data-panelclose="${esc(p.panel)}" title="Close">✕</button></div>`)
    .join("");
  const tabs = (editor.open.length || editor.panels.length) ? fileTabs + panelTabs : `<div class="tab-empty">No file open</div>`;
  const pchip = proposals.length
    ? `<span class="tabs-spacer"></span><button class="pending-chip${editor.diffId ? " on" : ""}" data-action="show-proposals" title="Pending agent edits — review the diff + approve">⬤ ${proposals.length} pending edit${proposals.length > 1 ? "s" : ""}</button>`
    : "";
  tabsEl.innerHTML = tabs + pchip;
  // body precedence: a center panel (Settings) is the foreground when active, then a pending
  // diff, then the open file, then the empty placeholder. The panel SHELL renders synchronously
  // (a loading placeholder); fillCenterPanel() populates it async (mirrors openPanel).
  if (editor.activePanel) { bodyEl.innerHTML = centerPanelShellHTML(editor.activePanel); fillCenterPanel(); return; }
  if (editor.diffId) { bodyEl.innerHTML = diffHTML(); return; }
  if (!editor.open.length) { bodyEl.innerHTML = editorPlaceholderHTML(); return; }
  const f = editor.open.find((x) => x.relpath === editor.active) || editor.open[0];
  bodyEl.innerHTML = viewerHTML(f);
  if (HAS_CM && f.lines) mountCM6(f);   // reconcile the persistent EditorView into #cm6-host
}
function onTabsClick(e) {
  const pclose = e.target.closest("[data-panelclose]");
  if (pclose) { closeCenterPanel(pclose.dataset.panelclose); return; }
  const ptab = e.target.closest("[data-paneltab]");
  if (ptab) { editor.activePanel = ptab.dataset.paneltab; renderEditor(); return; }
  const close = e.target.closest("[data-tabclose]");
  if (close) { closeTab(close.dataset.tabclose); return; }
  const tab = e.target.closest("[data-tab]");
  if (tab) { editor.activePanel = null; editor.diffId = null; editor.active = tab.dataset.tab; renderEditor(); renderFiles(); }
}
function closeTab(relpath) {
  const i = editor.open.findIndex((f) => f.relpath === relpath);
  if (i < 0) return;
  editor.open.splice(i, 1);
  if (editor.active === relpath) editor.active = editor.open.length ? editor.open[Math.max(0, i - 1)].relpath : null;
  renderEditor(); renderFiles();
}

/* ── R5: pending edits → diff → SINGLE approval (P3-2) ────────────────────────
   The model PROPOSES (a PROPOSE-EDIT answer); the owner reviews ONE diff and
   approves. The write itself is the core's `tool apply file-apply-owner-live
   <id>` ceremony — typed phrase + staleness lock + atomic replace, ALL enforced
   in the core (the GUI never writes a file; it surfaces the proposal + triggers
   the ceremony). The audit soul = one clear yes/no gate, not scattered Accepts. */
async function loadProposals() {
  if (!hasTauri()) { proposals = []; return; }
  try { proposals = (await invoke("read_proposals")) || []; }
  catch (_) { proposals = []; }
  if (editor.diffId && !proposals.some((p) => p.id === editor.diffId)) editor.diffId = null;
  renderEditor();
}
// Coarse line diff (common prefix/suffix trim, no LCS) — mirrors the core's
// `render_line_diff` shape. COSMETIC only: the apply ceremony is the truth.
// R9: char-level (intra-line) diff — trim the common prefix + common suffix; the
// middle is the changed run. Returns per-side span arrays of [text, changed?]. Pure
// + character-preserving (concatenating the texts reproduces each input exactly).
function charSpans(a, b) {
  a = String(a == null ? "" : a); b = String(b == null ? "" : b);
  let p = 0; const la = a.length, lb = b.length;
  while (p < la && p < lb && a[p] === b[p]) p++;
  let sa = la, sb = lb;
  while (sa > p && sb > p && a[sa - 1] === b[sb - 1]) { sa--; sb--; }
  return {
    a: [[a.slice(0, p), 0], [a.slice(p, sa), 1], [a.slice(sa), 0]],
    b: [[b.slice(0, p), 0], [b.slice(p, sb), 1], [b.slice(sb), 0]],
  };
}
// Render a diff row's text, honoring char-level spans when present (a changed,
// paired line) — the changed chars get the .diff-ch emphasis, unchanged stay plain.
function diffText(r) {
  if (!r.spans) return esc(r.text) || "&nbsp;";
  const html = r.spans.map(([t, c]) => (t === "" ? "" : c ? `<span class="diff-ch">${esc(t)}</span>` : esc(t))).join("");
  return html || "&nbsp;";
}
function lineDiff(oldText, newText) {
  const a = String(oldText == null ? "" : oldText).split("\n");
  const b = String(newText == null ? "" : newText).split("\n");
  if (a.length > 1 && a[a.length - 1] === "") a.pop();
  if (b.length > 1 && b[b.length - 1] === "") b.pop();
  let p = 0; while (p < a.length && p < b.length && a[p] === b[p]) p++;
  let sa = a.length, sb = b.length;
  while (sa > p && sb > p && a[sa - 1] === b[sb - 1]) { sa--; sb--; }
  const rows = [];
  for (let i = 0; i < p; i++) rows.push({ t: " ", a: i + 1, b: i + 1, text: a[i] });
  // R9: within the changed region, pair removed[k] with added[k] (the common
  // in-place-edit case) and attach char spans for intra-line highlighting (research
  // D-3/D-5 #4: intra-line is the diff standard). Unpaired extras stay pure add/del.
  const delN = sa - p, addN = sb - p, paired = Math.min(delN, addN);
  for (let k = 0; k < delN; k++) {
    const i = p + k;
    const row = { t: "-", a: i + 1, b: null, text: a[i] };
    if (k < paired) row.spans = charSpans(a[i], b[p + k]).a;
    rows.push(row);
  }
  for (let k = 0; k < addN; k++) {
    const i = p + k;
    const row = { t: "+", a: null, b: i + 1, text: b[i] };
    if (k < paired) row.spans = charSpans(a[p + k], b[i]).b;
    rows.push(row);
  }
  for (let i = sa; i < a.length; i++) rows.push({ t: " ", a: i + 1, b: sb + (i - sa) + 1, text: a[i] });
  return rows;
}
function diffStat(rows) {
  let add = 0, del = 0;
  for (const r of rows) { if (r.t === "+") add++; else if (r.t === "-") del++; }
  return `<span class="stat-add">+${add}</span> <span class="stat-del">−${del}</span>`;
}
function renderDiffRows(rows) {
  const CTX = 3; // collapse unchanged runs, keep 3 context lines around edits
  const keep = new Array(rows.length).fill(false);
  for (let i = 0; i < rows.length; i++) if (rows[i].t !== " ") for (let j = Math.max(0, i - CTX); j <= Math.min(rows.length - 1, i + CTX); j++) keep[j] = true;
  let html = "", gap = false;
  for (let i = 0; i < rows.length; i++) {
    if (!keep[i]) { if (!gap) { html += `<div class="diff-row gap"><span class="dg"></span><span class="dg"></span><span class="dsign"></span><span class="dtext">⋯</span></div>`; gap = true; } continue; }
    gap = false;
    const r = rows[i];
    const cls = r.t === "+" ? "add" : r.t === "-" ? "del" : "ctx";
    html += `<div class="diff-row ${cls}"><span class="dg">${r.a == null ? "" : r.a}</span><span class="dg">${r.b == null ? "" : r.b}</span><span class="dsign">${r.t === " " ? "" : r.t}</span><span class="dtext">${diffText(r)}</span></div>`;
  }
  return html;
}
// ── B⑧: Cmd-K inline edit — select → NL instruction → INERT proposal → owner single-approve ──
// The ⌘K keymap captures the center editor's selection + a bounded context window; the owner types a
// natural-language instruction; the core loopback-transforms ONLY the selection and SEALS an INERT
// proposal (the EXISTING PROPOSE-EDIT machinery). We then reload proposals and show the diff in the
// EXISTING diff view — the owner single-approves via the EXISTING "Approve & apply" (tool apply). The
// model NEVER applies; no silent mutation. LOOPBACK-only (zero egress).
let cmdkCtx = null; // {selText, before, after} captured at ⌘K time
function cmdkRun(view) {
  const sel = view.state.selection.main;
  if (sel.empty) { toast("⌘K: select the code to edit first"); return true; }
  const doc = view.state.doc;
  const selText = doc.sliceString(sel.from, sel.to);
  const before = doc.sliceString(Math.max(0, sel.from - 4000), sel.from);
  const after = doc.sliceString(sel.to, Math.min(doc.length, sel.to + 4000));
  openCmdkBar(selText, before, after);
  return true;
}
function ensureCmdkBar() {
  let bar = document.getElementById("cmdk-bar");
  if (bar) return bar;
  bar = document.createElement("div");
  bar.id = "cmdk-bar";
  bar.setAttribute("style", "position:fixed;left:50%;top:72px;transform:translateX(-50%);display:none;z-index:9999;gap:8px;align-items:center;padding:8px 10px;border-radius:8px;background:var(--panel,#1b1d23);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);box-shadow:0 6px 24px rgba(0,0,0,.4);min-width:520px;max-width:80vw;");
  bar.innerHTML = '<span style="font-size:12px;opacity:.7;white-space:nowrap;">⌘K edit</span>'
    + '<input id="cmdk-input" type="text" autocomplete="off" placeholder="describe the change to the selection — Enter to propose, Esc to cancel" style="flex:1;min-width:0;background:var(--bg,#0e0f13);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:6px;padding:6px 8px;font-size:13px;outline:none;" />'
    + '<button id="cmdk-go" style="background:var(--accent,#3b82f6);color:#fff;border:none;border-radius:6px;padding:6px 12px;font-size:13px;cursor:pointer;">Edit</button>';
  document.body.appendChild(bar);
  bar.querySelector("#cmdk-go").addEventListener("click", submitCmdk);
  bar.querySelector("#cmdk-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); submitCmdk(); }
    else if (e.key === "Escape") { e.preventDefault(); closeCmdkBar(); }
  });
  return bar;
}
function openCmdkBar(selText, before, after) {
  cmdkCtx = { selText, before, after };
  const bar = ensureCmdkBar();
  bar.style.display = "flex";
  const inp = bar.querySelector("#cmdk-input");
  inp.value = "";
  inp.focus();
}
function closeCmdkBar() {
  cmdkCtx = null;
  const bar = document.getElementById("cmdk-bar");
  if (bar) bar.style.display = "none";
  if (HAS_CM && cmView) cmView.focus();
}
async function submitCmdk() {
  if (!cmdkCtx) return;
  const inp = document.getElementById("cmdk-input");
  const instruction = (inp ? inp.value : "").trim();
  if (!instruction) { toast("⌘K: type an instruction"); return; }
  const path = (HAS_CM && cmView) ? cmView._abspath : null;
  if (!path) { toast("⌘K: no active file"); closeCmdkBar(); return; }
  const ctx = cmdkCtx;
  closeCmdkBar();
  toast("inline edit: transforming the selection…");
  let res;
  try {
    res = await invoke("inline_edit_propose", { payload: { path, sel_text: ctx.selText, instruction, ctx_before: ctx.before, ctx_after: ctx.after } });
  } catch (e) {
    toast("inline edit: " + (e && e.message ? e.message : e));
    return;
  }
  await loadProposals();
  editor.activePanel = null;
  editor.diffId = res.id;
  renderEditor();
  toast("inline edit ready — review the diff, then Approve & apply");
  if (/\.move$/i.test(path)) {
    try {
      const badge = await invoke("inline_edit_oracle", { payload: { id: res.id, path } });
      if (badge) { inlineOracle[res.id] = badge; if (editor.diffId === res.id) renderEditor(); }
    } catch (_) {}
  }
}
// ── A④-rg half②: find-in-files PANEL over the LIVE `context search` chokepoint ──────────────
// ⌘⇧F (Mod-Shift-f, an editor keymap — ⌘F stays the in-editor CM6 find) opens a floating panel; a
// regex runs the EXISTING `context search <regex>` core verb (read-only, in-Rust bounded walk,
// per-line redacted — half① shipped) via the SAME `runLine` dispatch bridge the chat uses; the
// `path:line: content` hits render as clickable rows → open the file + jump to the line. NO new
// core, NO new IPC; pure GUI wiring over the live chokepoint. custody/funds HARD-LOCKED.
let fifOpen = false;
function ensureFindPanel() {
  let p = document.getElementById("find-in-files");
  if (p) return p;
  p = document.createElement("div");
  p.id = "find-in-files";
  p.setAttribute("style", "position:fixed;right:20px;top:64px;width:min(560px,46vw);max-height:70vh;display:none;flex-direction:column;z-index:9998;background:var(--panel,#1b1d23);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.45);overflow:hidden;");
  p.innerHTML = '<div style="display:flex;gap:8px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--border,#3a3d44);">'
    + '<span style="font-size:12px;opacity:.7;white-space:nowrap;">find in files</span>'
    + '<input id="fif-input" type="text" autocomplete="off" placeholder="regex — Enter to search, Esc to close" style="flex:1;min-width:0;background:var(--bg,#0e0f13);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:6px;padding:6px 8px;font-size:13px;outline:none;" />'
    + '</div>'
    + '<div id="fif-results" style="overflow:auto;padding:6px 8px;font-size:12px;"></div>';
  document.body.appendChild(p);
  const inp = p.querySelector("#fif-input");
  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); runFindInFiles(); }
    else if (e.key === "Escape") { e.preventDefault(); closeFindPanel(); }
  });
  p.querySelector("#fif-results").addEventListener("click", (e) => {
    const row = e.target.closest("[data-fif-path]");
    if (!row) return;
    const path = row.dataset.fifPath;
    const line = parseInt(row.dataset.fifLine, 10) || 1;
    closeFindPanel();
    openFile(path).then(() => jumpToLine(line));
  });
  return p;
}
function openFindPanel() {
  const p = ensureFindPanel();
  p.style.display = "flex";
  fifOpen = true;
  const inp = p.querySelector("#fif-input");
  if (inp) { inp.focus(); inp.select(); }
}
function closeFindPanel() {
  const p = document.getElementById("find-in-files");
  if (p) p.style.display = "none";
  fifOpen = false;
  if (HAS_CM && cmView) cmView.focus();
}
async function runFindInFiles() {
  const p = document.getElementById("find-in-files");
  if (!p) return;
  const inp = p.querySelector("#fif-input");
  const out = p.querySelector("#fif-results");
  const query = inp && inp.value ? inp.value.trim() : "";
  if (!query) { if (out) out.innerHTML = ""; return; }
  if (out) out.innerHTML = `<div style="opacity:.6;padding:4px;">searching…</div>`;
  const card = await runLine("context search " + query, "context search");
  renderFifResults(out, card.body || []);
}
function renderFifResults(out, lines) {
  if (!out) return;
  const rows = lines.map((l) => {
    const m = l.match(/^(.+?):(\d+): (.*)$/);
    if (m) {
      return `<div class="fif-hit" data-fif-path="${esc(m[1])}" data-fif-line="${esc(m[2])}" style="padding:3px 4px;border-radius:4px;cursor:pointer;" title="${esc(m[1])}:${esc(m[2])}"><span class="mono" style="opacity:.6;">${esc(m[1])}:${esc(m[2])}</span> <span class="mono">${esc(m[3])}</span></div>`;
    }
    return `<div style="opacity:.55;padding:3px 4px;">${esc(l)}</div>`;
  });
  out.innerHTML = rows.length ? rows.join("") : `<div style="opacity:.6;padding:4px;">no hits</div>`;
}

// ── S-A ⌘P quick-open: fuzzy file jump (REUSES the fuzzyFiles subsequence scorer +
// tree.files; mirrors the find-in-files panel). Opening a hit = openFile, so the lane-A
// read walls + redaction still gate every byte — the GUI never reads file content. ──
let qoOpen = false;
let qo = { items: [], active: 0 };
function ensureQuickOpen() {
  let p = document.getElementById("quick-open");
  if (p) return p;
  p = document.createElement("div");
  p.id = "quick-open";
  p.setAttribute("style", "position:fixed;left:50%;top:72px;transform:translateX(-50%);width:min(560px,80vw);max-height:60vh;display:none;flex-direction:column;z-index:9998;background:var(--panel,#1b1d23);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:8px;box-shadow:0 8px 28px rgba(0,0,0,.45);overflow:hidden;");
  p.innerHTML = '<div style="display:flex;gap:8px;align-items:center;padding:8px 10px;border-bottom:1px solid var(--border,#3a3d44);">'
    + '<span style="font-size:12px;opacity:.7;white-space:nowrap;">quick open</span>'
    + '<input id="qo-input" type="text" autocomplete="off" placeholder="file name — ↑↓ select, Enter open, Esc close" style="flex:1;min-width:0;background:var(--bg,#0e0f13);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:6px;padding:6px 8px;font-size:13px;outline:none;" />'
    + '</div>'
    + '<div id="qo-results" style="overflow:auto;padding:6px 8px;font-size:12px;"></div>';
  document.body.appendChild(p);
  const inp = p.querySelector("#qo-input");
  inp.addEventListener("input", () => renderQuickOpen(false));
  inp.addEventListener("keydown", (e) => {
    const n = (qo.items || []).length;
    if (e.key === "ArrowDown") { e.preventDefault(); qo.active = n ? (qo.active + 1) % n : 0; renderQuickOpen(true); }
    else if (e.key === "ArrowUp") { e.preventDefault(); qo.active = n ? (qo.active - 1 + n) % n : 0; renderQuickOpen(true); }
    else if (e.key === "Enter") { e.preventDefault(); chooseQuickOpen(qo.active); }
    else if (e.key === "Escape") { e.preventDefault(); closeQuickOpen(); }
  });
  p.querySelector("#qo-results").addEventListener("click", (e) => {
    const row = e.target.closest("[data-qo-i]");
    if (row) chooseQuickOpen(parseInt(row.dataset.qoI, 10));
  });
  return p;
}
function openQuickOpen() {
  if (!(tree.files && tree.files.length)) { toast("⌘P: open a folder first (no indexed files)"); return; }
  const p = ensureQuickOpen();
  p.style.display = "flex";
  qoOpen = true;
  const inp = p.querySelector("#qo-input");
  if (inp) inp.value = "";
  qo.active = 0;
  renderQuickOpen(false);
  if (inp) setTimeout(() => { try { inp.focus(); } catch (_) {} }, 0);
}
function closeQuickOpen() {
  if (!qoOpen) return false;
  const p = document.getElementById("quick-open");
  if (p) p.style.display = "none";
  qoOpen = false;
  if (HAS_CM && cmView) cmView.focus();
  return true;
}
function renderQuickOpen(keepActive) {
  const p = document.getElementById("quick-open");
  if (!p) return;
  const inp = p.querySelector("#qo-input");
  const out = p.querySelector("#qo-results");
  const items = fuzzyFiles(inp ? inp.value : ""); // REUSE the subsequence scorer (no new fuzzy lib)
  qo.items = items;
  if (!keepActive) qo.active = 0;
  qo.active = Math.min(qo.active, Math.max(0, items.length - 1));
  if (!out) return;
  out.innerHTML = items.length
    ? items.map((it, i) => `<div class="qo-row" data-qo-i="${i}" style="padding:4px 6px;border-radius:4px;cursor:pointer;${i === qo.active ? "background:var(--accent,#3b82f6);color:#fff;" : ""}"><span class="mono">${esc(it.name)}</span></div>`).join("")
    : `<div style="opacity:.6;padding:4px;">no files</div>`;
}
function chooseQuickOpen(i) {
  const it = (qo.items || [])[i];
  if (!it) return;
  closeQuickOpen();
  openFile(it.name);
}

// ── S-A ⌘G go-to-line: a tiny centered input → jumpToLine in the active file ──
let gotoOpen = false;
function ensureGoToLine() {
  let bar = document.getElementById("goto-line");
  if (bar) return bar;
  bar = document.createElement("div");
  bar.id = "goto-line";
  bar.setAttribute("style", "position:fixed;left:50%;top:72px;transform:translateX(-50%);display:none;z-index:9999;gap:8px;align-items:center;padding:8px 10px;border-radius:8px;background:var(--panel,#1b1d23);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);box-shadow:0 6px 24px rgba(0,0,0,.4);min-width:300px;");
  bar.innerHTML = '<span style="font-size:12px;opacity:.7;white-space:nowrap;">go to line</span>'
    + '<input id="goto-input" type="text" inputmode="numeric" autocomplete="off" placeholder="line # — Enter, Esc" style="flex:1;min-width:0;background:var(--bg,#0e0f13);color:var(--fg,#e6e6e6);border:1px solid var(--border,#3a3d44);border-radius:6px;padding:6px 8px;font-size:13px;outline:none;" />';
  document.body.appendChild(bar);
  const inp = bar.querySelector("#goto-input");
  inp.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); const n = parseInt(inp.value, 10); closeGoToLine(); if (n) jumpToLine(n); }
    else if (e.key === "Escape") { e.preventDefault(); closeGoToLine(); }
  });
  return bar;
}
function openGoToLine() {
  if (!editor.active) { toast("⌘G: open a file first"); return; }
  const bar = ensureGoToLine();
  bar.style.display = "flex";
  gotoOpen = true;
  const inp = bar.querySelector("#goto-input");
  if (inp) { inp.value = ""; setTimeout(() => { try { inp.focus(); } catch (_) {} }, 0); }
}
function closeGoToLine() {
  if (!gotoOpen) return false;
  const bar = document.getElementById("goto-line");
  if (bar) bar.style.display = "none";
  gotoOpen = false;
  if (HAS_CM && cmView) cmView.focus();
  return true;
}
function diffHTML() {
  const p = proposals.find((x) => x.id === editor.diffId) || proposals[0];
  if (!p) { editor.diffId = null; return editorPlaceholderHTML(); }
  const switcher = proposals.length > 1
    ? `<div class="diff-switch">${proposals.map((x) => `<button class="diff-pick${x.id === p.id ? " on" : ""}" data-diffpick="${esc(x.id)}" title="${esc(x.target)}">${esc(x.target.split(/[\\/]/).pop())}${x.stale ? " ⚠" : ""}</button>`).join("")}</div>`
    : "";
  const stale = p.stale ? `<span class="diff-stale" title="the target changed since this was proposed — the core refuses apply until it is re-proposed">⚠ stale</span>` : "";
  const note = p.note ? `<div class="diff-note">${esc(p.note)}</div>` : "";
  const oracle = inlineOracle[p.id] ? `<span class="diff-oracle" title="advisory Move build check — the owner single-approve is final" style="margin-left:8px;font-size:11px;opacity:.85;">oracle: ${esc(inlineOracle[p.id])}</span>` : "";
  const canDiff = p.old_content != null;
  const rows = canDiff ? lineDiff(p.old_content, p.new_content) : [];
  const stat = canDiff ? diffStat(rows) : "";
  const body = canDiff ? renderDiffRows(rows) : `<div class="viewer-msg">${esc(p.note || "no textual diff available")}</div>`;
  return `
    <div class="diff-head">
      <div class="diff-meta"><span class="diff-target mono">${esc(p.target)}</span>${stale}${oracle}<span class="diff-stat">${stat}</span></div>
      <div class="diff-actions">
        <button class="diff-approve" data-diffapprove="${esc(p.id)}"${p.stale ? " disabled" : ""}>Approve &amp; apply</button>
        <button class="diff-close" data-action="close-diff">Close</button>
      </div>
    </div>
    ${switcher}${note}
    <div class="diff-body">${body}</div>`;
}
async function approveProposal(id) {
  const p = proposals.find((x) => x.id === id);
  if (!p) return;
  if (p.stale) { toast("stale — the file changed since this edit was proposed; ask the agent to re-propose."); return; }
  toast("applying edit…");
  let card;
  try { card = parseResponse(await invoke("dispatch_line", { line: "tool apply file-apply-owner-live " + id })); }
  catch (e) { toast("apply failed: " + (e && e.message ? e.message : e)); return; }
  const txt = (card.body || []).join(" ");
  const failed = card.error || /denied|stale|unknown|ambiguous|fail|locked|withheld/i.test(txt);
  if (failed) {
    toast((card.body || []).find((l) => /denied|stale|unknown|ambiguous|fail|locked|withheld/i.test(l)) || "apply was not completed");
    await loadProposals();
    return;
  }
  toast("✓ edit applied to " + p.target.split(/[\\/]/).pop());
  const reopenRel = (editor.open.find((f) => f.abspath === p.target) || {}).relpath;
  editor.diffId = null;
  await loadProposals();
  if (uiRoot) await loadTree(uiRoot);
  if (reopenRel) openFile(reopenRel);
  else renderEditor();
}
function onCodeBodyClick(e) {
  // P2-S3: the Settings center tab's left rail (persistent #code-body delegation, survives re-renders).
  const sec = e.target.closest("[data-settings-section]");
  if (sec) { setSettingsSection(sec.dataset.settingsSection); return; }
  // P2-S4a: the LoRA/Routing editor — add/remove/save (delegated so dynamically-added rows work).
  const radd = e.target.closest("[data-routing-add]");
  if (radd) { addRoutingRow(); return; }
  const rdel = e.target.closest("[data-routing-remove]");
  if (rdel) { const row = rdel.closest("[data-routing-row]"); if (row) row.remove(); return; }
  const rsave = e.target.closest("[data-routing-save]");
  if (rsave) { saveRoutingTable(); return; }
  // P2-S4f: one-click adapter connect (pick a LoRA folder → auto-detect → wire the routing rows).
  const apick = e.target.closest("[data-adapter-pick]");
  if (apick) { pickAdapterFolder(); return; }
  const aconn = e.target.closest("[data-adapter-connect]");
  if (aconn) { connectAdapter(); return; }
  // P2-S5: center editor edit-mode — Edit toggles, Save persists (owner_save_file), Cancel discards.
  if (e.target.closest("[data-edit-file]")) { setEditing(true); return; }
  if (e.target.closest("[data-cancel-edit]")) { setEditing(false); return; }
  if (e.target.closest("[data-save-file]")) { saveOwnerFile(); return; }
  const pick = e.target.closest("[data-diffpick]");
  if (pick) { editor.diffId = pick.dataset.diffpick; renderEditor(); return; }
  const appr = e.target.closest("[data-diffapprove]");
  if (appr) approveProposal(appr.dataset.diffapprove);
}

/* ── R10: first-run capability disclosure gate ───────────────────────────────
   Show the disclosure ONCE on first launch, then remember (D-2: never force it
   again — the topbar "?" re-opens it any time). localStorage-gated; the flag is set
   BEFORE opening so it is idempotent (a reload never re-pops it). Pure static panel
   ⇒ works in any build (no invoke / no Tauri dependency). */
function maybeFirstRunDisclosure() {
  // FACELIFT (2026-06-22): the full-window welcome HERO is the first-run onboarding now;
  // the capability disclosure is on-demand via the topbar "?" (data-action="disclosure"),
  // never an auto-modal covering the hero. (D-2 honored: never forced, always recallable.)
  return;
}

/* ── init ────────────────────────────────────────────────────────────────── */
/* ── E13-2 (⑱): inbound Telegram remote-control poll ──────────────────────────
   The core exposes NO backend→frontend push channel, so we POLL the read-only
   `poll_inbound_telegram` command — the HONEST wiring (never a faked event). The
   core owner-pins + redacts before anything reaches here: a non-owner update never
   arrives; a secret-shaped one arrives only as a withheld marker. We dedupe by
   content (a stateless re-poll returns the same pending updates) so duplicates never
   spam, and an in-flight guard avoids overlapping long-polls. Reply is the CLI
   `daemon serve-chat` (Option A); this surface NEVER runs a turn or sends. */
const INBOUND_TG_POLL_MS = 8000;
const inboundTgSeen = new Set();
let inboundTgTimer = null;
let inboundTgInFlight = false;

async function pollInboundTelegram() {
  if (!hasTauri() || inboundTgInFlight) return;
  inboundTgInFlight = true;
  let cards;
  try { cards = await invoke("poll_inbound_telegram"); }
  catch (_) { return; } // honest absence on any error — never a fabricated card
  finally { inboundTgInFlight = false; }
  if (!Array.isArray(cards) || cards.length === 0) return;
  const s = currentSession();
  if (!s) return;
  let added = false;
  for (const c of cards) {
    const key = (c.kind || "chat") + "|" + (c.text || "");
    if (inboundTgSeen.has(key)) continue;
    inboundTgSeen.add(key);
    s.messages.push({
      role: "system",
      time: nowLabel(),
      card: { kind: "inbound-telegram", tgKind: c.kind || "chat", text: c.text || "" },
    });
    added = true;
  }
  if (added) { renderView(); renderSidebar(); persist(); }
}

function startInboundTelegramPoll() {
  if (inboundTgTimer != null) return;
  pollInboundTelegram();
  inboundTgTimer = setInterval(pollInboundTelegram, INBOUND_TG_POLL_MS);
}

async function init() {
  bindChrome();
  applyUiPrefs();   // P2-S3: restore the GUI-owned UI / code font prefs (localStorage) before first render
  const restored = await restore();
  if (!restored) {
    newSession(false);
    state.currentSession = state.projects[0].sessions[0].id;
  } else if (!currentSession()) {
    const proj = state.projects.find((p) => p.id === state.currentProject) || state.projects[0];
    state.currentSession = (proj.sessions[0] && proj.sessions[0].id) || null;
    if (!state.currentSession) { newSession(false); state.currentSession = proj.sessions[0].id; }
  }
  renderSidebar();
  renderView();
  refreshModelLabel();
  refreshStatus();
  loadGates(); // core-derived palette lock badges (single source of truth); fire-and-forget
  refreshKeyPresence(); // A#13: key-conditional empty-screen onboarding; fire-and-forget
  initFileDrop();
  initSplitters();
  applyPaneVisibility();   // restore the chat/files pane toggles + reflect state on the topbar buttons
  renderFiles();
  renderEditor();
  restoreRoot();
  loadProposals();
  startInboundTelegramPoll();   // E13-2: surface inbound owner Telegram messages as cards (read-only poll)
  maybeFirstRunDisclosure();   // R10: first-run capability disclosure (1x, then remembered)
  fillIcons();   // FACELIFT: fill the static [data-icon] SVGs (topbar · agent rail · files)
  if (!hasTauri()) toast("Tauri bridge not detected — run with `cargo tauri dev` to dispatch commands into the core.");
}
// blind-debug: surface any uncaught runtime error as a toast (agent can't see console)
window.addEventListener("error", (e) => { try { toast("⚠ JS: " + (e.message || "error")); } catch (_) {} });
window.addEventListener("unhandledrejection", (e) => { try { toast("⚠ JS: " + (e.reason && e.reason.message ? e.reason.message : e.reason)); } catch (_) {} });

if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
else init();
