//! `provider::executor_route` — the task-aware EXECUTOR router (the
//! orchestrator spine).
//!
//! L2 of the three-layer separation: a PURE, DETERMINISTIC map from a sub-task's
//! declared expert-domain `kind` to the executor TARGET `(port, model_id)` that
//! serves it. This is the "WHICH specialist brain" decision — ORTHOGONAL to
//! [`crate::provider::route_select::select_consult_route`] (the "WHO/permission"
//! local-vs-frontier decision). The dynamic-LoRA reality is EXTERNAL: the model
//! server hot-switches adapters behind the OpenAI-compatible
//! `model` field; sinabro's whole job is to emit the right `(port, model_id)` per
//! sub-task. Modes A (sequential = the v1 default), Macro (per-chain worker = a
//! different `port`), and B (weighted-MoE = a merged `model_id`) are therefore
//! DATA in the routing table, not three code paths.
//!
//! META-LAW (control-plane drift-0): this selector is a TOTAL pure function — the
//! `kind` tag is advisory (the frontier tags each sub-task), but the kind->target
//! MAPPING is deterministic and ALWAYS resolves (an unmapped kind falls back to
//! the table's typed default; never a panic, never a hole). The expert set is
//! OPEN / user-configurable (owner law: sinabro is NOT an audit/coding agent — a
//! natural-language LoRA, a personal-memory expert, anything is a valid kind):
//! openness lives in the table DATA, determinism in the lookup.
//!
//! No real adapter exists on disk — the table is seeded with STUB model-ids
//! and proven against the canned loopback double; the same shape drives a real
//! multi-LoRA server unchanged at owner go-live. The per-request `model` field is
//! consumed by `LocalChatTransport::send_local_text_with` (the seam; that
//! module is feature-gated, so this is a plain reference not an intra-doc link).
//! Mode tagging and the owner config that fills this table, and the orchestrator
//! that consumes this router, are handled by separate components.

/// A validated expert-domain label (OPEN / user-configurable) — the routing key
/// the frontier tags onto a sub-task. Closed charset (ascii-lowercase alnum +
/// `_`, 1..=48 bytes) so the routing path is fail-closed + drift-0; any garbage
/// label is rejected at construction (no free-form string ever reaches the map).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorKind(String);

impl ExecutorKind {
    /// Well-known seed kinds (the v1 table maps these; the set is NOT closed —
    /// `new` accepts any valid label, e.g. a user-registered `personal_memory`).
    pub const SUI_MOVE: &'static str = "sui_move";
    /// Solana / Anchor implementation expert.
    pub const SOLANA_ANCHOR: &'static str = "solana_anchor";
    /// Web3 frontend coding expert.
    pub const WEB3_FRONTEND: &'static str = "web3_frontend";
    /// Audit / review expert (a TASK kind, never sinabro's identity).
    pub const AUDIT: &'static str = "audit";
    /// Natural-language bridge expert (owner: an NL LoRA is a first-class kind).
    pub const NL_BRIDGE: &'static str = "nl_bridge";
    /// Personal-memory expert (owner: a personal-memory LoRA is a first-class kind).
    /// Verification class = `PersonalOwner` (provenance + human gate).
    pub const PERSONAL_MEMORY: &'static str = "personal_memory";
    /// External-fact expert. Verification class = `ExternalFact` (independent corroboration).
    pub const EXTERNAL_FACT: &'static str = "external_fact";
    /// Research expert. Verification class = `ExternalFact` (independent corroboration).
    pub const RESEARCH: &'static str = "research";
    /// Cross-memory reconciliation. Verification class = `CrossMemory` (contradiction-detection).
    pub const CROSS_MEMORY: &'static str = "cross_memory";

    /// Validate + construct. Fail-closed: empty, over-length (>48 bytes), or any
    /// byte outside `[a-z0-9_]` ⇒ `None`.
    #[must_use]
    pub fn new(label: &str) -> Option<Self> {
        if label.is_empty() || label.len() > 48 {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            return None;
        }
        Some(Self(label.to_string()))
    }

    /// The validated label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.0
    }
}

/// The executor target a sub-task routes to: the loopback `port` (which worker —
/// Macro mode varies this) and the `model_id` sent in the OpenAI-compatible
/// request body (which adapter — sequential/weighted mode varies this). This is
/// the ENTIRE sinabro-side surface of "dynamic LoRA switching" (R1/R2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorTarget {
    /// The loopback port of the model worker that serves this sub-task.
    pub port: u16,
    /// The `model` id placed in the request body (the adapter selector).
    pub model_id: String,
}

/// The kind->target lookup (OPEN data; owner config fills it). Holds an
/// ordered list of `(kind, target)` bindings + a typed `default` target so the
/// lookup is TOTAL (drift-0: every kind resolves). First match wins (stable,
/// deterministic ordering).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorRoutingTable {
    bindings: Vec<(ExecutorKind, ExecutorTarget)>,
    default: ExecutorTarget,
}

impl ExecutorRoutingTable {
    /// Construct from explicit `bindings` + the `default` target (the totality
    /// anchor served when a kind is unmapped).
    #[must_use]
    pub fn new(bindings: Vec<(ExecutorKind, ExecutorTarget)>, default: ExecutorTarget) -> Self {
        Self { bindings, default }
    }

    /// The default target (served when a kind is unmapped — totality anchor).
    #[must_use]
    pub fn default_target(&self) -> &ExecutorTarget {
        &self.default
    }

    /// The explicit `(kind, target)` bindings, in order (the config seam
    /// serializes these; the default is rendered separately).
    #[must_use]
    pub fn bindings(&self) -> &[(ExecutorKind, ExecutorTarget)] {
        &self.bindings
    }

    /// Number of explicit kind bindings (excludes the default).
    #[must_use]
    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    /// Whether there are no explicit bindings (only the default would serve).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// The default local port for the v1 proof + out-of-box default (the ollama
/// default; deploy/owner config overrides per worker).
pub const DEFAULT_LOCAL_PORT: u16 = 11434;

/// A seed routing table for the v1 proof + the out-of-box default — each known
/// expert kind mapped to a STUB model-id on the default local port (Mode A
/// sequential; no real adapter exists on disk). Owner config replaces
/// this; the SHAPE is unchanged when a real multi-LoRA server is wired.
#[must_use]
pub fn default_routing_table() -> ExecutorRoutingTable {
    let stub = |id: &str| ExecutorTarget {
        port: DEFAULT_LOCAL_PORT,
        model_id: id.to_string(),
    };
    // In-module construction of known-valid labels (the public `new` validator is
    // exercised by tests; these constants are statically valid).
    let kind = |s: &str| ExecutorKind(s.to_string());
    ExecutorRoutingTable::new(
        vec![
            (kind(ExecutorKind::SUI_MOVE), stub("naite_sui_move")),
            (
                kind(ExecutorKind::SOLANA_ANCHOR),
                stub("naite_solana_anchor"),
            ),
            (
                kind(ExecutorKind::WEB3_FRONTEND),
                stub("web3_frontend_coder"),
            ),
            (kind(ExecutorKind::AUDIT), stub("naite_audit")),
            (kind(ExecutorKind::NL_BRIDGE), stub("nl_bridge")),
        ],
        stub("default"),
    )
}

/// Select the executor target for a sub-task's declared `kind` — the single typed
/// L2 routing truth. TOTAL: an unmapped kind resolves to the table's default
/// (drift-0, no panic, no hole). First binding wins.
#[must_use]
pub fn select_executor_route<'t>(
    kind: &ExecutorKind,
    table: &'t ExecutorRoutingTable,
) -> &'t ExecutorTarget {
    table
        .bindings
        .iter()
        .find_map(|(k, target)| (k == kind).then_some(target))
        .unwrap_or(&table.default)
}

/// One decomposed sub-task — the cross-language envelope the frontier PLAN emits,
/// the router consumes (`kind`), and the local executor implements (`goal`). The
/// schema is fixed across languages; `kind` is the routing
/// key, `deps` the intra-plan ordering (DAG edges by id).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubTask {
    /// Stable sub-task id within the plan.
    pub id: u32,
    /// The declared expert-domain (the routing key; advisory tag from the frontier).
    pub kind: ExecutorKind,
    /// The implementation goal (handed to the local executor verbatim).
    pub goal: String,
    /// Ids of sub-tasks this one depends on (DAG edges).
    pub deps: Vec<u32>,
}

/// Parse ONE `SUBTASK <id> <kind> <deps|-> <goal...>` line into a [`SubTask`].
/// Fail-closed: wrong prefix, non-u32 id, invalid kind label, malformed deps, or
/// an empty goal ⇒ `None`. `deps` is `-` (none) or a comma-separated u32 list.
#[must_use]
pub fn parse_subtask_line(line: &str) -> Option<SubTask> {
    let rest = line.trim().strip_prefix("SUBTASK ")?;
    let (id_str, rest) = rest.trim_start().split_once(' ')?;
    let (kind_str, rest) = rest.trim_start().split_once(' ')?;
    let (deps_str, goal) = rest.trim_start().split_once(' ')?;
    let id = id_str.parse::<u32>().ok()?;
    let kind = ExecutorKind::new(kind_str)?;
    let goal = goal.trim();
    if goal.is_empty() {
        return None;
    }
    let deps = if deps_str == "-" {
        Vec::new()
    } else {
        deps_str
            .split(',')
            .map(str::parse::<u32>)
            .collect::<Result<Vec<u32>, _>>()
            .ok()?
    };
    Some(SubTask {
        id,
        kind,
        goal: goal.to_string(),
        deps,
    })
}

/// Parse a decompose envelope (one `SUBTASK ...` line per sub-task) fail-closed:
/// every non-empty line MUST be a valid SUBTASK line, and at least one sub-task
/// must result — otherwise `None` (a malformed plan never half-parses).
#[must_use]
pub fn parse_subtask_envelope(text: &str) -> Option<Vec<SubTask>> {
    let mut tasks = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        tasks.push(parse_subtask_line(trimmed)?);
    }
    if tasks.is_empty() { None } else { Some(tasks) }
}

/// Layer a decomposed sub-task list into DETERMINISTIC topological WAVES by its
/// `deps` DAG — the parallel-fleet ordering truth (the parsed-but-unused
/// [`SubTask::deps`] becomes load-bearing). Returns waves of INDICES into
/// `subtasks`: wave 0 is every sub-task with no (resolved) dependency; each later
/// wave becomes ready only once every one of its deps has landed in an earlier
/// wave. Within a wave the indices are ordered by sub-task `id` (drift-0: a stable,
/// schedule-INDEPENDENT order, so the fan-out's collected result never depends on
/// thread timing).
///
/// Fail-closed `None` on (a) a duplicate sub-task `id` (a dep could not name it
/// uniquely), (b) a `dep` id that names no sub-task, (c) a self-dependency, or (d) a
/// dependency CYCLE — the caller stops typed rather than guessing an order or
/// deadlocking. An empty input yields `Some(vec![])` (no waves).
#[must_use]
pub fn topological_waves(subtasks: &[SubTask]) -> Option<Vec<Vec<usize>>> {
    use std::collections::BTreeMap;
    // id -> index; a duplicate id is fail-closed (deps would be ambiguous).
    let mut id_to_idx: BTreeMap<u32, usize> = BTreeMap::new();
    for (idx, st) in subtasks.iter().enumerate() {
        if id_to_idx.insert(st.id, idx).is_some() {
            return None;
        }
    }
    let n = subtasks.len();
    let mut indeg: Vec<usize> = vec![0; n];
    let mut succ: Vec<Vec<usize>> = vec![Vec::new(); n]; // edges: dep -> dependent
    for (idx, st) in subtasks.iter().enumerate() {
        for dep_id in &st.deps {
            let dep_idx = *id_to_idx.get(dep_id)?; // unknown dep id ⇒ None
            if dep_idx == idx {
                return None; // self-dependency is a 1-cycle
            }
            succ[dep_idx].push(idx);
            indeg[idx] += 1;
        }
    }
    let mut ready: Vec<usize> = (0..n).filter(|&i| indeg[i] == 0).collect();
    ready.sort_by_key(|&i| subtasks[i].id);
    let mut waves: Vec<Vec<usize>> = Vec::new();
    let mut peeled = 0usize;
    while !ready.is_empty() {
        peeled += ready.len();
        let mut next: Vec<usize> = Vec::new();
        for &i in &ready {
            for &j in &succ[i] {
                indeg[j] -= 1;
                if indeg[j] == 0 {
                    next.push(j);
                }
            }
        }
        next.sort_by_key(|&i| subtasks[i].id);
        waves.push(std::mem::take(&mut ready));
        ready = next;
    }
    // Unpeeled nodes ⇒ a cycle left the graph non-empty (fail-closed).
    if peeled == n { Some(waves) } else { None }
}

// ===========================================================================
// The LoRA router-table CONFIG SEAM (PURE codec; the owner fills the table).
// ===========================================================================

/// The owner config filename (under the data dir) that REPLACES the seed routing table.
/// Format: one `<kind|default> <port> <model_id>` line per binding (`#` comments / blank
/// lines ignored); a `default` line sets the totality-anchor target. The IO load lives in
/// the dispatch layer (this module stays PURE) — `load_routing_table` reads this file.
pub const ROUTING_TABLE_CONFIG_FILE: &str = "routing_table.txt";

/// Parse an owner routing-table config (PURE, fail-closed): every non-comment line must be
/// `<kind|default> <port> <model_id>` (exactly 3 tokens, a valid u16 port, a non-empty
/// model_id, a valid kind label or the literal `default`), and a `default` line MUST be
/// present (the totality anchor). Any malformed line ⇒ `None` (the whole config is
/// rejected and the caller falls back to the seed table — never a half-parsed router).
#[must_use]
pub fn parse_routing_table_config(text: &str) -> Option<ExecutorRoutingTable> {
    let mut bindings: Vec<(ExecutorKind, ExecutorTarget)> = Vec::new();
    let mut default: Option<ExecutorTarget> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut it = line.split_whitespace();
        let kind_s = it.next()?;
        let port_s = it.next()?;
        let model = it.next()?;
        if it.next().is_some() {
            return None; // extra tokens — fail-closed
        }
        let port: u16 = port_s.parse().ok()?;
        if model.is_empty() {
            return None;
        }
        let target = ExecutorTarget {
            port,
            model_id: model.to_string(),
        };
        if kind_s == "default" {
            default = Some(target);
        } else {
            let kind = ExecutorKind::new(kind_s)?;
            bindings.push((kind, target));
        }
    }
    let default = default?; // a config MUST declare the default target
    Some(ExecutorRoutingTable::new(bindings, default))
}

/// Serialize a routing table to the owner config format (PURE; round-trips through
/// [`parse_routing_table_config`]).
#[must_use]
pub fn serialize_routing_table(table: &ExecutorRoutingTable) -> String {
    use std::fmt::Write as _;
    let mut s = String::from("# sinabro LoRA routing table: <kind|default> <port> <model_id>\n");
    for (kind, target) in table.bindings() {
        let _ = writeln!(s, "{} {} {}", kind.label(), target.port, target.model_id);
    }
    let d = table.default_target();
    let _ = writeln!(s, "default {} {}", d.port, d.model_id);
    s
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    // ---- ExecutorKind validation (fail-closed, drift-0 charset) ----

    #[test]
    fn kind_accepts_valid_labels_and_rejects_garbage() {
        assert!(ExecutorKind::new("sui_move").is_some());
        assert!(ExecutorKind::new("personal_memory").is_some(), "OPEN set");
        assert!(ExecutorKind::new("nl2").is_some());
        assert!(ExecutorKind::new("").is_none(), "empty rejected");
        assert!(
            ExecutorKind::new("Sui_Move").is_none(),
            "uppercase rejected"
        );
        assert!(ExecutorKind::new("sui move").is_none(), "space rejected");
        assert!(ExecutorKind::new("sui-move").is_none(), "dash rejected");
        assert!(
            ExecutorKind::new(&"x".repeat(49)).is_none(),
            "over-length rejected"
        );
        assert_eq!(
            ExecutorKind::new("sui_move").map(|k| k.label().to_string()),
            Some("sui_move".to_string())
        );
    }

    // ---- routing: deterministic, total, drift-0 ----

    #[test]
    fn known_kind_routes_to_its_bound_target() {
        let table = default_routing_table();
        let sui = ExecutorKind::new(ExecutorKind::SUI_MOVE).expect("valid");
        let target = select_executor_route(&sui, &table);
        assert_eq!(target.model_id, "naite_sui_move");
        assert_eq!(target.port, DEFAULT_LOCAL_PORT);
    }

    #[test]
    fn unmapped_kind_falls_back_to_default_totality() {
        let table = default_routing_table();
        let unknown = ExecutorKind::new("some_unregistered_expert").expect("valid label");
        let target = select_executor_route(&unknown, &table);
        assert_eq!(
            target,
            table.default_target(),
            "unmapped kind resolves to the default (no panic, no hole)"
        );
        assert_eq!(target.model_id, "default");
    }

    /// THE DRIFT-0 ROUTING PROOF: the SAME router, queried with two
    /// DIFFERENT kinds, returns DIFFERENT targets ⇒ the model_id that will ride
    /// the request body differs by task kind. This is the whole sinabro-side
    /// "dynamic LoRA switch" — deterministic, no model in the loop.
    #[test]
    fn different_kinds_route_to_different_model_ids() {
        let table = default_routing_table();
        let sui = ExecutorKind::new(ExecutorKind::SUI_MOVE).expect("valid");
        let solana = ExecutorKind::new(ExecutorKind::SOLANA_ANCHOR).expect("valid");
        let a = select_executor_route(&sui, &table).model_id.clone();
        let b = select_executor_route(&solana, &table).model_id.clone();
        assert_ne!(a, b, "different expert kinds select different adapters");
        assert_eq!(a, "naite_sui_move");
        assert_eq!(b, "naite_solana_anchor");
    }

    /// Determinism canary: the SAME kind always routes to the SAME target (a
    /// wrong `assert_eq` here would FAIL if routing were nondeterministic).
    #[test]
    fn routing_is_deterministic_canary() {
        let table = default_routing_table();
        let audit = ExecutorKind::new(ExecutorKind::AUDIT).expect("valid");
        let first = select_executor_route(&audit, &table).clone();
        let second = select_executor_route(&audit, &table).clone();
        assert_eq!(first, second);
    }

    #[test]
    fn first_binding_wins() {
        let kind = ExecutorKind::new("dup").expect("valid");
        let table = ExecutorRoutingTable::new(
            vec![
                (
                    kind.clone(),
                    ExecutorTarget {
                        port: 1,
                        model_id: "first".to_string(),
                    },
                ),
                (
                    kind.clone(),
                    ExecutorTarget {
                        port: 2,
                        model_id: "second".to_string(),
                    },
                ),
            ],
            ExecutorTarget {
                port: 9,
                model_id: "default".to_string(),
            },
        );
        assert_eq!(select_executor_route(&kind, &table).model_id, "first");
        assert_eq!(table.len(), 2);
        assert!(!table.is_empty());
    }

    // ---- envelope parse: fail-closed cross-language lock ----

    #[test]
    fn parse_valid_subtask_line() {
        let t = parse_subtask_line("SUBTASK 3 sui_move 1,2 implement transfer entry fun")
            .expect("valid line parses");
        assert_eq!(t.id, 3);
        assert_eq!(t.kind.label(), "sui_move");
        assert_eq!(t.goal, "implement transfer entry fun");
        assert_eq!(t.deps, vec![1, 2]);
    }

    #[test]
    fn parse_line_no_deps_dash() {
        let t = parse_subtask_line("SUBTASK 1 nl_bridge - explain the plan to the user")
            .expect("valid");
        assert_eq!(t.deps, Vec::<u32>::new());
        assert_eq!(t.kind.label(), "nl_bridge");
    }

    #[test]
    fn parse_fails_closed_on_malformed() {
        assert!(parse_subtask_line("not a subtask").is_none(), "bad prefix");
        assert!(
            parse_subtask_line("SUBTASK x sui_move - goal").is_none(),
            "non-u32 id"
        );
        assert!(
            parse_subtask_line("SUBTASK 1 Sui_Move - goal").is_none(),
            "invalid kind label"
        );
        assert!(
            parse_subtask_line("SUBTASK 1 sui_move 1,x goal").is_none(),
            "malformed deps"
        );
        assert!(
            parse_subtask_line("SUBTASK 1 sui_move -   ").is_none(),
            "empty goal"
        );
        assert!(
            parse_subtask_line("SUBTASK 1 sui_move").is_none(),
            "missing fields"
        );
    }

    #[test]
    fn parse_envelope_all_or_nothing() {
        let ok = parse_subtask_envelope(
            "SUBTASK 1 sui_move - build module\nSUBTASK 2 audit 1 review it\n",
        )
        .expect("all lines valid");
        assert_eq!(ok.len(), 2);
        assert_eq!(ok[1].deps, vec![1]);

        assert!(
            parse_subtask_envelope("SUBTASK 1 sui_move - ok\nGARBAGE LINE\n").is_none(),
            "one bad line fails the whole envelope (no half-parse)"
        );
        assert!(
            parse_subtask_envelope("\n   \n").is_none(),
            "no sub-tasks is malformed"
        );
    }

    // ---- topological waves (deps-DAG, deterministic, fail-closed) ----

    #[test]
    fn waves_independent_is_one_wave_in_id_order() {
        let st = parse_subtask_envelope(
            "SUBTASK 1 sui_move - a\nSUBTASK 2 audit - b\nSUBTASK 3 nl_bridge - c",
        )
        .expect("valid");
        // All independent ⇒ one wave, ordered by id (drift-0).
        assert_eq!(topological_waves(&st), Some(vec![vec![0, 1, 2]]));
    }

    #[test]
    fn waves_linear_chain_is_n_waves() {
        let st = parse_subtask_envelope(
            "SUBTASK 1 sui_move - a\nSUBTASK 2 audit 1 b\nSUBTASK 3 nl_bridge 2 c",
        )
        .expect("valid");
        assert_eq!(
            topological_waves(&st),
            Some(vec![vec![0], vec![1], vec![2]])
        );
    }

    #[test]
    fn waves_diamond_orders_by_dependency_then_id() {
        // 1 -> {2,3} -> 4
        let st = parse_subtask_envelope(
            "SUBTASK 1 sui_move - a\nSUBTASK 2 audit 1 b\nSUBTASK 3 audit 1 c\nSUBTASK 4 nl_bridge 2,3 d",
        )
        .expect("valid");
        assert_eq!(
            topological_waves(&st),
            Some(vec![vec![0], vec![1, 2], vec![3]])
        );
    }

    #[test]
    fn waves_fail_closed_on_cycle_unknown_self_and_dup() {
        let cyc =
            parse_subtask_envelope("SUBTASK 1 sui_move 2 a\nSUBTASK 2 audit 1 b").expect("parses");
        assert!(topological_waves(&cyc).is_none(), "cycle ⇒ None");

        let unknown = parse_subtask_envelope("SUBTASK 1 sui_move 9 a").expect("parses");
        assert!(
            topological_waves(&unknown).is_none(),
            "unknown dep id ⇒ None"
        );

        let self_dep = parse_subtask_envelope("SUBTASK 1 sui_move 1 a").expect("parses");
        assert!(topological_waves(&self_dep).is_none(), "self-dep ⇒ None");

        let dup =
            parse_subtask_envelope("SUBTASK 1 sui_move - a\nSUBTASK 1 audit - b").expect("parses");
        assert!(topological_waves(&dup).is_none(), "duplicate id ⇒ None");
    }

    #[test]
    fn waves_empty_is_empty() {
        assert_eq!(topological_waves(&[]), Some(Vec::<Vec<usize>>::new()));
    }

    // ---- routing-table config seam (pure, fail-closed) ----

    #[test]
    fn routing_config_parses_and_drives_selection() {
        let text = "# owner LoRA table\nsui_move 11500 my_sui_lora\nsolana_anchor 11501 my_sol_lora\ndefault 11434 fallback_model\n";
        let table = parse_routing_table_config(text).expect("valid config parses");
        assert_eq!(table.len(), 2);
        let sui = ExecutorKind::new("sui_move").expect("valid");
        let t = select_executor_route(&sui, &table);
        assert_eq!(t.port, 11500);
        assert_eq!(
            t.model_id, "my_sui_lora",
            "config OVERRIDES the seed model_id"
        );
        // an unmapped kind falls to the config's default (totality).
        let unknown = ExecutorKind::new("personal_memory").expect("valid");
        let d = select_executor_route(&unknown, &table);
        assert_eq!(d.model_id, "fallback_model");
    }

    #[test]
    fn routing_config_is_fail_closed() {
        // missing default ⇒ rejected (no totality anchor).
        assert!(parse_routing_table_config("sui_move 11500 m\n").is_none());
        // bad port ⇒ rejected.
        assert!(parse_routing_table_config("default notaport m\n").is_none());
        // extra tokens ⇒ rejected.
        assert!(parse_routing_table_config("default 11434 m extra\n").is_none());
        // invalid kind label ⇒ rejected.
        assert!(parse_routing_table_config("Sui_Move 11500 m\ndefault 11434 d\n").is_none());
        // empty / comments-only ⇒ no default ⇒ None.
        assert!(parse_routing_table_config("# just a comment\n").is_none());
    }

    #[test]
    fn routing_config_round_trips() {
        let table = default_routing_table();
        let text = serialize_routing_table(&table);
        let back = parse_routing_table_config(&text).expect("serialized table re-parses");
        assert_eq!(back, table, "serialize -> parse is the identity");
    }
}
