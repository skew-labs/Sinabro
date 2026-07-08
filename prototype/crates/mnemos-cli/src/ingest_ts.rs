//! N-1 (Nous IR) — TYPESCRIPT definition-unit ingest + CONSERVATIVE syntactic
//! normalization (owner seam-lock 2026-07-07: Q1 = TypeScript, Q3 = syntactic
//! normalization, conservative). File blob → one node per top-level definition
//! (function / class / interface / type / enum / const), each content-addressed
//! by [`crate::defn_node::node_cid`] (P-LOCK-2: the name is DATA, not identity).
//!
//! ## Soundness argument (why the normalizer cannot FALSE-MERGE)
//!
//! Normalization does exactly three things, each semantics-preserving or
//! identity-preserving:
//!
//! 1. **Whitespace/comments dropped, ASI-safely.** A line break between tokens is
//!    dropped ONLY when either neighbor proves no statement can end there
//!    ([`punct_safe_after`] / [`safe_before`]); a restricted production
//!    (`return`/`throw`/`break`/`continue`/`yield` + newline) is canonicalized to
//!    an explicit `;` exactly as ASI would; every other line break stays as a
//!    significant [`NormToken::Newline`]. Uncertain ⇒ kept ⇒ distinct nodes.
//! 2. **Uniform fresh renaming.** The own name and each alpha-eligible local are
//!    replaced at EVERY identifier occurrence by a placeholder token kind that no
//!    source text can spell ([`NormToken::SelfRef`] / [`NormToken::AlphaVar`]).
//!    A uniform substitution of ALL occurrences of one identifier by a FRESH
//!    name is semantics-preserving regardless of shadowing (it is a bijection on
//!    names). What is NOT a renameable identifier occurrence — a property access
//!    (`.x`), an object key (`x:`), an object method / shorthand, a TYPE position
//!    (after `:`), text inside a string/template/regex — VETOES eligibility
//!    (those are external-facing names; renaming them could merge two units with
//!    different public shapes). `eval`/`with` in a unit disables alpha entirely.
//! 3. **Raw text otherwise.** Literals keep their exact spelling (`1e3` ≠ `1000`,
//!    `'a'` ≠ `"a"`) — a false split is allowed, a false merge is not (Q3
//!    soundness-first).
//!
//! Anything the tokenizer cannot confidently lex fails the WHOLE file closed
//! ([`IngestDeny`], honest render, zero nodes) — never a guessed token stream. A
//! unit whose token payload exceeds the wire cap degrades to the OPAQUE tier
//! (identity = exact spelling, no invariance claimed, rendered honestly).
//!
//! ## Honest v1 scope
//!
//! * Alpha-conversion runs ONLY inside `function` definition units (the
//!   report's "one function = one node" core). Class/interface/type/enum/const
//!   units are normalized for whitespace/comments/own-name but keep their local
//!   names (conservative: a local rename there = a different node).
//! * Arrow-function parameters are not alpha candidates yet (conservative).
//! * No type checker runs (TypeScript has no `lsp.rs` oracle): `type_sig` is the
//!   normalized DECLARED header slice; `effect_sig` is the fixed conservative
//!   [`crate::defn_node::EFFECT_SIG_UNKNOWN_V1`] marker; `deps` is empty (N-3).
//!
//! PURITY: tokenize/split/normalize are PURE (no network, no clock, no fs). The
//! only fs touch is [`render_ingest_ts`], which reads the target through the
//! proven [`crate::file_context::FileReadPolicy::workspace_default`] wall and
//! redact-belts the render. READ-class; no egress/mutate/custody
//! capability is constructed (custody stays hard-locked).

use crate::defn_node::{
    DefinitionNode, DefnKind, DefnLang, EFFECT_SIG_UNKNOWN_V1, NormToken, encode_tokens,
    opaque_normalized,
};

// ---------------------------------------------------------------------------
// Raw tokens
// ---------------------------------------------------------------------------

/// The raw lexical classes the tokenizer emits (comments/whitespace are consumed
/// at the lexer, never reach a unit).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TokKind {
    /// Identifier or keyword.
    Word,
    /// Numeric literal.
    Number,
    /// String literal (raw, incl. quotes).
    Str,
    /// Template literal (raw, incl. backticks + `${…}` interior).
    Template,
    /// Regex literal (raw, incl. slashes + flags).
    Regex,
    /// Punctuator / operator.
    Punct,
}

/// One raw token + the layout facts normalization needs (`nl_before` feeds the
/// ASI rules; byte span feeds the opaque tier + renders).
#[derive(Clone, Debug)]
struct Tok {
    kind: TokKind,
    text: String,
    /// True iff at least one line terminator (or a multi-line comment, which the
    /// spec treats as one) separates this token from the previous one.
    nl_before: bool,
    /// 1-based source line of the token start (render data).
    line: u32,
    /// Byte span in the source (for the opaque tier's exact-spelling identity).
    byte_start: usize,
    byte_end: usize,
}

/// Why a WHOLE FILE refuses to ingest (fail-closed: no guessed token stream).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum IngestDeny {
    /// A string literal hit a raw line terminator / EOF before its close quote.
    UnterminatedString,
    /// A template literal (or its `${…}` interior) never closed.
    UnterminatedTemplate,
    /// A `/* … */` comment never closed.
    UnterminatedComment,
    /// A regex literal hit a line terminator / EOF before its close slash.
    UnterminatedRegex,
    /// A code-position character outside the supported lexical alphabet.
    UnsupportedChar,
}

impl IngestDeny {
    /// A stable, honest one-liner for renders.
    #[must_use]
    pub const fn message(self) -> &'static str {
        match self {
            IngestDeny::UnterminatedString => "unterminated string literal",
            IngestDeny::UnterminatedTemplate => "unterminated template literal",
            IngestDeny::UnterminatedComment => "unterminated block comment",
            IngestDeny::UnterminatedRegex => "unterminated regex literal",
            IngestDeny::UnsupportedChar => {
                "unsupported character in code position (conservative lexer)"
            }
        }
    }
}

/// Multi-char punctuators, LONGEST FIRST (maximal munch is deterministic).
const PUNCT_TABLE: &[&str] = &[
    ">>>=", "===", "!==", "**=", "...", "<<=", ">>=", ">>>", "&&=", "||=", "??=", "=>", "==", "!=",
    "<=", ">=", "&&", "||", "??", "?.", "++", "--", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=",
    "<<", ">>", "**",
];

/// Single-char punctuators (code-position alphabet floor).
const PUNCT_SINGLE: &str = "{}()[];,.<>+-*/%&|^!~?:=@#";

/// Words after which a `/` starts a REGEX (an expression is expected).
const REGEX_AFTER_WORD: &[&str] = &[
    "return",
    "typeof",
    "instanceof",
    "in",
    "of",
    "new",
    "delete",
    "void",
    "throw",
    "case",
    "do",
    "else",
    "yield",
    "await",
];

fn is_word_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_' || c == '$'
}

fn is_word_continue(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '$'
}

/// True iff a `/` after `prev` begins a regex literal. Deterministic: after a
/// value-shaped token it is division; after `}` we CHOOSE division (documented —
/// either deterministic choice preserves the soundness argument, because every
/// source byte lands verbatim in some token either way).
fn regex_allowed(prev: Option<&Tok>) -> bool {
    match prev {
        None => true,
        Some(p) => match p.kind {
            TokKind::Word => REGEX_AFTER_WORD.contains(&p.text.as_str()),
            TokKind::Number | TokKind::Str | TokKind::Template | TokKind::Regex => false,
            TokKind::Punct => !matches!(p.text.as_str(), ")" | "]" | "}" | "++" | "--"),
        },
    }
}

/// Tokenize a whole TypeScript source. Fail-closed: any lexical uncertainty
/// refuses the FILE (never a guessed stream). PURE.
#[allow(clippy::too_many_lines)]
fn tokenize_ts(src: &str) -> Result<Vec<Tok>, IngestDeny> {
    let chars: Vec<(usize, char)> = src.char_indices().collect();
    let n = chars.len();
    let mut toks: Vec<Tok> = Vec::new();
    let mut i = 0usize;
    let mut line: u32 = 1;
    let mut nl_pending = false;

    let byte_at = |k: usize| -> usize { if k < n { chars[k].0 } else { src.len() } };

    while i < n {
        let c = chars[i].1;
        if c == '\n' {
            line = line.saturating_add(1);
            nl_pending = true;
            i += 1;
            continue;
        }
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // Comments (consumed here; a multi-line body counts as a line terminator).
        if c == '/' && i + 1 < n && chars[i + 1].1 == '/' {
            while i < n && chars[i].1 != '\n' {
                i += 1;
            }
            continue;
        }
        if c == '/' && i + 1 < n && chars[i + 1].1 == '*' {
            let mut k = i + 2;
            let mut closed = false;
            while k + 1 < n {
                if chars[k].1 == '\n' {
                    line = line.saturating_add(1);
                    nl_pending = true;
                }
                if chars[k].1 == '*' && chars[k + 1].1 == '/' {
                    closed = true;
                    break;
                }
                k += 1;
            }
            if !closed {
                return Err(IngestDeny::UnterminatedComment);
            }
            i = k + 2;
            continue;
        }
        let tok_line = line;
        let start_byte = byte_at(i);
        // String literal.
        if c == '"' || c == '\'' {
            let quote = c;
            let mut k = i + 1;
            let mut closed = false;
            while k < n {
                let ck = chars[k].1;
                if ck == '\\' {
                    k += 2;
                    continue;
                }
                if ck == '\n' {
                    return Err(IngestDeny::UnterminatedString);
                }
                if ck == quote {
                    closed = true;
                    break;
                }
                k += 1;
            }
            if !closed {
                return Err(IngestDeny::UnterminatedString);
            }
            let end_byte = byte_at(k + 1);
            toks.push(Tok {
                kind: TokKind::Str,
                text: src
                    .get(start_byte..end_byte)
                    .unwrap_or_default()
                    .to_string(),
                nl_before: core::mem::take(&mut nl_pending),
                line: tok_line,
                byte_start: start_byte,
                byte_end: end_byte,
            });
            i = k + 1;
            continue;
        }
        // Template literal — raw capture including `${…}` interiors (which may
        // nest templates); a small mode stack keeps it deterministic.
        if c == '`' {
            let mut k = i + 1;
            // Stack entries: true = inside a template's text; false = inside a
            // `${…}` interior (brace-counted via the paired depth stack).
            let mut modes: Vec<bool> = vec![true];
            let mut brace_depths: Vec<u32> = Vec::new();
            let mut closed_at: Option<usize> = None;
            while k < n {
                let ck = chars[k].1;
                if ck == '\n' {
                    line = line.saturating_add(1);
                }
                let in_text = *modes.last().unwrap_or(&true);
                if in_text {
                    if ck == '\\' {
                        k += 2;
                        continue;
                    }
                    if ck == '`' {
                        modes.pop();
                        if modes.is_empty() {
                            closed_at = Some(k);
                            break;
                        }
                    } else if ck == '$' && k + 1 < n && chars[k + 1].1 == '{' {
                        modes.push(false);
                        brace_depths.push(0);
                        k += 2;
                        continue;
                    }
                } else if ck == '{' {
                    if let Some(d) = brace_depths.last_mut() {
                        *d = d.saturating_add(1);
                    }
                } else if ck == '}' {
                    match brace_depths.last_mut() {
                        Some(0) | None => {
                            brace_depths.pop();
                            modes.pop();
                        }
                        Some(d) => *d -= 1,
                    }
                } else if ck == '`' {
                    modes.push(true);
                }
                k += 1;
            }
            let Some(close) = closed_at else {
                return Err(IngestDeny::UnterminatedTemplate);
            };
            let end_byte = byte_at(close + 1);
            toks.push(Tok {
                kind: TokKind::Template,
                text: src
                    .get(start_byte..end_byte)
                    .unwrap_or_default()
                    .to_string(),
                nl_before: core::mem::take(&mut nl_pending),
                line: tok_line,
                byte_start: start_byte,
                byte_end: end_byte,
            });
            i = close + 1;
            continue;
        }
        // Number.
        if c.is_ascii_digit() || (c == '.' && i + 1 < n && chars[i + 1].1.is_ascii_digit()) {
            let mut k = i + 1;
            while k < n {
                let ck = chars[k].1;
                let prev = chars[k - 1].1;
                let exp_sign = (ck == '+' || ck == '-') && (prev == 'e' || prev == 'E');
                if ck.is_ascii_alphanumeric() || ck == '.' || ck == '_' || exp_sign {
                    k += 1;
                } else {
                    break;
                }
            }
            let end_byte = byte_at(k);
            toks.push(Tok {
                kind: TokKind::Number,
                text: src
                    .get(start_byte..end_byte)
                    .unwrap_or_default()
                    .to_string(),
                nl_before: core::mem::take(&mut nl_pending),
                line: tok_line,
                byte_start: start_byte,
                byte_end: end_byte,
            });
            i = k;
            continue;
        }
        // Word (identifier / keyword).
        if is_word_start(c) {
            let mut k = i + 1;
            while k < n && is_word_continue(chars[k].1) {
                k += 1;
            }
            let end_byte = byte_at(k);
            toks.push(Tok {
                kind: TokKind::Word,
                text: src
                    .get(start_byte..end_byte)
                    .unwrap_or_default()
                    .to_string(),
                nl_before: core::mem::take(&mut nl_pending),
                line: tok_line,
                byte_start: start_byte,
                byte_end: end_byte,
            });
            i = k;
            continue;
        }
        // Slash: regex (expression position) or division (falls through to punct).
        if c == '/' && regex_allowed(toks.last()) {
            let mut k = i + 1;
            let mut in_class = false;
            let mut closed = false;
            while k < n {
                let ck = chars[k].1;
                if ck == '\\' {
                    k += 2;
                    continue;
                }
                if ck == '\n' {
                    return Err(IngestDeny::UnterminatedRegex);
                }
                if ck == '[' {
                    in_class = true;
                } else if ck == ']' {
                    in_class = false;
                } else if ck == '/' && !in_class {
                    closed = true;
                    break;
                }
                k += 1;
            }
            if !closed {
                return Err(IngestDeny::UnterminatedRegex);
            }
            let mut f = k + 1;
            while f < n && chars[f].1.is_ascii_lowercase() {
                f += 1;
            }
            let end_byte = byte_at(f);
            toks.push(Tok {
                kind: TokKind::Regex,
                text: src
                    .get(start_byte..end_byte)
                    .unwrap_or_default()
                    .to_string(),
                nl_before: core::mem::take(&mut nl_pending),
                line: tok_line,
                byte_start: start_byte,
                byte_end: end_byte,
            });
            i = f;
            continue;
        }
        // Punctuator — maximal munch over the fixed tables.
        let rest: String = chars[i..n.min(i + 4)].iter().map(|&(_, ch)| ch).collect();
        let mut matched: Option<&str> = None;
        for cand in PUNCT_TABLE {
            if rest.starts_with(cand) {
                matched = Some(cand);
                break;
            }
        }
        if matched.is_none() {
            if let Some(pos) = PUNCT_SINGLE.find(c) {
                matched = Some(&PUNCT_SINGLE[pos..pos + c.len_utf8()]);
            }
        }
        let Some(p) = matched else {
            return Err(IngestDeny::UnsupportedChar);
        };
        let plen = p.chars().count();
        let end_byte = byte_at(i + plen);
        toks.push(Tok {
            kind: TokKind::Punct,
            text: p.to_string(),
            nl_before: core::mem::take(&mut nl_pending),
            line: tok_line,
            byte_start: start_byte,
            byte_end: end_byte,
        });
        i += plen;
    }
    Ok(toks)
}

// ---------------------------------------------------------------------------
// Unit extraction (module-level definitions)
// ---------------------------------------------------------------------------

/// One recognized top-level definition span (token index range `[start, end)`;
/// `name_idx`/`body_open` are absolute token indices).
struct UnitSpan {
    kind: DefnKind,
    name_idx: usize,
    start: usize,
    end: usize,
    /// The body `{` index for brace-bodied kinds (feeds the `type_sig` slice).
    body_open: Option<usize>,
}

fn is_punct(t: &Tok, s: &str) -> bool {
    t.kind == TokKind::Punct && t.text == s
}

fn is_word(t: &Tok, s: &str) -> bool {
    t.kind == TokKind::Word && t.text == s
}

/// Find the statement end from `i` (exclusive): the token after a depth-0 `;`,
/// or the first depth-0 token that begins a NEW line whose previous token could
/// end a statement (the conservative ASI boundary), or EOF.
fn statement_end(toks: &[Tok], i: usize) -> usize {
    let mut depth: i32 = 0;
    let mut k = i;
    while k < toks.len() {
        let t = &toks[k];
        if k > i && depth == 0 && t.nl_before {
            if let Some(prev) = toks.get(k - 1) {
                let prev_can_end = matches!(
                    prev.kind,
                    TokKind::Word
                        | TokKind::Number
                        | TokKind::Str
                        | TokKind::Template
                        | TokKind::Regex
                ) || (prev.kind == TokKind::Punct
                    && matches!(prev.text.as_str(), ")" | "]" | "}"));
                let starts_new = t.kind == TokKind::Word || is_punct(t, "@");
                if prev_can_end && starts_new {
                    return k;
                }
            }
        }
        match t.text.as_str() {
            "(" | "[" | "{" if t.kind == TokKind::Punct => depth += 1,
            ")" | "]" | "}" if t.kind == TokKind::Punct => {
                depth -= 1;
                if depth < 0 {
                    return k; // malformed close: stop before it (bounded).
                }
            }
            ";" if t.kind == TokKind::Punct && depth == 0 => return k + 1,
            _ => {}
        }
        k += 1;
    }
    toks.len()
}

/// Find the BODY `{` from `i` (a depth-0 `{` not preceded by a type/continuation
/// token) and return `(body_open, end_exclusive)` = the balanced close + 1.
fn brace_body_end(toks: &[Tok], i: usize) -> Option<(usize, usize)> {
    let mut depth: i32 = 0;
    let mut k = i;
    while k < toks.len() {
        let t = &toks[k];
        if t.kind == TokKind::Punct {
            match t.text.as_str() {
                "(" | "[" => depth += 1,
                ")" | "]" => depth -= 1,
                "{" => {
                    let is_body = depth == 0
                        && !matches!(
                            toks.get(k.wrapping_sub(1)).map(|p| p.text.as_str()),
                            Some(":" | "=>" | "|" | "&" | "<" | "," | "(" | "[" | "=")
                        );
                    if is_body {
                        // Balance from here.
                        let mut d: i32 = 0;
                        let mut e = k;
                        while e < toks.len() {
                            if toks[e].kind == TokKind::Punct {
                                match toks[e].text.as_str() {
                                    "(" | "[" | "{" => d += 1,
                                    ")" | "]" | "}" => {
                                        d -= 1;
                                        if d == 0 {
                                            return Some((k, e + 1));
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            e += 1;
                        }
                        return None;
                    }
                    depth += 1;
                }
                "}" => depth -= 1,
                _ => {}
            }
        }
        if depth < 0 {
            return None;
        }
        k += 1;
    }
    None
}

/// Split the token stream into recognized top-level definition units. Everything
/// unrecognized (imports, re-exports, expression statements, namespace blocks,
/// anonymous defaults, multi-declarator lets…) is SKIPPED and counted honestly.
fn split_units(toks: &[Tok]) -> (Vec<UnitSpan>, usize) {
    let mut units = Vec::new();
    let mut skipped = 0usize;
    let mut i = 0usize;
    while i < toks.len() {
        let start = i;
        let mut j = i;
        // Decorators: `@word` (+ optional balanced call args) prefix the unit.
        while j < toks.len() && is_punct(&toks[j], "@") {
            j += 1;
            if j < toks.len() && toks[j].kind == TokKind::Word {
                j += 1;
            }
            if j < toks.len() && is_punct(&toks[j], "(") {
                let mut d = 0i32;
                while j < toks.len() {
                    if toks[j].kind == TokKind::Punct {
                        match toks[j].text.as_str() {
                            "(" | "[" | "{" => d += 1,
                            ")" | "]" | "}" => {
                                d -= 1;
                                if d == 0 {
                                    j += 1;
                                    break;
                                }
                            }
                            _ => {}
                        }
                    }
                    j += 1;
                }
            }
        }
        // Modifiers.
        while j < toks.len()
            && toks[j].kind == TokKind::Word
            && matches!(
                toks[j].text.as_str(),
                "export" | "default" | "declare" | "async" | "abstract"
            )
        {
            j += 1;
        }
        let Some(head) = toks.get(j) else {
            break;
        };
        let unit = if head.kind == TokKind::Word {
            match head.text.as_str() {
                "function" => {
                    let mut nk = j + 1;
                    if toks.get(nk).is_some_and(|t| is_punct(t, "*")) {
                        nk += 1;
                    }
                    match toks.get(nk) {
                        Some(t) if t.kind == TokKind::Word => {
                            brace_body_end(toks, nk + 1).map(|(b, e)| UnitSpan {
                                kind: DefnKind::Function,
                                name_idx: nk,
                                start,
                                end: e,
                                body_open: Some(b),
                            })
                        }
                        _ => None,
                    }
                }
                "class" | "interface" => match toks.get(j + 1) {
                    Some(t) if t.kind == TokKind::Word => {
                        brace_body_end(toks, j + 2).map(|(b, e)| UnitSpan {
                            kind: if head.text == "class" {
                                DefnKind::Class
                            } else {
                                DefnKind::Interface
                            },
                            name_idx: j + 1,
                            start,
                            end: e,
                            body_open: Some(b),
                        })
                    }
                    _ => None,
                },
                "enum" => match toks.get(j + 1) {
                    Some(t) if t.kind == TokKind::Word => {
                        brace_body_end(toks, j + 2).map(|(b, e)| UnitSpan {
                            kind: DefnKind::Enum,
                            name_idx: j + 1,
                            start,
                            end: e,
                            body_open: Some(b),
                        })
                    }
                    _ => None,
                },
                "const" if toks.get(j + 1).is_some_and(|t| is_word(t, "enum")) => {
                    match toks.get(j + 2) {
                        Some(t) if t.kind == TokKind::Word => {
                            brace_body_end(toks, j + 3).map(|(b, e)| UnitSpan {
                                kind: DefnKind::Enum,
                                name_idx: j + 2,
                                start,
                                end: e,
                                body_open: Some(b),
                            })
                        }
                        _ => None,
                    }
                }
                "type" => match toks.get(j + 1) {
                    Some(t)
                        if t.kind == TokKind::Word
                            && toks
                                .get(j + 2)
                                .is_some_and(|t2| is_punct(t2, "=") || is_punct(t2, "<")) =>
                    {
                        Some(UnitSpan {
                            kind: DefnKind::TypeAlias,
                            name_idx: j + 1,
                            start,
                            end: statement_end(toks, j),
                            body_open: None,
                        })
                    }
                    _ => None,
                },
                "const" | "let" | "var" => match toks.get(j + 1) {
                    Some(t) if t.kind == TokKind::Word => {
                        let end = statement_end(toks, j);
                        // Multi-declarator (`const a = 1, b = 2;`): a depth-0 `,`
                        // inside the statement ⇒ conservative skip.
                        let mut d = 0i32;
                        let mut multi = false;
                        for t2 in toks.get(j..end).unwrap_or_default() {
                            if t2.kind == TokKind::Punct {
                                match t2.text.as_str() {
                                    "(" | "[" | "{" => d += 1,
                                    ")" | "]" | "}" => d -= 1,
                                    "," if d == 0 => multi = true,
                                    _ => {}
                                }
                            }
                        }
                        if multi {
                            None
                        } else {
                            Some(UnitSpan {
                                kind: DefnKind::ConstBinding,
                                name_idx: j + 1,
                                start,
                                end,
                                body_open: None,
                            })
                        }
                    }
                    _ => None,
                },
                _ => None,
            }
        } else {
            None
        };
        match unit {
            Some(u) => {
                i = u.end.max(start + 1);
                units.push(u);
            }
            None => {
                skipped += 1;
                let end = statement_end(toks, start).max(start + 1);
                i = end;
            }
        }
    }
    (units, skipped)
}

// ---------------------------------------------------------------------------
// Normalization (Q3: syntactic, conservative)
// ---------------------------------------------------------------------------

/// Punctuators/words after which a line break can NEVER end a statement — the
/// newline is droppable (formatting, not semantics).
fn punct_safe_after(prev: &Tok) -> bool {
    match prev.kind {
        TokKind::Punct => matches!(
            prev.text.as_str(),
            ";" | "{"
                | "}"
                | ","
                | "("
                | "["
                | ":"
                | "=>"
                | "="
                | "+"
                | "-"
                | "*"
                | "/"
                | "%"
                | "<"
                | ">"
                | "<="
                | ">="
                | "=="
                | "==="
                | "!="
                | "!=="
                | "&&"
                | "||"
                | "??"
                | "&"
                | "|"
                | "^"
                | "<<"
                | ">>"
                | ">>>"
                | "**"
                | "!"
                | "~"
                | "?"
                | "."
                | "?."
                | "+="
                | "-="
                | "*="
                | "/="
                | "%="
                | "&&="
                | "||="
                | "??="
                | "&="
                | "|="
                | "^="
                | "<<="
                | ">>="
                | ">>>="
                | "**="
                | "..."
                | "@"
        ),
        // NOT here (each is a VALID lone expression-statement, so a newline after
        // it can be a real ASI boundary): `async`, `static`, `declare`, `abstract`.
        TokKind::Word => matches!(
            prev.text.as_str(),
            "else"
                | "do"
                | "in"
                | "of"
                | "typeof"
                | "new"
                | "instanceof"
                | "case"
                | "await"
                | "void"
                | "delete"
                | "extends"
                | "implements"
                | "export"
                | "default"
        ),
        _ => false,
    }
}

/// Tokens BEFORE which a line break can never end a statement (they cannot start
/// a new one) — the newline is droppable.
fn safe_before(tok: &Tok) -> bool {
    match tok.kind {
        // `{` is sound here: if `expr \n {` is a valid two-statement split (ASI),
        // the same tokens WITHOUT the newline are syntactically invalid — so
        // dropping the newline can never merge two VALID programs. In every
        // position where `X {` is valid (a body/block opener), the newline is
        // pure formatting (K&R vs Allman).
        TokKind::Punct => matches!(
            tok.text.as_str(),
            "{" | ")"
                | "]"
                | "}"
                | ";"
                | ","
                | ":"
                | "."
                | "?."
                | "="
                | "=>"
                | "=="
                | "==="
                | "!="
                | "!=="
                | "<="
                | ">="
                | "&&"
                | "||"
                | "??"
                | "*"
                | "%"
                | "**"
                | "<<"
                | ">>"
                | ">>>"
                | "&"
                | "|"
                | "^"
                | "?"
                | "<"
                | ">"
                | "+="
                | "-="
                | "*="
                | "/="
                | "%="
                | "&&="
                | "||="
                | "??="
                | "&="
                | "|="
                | "^="
                | "<<="
                | ">>="
                | ">>>="
                | "**="
        ),
        TokKind::Word => matches!(
            tok.text.as_str(),
            "else" | "catch" | "finally" | "instanceof" | "in" | "of" | "extends" | "implements"
        ),
        _ => false,
    }
}

/// The innermost open bracket at each token position (BEFORE the token itself is
/// processed): `Some('(' | '[' | '{')` or `None` at unit top level. Feeds the
/// property/key/method position vetoes.
fn bracket_context(slice: &[Tok]) -> Vec<Option<char>> {
    let mut ctx = Vec::with_capacity(slice.len());
    let mut stack: Vec<char> = Vec::new();
    for t in slice {
        ctx.push(stack.last().copied());
        if t.kind == TokKind::Punct {
            match t.text.as_str() {
                "(" => stack.push('('),
                "[" => stack.push('['),
                "{" => stack.push('{'),
                ")" | "]" | "}" => {
                    stack.pop();
                }
                _ => {}
            }
        }
    }
    ctx
}

/// True iff replacing every `Word == name` occurrence in `slice` with a fresh
/// placeholder is a pure α-substitution — i.e. NO occurrence sits in an
/// external-facing (property/key/method/shorthand/type) position and the name
/// never hides inside a string/template/regex text.
fn name_occurrences_are_clean(slice: &[Tok], ctx: &[Option<char>], name: &str) -> bool {
    for (k, t) in slice.iter().enumerate() {
        match t.kind {
            TokKind::Str | TokKind::Template | TokKind::Regex => {
                if t.text.contains(name) {
                    return false; // a rename tool may or may not touch it — split.
                }
            }
            TokKind::Word if t.text == name => {
                let prev = k.checked_sub(1).and_then(|p| slice.get(p));
                let next = slice.get(k + 1);
                let inner = ctx.get(k).copied().flatten();
                // Property access: `.name` / `?.name`.
                if prev.is_some_and(|p| is_punct(p, ".") || is_punct(p, "?.")) {
                    return false;
                }
                // Type position: `: name` (annotation) — a different symbol space.
                if prev.is_some_and(|p| is_punct(p, ":")) {
                    return false;
                }
                // Object key: `{ name: … }`.
                if inner == Some('{') && next.is_some_and(|nx| is_punct(nx, ":")) {
                    return false;
                }
                // Object shorthand: `{ name , }` / `{ name }`.
                if inner == Some('{')
                    && prev.is_some_and(|p| is_punct(p, "{") || is_punct(p, ","))
                    && next.is_some_and(|nx| is_punct(nx, ",") || is_punct(nx, "}"))
                {
                    return false;
                }
                // Object/class method or field name: `{ name(…) }` / `{ name = … }`.
                if inner == Some('{')
                    && (prev.is_none()
                        || prev.is_some_and(|p| {
                            is_punct(p, "{")
                                || is_punct(p, ",")
                                || is_punct(p, ";")
                                || (p.kind == TokKind::Word
                                    && matches!(
                                        p.text.as_str(),
                                        "get"
                                            | "set"
                                            | "static"
                                            | "async"
                                            | "public"
                                            | "private"
                                            | "protected"
                                            | "readonly"
                                    ))
                        }))
                    && next.is_some_and(|nx| {
                        is_punct(nx, "(") || is_punct(nx, "=") || is_punct(nx, "?")
                    })
                {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

/// Alpha-candidate binder names for a FUNCTION unit, in first-binding order:
/// header params (simple identifiers) + body `let`/`const`/`var`/nested
/// `function`/`catch(` names. Names bound more than once are dropped (quality
/// filter — uniform renaming stays sound, but invariance would not hold).
fn alpha_candidates(slice: &[Tok], body_open_rel: usize, name_rel: usize) -> Vec<String> {
    let mut order: Vec<String> = Vec::new();
    let mut counts: std::collections::BTreeMap<String, u32> = std::collections::BTreeMap::new();
    let mut push = |nm: &str| {
        if !order.iter().any(|o| o == nm) {
            order.push(nm.to_string());
        }
        *counts.entry(nm.to_string()).or_insert(0) += 1;
    };
    // Header params: Words at paren depth 1 between the header '(' and the body,
    // preceded by '(' or ',', followed by ':' | ',' | ')' | '=' | '?'.
    let mut d = 0i32;
    for k in name_rel + 1..body_open_rel.min(slice.len()) {
        let t = &slice[k];
        if t.kind == TokKind::Punct {
            match t.text.as_str() {
                "(" | "[" | "{" => d += 1,
                ")" | "]" | "}" => d -= 1,
                _ => {}
            }
        }
        if d == 1
            && t.kind == TokKind::Word
            && k.checked_sub(1)
                .and_then(|p| slice.get(p))
                .is_some_and(|p| is_punct(p, "(") || is_punct(p, ","))
            && slice.get(k + 1).is_some_and(|nx| {
                is_punct(nx, ":")
                    || is_punct(nx, ",")
                    || is_punct(nx, ")")
                    || is_punct(nx, "=")
                    || is_punct(nx, "?")
            })
        {
            push(&t.text);
        }
    }
    // Body binders.
    for k in body_open_rel..slice.len() {
        let t = &slice[k];
        if t.kind != TokKind::Word {
            continue;
        }
        match t.text.as_str() {
            "let" | "const" | "var" | "function" => {
                if let Some(nx) = slice.get(k + 1) {
                    if nx.kind == TokKind::Word {
                        push(&nx.text);
                    }
                }
            }
            "catch" => {
                if slice.get(k + 1).is_some_and(|p| is_punct(p, "(")) {
                    if let Some(nx) = slice.get(k + 2) {
                        if nx.kind == TokKind::Word {
                            push(&nx.text);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    order.retain(|nm| counts.get(nm).copied().unwrap_or(0) == 1);
    order
}

/// The normalized output of one unit.
struct NormalizedUnit {
    normalized: Vec<u8>,
    type_sig: Vec<u8>,
    alpha_renamed: u16,
    opaque: bool,
}

/// Normalize one unit per the Q3 contract (see module docs). PURE.
fn normalize_unit(src: &str, toks: &[Tok], span: &UnitSpan) -> NormalizedUnit {
    let slice = toks.get(span.start..span.end).unwrap_or_default();
    let name_rel = span.name_idx.saturating_sub(span.start);
    let body_open_rel = span.body_open.map(|b| b.saturating_sub(span.start));
    let own_name = slice
        .get(name_rel)
        .map(|t| t.text.clone())
        .unwrap_or_default();
    let ctx = bracket_context(slice);

    // OWN-NAME substitution: the binding position always; every other occurrence
    // only when ALL occurrences are clean α-positions (else leave raw — a rename
    // then honestly yields a different node).
    let own_clean = name_occurrences_are_clean(slice, &ctx, &own_name);

    // Alpha: FUNCTION units only (v1); a body `eval`/`with` disables it.
    let dynamic_scope = slice
        .iter()
        .any(|t| t.kind == TokKind::Word && (t.text == "eval" || t.text == "with"));
    let eligible: Vec<String> = match (span.kind, body_open_rel) {
        (DefnKind::Function, Some(b)) if !dynamic_scope => alpha_candidates(slice, b, name_rel)
            .into_iter()
            .filter(|nm| *nm != own_name && name_occurrences_are_clean(slice, &ctx, nm))
            .collect(),
        _ => Vec::new(),
    };
    // Cap: more than u16::MAX binders is unreal; stay fail-closed anyway.
    let eligible = if eligible.len() > usize::from(u16::MAX) {
        Vec::new()
    } else {
        eligible
    };

    let mut out: Vec<(usize, NormToken)> = Vec::with_capacity(slice.len() + 8);
    for (k, t) in slice.iter().enumerate() {
        // ASI-aware newline handling.
        if k > 0 && t.nl_before {
            let prev = &slice[k - 1];
            if prev.kind == TokKind::Word
                && matches!(
                    prev.text.as_str(),
                    "return" | "throw" | "break" | "continue" | "yield"
                )
            {
                out.push((k, NormToken::Punct(";".to_string())));
            } else if t.kind == TokKind::Punct && (t.text == "++" || t.text == "--") {
                out.push((k, NormToken::Newline));
            } else if punct_safe_after(prev) || safe_before(t) {
                // droppable formatting newline
            } else {
                out.push((k, NormToken::Newline));
            }
        }
        let norm = match t.kind {
            TokKind::Word => {
                if t.text == own_name && (k == name_rel || own_clean) {
                    NormToken::SelfRef
                } else if let Some(i) = eligible.iter().position(|nm| *nm == t.text) {
                    // Bounded by the u16 cap above.
                    NormToken::AlphaVar(u16::try_from(i).unwrap_or(u16::MAX))
                } else {
                    NormToken::Word(t.text.clone())
                }
            }
            TokKind::Number => NormToken::Number(t.text.clone()),
            TokKind::Str => NormToken::Str(t.text.clone()),
            TokKind::Template => NormToken::Template(t.text.clone()),
            TokKind::Regex => NormToken::Regex(t.text.clone()),
            TokKind::Punct => NormToken::Punct(t.text.clone()),
        };
        out.push((k, norm));
    }

    // type_sig (FUNCTION only, v1): the normalized declared header — everything
    // strictly after the name up to (exclusive) the body `{`.
    let type_sig = match (span.kind, body_open_rel) {
        (DefnKind::Function, Some(b)) => {
            let header: Vec<NormToken> = out
                .iter()
                .filter(|(k, _)| *k > name_rel && *k < b)
                .map(|(_, t)| t.clone())
                .collect();
            encode_tokens(&header)
        }
        _ => Some(Vec::new()),
    };

    let tokens: Vec<NormToken> = out.into_iter().map(|(_, t)| t).collect();
    match (encode_tokens(&tokens), type_sig) {
        (Some(normalized), Some(sig)) => NormalizedUnit {
            normalized,
            type_sig: sig,
            alpha_renamed: u16::try_from(eligible.len()).unwrap_or(u16::MAX),
            opaque: false,
        },
        // Over-cap token payload: degrade to the exact-spelling OPAQUE tier.
        _ => {
            let lo = slice.first().map_or(0, |t| t.byte_start);
            let hi = slice.last().map_or(lo, |t| t.byte_end);
            NormalizedUnit {
                normalized: opaque_normalized(src.get(lo..hi).unwrap_or_default().as_bytes()),
                type_sig: Vec::new(),
                alpha_renamed: 0,
                opaque: true,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Ingest driver + render
// ---------------------------------------------------------------------------

/// The ingest result for one source: nodes + honest skip accounting.
#[derive(Debug)]
pub struct IngestTsReport {
    /// One node per recognized top-level definition.
    pub nodes: Vec<DefinitionNode>,
    /// Top-level statements that are not definitions (imports, expressions, …).
    pub skipped_statements: usize,
    /// A file-level lexical refusal (fail-closed; `nodes` is empty).
    pub deny: Option<IngestDeny>,
}

/// Ingest one TypeScript source into definition-unit nodes. PURE.
#[must_use]
pub fn ingest_ts_source(src: &str) -> IngestTsReport {
    let toks = match tokenize_ts(src) {
        Ok(t) => t,
        Err(deny) => {
            return IngestTsReport {
                nodes: Vec::new(),
                skipped_statements: 0,
                deny: Some(deny),
            };
        }
    };
    let (units, skipped) = split_units(&toks);
    let mut nodes = Vec::with_capacity(units.len());
    for u in &units {
        let nu = normalize_unit(src, &toks, u);
        let name = toks
            .get(u.name_idx)
            .map(|t| t.text.clone())
            .unwrap_or_default();
        let line = toks.get(u.start).map_or(1, |t| t.line);
        nodes.push(DefinitionNode::new(
            DefnLang::TypeScript,
            u.kind,
            name,
            line,
            nu.normalized,
            nu.type_sig,
            EFFECT_SIG_UNKNOWN_V1.to_vec(),
            Vec::new(),
            nu.opaque,
            nu.alpha_renamed,
        ));
    }
    IngestTsReport {
        nodes,
        skipped_statements: skipped,
        deny: None,
    }
}

/// `context ingest-ts <path>`: read `path` through the proven walled read policy,
/// ingest, and render an honest, redact-belted summary. Returns `(rendered,
/// ran)`; `ran` is true only when a real ingest produced a verdict.
#[must_use]
pub fn render_ingest_ts(path: &str) -> (String, bool) {
    use std::path::Path;
    if !path.to_ascii_lowercase().ends_with(".ts") {
        return (
            format!("defn ingest: unsupported file type for {path} (only .ts in v1)"),
            false,
        );
    }
    let policy = crate::file_context::FileReadPolicy::workspace_default();
    let file = match policy.read(Path::new(path)) {
        Ok(file) => file,
        Err(deny) => {
            return (
                format!("defn ingest: cannot read {path} (denied: {deny:?})"),
                false,
            );
        }
    };
    let Some(content) = file.text else {
        return (format!("defn ingest: {path} is binary (no source)"), false);
    };
    let report = ingest_ts_source(&content);
    if let Some(deny) = report.deny {
        return (
            format!(
                "defn ingest (typescript): {path}: refused — {} (fail-closed lexer; zero nodes)",
                deny.message()
            ),
            false,
        );
    }
    let mut lines = vec![format!(
        "defn ingest (typescript): {path}: {} node(s), {} non-definition statement(s) skipped",
        report.nodes.len(),
        report.skipped_statements
    )];
    for n in &report.nodes {
        // Two lines per node: the 64-hex cid gets its own line so the emit
        // body's line cap can never truncate the identity.
        lines.push(format!(
            "  {:9} {:28} line={:<5} alpha={:<3}{}",
            n.kind.label(),
            n.name,
            n.line,
            n.alpha_renamed,
            if n.opaque { " OPAQUE" } else { "" },
        ));
        lines.push(format!("    cid={}", n.cid));
    }
    lines.push(
        "  note: cid = content identity (name/file are data); effect_sig=unknown.v1; deps v1=0"
            .to_string(),
    );
    (redact_belt(&lines.join("\n")), true)
}

/// redaction belt (the `lsp.rs` idiom): a secret-shaped render ⇒ withheld.
fn redact_belt(rendered: &str) -> String {
    use crate::provider::redaction::{RedactionRequest, redact};
    let fragments = [rendered];
    match redact(&RedactionRequest {
        fragments: &fragments,
        candidate_memory_ids: &[],
        deleted_ids: &[],
        include_private_memory: false,
    }) {
        Ok(receipt) if receipt.secret_fragments_denied_u32() == 0 => rendered.to_string(),
        _ => "defn ingest: withheld (a rendered fragment was secret-shaped)".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Tests property gates (the kill criterion) + soundness negatives
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn one_node(src: &str) -> DefinitionNode {
        let r = ingest_ts_source(src);
        assert!(r.deny.is_none(), "deny: {:?}", r.deny);
        assert_eq!(r.nodes.len(), 1, "expected 1 node in: {src}");
        r.nodes.into_iter().next().expect("one node")
    }

    fn cid_of(src: &str) -> String {
        one_node(src).cid
    }

    /// KILL GATE 1 — RENAME invariance: renaming the definition (incl. Its
    /// recursive self-references) converges to the SAME cid.
    #[test]
    fn property_rename_of_definition_is_identity_invariant() {
        let a = cid_of("function fact(n: number): number { return n < 2 ? 1 : n * fact(n - 1); }");
        let b = cid_of(
            "function factorial(n: number): number { return n < 2 ? 1 : n * factorial(n - 1); }",
        );
        assert_eq!(a, b, "rename (incl. recursion) must not move the node");
        // …and across kinds:
        assert_eq!(
            cid_of("interface Point { x: number; y: number; }"),
            cid_of("interface Coord { x: number; y: number; }"),
        );
        assert_eq!(
            cid_of("type Meters = number;"),
            cid_of("type Distance = number;"),
        );
        assert_eq!(cid_of("const limit = 42;"), cid_of("const maxCount = 42;"),);
    }

    /// KILL GATE 2 — WHITESPACE/COMMENT invariance: reformatting (K&R vs
    /// Allman, compact vs pretty, commented vs bare) converges to the SAME cid.
    #[test]
    fn property_whitespace_and_comments_are_identity_invariant() {
        let compact = cid_of("function add(a: number, b: number): number { return a + b; }");
        let pretty = cid_of(
            "function add(\n    a: number,\n    b: number\n): number\n{\n    return a + b;\n}\n",
        );
        let commented = cid_of(
            "// adds two numbers\nfunction add(a: number, /* left */ b: number): number {\n  /* the sum */ return a + b; // done\n}",
        );
        assert_eq!(compact, pretty);
        assert_eq!(compact, commented);
        // `} else {` same-line vs next-line (the K&R/Allman classic):
        let knr = cid_of("function f(x: number) { if (x) { return 1; } else { return 2; } }");
        let allman = cid_of(
            "function f(x: number) {\n  if (x) {\n    return 1;\n  }\n  else {\n    return 2;\n  }\n}",
        );
        assert_eq!(knr, allman);
    }

    /// KILL GATE 3 — ALPHA invariance: renaming uniquely-bound locals
    /// (params, lets, catch) converges to the SAME cid.
    #[test]
    fn property_alpha_conversion_is_identity_invariant() {
        let a = cid_of(
            "function calc(width: number, height: number) { let area = width * height; return area; }",
        );
        let b = cid_of("function calc(w: number, h: number) { let a = w * h; return a; }");
        assert_eq!(a, b, "param + let alpha-rename must not move the node");
        let c = cid_of("function g(x: number) { try { return x; } catch (err) { throw err; } }");
        let d = cid_of("function g(x: number) { try { return x; } catch (e) { throw e; } }");
        assert_eq!(c, d, "catch binder alpha-rename must not move the node");
        // rename + reformat + alpha TOGETHER (the full convergence claim):
        let e = cid_of("function area(w:number,h:number){let s=w*h;return s;}");
        let f = cid_of(
            "// area of a rect\nfunction rectArea(width: number, height: number) {\n  let size = width * height;\n  return size;\n}",
        );
        assert_eq!(e, f);
    }

    /// Soundness negatives: any SEMANTIC change moves the cid.
    #[test]
    fn semantic_changes_move_the_cid() {
        let base = cid_of("function f(a: number) { return a + 1; }");
        // literal change
        assert_ne!(base, cid_of("function f(a: number) { return a + 2; }"));
        // operator change
        assert_ne!(base, cid_of("function f(a: number) { return a - 1; }"));
        // declared type change
        assert_ne!(base, cid_of("function f(a: string) { return a + 1; }"));
        // property name is EXTERNAL-FACING — renaming it is a different node
        let p = cid_of("function g(o: T) { return o.alpha; }");
        let q = cid_of("function g(o: T) { return o.beta; }");
        assert_ne!(p, q);
        // string contents are semantics
        assert_ne!(cid_of("const s = 'hello';"), cid_of("const s = 'world';"));
        // numeric spelling is kept raw (1e3 ≠ 1000 — sound split)
        assert_ne!(cid_of("const n = 1e3;"), cid_of("const n = 1000;"));
    }

    /// ASI soundness: a newline in a RESTRICTED position is canonicalized to the
    /// `;` ASI inserts — so `return\nx` ≠ `return x` (semantics differ).
    #[test]
    fn asi_restricted_return_stays_distinct() {
        let a = cid_of("function f(x: number) { return\n  x; }");
        let b = cid_of("function f(x: number) { return x; }");
        assert_ne!(
            a, b,
            "ASI inserts `;` after bare return — different program"
        );
    }

    /// Conservative vetoes: positions a rename could NOT safely cross keep their
    /// names (a rename there honestly yields a DIFFERENT node — Q3 sound-first).
    #[test]
    fn conservative_vetoes_split_instead_of_merging() {
        // shorthand `{count}` references the binder in an external-facing shape:
        let a = cid_of("function f() { let count = 1; return { count }; }");
        let b = cid_of("function f() { let total = 1; return { total }; }");
        assert_ne!(a, b, "shorthand-veto: locals stay raw, nodes stay split");
        // a template mentioning the binder vetoes its alpha:
        let c = cid_of("function f() { let user = 1; return `${user}`; }");
        let d = cid_of("function f() { let name = 1; return `${name}`; }");
        assert_ne!(c, d, "template-substring veto");
        // `eval` disables alpha wholesale:
        let e = cid_of("function f(a: number) { eval('x'); return a; }");
        let g = cid_of("function f(b: number) { eval('x'); return b; }");
        assert_ne!(e, g, "eval disables alpha");
        // object METHOD names are external-facing:
        let h = cid_of("function f() { let m = 1; return { m() { return m; } }; }");
        let i = cid_of("function f() { let n = 1; return { n() { return n; } }; }");
        assert_ne!(h, i, "method-name veto");
        // class locals are not alpha'd in v1 (kind-scoped conservatism):
        let j = cid_of("class C { go() { let a = 1; return a; } }");
        let k = cid_of("class C { go() { let b = 1; return b; } }");
        assert_ne!(j, k, "v1: class units keep local names");
    }

    /// Unit splitting handles a return-type object literal (the `{` that is NOT
    /// a body) and finds subsequent definitions.
    #[test]
    fn split_handles_return_type_braces_and_multiple_units() {
        let src = "function f(): { a: number } { return { a: 1 }; }\nfunction g() { return 2; }\n";
        let r = ingest_ts_source(src);
        assert!(r.deny.is_none());
        let names: Vec<&str> = r.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, vec!["f", "g"]);
        assert_eq!(r.nodes[0].kind, DefnKind::Function);
    }

    /// Kinds + honest skip accounting: imports/expressions are skipped, counted.
    #[test]
    fn kinds_and_skip_accounting() {
        let src = "import { x } from 'y';\nexport function a() { return 1; }\nexport default class B { m() { return 2; } }\ninterface I { k: string; }\ntype T = string | number;\nenum E { A, B }\nconst c = (v: number) => v + 1;\nconsole.log('side effect');\n";
        let r = ingest_ts_source(src);
        assert!(r.deny.is_none());
        let kinds: Vec<DefnKind> = r.nodes.iter().map(|n| n.kind).collect();
        assert_eq!(
            kinds,
            vec![
                DefnKind::Function,
                DefnKind::Class,
                DefnKind::Interface,
                DefnKind::TypeAlias,
                DefnKind::Enum,
                DefnKind::ConstBinding,
            ]
        );
        assert_eq!(r.skipped_statements, 2, "import + console.log");
        // node names + cid self-check
        for n in &r.nodes {
            assert!(n.cid_matches_content());
            assert_eq!(n.cid.len(), 64);
        }
    }

    /// Fail-closed lexer: an unterminated construct refuses the WHOLE file.
    #[test]
    fn lexer_fails_closed() {
        for bad in [
            "const s = 'unterminated;\nconst t = 1;",
            "const s = `unterminated;",
            "/* never closed\nconst a = 1;",
        ] {
            let r = ingest_ts_source(bad);
            assert!(r.deny.is_some(), "must refuse: {bad}");
            assert!(r.nodes.is_empty(), "zero nodes on refusal");
        }
    }

    /// Deterministic mini-space enumeration (hand-rolled LCG — no rand crate):
    /// across a space of name choices, α-equivalent spellings converge and
    /// semantically distinct spellings stay distinct.
    #[test]
    fn property_minispace_enumeration() {
        const NAMES_F: &[&str] = &["run", "step", "apply", "compute", "handle"];
        const NAMES_A: &[&str] = &["a", "left", "first", "x0", "acc"];
        const NAMES_B: &[&str] = &["b", "right", "second", "y0", "cur"];
        const OPS: &[&str] = &["+", "-", "*", "%"];
        let mut seed: u64 = 0x5EED_5EED_5EED_5EED;
        let mut lcg = move || {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            (seed >> 33) as usize
        };
        for op in OPS {
            let mut cids = std::collections::BTreeSet::new();
            for _ in 0..24 {
                let fname = NAMES_F[lcg() % NAMES_F.len()];
                let an = NAMES_A[lcg() % NAMES_A.len()];
                let bn = NAMES_B[lcg() % NAMES_B.len()];
                // Random benign formatting: pick one of three layouts.
                let src = match lcg() % 3 {
                    0 => format!(
                        "function {fname}({an}: number, {bn}: number) {{ let out = {an} {op} {bn}; return out; }}"
                    ),
                    1 => format!(
                        "function {fname}(\n  {an}: number,\n  {bn}: number\n) {{\n  let out = {an} {op} {bn};\n  return out;\n}}"
                    ),
                    _ => format!(
                        "// generated\nfunction {fname}({an}: number, {bn}: number) {{\n  let out = {an} {op} {bn}; // combine\n  return out;\n}}"
                    ),
                };
                cids.insert(cid_of(&src));
            }
            assert_eq!(
                cids.len(),
                1,
                "all α/format variants of `{op}` must converge to ONE node"
            );
        }
        // Distinct operators are distinct nodes (4 ops ⇒ 4 cids).
        let mut all = std::collections::BTreeSet::new();
        for op in OPS {
            all.insert(cid_of(&format!(
                "function f(a: number, b: number) {{ let out = a {op} b; return out; }}"
            )));
        }
        assert_eq!(all.len(), OPS.len());
    }

    /// Arrow-param conservatism (documented v1 scope): arrow params are not
    /// alpha candidates — renaming one is honestly a different node.
    #[test]
    fn arrow_params_are_conservative_v1() {
        let a = cid_of("const inc = (v: number) => v + 1;");
        let b = cid_of("const inc = (n: number) => n + 1;");
        assert_ne!(a, b, "v1: arrow params stay raw (conservative split)");
        // …but the BINDING name itself is still rename-invariant:
        assert_eq!(
            cid_of("const inc = (v: number) => v + 1;"),
            cid_of("const bump = (v: number) => v + 1;"),
        );
    }

    /// The dispatch render is honest for a non-.ts path (no fabricated ingest).
    #[test]
    fn render_refuses_non_ts() {
        let (msg, ran) = render_ingest_ts("/tmp/nope.rs");
        assert!(!ran);
        assert!(msg.contains("unsupported file type"));
    }
}
