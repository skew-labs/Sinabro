// sinabro CM6 bundle entry — the ONLY thing that becomes the vendored global `CM`.
// esbuild --format=iife --global-name=CM turns every named export below into a
// property of window.CM. app.js composes the editor from these primitives; the
// FIM ghost / diagnostics gutter / save-flow logic stays in app.js (the GUI lane).
// Languages are scoped to sinabro's real targets: Rust/Solana + Sui Move + the JS
// GUI itself + JSON/Python configs. Everything else => plain (still gets gutter,
// search, multi-cursor, line numbers — just no syntax colors; honest, not faked).

export {
  EditorState, StateField, StateEffect, Compartment, RangeSet, RangeSetBuilder,
  Prec, Text,
} from "@codemirror/state";

export {
  EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter,
  drawSelection, rectangularSelection, crosshairCursor, gutter, GutterMarker,
  Decoration, WidgetType, ViewPlugin,
} from "@codemirror/view";

export {
  defaultKeymap, history, historyKeymap, indentWithTab,
} from "@codemirror/commands";

export {
  searchKeymap, highlightSelectionMatches, search, openSearchPanel,
} from "@codemirror/search";

export {
  syntaxHighlighting, defaultHighlightStyle, HighlightStyle, StreamLanguage,
  bracketMatching, indentOnInput, foldGutter, foldKeymap,
} from "@codemirror/language";

export { tags } from "@lezer/highlight";

import { StreamLanguage } from "@codemirror/language";
import { LanguageSupport } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";
import { rust } from "@codemirror/lang-rust";
import { javascript } from "@codemirror/lang-javascript";
import { json } from "@codemirror/lang-json";
import { python } from "@codemirror/lang-python";

// ── Sui Move — no official CodeMirror grammar exists, so a small StreamLanguage.
// Token names are mapped to tags explicitly via tokenTable (no reliance on legacy
// CM5 name resolution). Covers comments / strings (incl. b"" and x"") / numbers /
// keywords / the Move primitive types. Good enough for read + edit highlight v1.
const MOVE_KEYWORDS = new Set([
  "module", "script", "fun", "public", "entry", "native", "inline", "friend",
  "struct", "enum", "has", "key", "store", "copy", "drop", "phantom",
  "let", "mut", "return", "abort", "break", "continue", "loop", "while", "if",
  "else", "match", "const", "use", "as", "move", "acquires", "spec", "schema",
  "pragma", "invariant", "ensures", "requires", "aborts_if", "modifies", "assert",
  "macro", "for", "in",
]);
const MOVE_TYPES = new Set([
  "u8", "u16", "u32", "u64", "u128", "u256", "bool", "address", "vector",
  "signer", "true", "false",
]);

const moveMode = {
  name: "move",
  startState() { return { inBlock: false }; },
  token(stream, state) {
    if (state.inBlock) {
      if (stream.match(/^.*?\*\//)) state.inBlock = false;
      else stream.skipToEnd();
      return "comment";
    }
    if (stream.eatSpace()) return null;
    if (stream.match("/*")) { state.inBlock = true; return "comment"; }
    if (stream.match("//")) { stream.skipToEnd(); return "comment"; }
    // byte/hex string prefixes then a regular double-quoted string
    if (stream.match(/^[bx]?"(?:\\.|[^"\\])*"/)) return "string";
    if (stream.match(/^@?0x[0-9a-fA-F_]+/)) return "number";
    if (stream.match(/^\d[\d_]*(?:u(?:8|16|32|64|128|256))?/)) return "number";
    const word = stream.match(/^[A-Za-z_][A-Za-z0-9_]*/);
    if (word) {
      const w = word[0];
      if (MOVE_KEYWORDS.has(w)) return "keyword";
      if (MOVE_TYPES.has(w)) return "type";
      if (/^[A-Z]/.test(w)) return "type";
      return null;
    }
    stream.next();
    return null;
  },
  tokenTable: {
    keyword: t.keyword,
    comment: t.comment,
    string: t.string,
    number: t.number,
    type: t.typeName,
  },
  languageData: { commentTokens: { line: "//", block: { open: "/*", close: "*/" } } },
};

const moveLang = StreamLanguage.define(moveMode);
export function move() { return new LanguageSupport(moveLang); }

// Resolve a filename → a LanguageSupport (or null for plain text).
export function languageFor(name) {
  const n = String(name || "");
  if (n === "Cargo.lock") return null;
  const ext = (n.split(".").pop() || "").toLowerCase();
  switch (ext) {
    case "rs": return rust();
    case "move": return move();
    case "js": case "mjs": case "cjs": case "jsx": return javascript();
    case "ts": return javascript({ typescript: true });
    case "tsx": return javascript({ typescript: true, jsx: true });
    case "json": return json();
    case "py": return python();
    default: return null;
  }
}
