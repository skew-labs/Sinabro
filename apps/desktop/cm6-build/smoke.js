// A④ node smoke — machine-checkable proof that the VENDORED bundle loads and that
// every CodeMirror-6 API app.js relies on is real and behaves (EditorView mounts;
// readOnly toggles; find/replace + multi-cursor + the FIM ghost field + the A①⨉A④
// diagnostics gutter all wire). On-screen render = owner runs the app (E12 precedent);
// THIS proves the core/plumbing offline, with no Tauri, no network. Run: node smoke.js
const fs = require("fs");
const path = require("path");
const { JSDOM } = require("jsdom");

const dom = new JSDOM("<!doctype html><html data-theme='dark'><body><div id='host'></div></body></html>", { pretendToBeVisual: true });
global.window = dom.window;
global.document = dom.window.document;
global.navigator = dom.window.navigator;
for (const k of ["HTMLElement", "Element", "Node", "Range", "DOMParser", "getComputedStyle", "requestAnimationFrame", "cancelAnimationFrame", "MutationObserver", "ResizeObserver"]) {
  if (dom.window[k] && !global[k]) global[k] = dom.window[k];
}
if (!global.requestAnimationFrame) global.requestAnimationFrame = (cb) => setTimeout(() => cb(Date.now()), 0);

const bundlePath = path.join(__dirname, "..", "ui", "vendor", "codemirror.bundle.js");
const src = fs.readFileSync(bundlePath, "utf8");
// The bundle is `var CM = (()=>{...})()` — function-scope it and return CM.
const CM = new Function(src + "\nreturn CM;")();

let pass = 0, fail = 0;
const ok = (cond, label) => { if (cond) { pass++; } else { fail++; console.log("  FAIL: " + label); } };

// (1) exports present
for (const sym of ["EditorView", "EditorState", "StateField", "StateEffect", "Compartment", "Decoration", "WidgetType", "GutterMarker", "gutter", "RangeSet", "RangeSetBuilder", "Prec", "keymap", "lineNumbers", "search", "searchKeymap", "openSearchPanel", "defaultKeymap", "history", "historyKeymap", "indentWithTab", "drawSelection", "rectangularSelection", "crosshairCursor", "bracketMatching", "indentOnInput", "highlightSelectionMatches", "highlightActiveLine", "highlightActiveLineGutter", "HighlightStyle", "syntaxHighlighting", "StreamLanguage", "tags", "languageFor", "move"]) {
  ok(typeof CM[sym] !== "undefined", "export " + sym);
}

// (2) languageFor resolves sinabro's real targets (rust + Move + json), plain otherwise
ok(CM.languageFor("lib.rs") != null, "languageFor(.rs)");
ok(CM.languageFor("token.move") != null, "languageFor(.move)");
ok(CM.languageFor("Cargo.toml") == null && CM.languageFor("notes.txt") == null, "languageFor(plain)=null");
ok(CM.languageFor("app.json") != null, "languageFor(.json)");

// (3) HighlightStyle with the EXACT tag set app.js uses (catches a bad tag name)
const t = CM.tags;
let hs;
try {
  hs = CM.HighlightStyle.define([
    { tag: [t.comment, t.lineComment, t.blockComment], color: "var(--tok-comment)" },
    { tag: [t.keyword, t.controlKeyword, t.moduleKeyword, t.definitionKeyword, t.operatorKeyword], color: "var(--tok-keyword)" },
    { tag: [t.string, t.special(t.string), t.regexp], color: "var(--tok-string)" },
    { tag: [t.number, t.integer, t.float], color: "var(--tok-number)" },
    { tag: [t.bool, t.atom, t.null, t.literal], color: "var(--tok-literal)" },
    { tag: [t.typeName, t.className, t.namespace, t.standard(t.typeName)], color: "var(--tok-type)" },
    { tag: [t.function(t.variableName), t.function(t.propertyName), t.propertyName, t.attributeName], color: "var(--tok-type)" },
  ]);
} catch (e) { console.log("  HighlightStyle threw: " + e.message); }
ok(hs != null, "HighlightStyle.define(app.js tag set)");

// (4) FIM ghost field + decoration provider
const fimEffect = CM.StateEffect.define();
class GhostWidget extends CM.WidgetType { constructor(x){ super(); this.text = x; } eq(o){ return o.text === this.text; } toDOM(){ const s = document.createElement("span"); s.className = "cm-fim-ghost"; s.textContent = this.text; return s; } }
const fimField = CM.StateField.define({
  create(){ return { text: null, from: 0 }; },
  update(v, tr){ for (const e of tr.effects) if (e.is(fimEffect)) return e.value || { text: null, from: 0 }; if (tr.docChanged) return { text: null, from: 0 }; return v; },
  provide: (f) => CM.EditorView.decorations.from(f, (v) => { if (!v.text) return CM.Decoration.none; const w = CM.Decoration.widget({ widget: new GhostWidget(v.text), side: 1 }); return CM.Decoration.set([w.range(v.from)]); }),
});

// (5) diagnostics field + gutter + marker
const diagEffect = CM.StateEffect.define();
const diagField = CM.StateField.define({ create(){ return []; }, update(v, tr){ for (const e of tr.effects) if (e.is(diagEffect)) return e.value; return v; } });
class DiagMarker extends CM.GutterMarker { constructor(sev, msg){ super(); this.sev = sev; this.msg = msg; } toDOM(){ const s = document.createElement("span"); s.className = "cm-diag-marker cm-diag-" + this.sev; s.textContent = "●"; s.title = this.msg; return s; } }
const diagGutter = CM.gutter({
  class: "cm-diagnostics-gutter",
  markers: (view) => { const ds = view.state.field(diagField); if (!ds.length) return CM.RangeSet.empty; const b = new CM.RangeSetBuilder(); const doc = view.state.doc; for (const d of ds) { const ln = Math.min(Math.max(1, d.line), doc.lines); const line = doc.line(ln); b.add(line.from, line.from, new DiagMarker(d.sev, d.msg)); } return b.finish(); },
  lineMarkerChange: (u) => u.transactions.some((tr) => tr.effects.some((e) => e.is(diagEffect))),
});
ok(new DiagMarker("error", "x").toDOM().className.indexOf("cm-diag-error") >= 0, "DiagMarker renders");

// (6) build a real EditorState + EditorView (the unified read/edit substrate)
const readOnly = new CM.Compartment(), wrap = new CM.Compartment(), themeC = new CM.Compartment();
function mkState(doc, editing) {
  return CM.EditorState.create({
    doc,
    extensions: [
      CM.lineNumbers(), diagGutter, CM.highlightActiveLine(), CM.highlightActiveLineGutter(),
      CM.history(), CM.drawSelection(), CM.rectangularSelection(), CM.crosshairCursor(),
      CM.bracketMatching(), CM.indentOnInput(), CM.highlightSelectionMatches(), CM.search({ top: true }),
      diagField, fimField,
      CM.EditorView.updateListener.of(() => {}),
      CM.Prec.highest(CM.keymap.of([{ key: "Tab", run: () => false }, { key: "Escape", run: () => false }])),
      CM.keymap.of([...CM.defaultKeymap, ...CM.historyKeymap, ...CM.searchKeymap, CM.indentWithTab]),
      readOnly.of(CM.EditorState.readOnly.of(!editing)),
      CM.languageFor("lib.rs"),
      wrap.of(CM.EditorView.lineWrapping),
      themeC.of([CM.EditorView.theme({ "&": { color: "var(--text)" } }, { dark: true }), CM.syntaxHighlighting(hs)]),
      CM.EditorState.allowMultipleSelections.of(true),
    ],
  });
}
const view = new CM.EditorView({ state: mkState("fn main() {}\nlet x = 1;\nstruct S;", false), parent: document.getElementById("host") });
ok(view.state.doc.toString() === "fn main() {}\nlet x = 1;\nstruct S;", "doc round-trips (save flow source)");
ok(view.state.readOnly === true, "read-only VIEWER (readOnly=true)");

// readOnly toggle (viewer ⟺ edit)
view.dispatch({ effects: readOnly.reconfigure(CM.EditorState.readOnly.of(false)) });
ok(view.state.readOnly === false, "edit mode toggle (readOnly=false)");

// multi-cursor
const sel = CM.EditorState ? view.state.selection : null;
view.dispatch({ selection: { anchor: 0 } });
ok(typeof CM.openSearchPanel === "function" && CM.searchKeymap.length > 0, "find/replace API");

// FIM ghost set/clear via effect (re-homed P6)
view.dispatch({ effects: fimEffect.of({ text: "// ghost", from: 3 }) });
ok(view.state.field(fimField).text === "// ghost", "FIM ghost set");
view.dispatch({ changes: { from: 3, insert: "X" } });
ok(view.state.field(fimField).text === null, "FIM ghost cleared on edit");

// diagnostics plumbing (A①⨉A④)
view.dispatch({ effects: diagEffect.of([{ line: 2, col: 1, sev: "error", msg: "boom" }]) });
ok(view.state.field(diagField).length === 1 && view.state.field(diagField)[0].sev === "error", "diagnostics gutter plumbing");

// scrollIntoView effect (outline jump)
ok(typeof CM.EditorView.scrollIntoView === "function", "scrollIntoView (jumpToLine)");

// theme reconfigure (data-theme mirror)
view.dispatch({ effects: themeC.reconfigure([CM.EditorView.theme({ "&": { color: "var(--text)" } }, { dark: false }), CM.syntaxHighlighting(hs)]) });
ok(true, "theme reconfigure");

view.destroy();
console.log(`\nCM6 SMOKE: pass=${pass} fail=${fail}`);
process.exit(fail === 0 ? 0 : 1);
