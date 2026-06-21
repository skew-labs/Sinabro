# Stage D · #266 — try-before-use fixtures

Declarative dry-run fixture inputs for `mnemos_e_skill::try_before_use`.

| fixture | `FixtureSource` | eligible? |
|---|---|---|
| `sample_input.json` | `Sample` | always |
| `redacted_slice.json` | `RedactedWorkspaceSlice` | only with a non-zero redaction token |
| (raw workspace slice) | `RawWorkspace` | never |

A dry-run over any eligible fixture performs **no persistence, no network, no
wallet, no chain write, and no local state mutation** — it produces a
`TryBeforeUseRun` (package digest, module id, fixture hash, decision, trace) that
**cannot create install state**. The unit tests in
`crates/e-skill/src/try_before_use.rs` exercise these fixture classes in-memory;
these files document the on-disk fixture contract.
