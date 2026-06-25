# sinabro release checklist — macOS + Windows (CLI + desktop)

> Owner-locked 2026-06-18 (Mac + Windows; supersedes the 2026-06-10 "NOT a GUI"
> lock): the distribution targets **macOS AND Windows** (Linux CLI is kept as a
> free bonus), in two forms each, built by `.github/workflows/release.yml` and
> attached to one GitHub Release on a `v*` tag:
>   1. an **installable terminal agent** (the CLI binary on PATH):
>      - macOS / Linux: `curl -fsSL https://<host>/install.sh | bash`
>      - Windows: `irm https://<host>/install.ps1 | iex`
>   2. the **Tauri desktop app** — the GUI window (sidebar + chat + the ✦ MEGA panel
>      surfacing web3-read · settings-sync · codebase · image · remote-run):
>      - macOS: `.dmg` (drag to /Applications)
>      - Windows: `.msi` (+ NSIS `setup.exe`) — download + run
>
> **Phase gate:** this is the go-live plan. Nothing here is live yet (no signed
> release published; funds LOCKED; no git remote). Both `install.sh` and `install.ps1`
> are reviewable design artifacts that **fail closed** until `RELEASE_READY=true`.

## Why this model fits
- The CLI is one static Rust binary (`sinabro` / `sinabro.exe`; release target <15 MB)
  with no runtime deps — ideal for a download-and-run installer on every platform.
- The desktop app is the Tauri (WKWebView / WebView2) GUI lane (G-WP-13+): the same
  surface-neutral Rust core behind a window, matching Claude/Codex desktop. The
  CodeMirror bundle is VENDORED, so the desktop build fetches no `node_modules`.

## Go-live blockers (all required before flipping `RELEASE_READY=true`)
1. **git repo + tagged releases** — a repo with signed, versioned `v*` tags driving
   `release.yml`. Local `git init` + `.gitignore` (excludes `target/`, datasets,
   `node_modules/`, and ALL key material) is done + staging-audited (0 secrets
   staged); the GitHub remote create + first commit + push are owner go-live steps.
2. **cross-platform CI build matrix** — `release.yml` `build-cli` publishes prebuilt
   binaries for `aarch64-apple-darwin`, `x86_64-apple-darwin`,
   **`x86_64-pc-windows-msvc`**, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`.
   `install.sh` (macOS/Linux) and `install.ps1` (Windows) map the host arch → these
   targets. `build-desktop-macos` publishes the `.dmg`; `build-desktop-windows`
   publishes the `.msi` (+ NSIS `setup.exe`). (ARM64 Windows CLI/desktop = follow-on;
   needs the VS ARM64 build tools on the runner.)
3. **macOS Developer-ID signing + notarization** — both a downloaded binary AND the
   `.dmg` are Gatekeeper-quarantined unless Developer-ID signed + notarized ("cannot
   be opened because the developer cannot be verified"). `release.yml`'s
   codesign/notarize steps run ONLY when the `APPLE_SIGNING_IDENTITY` secret exists
   (absent ⇒ UNSIGNED draft). Paid Apple Developer account — NOT a Gatekeeper-disable
   workaround.
4. **Windows Authenticode signing** — an unsigned downloaded `.exe` / `.msi` trips
   SmartScreen ("Windows protected your PC"). `release.yml`'s `signtool` steps run
   ONLY when the `WINDOWS_CERT_BASE64` (+ `WINDOWS_CERT_PASSWORD`) secrets exist
   (absent ⇒ UNSIGNED draft). Needs a code-signing certificate (OV/EV from a CA) —
   NOT a SmartScreen-disable workaround.
5. **supply-chain integrity** — every artifact (`sinabro-<target>(.exe)` + `.dmg` +
   `.msi`) ships a `.sha256`; the installers verify the CLI checksum and refuse to
   install on mismatch. Add a **detached signature over the checksum** (minisign or
   cosign), public key pinned in both installers, verified before install. curl|bash
   / irm|iex is itself a threat surface — the integrity chain is mandatory.
6. **version pinning** — the installers pin `SINABRO_VERSION` to an exact tag (no
   "latest" silent drift); the host serves `…/v<VERSION>/sinabro-<target>(.exe)`.
7. **release host** — a domain serving `install.sh`, `install.ps1`, and the artifacts
   over HTTPS. Replace the `example.invalid` placeholder in both installers.
8. **SHA-pin external actions** — like `ci.yml`, every `uses:` in `release.yml` is
   semver; the `ci.yml` sha-pin-guard FAILS until each is pinned to a 40-hex commit
   SHA. Pin them in the go-live PR.
9. **security review** — threat-model the installers + release pipeline (host
   compromise, MITM, key custody for the signing keys, reproducible builds, the
   notarization / Authenticode chains) before the first public install.

## Safety posture preserved
- The installers only run at go-live; this plan adds no live network egress on its
  own. funds/wallet/mainnet/chain-write stay HARD-LOCKED (`CustodyCapability`
  uninhabited, PD-6) — a release build never touches them.
- Both installers run nothing today: `RELEASE_READY` defaults to `false` → they
  print the gate message and exit 1.

## What is done now (deploy-prep, Mac+Windows 2026-06-18)
- Distribution decision LOCKED: **macOS + Windows, CLI + desktop both** (Linux CLI bonus).
- `.gitignore` — deny-broad excludes for `target/`, datasets, `node_modules/`, and
  ALL key material; `git init` done + `git add -n` staging audit (0 secrets staged).
- `.github/workflows/release.yml` — `build-cli` matrix (macOS×2 + Windows×1 + Linux×2)
  + `build-desktop-macos` (.dmg) + `build-desktop-windows` (.msi/setup.exe) + tag-only
  `publish` (draft Release); `permissions: contents: read` default, only `publish`
  elevates to `contents: write` on a `v*` tag; macOS signing gated on `APPLE_*`,
  Windows signing gated on `WINDOWS_CERT_*`; CodeMirror vendored.
- `ops/release/install.sh` (macOS/Linux) + `ops/release/install.ps1` (Windows) —
  structurally-complete, fail-closed installers (arch→target map, pinned version,
  checksum-verify + refuse-on-mismatch, per-user install, PATH hint; signature-verify
  hook marked for go-live).
- This checklist + `ops/evidence/stage_g/deploy_release_grep.sh` (structural verifier).

## Owner go-live steps (NOT done here — need owner creds/decisions)
- GitHub remote create + first commit + push + first `v*` tag.
- `APPLE_*` signing/notarization secrets (paid Apple Developer ID, macOS).
- `WINDOWS_CERT_BASE64` + `WINDOWS_CERT_PASSWORD` secrets (code-signing cert, Windows).
- Release host domain (replace `example.invalid`) serving both installers + flip
  `RELEASE_READY=true`.
- SHA-pin every `uses:` in `release.yml`; detached-signature pubkey in both installers.
- Security review of the installers + release pipeline.
