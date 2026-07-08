#!/usr/bin/env bash
# sinabro installer — DESIGN-ONLY (G-WP-12 follow-on; updated for the desktop lane 2026-06-18).
#
# Distribution model (owner-locked 2026-06-18): sinabro now ships in TWO forms, both
# built + checksummed by `.github/workflows/release.yml` and attached to one GitHub Release:
#   (1) the installable terminal agent — same category as Claude Code / Codex CLI / Hermes —
#         curl -fsSL https://<release-host>/install.sh | bash
#       downloads a prebuilt, checksum-verified `sinabro` binary and drops it on PATH;
#   (2) the Tauri DESKTOP app (`.dmg`) — the GUI window (sidebar + chat + the ✦ MEGA panel).
# THIS SCRIPT installs form (1), the CLI, on macOS + Linux. The desktop `.dmg` is a
# separate Release asset the owner downloads + drags to /Applications (codesigned +
# notarized at go-live), NOT a curl|bash target. (The earlier "NOT a desktop GUI" note is
# superseded — the Tauri app now exists, is wired, and is in the release pipeline.)
#
# WINDOWS users: this bash script does not run on Windows. Use the PowerShell sibling
# `install.ps1` (`irm https://<release-host>/install.ps1 | iex`) for the Windows `.exe`,
# and the desktop `.msi` for the GUI. Both installers share the same fail-closed
# (RELEASE_READY gate + checksum-verify) discipline.
#
# PHASE-2 GATE (fail-closed): the release host, cross-platform CI artifacts, and
# macOS notarization/signing do not exist yet (no signed release published; funds LOCKED).
# This script is therefore STRUCTURALLY COMPLETE but REFUSES TO RUN until `RELEASE_READY=true`
# AND a real signed release is published. It is a reviewable design artifact, not a live
# installer — running `curl|bash` of it today fails closed with a clear message (no
# half-installed / unverified binary).
#
# Why curl|bash needs care (this script's hard rules):
#   - pin an exact VERSION (no "latest" silent drift),
#   - download the binary AND its .sha256, and REFUSE to install on mismatch,
#   - (go-live) also verify a minisign/cosign signature over the checksum,
#   - never run an unverified binary; never need root (install to ~/.local/bin),
#   - macOS: a downloaded binary is Gatekeeper-quarantined unless Developer-ID
#     signed + notarized — that is a go-live requirement, not a workaround.
set -euo pipefail

# ── go-live gate ───────────────────────────────────────────────────────────────
RELEASE_READY="${SINABRO_RELEASE_READY:-false}"   # flipped to true only at go-live
VERSION="${SINABRO_VERSION:-0.0.0-phase0}"         # pinned exact release tag
BASE_URL="${SINABRO_BASE_URL:-https://example.invalid/sinabro}"  # placeholder host

if [ "$RELEASE_READY" != "true" ]; then
  cat >&2 <<'EOF'
sinabro installer is not live yet (Phase-0).

  This is the installable-terminal-agent distribution (like Claude/Codex/Hermes),
  but the signed cross-platform release + host are gated to go-live (Phase-2).
  Funds are LOCKED and there is no live release to fetch.

  When go-live ships, this exact script (checksum + signature verified) will be
  served from the release host and installation will be one line.
EOF
  exit 1
fi

# ── platform detection ──────────────────────────────────────────────────────────
detect_target() {
  local os arch
  os="$(uname -s)"; arch="$(uname -m)"
  case "$os" in
    Darwin) os="apple-darwin" ;;
    Linux)  os="unknown-linux-gnu" ;;
    *) echo "unsupported OS: $os" >&2; exit 1 ;;
  esac
  case "$arch" in
    arm64|aarch64) arch="aarch64" ;;
    x86_64|amd64)  arch="x86_64" ;;
    *) echo "unsupported arch: $arch" >&2; exit 1 ;;
  esac
  echo "${arch}-${os}"
}

# ── install ───────────────────────────────────────────────────────────────────
main() {
  local target tmp url bin_dir
  target="$(detect_target)"
  bin_dir="${SINABRO_BIN_DIR:-$HOME/.local/bin}"
  url="${BASE_URL}/v${VERSION}/sinabro-${target}"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  echo "downloading sinabro v${VERSION} (${target}) ..."
  curl -fsSL "$url"        -o "$tmp/sinabro"
  curl -fsSL "$url.sha256" -o "$tmp/sinabro.sha256"

  echo "verifying checksum ..."
  ( cd "$tmp" && \
    if command -v sha256sum >/dev/null 2>&1; then
      sha256sum -c sinabro.sha256
    else
      # macOS: shasum -a 256 -c expects "<hash>  <file>" format
      shasum -a 256 -c sinabro.sha256
    fi )

  # go-live: also verify a detached signature over sinabro.sha256 here
  # (minisign -Vm sinabro.sha256 -P <pubkey>) and abort on failure.

  mkdir -p "$bin_dir"
  install -m 0755 "$tmp/sinabro" "$bin_dir/sinabro"
  echo "installed: $bin_dir/sinabro"

  case ":$PATH:" in
    *":$bin_dir:"*) : ;;
    *) echo "note: add $bin_dir to your PATH, then run: sinabro repl" ;;
  esac
}

main "$@"
