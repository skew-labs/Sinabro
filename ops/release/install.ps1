#!/usr/bin/env pwsh
# sinabro Windows installer — DESIGN-ONLY (Mac+Windows deploy-prep, 2026-06-18).
#
# The Windows sibling of install.sh. Distribution model (owner-locked 2026-06-18):
# an installable terminal agent — same category as Claude Code / Codex CLI —
#     irm https://<release-host>/install.ps1 | iex
# downloads a prebuilt, checksum-verified `sinabro.exe` and drops it on PATH.
# This installs the CLI; the Tauri DESKTOP app ships separately as a signed `.msi`
# (download + run), NOT an irm|iex target.
#
# GO-LIVE GATE (fail-closed): the release host, cross-platform CI artifacts, and
# Windows Authenticode signing do not exist yet (no signed release published; funds
# LOCKED). This script is STRUCTURALLY COMPLETE but REFUSES TO RUN until
# $env:SINABRO_RELEASE_READY -eq 'true' AND a real signed release is published. It is a
# reviewable design artifact, not a live installer — running `irm|iex` of it today fails
# closed with a clear message (no half-installed / unverified binary).
#
# Why irm|iex needs care (this script's hard rules):
#   - pin an exact VERSION (no "latest" silent drift),
#   - download the binary AND its .sha256, and REFUSE to install on mismatch,
#   - (go-live) also verify a detached signature over the checksum,
#   - never run an unverified binary; never need admin (install under %LOCALAPPDATA%),
#   - Windows: an unsigned downloaded .exe trips SmartScreen — Authenticode signing is a
#     go-live requirement, not a workaround to disable SmartScreen.

$ErrorActionPreference = 'Stop'

# ── go-live gate ────────────────────────────────────────────────────────────────
$ReleaseReady = $env:SINABRO_RELEASE_READY                              # flipped to 'true' only at go-live
$Version = if ($env:SINABRO_VERSION) { $env:SINABRO_VERSION } else { '0.0.0-phase0' }   # pinned exact release tag
$BaseUrl = if ($env:SINABRO_BASE_URL) { $env:SINABRO_BASE_URL } else { 'https://example.invalid/sinabro' }  # placeholder host

if ($ReleaseReady -ne 'true') {
  Write-Error @'
sinabro installer is not live yet.

  This is the Windows installable-terminal-agent distribution (like Claude/Codex),
  but the signed cross-platform release + host are gated to go-live. Funds are
  LOCKED and there is no live release to fetch.

  When go-live ships, this exact script (checksum + signature verified) will be
  served from the release host and installation will be one line.
'@
  exit 1
}

# ── platform detection (Windows) ─────────────────────────────────────────────────
switch ($env:PROCESSOR_ARCHITECTURE) {
  'AMD64' { $arch = 'x86_64' }
  'ARM64' { $arch = 'aarch64' }   # go-live: the aarch64-pc-windows-msvc CLI target is a follow-on
  default { Write-Error "unsupported arch: $env:PROCESSOR_ARCHITECTURE"; exit 1 }
}
$target = "$arch-pc-windows-msvc"

# ── install ──────────────────────────────────────────────────────────────────────
$binDir = if ($env:SINABRO_BIN_DIR) { $env:SINABRO_BIN_DIR } else { Join-Path $env:LOCALAPPDATA 'sinabro\bin' }
$url = "$BaseUrl/v$Version/sinabro-$target.exe"
$tmp = Join-Path $env:TEMP ('sinabro-' + [guid]::NewGuid().ToString())
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
try {
  Write-Host "downloading sinabro v$Version ($target) ..."
  Invoke-WebRequest -Uri $url          -OutFile (Join-Path $tmp 'sinabro.exe')        -UseBasicParsing
  Invoke-WebRequest -Uri "$url.sha256" -OutFile (Join-Path $tmp 'sinabro.exe.sha256') -UseBasicParsing

  Write-Host "verifying checksum ..."
  $expected = (((Get-Content (Join-Path $tmp 'sinabro.exe.sha256') -Raw) -split '\s+') | Where-Object { $_ })[0].ToLower()
  $actual = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $tmp 'sinabro.exe')).Hash.ToLower()
  if ($expected -ne $actual) {
    Write-Error "checksum mismatch: expected $expected got $actual (refusing to install)"
    exit 1
  }

  # go-live: also verify a detached signature over sinabro.exe.sha256 here
  # (minisign -Vm sinabro.exe.sha256 -P <pubkey>) and abort on failure.

  New-Item -ItemType Directory -Force -Path $binDir | Out-Null
  Copy-Item -Path (Join-Path $tmp 'sinabro.exe') -Destination (Join-Path $binDir 'sinabro.exe') -Force
  Write-Host "installed: $(Join-Path $binDir 'sinabro.exe')"

  $onPath = ($env:PATH -split ';') -contains $binDir
  if (-not $onPath) {
    Write-Host "note: add $binDir to your PATH, then run: sinabro repl"
  }
}
finally {
  Remove-Item -Recurse -Force -Path $tmp -ErrorAction SilentlyContinue
}
