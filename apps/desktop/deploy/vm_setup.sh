#!/usr/bin/env bash
# sinabro VM setup (A1 SSH-exec lane) — run ON a fresh Ubuntu VM (x86_64/aarch64).
#
# STATUS: AUTHORED 2026-06-10 — NOT YET VERIFIED on a real VM. Verification = V3
# in ops/evidence/stage_g/gui_desktop/SSH_REMOTE_DISPATCH_THREAT_MODEL.md.
# Do not report this green until it has actually run on an owner-provisioned VM.
#
# mnemos is a LOCAL workspace (not a git remote), so the source must arrive by
# rsync BEFORE this script runs. From the local mac:
#
#   rsync -az --exclude 'target/' /Users/heoun/mnemos/prototype/ user@VM:~/sinabro-src/
#   ssh user@VM 'bash -s' < /Users/heoun/mnemos/apps/desktop/deploy/vm_setup.sh
#
# What this installs is the DEFAULT (egress-free) sinabro build: no
# put-fixture-net / provider-egress features. Enabling a gated egress feature on
# the VM is a separate owner decision. No secrets are read, written, or echoed
# here (secret-zero); provider/telegram keys are configured later by the owner
# (env/keyring on the VM, never logged).
set -euo pipefail

SRC="${SINABRO_SRC:-$HOME/sinabro-src}"
RUST_TOOLCHAIN="1.94.1"   # pinned to the toolchain the workspace is verified on

echo "[1/5] apt build deps"
sudo apt-get update -y
sudo apt-get install -y build-essential pkg-config curl ca-certificates

echo "[2/5] rust toolchain (rustup, pinned ${RUST_TOOLCHAIN})"
if ! command -v cargo >/dev/null 2>&1; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain "${RUST_TOOLCHAIN}"
fi
# shellcheck disable=SC1091
. "$HOME/.cargo/env"

echo "[3/5] build sinabro (Cargo.lock-pinned fetch; default features = egress-free)"
cd "${SRC}"
cargo build --release --locked -p sinabro
BUILD_EXIT=$?
echo "BUILD_EXIT=${BUILD_EXIT}"

echo "[4/5] install to /usr/local/bin (PATH-safe for non-interactive ssh exec)"
sudo install -m 0755 target/release/sinabro /usr/local/bin/sinabro
sinabro --version

echo "[5/5] readiness + host-key fingerprints"
# Readiness is REPORTED, not masked: doctor's exit code is printed verbatim so
# the owner reads the true state (a fresh VM with zero providers configured is
# an expected non-green readiness, not a script failure).
set +e
sinabro doctor
echo "DOCTOR_EXIT=$?"
sinabro provider status
echo "PROVIDER_STATUS_EXIT=$?"
set -e

# TOFU support (TM R2): print the host key fingerprints so the owner can
# eyeball-compare what the GUI records on first connect.
for f in /etc/ssh/ssh_host_*_key.pub; do
  ssh-keygen -lf "$f"
done

echo "vm_setup complete — point the GUI host selector at user@$(hostname -I 2>/dev/null | awk '{print $1}')"
