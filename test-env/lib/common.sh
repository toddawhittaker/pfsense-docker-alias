#!/usr/bin/env bash
# Shared settings for the pfSense test environment. Sourced, not run.
#
# The VM's disk and credentials are deliberately kept outside the repository:
# the qcow2 alone is several gigabytes, and lab.env holds an API key.

# Repository directory holding these scripts.
TEST_ENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export TEST_ENV_DIR

# Where the VM's disk, snapshots, keys and credentials live. Override by
# exporting PFSENSE_LAB_DIR before calling any of these scripts.
LAB_DIR="${PFSENSE_LAB_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/pfsense-docker-alias-lab}"
export LAB_DIR

# pfSense CE 2.7.2 is the newest release whose installer images Netgate serves
# from an open mirror; 2.8.x is only available through a form on pfsense.org.
# The REST API package is pinned to match: pfRest v2.4.3 is the last release
# built for 2.7.2, and every release after it requires 2.8.x. Bump these two
# together or not at all.
PFSENSE_VERSION="2.7.2"
PFSENSE_IMAGE="pfSense-CE-memstick-serial-${PFSENSE_VERSION}-RELEASE-amd64.img"
PFSENSE_IMAGE_URL="https://atxfiles.netgate.com/mirror/downloads/${PFSENSE_IMAGE}.gz"
PFSENSE_IMAGE_SHA256="bc3ee3d82b8195387114a64c3398505f238a6cb5393ae9b2d45d1bf9408ed192"

RESTAPI_VERSION="v2.4.3"
RESTAPI_PKG="pfSense-${PFSENSE_VERSION}-pkg-RESTAPI.pkg"
RESTAPI_URL="https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/download/${RESTAPI_VERSION}/${RESTAPI_PKG}"
# bootstrap.sh installs this package as root inside the VM, so pin it like the
# pfSense image above. A GitHub release asset is mutable -- the publisher can
# replace it without moving the tag -- so the version alone is not an immutable
# reference. Take the hash from the asset's `digest` field, which GitHub computes:
#   gh api repos/pfrest/pfSense-pkg-RESTAPI/releases/tags/$RESTAPI_VERSION \
#     --jq '.assets[] | select(.name == "'"$RESTAPI_PKG"'") | .digest'
RESTAPI_SHA256="69f84530890c62dc0209e188af3f697fa1952b9de532720cfc6e3ebe42331438"

# Guest addressing. The LAN address is fixed because QEMU's port forwarding
# rules name it explicitly.
LAN_IP="10.0.3.15"
LAN_GATEWAY="10.0.3.2"        # the QEMU user-mode gateway: every request from
                              # the host reaches pfSense from this address
PARENT_HOST="caddy"
PARENT_DOMAIN="lab.internal"
PARENT_IP="10.0.3.100"

# Host-side ports. All bind to loopback only; see run notes in vm.sh.
API_PORT="8443"
SSH_PORT="2222"
DNS_PORT="15353"

# Where containers reach the API, via relay.sh.
BRIDGE_IP="172.17.0.1"

export PFSENSE_VERSION PFSENSE_IMAGE PFSENSE_IMAGE_URL PFSENSE_IMAGE_SHA256
export RESTAPI_VERSION RESTAPI_PKG RESTAPI_URL RESTAPI_SHA256
export LAN_IP LAN_GATEWAY PARENT_HOST PARENT_DOMAIN PARENT_IP
export API_PORT SSH_PORT DNS_PORT BRIDGE_IP

log()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# QEMU needs read/write on /dev/kvm, which normally means membership of the kvm
# group. A fresh group membership does not apply to already-running shells, so
# run QEMU under `sg` when the current process cannot open the device yet.
#
# Note the argument to `id`: bare `id -nG` reports the calling process's own
# credentials, which is exactly what has not caught up yet after a usermod.
# Naming the user makes it consult the group database instead, which is the
# question actually being asked.
in_kvm_group() { id -nG "$USER" | tr ' ' '\n' | grep -qx kvm; }

kvm_run() {
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    "$@"
  elif in_kvm_group; then
    sg kvm -c "$(printf '%q ' "$@")"
  else
    die "no access to /dev/kvm. Run: sudo usermod -aG kvm $USER"
  fi
}

api() {
  # api METHOD PATH [curl args...]
  local method="$1" path="$2"; shift 2
  curl -sk --max-time 30 -X "$method" \
    -H "X-API-Key: ${PFSENSE_API_TOKEN:?PFSENSE_API_TOKEN is not set}" \
    -H 'Content-Type: application/json' \
    "https://127.0.0.1:${API_PORT}/api/v2${path}" "$@"
}
