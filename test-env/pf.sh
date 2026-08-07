#!/usr/bin/env bash
# Run a command on the pfSense test VM over SSH, as root.
#
#   ./pf.sh 'pkg info | grep RESTAPI'
#   ./pf.sh 'cat /etc/version'
set -euo pipefail

# shellcheck source-path=SCRIPTDIR  # resolve relative to this script, not the CWD
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

KEY="$LAB_DIR/pfsense_lab_key"
[[ -f "$KEY" ]] || die "no SSH key at $KEY — run ./bootstrap.sh first"

# IdentitiesOnly stops ssh offering every key in the agent first. pfSense's sshd
# rejects the connection as "Too many authentication failures" before it ever
# reaches the right key, and each rejected offer counts toward the brute-force
# lockout described in the README.
exec ssh -i "$KEY" \
  -o IdentitiesOnly=yes \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  -o LogLevel=ERROR \
  -o ConnectTimeout=10 \
  -p "$SSH_PORT" admin@127.0.0.1 "$@"
