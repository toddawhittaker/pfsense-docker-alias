#!/usr/bin/env bash
# Publish the pfSense REST API to Docker containers.
#
# QEMU's own port forwarding only works on loopback here: a hostfwd rule bound
# to the Docker bridge address accepts the connection and then carries no data,
# which a client sees as a connect that succeeds followed by a read timeout. So
# the VM forwards to 127.0.0.1 and this relays the bridge address to it.
#
# The bind is the bridge address specifically, not 0.0.0.0, so the physical
# network still cannot reach a VM running with pfSense's default credentials.
#
#   ./relay.sh start
#   ./relay.sh stop
#   ./relay.sh status
set -euo pipefail

# shellcheck source-path=SCRIPTDIR  # resolve relative to this script, not the CWD
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

PIDFILE="$LAB_DIR/relay.pid"

relay_running() {
  [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null
}

case "${1:-start}" in
  start)
    if relay_running; then
      log "relay already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi
    ip -br addr show docker0 >/dev/null 2>&1 || \
      warn "docker0 not present; the relay will fail to bind $BRIDGE_IP"
    setsid socat "TCP-LISTEN:${API_PORT},bind=${BRIDGE_IP},fork,reuseaddr" \
      "TCP:127.0.0.1:${API_PORT}" >"$LAB_DIR/relay.log" 2>&1 &
    echo $! >"$PIDFILE"
    sleep 1
    relay_running || { cat "$LAB_DIR/relay.log" >&2; die "relay failed to start"; }
    log "relay started: ${BRIDGE_IP}:${API_PORT} -> 127.0.0.1:${API_PORT}"
    ;;
  stop)
    if relay_running; then
      kill "$(cat "$PIDFILE")" 2>/dev/null || true
      rm -f "$PIDFILE"
      log "relay stopped"
    else
      rm -f "$PIDFILE"
      log "relay not running"
    fi
    ;;
  status)
    if relay_running; then log "relay running (pid $(cat "$PIDFILE"))"; else log "relay not running"; fi
    ;;
  *)
    die "usage: $0 {start|stop|status}"
    ;;
esac
