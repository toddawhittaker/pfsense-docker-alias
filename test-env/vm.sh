#!/usr/bin/env bash
# Control the pfSense test VM.
#
#   ./vm.sh start            boot the installed system
#   ./vm.sh start install    boot the memstick installer instead
#   ./vm.sh stop             ask pfSense to shut down, and wait for it
#   ./vm.sh kill             terminate QEMU without a clean shutdown
#   ./vm.sh status           is it running, and are its ports listening
#   ./vm.sh snapshot [tag]   save a live snapshot, default tag "clean"
#   ./vm.sh reset [tag]      roll back to a snapshot, about a second
#   ./vm.sh monitor <cmd>    send a raw command to the QEMU monitor
#
# Networking is QEMU user-mode (slirp) on both NICs, so this needs no bridge, no
# tap device and no root. em0 is WAN and reaches the internet, which the REST API
# package install needs. em1 is LAN at a fixed address.
#
# Forwards bind to 127.0.0.1 only. This VM keeps pfSense's default credentials,
# so binding to 0.0.0.0 would publish its webGUI and SSH to the whole physical
# network.
#
#   127.0.0.1:8443   -> 443  webGUI and REST API
#   127.0.0.1:2222   -> 22   SSH
#   127.0.0.1:15353  -> 53   unbound, for checking that aliases resolve
#
# Containers cannot use these directly. A hostfwd rule bound to the Docker
# bridge address accepts the TCP connection and then carries no data, so the
# client sees a connect that succeeds followed by a read timeout. Run relay.sh
# to publish the API to containers.
set -euo pipefail

# shellcheck source-path=SCRIPTDIR  # resolve relative to this script, not the CWD
# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

DISK="$LAB_DIR/pfsense.qcow2"
STICK="$LAB_DIR/$PFSENSE_IMAGE"
PIDFILE="$LAB_DIR/qemu.pid"

vm_pid() { [[ -f "$PIDFILE" ]] && cat "$PIDFILE"; }

vm_running() {
  local pid
  pid="$(vm_pid || true)"
  [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null
}

monitor() {
  vm_running || die "VM is not running"
  printf '%s\n' "$*" | socat - "UNIX-CONNECT:$LAB_DIR/monitor.sock" | sed -n '3,$p'
}

start_console() {
  # One long-lived process owns the serial socket, logging everything it prints
  # and forwarding anything written to the FIFO. QEMU's chardev accepts a single
  # client, so nothing else may connect while this runs.
  pgrep -f "[c]onmux.py $LAB_DIR" >/dev/null && return 0
  ( setsid nohup python3 "$TEST_ENV_DIR/lib/conmux.py" \
      "$LAB_DIR/console.sock" "$LAB_DIR/console.log" "$LAB_DIR/console.fifo" \
      >"$LAB_DIR/conmux.log" 2>&1 & )
  sleep 2
}

stop_console() {
  pkill -f "[c]onmux.py $LAB_DIR" 2>/dev/null || true
}

start() {
  vm_running && { log "VM already running (pid $(vm_pid))"; return 0; }
  [[ -f "$DISK" ]] || die "no disk at $DISK — run ./bootstrap.sh first"

  # shellcheck disable=SC2054  # QEMU options carry commas inside single arguments
  local args=(
    -name pfsense-lab
    -machine q35,accel=kvm
    -cpu host
    -smp 2
    -m 4096
    -display none
    -vga none

    -drive "file=$DISK,if=none,id=hd0,format=qcow2,cache=writeback"
    -device virtio-blk-pci,drive=hd0,bootindex=1

    -netdev user,id=wan,net=10.0.2.0/24,dhcpstart=10.0.2.15
    -device e1000,netdev=wan

    -netdev "user,id=lan,net=10.0.3.0/24,dhcpstart=10.0.3.20,hostfwd=tcp:127.0.0.1:${API_PORT}-${LAN_IP}:443,hostfwd=tcp:127.0.0.1:${SSH_PORT}-${LAN_IP}:22,hostfwd=udp:127.0.0.1:${DNS_PORT}-${LAN_IP}:53"
    -device e1000,netdev=lan

    -serial "unix:$LAB_DIR/console.sock,server=on,wait=off"
    -monitor "unix:$LAB_DIR/monitor.sock,server=on,wait=off"
    -pidfile "$PIDFILE"
    -daemonize
  )

  if [[ "${1:-}" == "install" ]]; then
    # The installer is attached over SATA rather than USB. Under qemu-xhci the
    # memstick image throws persistent da0 read errors and the boot stalls
    # retrying them. SATA also keeps the installer (ada0) and the target disk
    # (vtbd0) on separate buses, so removing the installer afterwards cannot
    # renumber the target.
    # shellcheck disable=SC2054  # as above
    args+=(
      -drive "file=$STICK,if=none,id=stick,format=raw"
      -device ide-hd,drive=stick,bootindex=0
    )
  fi

  rm -f "$LAB_DIR/console.sock" "$LAB_DIR/monitor.sock" "$PIDFILE"
  kvm_run qemu-system-x86_64 "${args[@]}"
  sleep 2
  start_console
  log "VM started (pid $(vm_pid))"
}

stop() {
  if ! vm_running; then
    log "VM is not running"
    stop_console
    return 0
  fi
  log "asking pfSense to shut down"
  "$TEST_ENV_DIR/pf.sh" 'nohup shutdown -p +1s >/dev/null 2>&1 &' >/dev/null 2>&1 || true
  local waited=0
  while vm_running && (( waited < 120 )); do
    sleep 3
    waited=$(( waited + 3 ))
  done
  if vm_running; then
    warn "clean shutdown timed out; terminating QEMU"
    kill "$(vm_pid)" 2>/dev/null || true
    sleep 3
  fi
  stop_console
  log "VM stopped"
}

case "${1:-status}" in
  start)    start "${2:-}" ;;
  stop)     stop ;;
  kill)     kill "$(vm_pid)" 2>/dev/null || true; stop_console; log "VM killed" ;;
  status)
    if vm_running; then
      log "VM running (pid $(vm_pid))"
      ss -ltn 2>/dev/null | grep -E ":(${API_PORT}|${SSH_PORT})\b" || true
    else
      log "VM not running"
    fi
    ;;
  snapshot) monitor savevm "${2:-clean}"; log "snapshot '${2:-clean}' saved" ;;
  reset)    monitor loadvm "${2:-clean}"; log "rolled back to '${2:-clean}'" ;;
  monitor)  shift; monitor "$@" ;;
  *)        die "usage: $0 {start [install]|stop|kill|status|snapshot [tag]|reset [tag]|monitor <cmd>}" ;;
esac
