#!/usr/bin/env bash
# Run the service against the test VM and assert the whole path end to end.
#
#   ./smoke.sh            run against the VM as it stands
#   ./smoke.sh --reset    roll back to the clean snapshot first
#
# This is the check the unit suite structurally cannot make. That suite stubs
# both Docker and the pfSense API, so it can only confirm the client matches our
# own idea of the API. Here a container start has to travel through the real
# Docker event stream, the real REST API and a real unbound reload before a DNS
# query answers.
#
# Runs every assertion, then exits non-zero if any of them failed.
set -euo pipefail

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

REPO_DIR="$(cd "$TEST_ENV_DIR/.." && pwd)"
SERVICE="smoke-alias-service"
TARGET="smoke-target"
ALIAS_NAME="smoke.$PARENT_DOMAIN"
DESCRIPTION="set by smoke.sh"
IMAGE="pfsense-docker-alias:smoke"

FAILURES=0

pass() { printf '  \033[32mok\033[0m   %s\n' "$*"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAILURES=$(( FAILURES + 1 )); }

cleanup() {
  docker rm -f "$SERVICE" "$TARGET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

resolves()     { [[ -n "$(dig +short +timeout=3 "@127.0.0.1" -p "$DNS_PORT" "$1" 2>/dev/null)" ]]; }
not_resolves() { ! resolves "$1"; }
logged()       { docker logs "$SERVICE" 2>&1 | grep -q "$1"; }

# assert_within DESCRIPTION TIMEOUT PREDICATE [ARGS...]
#
# The predicate must be a function or command, not a pipeline: everything after
# the timeout is passed to it as arguments. Always returns 0 so that one failed
# assertion does not abort the run under `set -e`; failures are counted instead
# and reported at the end.
assert_within() {
  local what="$1" timeout="$2"; shift 2
  local waited=0
  until "$@" >/dev/null 2>&1; do
    sleep 3
    waited=$(( waited + 3 ))
    if (( waited >= timeout )); then
      fail "$what (gave up after ${timeout}s)"
      return 0
    fi
  done
  pass "$what"
}

# --------------------------------------------------------------------------
[[ -f "$LAB_DIR/lab.env" ]] || die "no test environment yet — run ./bootstrap.sh"
"$TEST_ENV_DIR/vm.sh" status | grep -q running || die "the VM is not running — run ./vm.sh start"

if [[ "${1:-}" == "--reset" ]]; then
  log "rolling back to the clean snapshot"
  "$TEST_ENV_DIR/vm.sh" reset clean >/dev/null
  sleep 5
fi

"$TEST_ENV_DIR/relay.sh" start >/dev/null

PFSENSE_API_TOKEN="$(grep '^PFSENSE_API_TOKEN=' "$LAB_DIR/lab.env" | cut -d= -f2-)"
export PFSENSE_API_TOKEN

log "building the image"
docker build -q -t "$IMAGE" "$REPO_DIR" >/dev/null

log "starting the service"
cleanup
docker run -d --name "$SERVICE" \
  --env-file "$LAB_DIR/lab.env" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  "$IMAGE" >/dev/null

assert_within "the service reaches its event loop" 60 logged "Listening for container start"

# --------------------------------------------------------------------------
log "a labelled container should create an alias that resolves"

# Deliberately not --rm. A container Docker has already deleted cannot have its
# labels read back when it stops, so its alias is left behind; see the README.
docker run -d --name "$TARGET" \
  -l "pfsense.dns.override=$PARENT_HOST.$PARENT_DOMAIN" \
  -l "pfsense.dns.alias=$ALIAS_NAME" \
  -l "pfsense.dns.description=$DESCRIPTION" \
  -l "pfsense.dns.remove_on_stop=true" \
  alpine sleep 600 >/dev/null

assert_within "the service logs the alias as added" 120 logged "$ALIAS_NAME added"
assert_within "$ALIAS_NAME resolves" 120 resolves "$ALIAS_NAME"

ANSWER="$(dig +short +timeout=3 "@127.0.0.1" -p "$DNS_PORT" "$ALIAS_NAME")"
if [[ "$ANSWER" == "$PARENT_IP" ]]; then
  pass "it resolves to the parent's address ($PARENT_IP)"
else
  fail "expected $PARENT_IP, got '${ANSWER:-nothing}'"
fi

STORED="$(api GET /services/dns_resolver/host_overrides | python3 -c "
import json, sys
for override in json.load(sys.stdin)['data']:
    for alias in override.get('aliases') or []:
        if alias.get('host') == '${ALIAS_NAME%%.*}':
            print(alias.get('descr', ''))
")"
if [[ "$STORED" == "$DESCRIPTION" ]]; then
  pass "the description round-trips through the API"
else
  fail "description was '$STORED', expected '$DESCRIPTION'"
fi

# --------------------------------------------------------------------------
log "stopping it should remove the alias"

docker stop "$TARGET" >/dev/null

assert_within "the service logs the alias as removed" 120 logged "$ALIAS_NAME removed"
assert_within "$ALIAS_NAME stops resolving" 120 not_resolves "$ALIAS_NAME"

# --------------------------------------------------------------------------
log "the service should still be running"

if [[ "$(docker inspect -f '{{.State.Running}}' "$SERVICE" 2>/dev/null)" == "true" ]]; then
  pass "it survived the whole run"
else
  fail "the service exited"
  docker logs "$SERVICE" 2>&1 | tail -20
fi

echo
if (( FAILURES )); then
  die "$FAILURES assertion(s) failed"
fi
log "all assertions passed"
