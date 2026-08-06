#!/usr/bin/env bash
# Build the pfSense test VM from nothing, unattended.
#
#   ./bootstrap.sh                 build it (refuses if a disk already exists)
#   ./bootstrap.sh --force         delete any existing VM and build a new one
#   ./bootstrap.sh --install-deps  apt-get the missing host packages first
#
# Takes roughly ten minutes and about 6 GB of disk. When it finishes there is a
# running pfSense with the REST API package, an API key, an SSH key, the parent
# host override this service expects, and a snapshot to roll back to.
#
# Everything it creates lives in $LAB_DIR, outside the repository.
set -euo pipefail

# shellcheck source=lib/common.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib/common.sh"

FORCE=0
INSTALL_DEPS=0
for arg in "$@"; do
  case "$arg" in
    --force)        FORCE=1 ;;
    --install-deps) INSTALL_DEPS=1 ;;
    -h|--help)      sed -n '2,14p' "$0"; exit 0 ;;
    *)              die "unknown option: $arg" ;;
  esac
done

DISK="$LAB_DIR/pfsense.qcow2"
KEY="$LAB_DIR/pfsense_lab_key"
ENV_FILE="$LAB_DIR/lab.env"

# pfSense's out-of-the-box webGUI login. Used only until the API key exists.
DEFAULT_USER="admin"
DEFAULT_PASS="pfsense"

ssh_pw() {
  sshpass -p "$DEFAULT_PASS" ssh \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -o PreferredAuthentications=password \
    -o ConnectTimeout=10 -p "$SSH_PORT" "$DEFAULT_USER@127.0.0.1" "$@"
}

scp_key() {
  scp -i "$KEY" -o IdentitiesOnly=yes \
    -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o LogLevel=ERROR -P "$SSH_PORT" "$1" "$DEFAULT_USER@127.0.0.1:$2"
}

pf() { "$TEST_ENV_DIR/pf.sh" "$@"; }
vm() { "$TEST_ENV_DIR/vm.sh" "$@"; }
console() { PFSENSE_LAB_DIR="$LAB_DIR" python3 "$TEST_ENV_DIR/lib/$1.py" "${@:2}"; }

# wait_for DESCRIPTION TIMEOUT COMMAND...
wait_for() {
  local what="$1" timeout="$2"; shift 2
  local waited=0
  until "$@" >/dev/null 2>&1; do
    sleep 3
    waited=$(( waited + 3 ))
    (( waited < timeout )) || die "timed out after ${timeout}s waiting for $what"
  done
}

console_says() { grep -qa "$1" "$LAB_DIR/console.log"; }

api_basic() {
  local method="$1" path="$2"; shift 2
  curl -sk --max-time 30 -X "$method" -u "$DEFAULT_USER:$DEFAULT_PASS" \
    -H 'Content-Type: application/json' \
    "https://127.0.0.1:${API_PORT}/api/v2${path}" "$@"
}

json_field() { python3 -c "import json,sys; print(json.load(sys.stdin)$1)"; }

# --------------------------------------------------------------------------
log "checking the host"

MISSING=()
for cmd in qemu-system-x86_64 qemu-img socat curl python3 dig ssh scp sshpass; do
  command -v "$cmd" >/dev/null || MISSING+=("$cmd")
done

if (( ${#MISSING[@]} )); then
  APT_PACKAGES="qemu-system-x86 qemu-utils socat curl python3 dnsutils openssh-client sshpass"
  if (( INSTALL_DEPS )) && command -v apt-get >/dev/null; then
    log "installing: $APT_PACKAGES"
    # shellcheck disable=SC2086  # deliberate word splitting into package names
    sudo apt-get install -y $APT_PACKAGES
  else
    die "missing: ${MISSING[*]}
On Debian or Ubuntu: sudo apt-get install -y $APT_PACKAGES
Or re-run with --install-deps. Other distributions need the equivalents."
  fi
fi

if [[ ! -e /dev/kvm ]]; then
  die "no /dev/kvm. This host cannot run KVM, so the test environment cannot be built here."
elif [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
  if in_kvm_group; then
    warn "you are in the kvm group but this shell predates it; QEMU will run under 'sg kvm'"
  elif (( INSTALL_DEPS )); then
    log "adding $USER to the kvm group"
    sudo usermod -aG kvm "$USER"
    in_kvm_group || die "usermod did not take effect"
    warn "group membership applies to new logins; QEMU will run under 'sg kvm' for now"
  else
    die "no access to /dev/kvm. Run: sudo usermod -aG kvm $USER
Then log out and back in, or start a new login session. Or re-run with
--install-deps, which will do it for you."
  fi
fi

# --------------------------------------------------------------------------
if [[ -f "$DISK" ]]; then
  (( FORCE )) || die "a VM already exists at $DISK. Re-run with --force to replace it."
  log "removing the existing VM"
  vm kill >/dev/null 2>&1 || true
  "$TEST_ENV_DIR/relay.sh" stop >/dev/null 2>&1 || true
  rm -f "$DISK" "$KEY" "$KEY.pub" "$ENV_FILE" \
        "$LAB_DIR/console.log" "$LAB_DIR/console.fifo" "$LAB_DIR/qemu.pid"
fi

mkdir -p "$LAB_DIR"
chmod 700 "$LAB_DIR"

# --------------------------------------------------------------------------
log "fetching pfSense CE $PFSENSE_VERSION"

cd "$LAB_DIR"

# A progress bar is worth having on a terminal and is unreadable in a log file.
CURL=(curl -fL)
if [[ -t 2 ]]; then CURL+=(--progress-bar); else CURL+=(-sS); fi

if [[ ! -f "$PFSENSE_IMAGE" ]]; then
  [[ -f "$PFSENSE_IMAGE.gz" ]] || "${CURL[@]}" -o "$PFSENSE_IMAGE.gz" "$PFSENSE_IMAGE_URL"
  echo "$PFSENSE_IMAGE_SHA256  $PFSENSE_IMAGE.gz" | sha256sum -c - \
    || die "checksum mismatch on $PFSENSE_IMAGE.gz — delete it and retry"
  gunzip -kf "$PFSENSE_IMAGE.gz"
fi

[[ -f "$RESTAPI_PKG" ]] || "${CURL[@]}" -o "$RESTAPI_PKG" "$RESTAPI_URL"

log "creating a 20 GB disk"
qemu-img create -f qcow2 "$DISK" 20G >/dev/null

# --------------------------------------------------------------------------
log "installing pfSense (this is the slow part)"

rm -f "$LAB_DIR/console.log"
vm start install
console install

# The installer reboots into itself, because the memstick still boots first.
# Give it a moment to finish writing, then bring it back up without the stick.
sleep 20
vm kill
sleep 2
rm -f "$LAB_DIR/console.log"
vm start

log "waiting for the first boot"
wait_for "the console menu" 600 console_says "Enter an option"

# --------------------------------------------------------------------------
log "configuring the LAN interface"

console sendkeys "{ENTER}"
console expect \
  "?Should VLANs be set up now=n" \
  "Enter an option:=2" \
  "the number of the interface you wish to configure=2" \
  "via DHCP?=n" \
  "new LAN IPv4 address=$LAN_IP" \
  "subnet bit count=24" \
  "press <ENTER> for none:=" \
  "via DHCP6?=n" \
  "new LAN IPv6 address=" \
  "DHCP server on LAN=n" \
  "revert to HTTP=n"

wait_for "the webGUI" 300 curl -sk --max-time 5 -o /dev/null "https://127.0.0.1:${API_PORT}/"

log "enabling SSH"
console sendkeys "{ENTER}"
console expect "Enter an option:=14" "Would you like to enable?=y"
wait_for "sshd" 180 ssh_pw true

# --------------------------------------------------------------------------
log "installing the REST API package ($RESTAPI_VERSION)"

ssh-keygen -t ed25519 -N '' -f "$KEY" -C 'pfsense-docker-alias test env' >/dev/null
ssh_pw "mkdir -p /root/.ssh && chmod 700 /root/.ssh && \
        cat >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys" < "$KEY.pub"

scp_key "$LAB_DIR/$RESTAPI_PKG" /tmp/
pf "pkg-static add /tmp/$RESTAPI_PKG" | tail -3

wait_for "the API after the webConfigurator restart" 300 \
  curl -sk --max-time 5 -o /dev/null "https://127.0.0.1:${API_PORT}/api/v2/status/system"

# --------------------------------------------------------------------------
log "configuring the API"

# pfRest ships with only BasicAuth enabled, so the X-API-Key header this project
# sends is rejected with a 401 until KeyAuth is added. login_protection is turned
# off for the reason described under "the lockout" in the README.
api_basic PATCH /system/restapi/settings \
  -d '{"auth_methods":["BasicAuth","KeyAuth"],"login_protection":false}' \
  | json_field "['data']['auth_methods']" >/dev/null

PFSENSE_API_TOKEN="$(
  api_basic POST /auth/key -d '{"descr":"pfsense-docker-alias test env"}' \
    | json_field "['data']['key']"
)"
export PFSENSE_API_TOKEN
[[ -n "$PFSENSE_API_TOKEN" ]] || die "the API did not return a key"

# A key written straight into /root/.ssh/authorized_keys is wiped on reboot;
# pfSense rewrites that file from its user configuration. Store it on the admin
# user so it survives.
ADMIN_ID="$(api GET /users | json_field "['data'][0]['id']")"
python3 -c "
import json, sys
print(json.dumps({'id': int(sys.argv[1]), 'authorizedkeys': open(sys.argv[2]).read().strip()}))
" "$ADMIN_ID" "$KEY.pub" > "$LAB_DIR/user.json"
api PATCH /user -d @"$LAB_DIR/user.json" | json_field "['code']" >/dev/null
rm -f "$LAB_DIR/user.json"

# --------------------------------------------------------------------------
log "whitelisting the gateway from login protection"

# Every request from the host reaches pfSense from the QEMU user-mode gateway
# address, so a handful of authentication failures would otherwise lock out SSH,
# the webGUI and the REST API all at once.
cat > "$LAB_DIR/whitelist.php" <<PHP
<?php
require_once("config.inc");
require_once("syslog.inc");
config_set_path('system/sshguard_whitelist', '$LAN_GATEWAY');
write_config("test env: whitelist the QEMU gateway from login protection");
system_syslogd_start();
PHP
scp_key "$LAB_DIR/whitelist.php" /tmp/whitelist.php
pf 'php -f /tmp/whitelist.php && pfctl -t sshguard -T flush' >/dev/null 2>&1
rm -f "$LAB_DIR/whitelist.php"

# --------------------------------------------------------------------------
log "creating the parent host override"

# This service never creates a host override, only aliases on one that already
# exists, so a test environment needs one to hang aliases from.
api POST /services/dns_resolver/host_override \
  -d "{\"host\":\"$PARENT_HOST\",\"domain\":\"$PARENT_DOMAIN\",\"ip\":[\"$PARENT_IP\"],\"descr\":\"test env parent override\"}" \
  | json_field "['code']" >/dev/null
api POST /services/dns_resolver/apply >/dev/null

wait_for "the parent override to resolve" 120 \
  dig +short +timeout=3 "@127.0.0.1" -p "$DNS_PORT" "$PARENT_HOST.$PARENT_DOMAIN"

# --------------------------------------------------------------------------
log "writing credentials and taking a snapshot"

cat > "$ENV_FILE" <<ENV
# Credentials for the local pfSense test VM, generated by test-env/bootstrap.sh.
# Test-only: this VM sits behind QEMU user-mode NAT with its ports bound to
# loopback, and it still uses pfSense's default webGUI password.
PFSENSE_HOSTNAME=${BRIDGE_IP}:${API_PORT}
PFSENSE_API_TOKEN=${PFSENSE_API_TOKEN}
PFSENSE_VERIFY_SSL=false
ENV
chmod 600 "$ENV_FILE"

vm snapshot clean >/dev/null

cat <<SUMMARY

$(log "ready")

  VM state      $LAB_DIR
  credentials   $ENV_FILE
  webGUI        https://127.0.0.1:${API_PORT}/  ($DEFAULT_USER / $DEFAULT_PASS)
  parent name   $PARENT_HOST.$PARENT_DOMAIN -> $PARENT_IP

Next:

  test-env/smoke.sh          run the service against it and assert end to end
  test-env/vm.sh reset       roll back to the clean snapshot
  test-env/vm.sh stop        shut it down

SUMMARY
