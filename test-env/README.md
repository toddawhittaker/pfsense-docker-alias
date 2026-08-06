# Local end-to-end test environment

A throwaway pfSense virtual machine with the REST API package installed, so
changes can be tested against a real firewall instead of a mock.

`CONTRIBUTING.md` explains when to reach for this. This file is the reference
for the scripts themselves.

## Build it

```bash
test-env/bootstrap.sh
```

About ten minutes and 6 GB of disk. It downloads pfSense, installs it over a
serial console, installs the REST API package, creates an API key, creates the
parent host override the service needs, and takes a snapshot.

It needs KVM and a handful of packages. It checks for both and tells you the
exact command to run if something is missing; `--install-deps` runs it for you
on Debian and Ubuntu.

Everything it creates lives outside the repository, under
`~/.local/share/pfsense-docker-alias-lab` by default. Set `PFSENSE_LAB_DIR` to
put it elsewhere. Nothing here writes into the working tree.

## Use it

```bash
test-env/smoke.sh            # run the service against it and assert end to end
test-env/smoke.sh --reset    # from the clean snapshot, for a repeatable run

test-env/vm.sh start         # boot it
test-env/vm.sh reset         # roll back to the clean snapshot, about a second
test-env/vm.sh stop          # shut it down
test-env/vm.sh status

test-env/relay.sh start      # publish the API to Docker containers
test-env/pf.sh 'pkg info'    # run a command on the firewall over SSH
```

Talking to the API by hand:

```bash
source ~/.local/share/pfsense-docker-alias-lab/lab.env
curl -sk -H "X-API-Key: $PFSENSE_API_TOKEN" \
  https://127.0.0.1:8443/api/v2/services/dns_resolver/host_overrides
```

Checking that an alias actually resolves, which is the assertion no unit test
can make:

```bash
dig +short @127.0.0.1 -p 15353 smoke.lab.internal
```

## What you get

| | |
|---|---|
| pfSense | CE 2.7.2-RELEASE, ZFS on a 20 GB qcow2 |
| REST API | pfRest v2.4.3 |
| WAN | `em0`, DHCP from QEMU user-mode networking, has internet |
| LAN | `em1`, static `10.0.3.15/24` |
| Parent host override | `caddy.lab.internal` → `10.0.3.100` |
| webGUI | <https://127.0.0.1:8443/>, `admin` / `pfsense` |

The two versions are pinned together in `lib/common.sh` and must move together.
pfRest v2.4.3 is the last release built for pfSense CE 2.7.2; everything after
it requires CE 2.8.x, whose installer images are not on Netgate's open mirror
and can only be fetched through a form on pfsense.org. Bumping the package
alone will not work.

## Ports

QEMU forwards to `127.0.0.1` only. This VM keeps pfSense's default credentials,
so binding to `0.0.0.0` would publish its webGUI and SSH to the whole physical
network.

| Host | pfSense | |
|---|---|---|
| `127.0.0.1:8443` | 443 | webGUI and REST API |
| `127.0.0.1:2222` | 22 | SSH |
| `127.0.0.1:15353/udp` | 53 | unbound |
| `172.17.0.1:8443` | — | `relay.sh`, for Docker containers |

Containers cannot use QEMU's forwarding directly. A `hostfwd` rule bound to the
Docker bridge address accepts the TCP connection and then carries no data, so
the client sees a connect that succeeds followed by a read timeout. `relay.sh`
socats the bridge address to the working loopback forward instead.

## Things that bite

**The lockout.** Every request from the host reaches pfSense as `10.0.3.2`, the
QEMU user-mode gateway. pfSense's login protection blocks a source address after
a few authentication failures, and it blocks *everything* from it at once —
SSH, the webGUI and the REST API — while the serial console stays up and makes
the VM look perfectly healthy. `bootstrap.sh` whitelists that address and turns
off pfRest's own login protection. If you still manage to trip it:

```bash
PFSENSE_LAB_DIR=... python3 test-env/lib/sendkeys.py "pfctl -t sshguard -T flush{ENTER}"
```

**`--rm` containers were the first real bug this environment found.** Docker can
delete a container started with `--rm` before its stop event is handled, so its
labels are unreadable and the alias was left behind: twenty stopped at once
orphaned nineteen aliases. The service now records alias configuration at start
and falls back to it, and `smoke.sh` asserts both paths — a container whose
labels are still readable, and one Docker has already deleted.

**Arrow keys cancel installer dialogs.** Over this serial console `dialog(1)`
reads the leading ESC of `ESC [ B` as a bare escape and treats it as cancel,
which quits the installer to a login prompt. Use TAB to move between buttons.
`showcon.py` marks bold and reverse-video so you can see which button actually
has focus, which is how `install.py` tells `<YES>` from `<NO>` on the
confirmation that defaults to NO.

## Files

| | |
|---|---|
| `bootstrap.sh` | build the whole thing from nothing |
| `smoke.sh` | run the service against it and assert end to end |
| `vm.sh` | boot, stop, snapshot, roll back, QEMU monitor |
| `relay.sh` | publish the API on the Docker bridge |
| `pf.sh` | run a command on pfSense over SSH |
| `lib/common.sh` | pinned versions, addresses, ports, shared helpers |
| `lib/conmux.py` | owns the serial console; logs it and accepts keystrokes |
| `lib/showcon.py` | render the console log as a screen, with focus markers |
| `lib/sendkeys.py` | send keystrokes to the console |
| `lib/expect.py` | drive a sequence of console prompts |
| `lib/install.py` | drive the installer's dialog screens |
| `lib/lab.py` | where the console helpers find the state directory |
