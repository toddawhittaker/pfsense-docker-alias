# AGENTS.md

This file is the authoritative guidance for AI coding agents working in this repository.
`CLAUDE.md` is a symlink to this file — edit `AGENTS.md`, never the symlink.

## Project context

This repository contains a lightweight Python Docker service that listens to Docker container events and updates pfSense DNS aliases through the unofficial pfSense REST API.

## Commands

A `.venv` (CPython 3.14, matching CI and the runtime image) is already set up at the repo root and is gitignored. Recreate it with:

```bash
uv venv --python 3.14
uv pip install -r requirements.txt -r requirements-dev.txt
```

```bash
.venv/bin/python -m py_compile main.py pfsense.py   # required after changing either Python file
.venv/bin/python -m pytest                          # full suite (160 tests)
.venv/bin/python -m pytest --cov --cov-report=term-missing   # with the coverage gate
.venv/bin/python -m pytest tests/test_main.py::test_parse_alias_labels_returns_alias_config   # single test
.venv/bin/python -m pylint main.py pfsense.py       # must stay at 10.00/10
.venv/bin/python -m pip_audit -r requirements.txt --strict       # no known CVEs allowed
.venv/bin/python -m pip_audit -r requirements-dev.txt --strict

docker build -t pfsense-docker-alias .              # required after changing Docker-related files
```

Run pytest as `python -m pytest` from the repo root. There is no `conftest.py`, `pyproject.toml`, or package layout — `main` and `pfsense` are importable only because `python -m` puts the CWD on `sys.path`. Bare `pytest` fails collection with `ModuleNotFoundError: No module named 'pfsense'`.

`pylint` must stay at 10.00/10 — CI fails on any message. Suppressions are local `# pylint: disable=` pragmas at the narrowest scope that works, never a config file: `logging-fstring-interpolation` module-wide in both modules (the codebase logs with f-strings by convention), `redefined-builtin` on `add_host_override_alias` and `del_host_override_alias` for their public `apply` parameter, and in `main.py` a `global-statement` on each function that updates the coalescing state plus a `broad-except` on each handler that must not let one failure kill the service.

The `too-many-return-statements` pragmas that used to sit on both mutators are **gone**, retired by extracting `_mutate_alias` rather than by raising a limit — see "Mutations are staged, then applied". Do not reintroduce one to buy room for another guard clause. The defaults are `max-returns=6` and `max-args=5`, and both mutators now sit at 6 and 5 returns with the helper itself at exactly 5 arguments, so there is no headroom left: the next guard clause that needs a pragma is telling you the method has outgrown its shape, which is what the pragma was covering up the first time.

Test coverage is gated at **80%** with branch coverage on, configured in `.coveragerc` (`fail_under`) and enforced by CI's `--cov` run — the step fails when coverage drops below the line even if every test passes. Coverage currently sits at ~99%, so the gate is a floor against regression, not a target to chase: the headroom is there to be spent on real behavior, never on tests written only to move the number. If a change genuinely cannot be covered, exclude it deliberately with a `# pragma: no cover` and say why, rather than lowering `fail_under`.

Coverage config lives in `.coveragerc` rather than `pyproject.toml` on purpose — this repo has no `pyproject.toml` or package layout, and pytest's imports depend on that, so introducing one to hold settings risks changing how rootdir and `sys.path` resolve.

`actionlint` checks the workflow files and is not a pip package — download it when you need it. It shells out to `shellcheck` for `run:` blocks **only if shellcheck is on `PATH`**, and GitHub runners have it while a plain dev box usually does not. Local actionlint without shellcheck is therefore weaker than CI and will miss shell issues that fail the build; install shellcheck before trusting a local pass.

CI installs it from a **pinned release asset verified against a SHA256**, not by piping upstream's install script into bash — that script is fetched from a branch we do not control and resolves `latest` at run time, and the job it runs in is triggered by `pull_request`. Dependabot does not track this pin, so it is the one version in this repo that drifts silently: bump `ACTIONLINT_VERSION` and `ACTIONLINT_SHA256` in `.github/workflows/docker-publish.yml` together, taking the hash for `linux_amd64` from the `actionlint_<version>_checksums.txt` published with the release. A version bump without a matching hash fails the `sha256sum -c` step, which is the intended failure — never drop the checksum to get past it.

`pip-audit` runs `--strict` against both requirements files, so a newly disclosed CVE in a pinned dependency turns CI red without any code change. That is intended: this service ships TLS calls and an API token, and `certifi` *is* its trust store. Fix by bumping the pin, not by ignoring the finding. Dependabot (`.github/dependabot.yml`) opens weekly PRs for pip, GitHub Actions, and the base image to keep that from accumulating.

### Manual end-to-end check

Docker and a running daemon are available locally, so the real event path can be exercised without a pfSense instance — point it at an unresolvable host and watch the retry/failure path:

```bash
docker run -d --name pfsense-alias-smoke \
  -e PFSENSE_HOSTNAME=pfsense.invalid -e PFSENSE_API_TOKEN=dummy \
  -v /var/run/docker.sock:/var/run/docker.sock pfsense-docker-alias
docker run -d --rm --name smoke-nginx \
  -l pfsense.dns.override=caddy.lab.internal -l pfsense.dns.alias=nginx.lab.internal \
  -l pfsense.dns.remove_on_stop=true alpine sleep 30
docker logs pfsense-alias-smoke
docker rm -f pfsense-alias-smoke smoke-nginx
```

Expect start/stop to be detected, three retries per API call, an error log, and the service to **stay running** — that resilience is the contract, so a crash here is a regression.

### The real end-to-end check, against a real pfSense

`test-env/bootstrap.sh` builds a throwaway pfSense VM with the REST API package installed (about ten minutes and 6 GB of disk, entirely outside the working tree), and `test-env/smoke.sh` runs the service against it and asserts the whole path: alias created, resolving through the firewall's own resolver, removed on stop, service still alive. `test-env/vm.sh reset` rolls back to a clean snapshot in about a second. `test-env/README.md` is the reference; `CONTRIBUTING.md` says when to reach for it.

This needs KVM, so it cannot run on GitHub's runners and is not part of CI. Run it by hand for any change touching `pfsense.py`, the apply/coalescing logic, or what goes into an API payload. The unit suite stubs both Docker and the API, so it can only confirm the client matches *our own idea* of the API — it cannot tell you whether a field lands where pfSense reads it, or whether a name resolves afterwards. Two things were settled here that the suite could not have reached: the alias description really does arrive (the API's `descr` is written to `config.xml` as `description`, which is the key the webGUI renders), and stopping twenty `--rm` containers at once orphaned nineteen aliases, which is the finding behind "A stopping container may already be gone" below.

Two things about that environment are worth knowing before using it. Every request from the host reaches pfSense from one address, so its brute-force protection can blackhole SSH, the webGUI and the REST API simultaneously while the serial console still looks healthy — `bootstrap.sh` whitelists it, but suspect it first if everything goes quiet at once. And containers cannot reach the VM through QEMU's port forwarding directly; `test-env/relay.sh` bridges that gap.

CI (`.github/workflows/docker-publish.yml`) runs on every PR and push to `main`: actionlint → shellcheck → compile → pylint → pip-audit → pytest with the coverage gate → `docker build` → Trivy image scan → two container smoke tests. The smoke tests run the built image and assert it exits 1 with a config error when unconfigured, then boots and reaches its event loop when configured. They exist because `docker build` cannot catch a runtime module missing its `COPY` — that image builds cleanly and dies at import. The ghcr.io publish job runs only on tag pushes.

The shellcheck step covers `test-env/*.sh` and `test-env/lib/*.sh`, which nothing else checks — actionlint shells out to shellcheck for `run:` blocks in workflows only. Each script carries `# shellcheck source-path=SCRIPTDIR` above its `source=` directive; without it shellcheck resolves the sourced path against the working directory, so the check passes from inside `test-env/` and fails from the repo root. If a new script sources `lib/common.sh`, it needs both directives.

**The publish job builds nothing.** The `test` job saves the image its smoke tests just ran and uploads it as an artifact; `build-and-push` downloads, loads, tags, and pushes that artifact, with no checkout and no `docker build` of its own. It used to rebuild from scratch, which meant the image users pulled was never the one anything had executed. Do not reintroduce a build step there — the whole point is that the published bytes are the tested bytes, and `docker save`/`docker load` preserves the image ID exactly.

**`:latest` moves only for a plain `vX.Y.Z` tag.** The trigger is `tags: ['v*']` and the push step gates `:latest` behind `^v[0-9]+\.[0-9]+\.[0-9]+$`, so `v0.3.0-rc1` publishes under its own tag and leaves `:latest` alone. The trigger was previously `'*'` with `:latest` moving for every tag, which meant any release candidate — or a stray tag — silently upgraded everyone tracking `:latest`. That matters more than usual for this image because a release can change a security default; `v0.2.0` turns TLS verification on.

The build is **`linux/amd64` only**. Buildx was previously set up with a comment claiming multi-platform support that no `platforms:` argument ever delivered; that comment is gone rather than left to mislead. Adding `linux/arm64` is a real decision, not a flag: an arm64 image cannot be smoke-tested on an amd64 runner without QEMU emulation, so it would either ship untested — the exact problem the build-once change fixes — or roughly double the job's runtime.

`concurrency` cancels superseded runs for the same ref, except on tags: a half-cancelled publish would leave a partly pushed release. Both jobs set `timeout-minutes`, since GitHub's default is six hours per job.

**The Trivy step exists because `pip-audit` cannot see the image.** `pip-audit` reads the two requirements files and nothing else, so the Alpine layer and anything the base image ships are invisible to it. That gap was real rather than theoretical: the scan found two HIGH findings the first time it ran, and **the Dockerfile removing pip is the fix for them**, not a cosmetic cleanup. Both came from pip's vendored dependency manifest (`pip/_vendor/vendor.txt`, `bom.cdx.json`) — a vendored `msgpack`, and `setuptools`, which is not installed in this image at all and is only named in that manifest. Neither is reachable when the container runs `python main.py`. Re-adding pip to the runtime image re-adds both findings and turns the scan red; if a future change needs pip at run time, the scan is the thing to satisfy, not to loosen.

The scan is gated on `severity: HIGH,CRITICAL` with **`ignore-unfixed: true`**, which is deliberate and is where it differs from `pip-audit --strict`. A pinned Python dependency always has a remedy — bump the pin — so blocking on any advisory is fair. A base-image CVE frequently has no fix available at all, and blocking every PR on something the author cannot act on is precisely how a gate teaches people to ignore CI. A *fixable* HIGH does block, and the remedy is a base-image bump, which Dependabot already proposes weekly. Note the Alpine layer itself reported zero findings when this was added, so the whole first-run result came from the Python side.

## Architecture

Two modules, no framework:

- **`main.py`** — Docker event loop, label parsing, dispatch.
- **`pfsense.py`** — `PFSense` class wrapping the unofficial [pfSense REST API](https://pfrest.org/) (`/api/v2/services/dns_resolver/...`).

Flow: `client.events(decode=True)` → filter to `Type == 'container'` and `Action in {start, stop, die}` → `handle_container_event` → `get_container_labels` → `parse_alias_labels` → `get_alias_event_action` → `process_start_event` / `process_stop_event` → `NAMESERVER` (the module-level `PFSense` instance, assigned in `main()`).

### Import-time side effects in `main.py`

Reading env vars, `docker.from_env()`, and `signal.signal()` registration all happen at module import, and missing required env vars call `sys.exit(1)`. Importing `main` therefore requires a configured environment and a stubbed `docker` module. `tests/test_main.py` handles this with a `load_main()` helper that sets env vars, injects a fake `docker` into `sys.modules`, pops `main`, and re-imports. Any new module-level state in `main.py` must survive that repeated re-import.

### Failure semantics

Deliberately asymmetric — keep it that way:

- pfSense API failures **log and return `False`**; they never raise, so one bad container can't kill the service.
- `_request` retries `requests.RequestException` up to `API_REQUEST_ATTEMPTS` (3) with a 1s sleep. `raise_for_status()` is called *outside* the retry, so HTTP error statuses are not retried. Tests monkeypatch `pfsense.time.sleep`.
- Docker event-stream errors **re-raise** out of `main()`; `run()` catches and exits non-zero so the container restarts.

### Mutations are staged, then applied

`add_host_override_alias` and `del_host_override_alias` perform the mutation, then apply it via `apply_changes()` unless called with `apply=False`. Any new mutating method needs the same option.

Both route that through `_mutate_alias`, which owns the whole shared shape: the request, the `response is None` guard, `raise_for_status()` inside the `RequestException`/`OSError` catch, setting `unapplied_changes`, and the conditional apply. A new mutating method should call it rather than copy it — that is where the failure semantics below actually live, so a hand-rolled copy is how they drift. Two things stay with the callers on purpose. The **log wording** does, because "added" and "staged" must differ and the caller is the only thing that knows which verb is true. The **endpoint** does not vary today, so `_mutate_alias` hard-codes the alias URL; a mutator targeting a different path should add the parameter at that point rather than the helper carrying an unused one now.

Applying is the expensive part: it reloads unbound, takes seconds, and **runs asynchronously** — the POST returns before the reload finishes. `apply_changes()` therefore polls `GET /dns_resolver/apply` until the response reports `applied`, up to `APPLY_POLL_ATTEMPTS`, and returns `False` with an error if it never confirms. Treat an unconfirmed reload as a possible lost update, not a success.

Confirmation is `data.get('applied') is True` — not `bool(...)`, not `== True`. It fails closed on every other encoding, including the strings `"false"` and `"true"` and the integer `1`; `bool("false")` and `1 == True` are both truthy, and either would let a hostile or buggy response report a reload as applied when it was not. `data` being a non-dict needs no separate guard: `response.json().get('data', {})` and `data.get('applied')` both raise `AttributeError` for a malformed body, and `AttributeError` is already in `_changes_applied`'s except tuple.

That status poll passes `attempts=1` to `_request`. Do not let it use the default retry budget — a retry budget nested inside a poll budget multiplies into a stall long enough to block the event loop.

**Never apply once per item in a loop.** `add_aliases_on_startup` stages every alias with `apply=False` and calls `apply_changes()` exactly once at the end, skipping it entirely when nothing staged. Applying per alias meant 20 containers cost 20 unbound reloads and ~40s of DNS disruption, with overlapping async reloads a likely cause of dropped updates. `tests/test_main.py::test_startup_scan_applies_once_for_many_aliases` pins this by counting.

### Event-driven applies are coalesced

The same burst arrives through the event loop — a `docker compose up` of twenty labeled services fires twenty events. `process_start_event` and `process_stop_event` therefore consult `should_apply_immediately()`:

- The **first** change after a quiet period applies immediately, so a lone container start is as fast as it was before coalescing.
- Everything during the burst that follows is staged with `apply=False` and flushed by one `apply_changes()`.

`flush_pending_changes()` fires when `APPLY_QUIET_SECONDS` (default 10) passes with no new change, when `APPLY_MAX_WAIT_SECONDS` (default 60) caps the wait so continuous churn cannot starve the apply, or with `force=True` on shutdown. Twenty services cost two reloads instead of twenty; `test_a_burst_of_starts_costs_two_applies_not_twenty` pins it.

Coalescing state (`PENDING_CHANGES`, `PENDING_SINCE`, `LAST_CHANGE_AT`, `LAST_APPLY_AT`) is module level and measured with `time.monotonic()`, so a wall-clock adjustment cannot strand pending changes. Note that `LAST_APPLY_AT = 0.0` reads as *long ago*, not *just now* — tests that need "an apply just happened" must set `time.monotonic()`.

**`cleanup()` flushes before exit.** A SIGTERM with staged changes would otherwise leave them in the config but never live. It guards on `NAMESERVER is not None`, since a signal can arrive before `main()` constructs it, and swallows flush errors so a broken apply cannot block shutdown. Docker's default 10s stop grace can still cut a slow apply short; the changes stay staged and go live on the next apply.

### A stopping container may already be gone

`handle_container_event` cannot rely on reading a stopping container's labels back from Docker. A container run with `docker run --rm` is deleted as it stops, and Docker frequently wins that race: `client.containers.get` raises `NotFound`, and the handler used to log "Container not found" and return, leaving the alias in pfSense. Measured against the test VM, one such container stopping alone was usually fine and **twenty stopping together orphaned nineteen aliases**. The unit suite could not see this at all, because it stubs the Docker client so the lookup always succeeds.

So `remember_alias_config()` records `(container_name, alias_config)` in `KNOWN_ALIASES`, keyed by container ID, whenever a start event is handled — and in `add_aliases_on_startup`, which is the only chance to record a container that was already running when this service started. On `NotFound`, `recall_alias_config()` supplies the fallback and the removal proceeds. When nothing was recorded, the original warning still fires.

Three properties are deliberate, and all three are now pinned by tests — two of them were not, and survived deliberate mutation of the source until `test_both_die_and_stop_remove_the_alias_for_a_deleted_container` and `test_re_recording_a_container_makes_it_the_newest_entry` were added:

- **Only a stop is answered from the record.** `recall_alias_config` returns `None` for any action other than `stop`/`die`. A start event for a container that has already gone is genuinely nothing to act on, and treating it as a removal would delete an alias in response to the wrong event.
- **The `remove_on_stop` opt-in still applies.** The recorded configuration is checked the same way a live label read would be, so falling back never removes an alias the labels did not ask to remove.
- **Entries are not dropped on stop.** Docker emits both `die` and `stop` for one shutdown, and the second event must reach the same answer as the first. Removing the entry on the first would make the second log "Container not found" for a container that was handled correctly a moment earlier.

That last choice means container IDs — which are never reused — would accumulate for the life of the process, so `KNOWN_ALIASES_MAX` (512) bounds the table and the oldest entry is evicted on overflow. Eviction relies on dictionaries preserving insertion order; `remember_alias_config` deletes before reinserting so a re-recorded container counts as newest. The second removal attempt costs one API call and no extra apply: `del_host_override_alias` returns `False` without mutating when the alias is already absent, so `_record_change_outcome` does nothing.

**How that no-op is detected is the subtle part, and reading `unapplied_changes` was not enough.** That flag answers "is there unapplied work?" and saturates at `True` for the length of a burst, so it cannot answer "did *this* call change anything?" — which is the question `_record_change_outcome` actually needs. Reading it alone meant the second of Docker's `die`/`stop` pair counted as a staged change once anything else was pending: a `docker compose down` of twenty services reported roughly 38 coalesced changes for 19 real removals, and a container in a restart loop could hold the quiet window open until the `APPLY_MAX_WAIT_SECONDS` cap. `PFSense.change_count` is therefore a **monotonic count of mutations that landed**, and `process_start_event` / `process_stop_event` compare it across the call and pass the result to `_record_change_outcome` as `mutated`. Both fields are needed and they answer different questions — do not collapse them. A fake nameserver in a test must move `change_count` on a successful mutation, or it models a service that never changes anything.

This is bounded, not unlimited memory: a container that starts, is recorded, and stops more than 512 container-starts later has been evicted, and its `--rm` removal fails the old way. Raising the cap trades memory for that window.

### The event loop yields window ticks

`iter_events()` replaces a single blocking `client.events()` with contiguous bounded windows (`since`/`until`, `EVENT_WINDOW_SECONDS`), yielding `None` at each boundary so `main()` can call `flush_pending_changes()`. This keeps the loop **single threaded** — no timer thread, no lock — which is why the resilience contract still holds. Note that single-threading removes thread races, not signal-handler re-entry: a SIGTERM arriving mid-flush still re-enters `flush_pending_changes()` and can issue a second apply. That is bounded and non-corrupting, but do not read "single threaded" as "reentrant-safe".

Windows are contiguous, so events between them are still delivered. An event landing exactly on a boundary may be delivered twice; that is harmless because adding an existing alias or removing an absent one is already detected and logged.

Tests drive `main()` by monkeypatching `main.iter_events` with a finite iterable. Do not stub `client.events` for loop tests — `iter_events` loops forever by design, so main() would never return.

With `apply=False`, a `True` return means **staged in the pfSense configuration but not yet live**. Staged changes persist and go live on the next successful apply. The log says "staged", not "added"/"removed", because an operator reading "removed" while the name still resolves is worse than no message at all.

**`PFSense.unapplied_changes` is the source of truth, not the return value.** A mutation can land while its apply fails, which returns `False` even though something is now staged. `unapplied_changes` is set as soon as the mutation POST succeeds and cleared only by a confirmed apply. `main._record_change_outcome()` consults it rather than the boolean — trusting the boolean stranded those changes, because nothing was pending so nothing ever retried and the alias never went live.

For the same reason, **a failed flush keeps its changes pending**. `flush_pending_changes()` calls `_defer_retry()` rather than `_record_applied()` when the apply fails, so a later tick or the shutdown flush retries. `_defer_retry()` pushes the timers out a full quiet window so a pfSense outage is not retried on every two-second window tick.

**The startup scan obeys the same rule, and for a while it did not.** When its single `apply_changes()` fails, `add_aliases_on_startup` calls `_record_staged(staged)` to hand the work to the coalescer. It used to only log. That left `PENDING_CHANGES` at `0` while `unapplied_changes` was `True`, and since `flush_pending_changes()` returns at its guard when nothing is pending, neither a window tick nor the shutdown flush ever retried — the aliases sat in `config.xml` with unbound never reloaded, and on an idle host no name resolved until something unrelated happened to trigger an apply. `test_a_failed_startup_apply_stays_pending_and_is_retried` pins both halves: that the count is recorded, and that a later flush actually clears it. Note this is the *whole* reason `_record_staged` takes a count — every other caller passes one.

### API responses are untrusted input

`get_all_host_overrides()` validates the payload shape — it returns `[]` for a non-list `data` and drops non-dict entries — and every accessor uses `.get()` rather than indexing. A well-formed 200 with an unexpected body previously raised `KeyError`/`TypeError` straight out of this module, which `main()` does not catch, exiting the service instead of logging and carrying on. An API schema change must degrade to a warning, never a crash loop.

`_request` catches `OSError` as well as `RequestException`. `requests` raises a **bare `OSError`** when `verify` names an unreadable CA bundle, which used to escape every public method and crash-loop the container — pushing operators toward disabling TLS verification to get the service running. `main.py` also checks `PFSENSE_CA_BUNDLE` is readable at startup and exits with a clear message, since that is a configuration error worth failing loudly on.

`add_host_override_alias` first calls `find_host_name(alias_fqdn)` to reject an alias already used as a host override or alias anywhere, then resolves the parent host override — the override must already exist in pfSense; this service never creates one.

Response-derived values are escaped with `sanitize_for_log()` before they reach a log call, same as any other externally supplied value — an API response is untrusted input for logging purposes just as much as for payload shape. The "already mapped to" warning reads the matched override's `host`/`domain` with `.get()`, not indexing: `find_host_name` returns a host override whenever one of its *aliases* matches, regardless of that override's own keys, so an override missing `host`/`domain` used to raise `KeyError` straight out of this module.

### Configuration parsing quirks

- `PFSENSE_VERIFY_SSL` is true unless it lowercases to exactly `"false"` (fail-secure). `ADD_ALIASES_ON_STARTUP` is false unless it lowercases to `"true"`.
- The `pfsense.dns.remove_on_stop` label must be the exact lowercase string `"true"` — case-sensitive, unlike the env vars. There is a test pinning this.
- `PFSENSE_CA_BUNDLE` wins over `PFSENSE_VERIFY_SSL`: `verify_ssl = ca_bundle if ca_bundle else verify_ssl`, and the result is passed straight to `requests`' `verify=`.
- Startup sync is additive only — it never prunes stale aliases. It stages every alias and applies once at the end; see "Mutations are staged, then applied".

### Validation and logging constraints

There are two injection barriers, not one, and they guard different things:

- `_split_fqdn` requires ≥2 non-empty labels each matching `DNS_LABEL_PATTERN`, **and** rejects any value over `MAX_FQDN_CHARS` (253, RFC 1035's presentation-format bound). The length check is placed before `fqdn.split('.')`, not after — the intent is that a multi-kilobyte label-supplied value is rejected without first being exploded into thousands of labels. That ordering is a deliberate placement, not a tested contract: every test passes whether the check runs before or after the split, because there is no honest way to assert it (you cannot monkeypatch `str.split`, and a timing assertion would be flaky). It is defended by review and by the code comment at the check itself, the same way the `exc_info` assumption below is. There is deliberately no separate label-count cap: 253 characters already bounds the count at 127 by construction (`DNS_LABEL_PATTERN` only bounds a single label at 63). The rejection message contains the literal phrase `exceeds 253 characters`, distinct from the two existing "Invalid FQDN" messages, so a test can tell which branch fired. One rule guards both directions: `del_host_override_alias` routes its FQDN through the same `_split_fqdn` — indirectly, via `find_host_name` and `find_alias_in_host_override`, so grepping its body for `_split_fqdn` finds nothing — and an over-long alias created before this bound existed (or by hand in the webGUI) can therefore no longer be **removed** by this service either. That remains an accepted regression rather than a bug, but not for the reason first recorded here.

**An over-long alias is not inert, and that changes how urgent the remedy is — measured 2026-08-07 on the test VM (pfSense CE 2.7.2, pfRest v2.4.3).** This file used to call such a name "unresolvable dead config". It is not. With a 255-character alias FQDN, `unbound-checkconf` fails (`Domainname length overflow`, then `fatal error: failed local-zone, local-data configuration`), and the reload pfSense actually runs, `services_unbound_configure()`, leaves **unbound not running at all** — so every name on the firewall stops resolving, not just this one. Deleting the alias and reloading recovers fully. Three details make it worse than the bare failure suggests: pfRest accepts the over-long alias with a `200` and does not validate length, so before `MAX_FQDN_CHARS` existed a container label alone was enough to do this; `POST /dns_resolver/apply` returns 200 and the `GET /dns_resolver/apply` poll that `apply_changes()` depends on reports `data.applied: true` while unbound is dead, so our confirmation logic is structurally unable to notice; and this service cannot clean the alias up, because `del_host_override_alias` rejects the name too. Read `MAX_FQDN_CHARS` accordingly — it is an availability guard, not input hygiene, and it is what stands between a container label and a firewall-wide DNS outage. The remedy for an inherited over-long alias is still one delete in the webGUI, but it is urgent rather than cosmetic, and a `del_host_override_alias`-only exemption would reopen the hole for whatever caller uses it next. The reproduction is cheap if this ever needs re-checking: write the alias into `config.xml` with `config_set_path("unbound/hosts", ...)`, call `services_unbound_configure()`, and `test-env/vm.sh reset` undoes it in a second. `_split_fqdn` is the barrier between container labels and API **payloads**; route new FQDN-derived input through it before it reaches a request body.
- `sanitize_for_log()` (in `pfsense.py`, next to `DNS_LABEL_PATTERN`) is the barrier for **logs**. Every log call that interpolates an FQDN, a container name, an exception message, or any other externally supplied or API-derived value routes through it, with no "already validated" carve-out. Both barriers are needed together because the rejection branches — `_split_fqdn`'s own warnings, "Host override not found", "Alias not found" — log the very value they just rejected, before or without validation ever having run on it.
- `clean_alias_descr()` (in `pfsense.py`, next to `sanitize_for_log`) is the payload rule for **free-text fields** — today, the alias description. It is not a third injection barrier in the same sense as the two above; it replaces every non-printable character with a single space and truncates to `ALIAS_DESCR_MAX_CHARS` (255) with no marker, so a value that has passed through it is safe to store and display, not safe to reverse. It is deliberately not `sanitize_for_log`: escaping a newline to `\n` and appending `LOG_TRUNCATION_MARKER` would write log furniture into firewall config, which is a stored artifact an operator reads with no reason to suspect it means anything about provenance. This is also the reject-vs-clean asymmetry: a bad FQDN is rejected outright because a wrong name is a wrong DNS record, while a bad description is cleaned and the alias is still created because a wrong description is cosmetic — refusing to create working DNS over a chatty description would be the barrier causing the outage it exists to prevent. `add_host_override_alias` calls it when building the payload and logs one conditional warning when the cleaned value differs from the input, naming the alias FQDN so an operator knows which container to fix; `clean_alias_descr` itself stays pure and does not log.

**Why the reject/clean asymmetry is right, not just convenient — observed 2026-08-02 against `pfsense/pfsense@9363ac5b8651a1c7a333180425ce7719070f95f9` (then `master`), which this repo does not vendor. Re-read by 2027-08-02, or sooner if `clean_alias_descr`, `DNS_LABEL_PATTERN`, or `MAX_FQDN_CHARS` change.** We cannot vendor the file, but the citation below is pinned to that commit, not to "master" — a moving ref would be unresolvable the moment a reader is on a different branch or a later commit, which is exactly what happened to two citations inside PR #12 and is the same rot pointed at source we control even less this time. [`services_unbound.php#L568`](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/usr/local/www/services_unbound.php#L568) and `#L571` echo `$alias['host']` / `$alias['domain']` with no `htmlspecialchars()`. [`system.inc#L505-L515`](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/system.inc#L505-L515) concatenates that same `$alias['host']` and `$alias['domain']` into `$fqdn` and pushes it into the array `unbound_generate_zone_data()` consumes — so an **alias** name from a container label, not just a host override's own name, really does reach that function. Inside it, the `local-data:` family in [`unbound.inc`'s `unbound_generate_zone_data()`](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/etc/inc/unbound.inc#L827) writes that value into `unbound.conf` with no quoting or escaping in at least three places: `local-data-ptr:` (`#L842`), `local-zone:` in redirect mode (`#L854`), and `local-data:` (`#L856`). `DNS_LABEL_PATTERN`'s character allowlist — which forbids `"` and newline — is the only thing standing between a container label and one unescaped HTML sink plus these unescaped, double-quoted config directives on the firewall itself; hence strict, reject-don't-clean treatment for names. [`services_unbound.php#L578`](https://github.com/pfsense/pfsense/blob/9363ac5b8651a1c7a333180425ce7719070f95f9/src/usr/local/www/services_unbound.php#L578), by contrast, renders the description through `htmlspecialchars($alias['description'])` before display, which is why replace-with-space-and-cap is correct for `descr` and HTML-escaping it here would be a regression: `clean_alias_descr` escaping would double-escape and show the operator `&lt;script&gt;` instead of the literal text they wrote.

If a cited line number ever misses, grep the construct quoted above (`$alias['host']` echoed unescaped, `htmlspecialchars($alias['description'])`, the `local-data`/`local-data-ptr`/`local-zone` strings in `unbound_generate_zone_data()`) rather than concluding the record is wrong — a shifted line number means a row got added above it, not that the asymmetry changed. Only one direction of drift is dangerous: if upstream ever *starts* escaping names, nothing here needs to change; if upstream ever *stops* escaping the description, `clean_alias_descr` becomes insufficient and `descr` needs the same strict treatment as a name. Neither drift is detectable from this repo, and the dangerous one is the one we cannot see — which is why this paragraph carries a re-read horizon instead of standing as an undated assertion nobody has reason to doubt. Keep the abstract reason (a wrong name is a wrong DNS record; a wrong description is cosmetic) alongside this source-derived one — the abstract reason survives upstream churn that this observation does not.

`sanitize_for_log()` escapes every non-printable character (`\n`, `\r`, `\t`, control characters, the U+2028/U+2029 line separators, and a literal backslash so the mapping stays injective) so a hostile value cannot fabricate a log record, then truncates to `LOG_VALUE_MAX_CHARS` (512) with `LOG_TRUNCATION_MARKER`. Escape before truncating, not the reverse — truncating a long run of control characters first would let it expand several-fold on escaping. The cap is **per value, not per message**: a message that interpolates two sanitized values is bounded at roughly `2 * LOG_VALUE_MAX_CHARS`, not at `LOG_VALUE_MAX_CHARS` overall. Capping the whole message would make one value's rendering depend on its neighbours and would break the exact-wording guarantee below. On any printable-ASCII value under 512 characters — every value in every test written before this barrier existed — the function is the identity, which is why no existing log-wording assertion moved when it was introduced; `test_valid_fqdn_log_wording_is_unchanged` pins that a clean FQDN renders unchanged, guarding against `repr()`/`!r` quoting being reintroduced later.

Sanitization applies to the **log call only**. It must never touch the value passed to `_split_fqdn` or written into an API payload — doing so would silently corrupt the alias pfSense actually creates.

**The trust-boundary rule, stated so it needs no judgment to apply:** sanitize every value that crosses a trust boundary into a log — container labels, container names, Docker API objects, pfSense API responses, and the exception strings derived from either. Do not sanitize values supplied by whoever configures and runs the service; that actor already owns the process, so escaping defends against nobody.

**Exclusions.** The mandated grep hits these; they are intended.

- **Values supplied by whoever configures and runs the service** — `get_positive_float_env`'s two "Ignoring…" warnings, the `PFSENSE_CA_BUNDLE` "is not readable" critical, and `PFSense.__init__`'s "pfSense host set to". That actor already owns the process, so escaping defends against nobody.
- **Values this service authored** — code literals such as `get_env_var`'s variable name; numbers from our own arithmetic such as `_handle_api_error`'s HTTP status code and `flush_pending_changes`'s coalesced count and reason.
- **The provable no-ops** described below.

Anything outside these three classes is a finding.

Any `sanitize_for_log` call on a value that has already passed `_split_fqdn` is a provable no-op today and cannot be pinned by a test. Since `_split_fqdn` added the `MAX_FQDN_CHARS` bound, this is a no-op for **truncation as well as escaping**: a value that passed the split is bounded at 253 characters, which is under `LOG_VALUE_MAX_CHARS` (512), so `sanitize_for_log` can neither truncate it nor (on an already-validated, pattern-matched FQDN) find anything to escape. This is why the maximal-FQDN test (`test_a_maximal_length_fqdn_reaches_the_payload_byte_for_byte`) asserts a validated 253-character value renders in the log and reaches the payload with no truncation marker anywhere — the old test that pinned this shape at an arbitrary large size was retargeted to the new length boundary, since sizes above it are now rejected before either call site runs. These calls exist so that a future edit which moves a log line above its validation — the exact shape of the log-forgery finding — is harmless by construction. Do not remove them as dead code.

This no-op has a cost, and it is actionable rather than merely a lament: because a post-`_split_fqdn` value is provably identity under `sanitize_for_log`, a mutated payload line such as `'host': sanitize_for_log(alias_host)` passes the entire suite today — there is no test that a name-derived payload field is the raw value and not its log-rendered form, because none is currently needed. Any change that raises `MAX_FQDN_CHARS` above `LOG_VALUE_MAX_CHARS`, or widens `DNS_LABEL_PATTERN` to admit a character `sanitize_for_log` would escape, reopens this gap and simultaneously re-enables the test that would have caught it; such a change must add back a payload-versus-log distinguishing test in the same PR, not merely note the gap closed. This is the second review-defended, no-test property recorded in this file (the first is the `exc_info` assumption below); a third should prompt a harder look at whether the design is drifting out of what the suite can reach.

**The `exc_info` assumption, made visible rather than fixed.** `_handle_error` logs with `exc_info=True`, and the formatter re-emits the exception text in the traceback tail **unescaped**. The escape on the message line does not cover it. That is safe only while no exception reaching `_handle_error` carries container-supplied text — today none does; `docker.errors.NotFound` is logged as a warning without `exc_info`. Wrapping label parsing or event handling in a broad `except` that funnels into `_handle_error` re-opens the log-forgery finding, or adding a new `_handle_error` call site whose exception can carry container-supplied text. Do not flatten the traceback to fix this; the traceback is the diagnostic, and `test_handle_error_escapes_the_message_but_keeps_the_traceback` pins that it stays multi-line and unescaped while the message line is escaped.

`test_handle_error_escapes_the_message_but_keeps_the_traceback` asserts through `record.getMessage()`, which structurally excludes `exc_info`. The property that makes that test correct also means a green suite is not evidence the traceback is clean. This finding is defended by review, not by test.

Never log API tokens, secrets, full authorization headers, sensitive environment values, or API response bodies. `_handle_api_error` logs the exception and status code but not `response.text`, and `test_http_error_logs_status_without_response_body` enforces it.

**Redirects are never followed, and a redirect fails the call.** `_request` passes `allow_redirects=False`, and treats `response.is_redirect` as a failure that returns `None` without retrying. Both halves are required and neither is a preference. `requests` strips only the `Authorization` header when a redirect crosses to another host — every other header is re-sent, and this service authenticates with a custom `X-API-Key`, so a `302` from the firewall's web tier would hand a live firewall credential to whatever host the `Location` names, including a plain `http://` one in cleartext, *even with verification enabled*, because the downgrade happens after the handshake with the original host. Failing the call is the second half because `raise_for_status()` treats 3xx as success: a followed-through redirect would otherwise be recorded as a landed mutation, setting `unapplied_changes` for a change that never reached pfSense. Every endpoint here is an exact `/api/v2/...` path, so a redirect is a misconfiguration rather than a transient fault — hence no retry. `test_requests_never_follow_redirects` and `test_a_redirect_is_treated_as_a_failure_not_a_success` pin the two halves, and the `applied_status_get` helper names `allow_redirects` in its signature for the same reason it names `verify`: so dropping it is a `TypeError` at every call site rather than a silent regression.

**An exception message can carry the token, so two exception types are never logged.** `requests` validates header values and raises `requests.exceptions.InvalidHeader` with **the offending value embedded in the message**. The only header this service sets is `X-API-Key`, so logging that message printed the API token in cleartext — on every call, since the request fails identically each time, flooding the log and anything downstream of it with a credential that can rewrite firewall DNS. `sanitize_for_log` does not help: it escapes the newline and renders the token characters as they are. `_handle_api_error` therefore returns early for `InvalidHeader` **and `UnicodeEncodeError`** with a fixed message that names `PFSENSE_API_TOKEN` and prints no value. Do not "improve" that branch by including the exception text. `UnicodeEncodeError` is the second one because HTTP header values are encoded as latin-1: a *printable* character outside that range — a euro sign, a smart quote pasted from formatted text — clears the startup printability check and then fails inside `http.client` with a message naming a character **of the token** and its exact index. `main.py` now also rejects a token that will not encode as latin-1, which is the condition the transport actually imposes; `isprintable()` alone was the wrong test.

There are two layers, and the outer one is why the inner is rarely reached. `main.py` **trims surrounding whitespace from `PFSENSE_API_TOKEN`** at startup, because a trailing newline is what `$(cat /run/secrets/token)` and a file-based Kubernetes secret both produce, and no API token has meaningful surrounding whitespace — trimming turns the common misconfiguration into a working deployment rather than a loud failure with a secret attached. What survives trimming and is still non-printable (an embedded line break in a pasted token) exits 1 at startup, naming the variable and never the value. The documented deployment paths happened to mask this — `docker run --env-file` strips a trailing `\r` and `docker compose` strips a leading space from a `.env` value — which is exactly why it went unnoticed.

`_handle_api_error`'s status-code branch requires `error.response is not None`. That is load-bearing, not defensive noise: the function runs inside an `except` block, so an `AttributeError` there escapes `_request`'s handler, escapes `_mutate_alias`'s, and reaches `run()`'s broad handler, which exits the process — inverting the contract that an API failure logs and returns `False` rather than killing the service.

`_handle_api_error` also logs one extra line for a `requests.exceptions.SSLError`, naming `PFSENSE_CA_BUNDLE` and `PFSENSE_VERIFY_SSL`. This exists because verification defaults to on while this service's own `v0.1.x` never verified at all, so an upgrading operator meets a certificate error naming a setting they have no reason to know exists. Two properties are deliberate. The hint is **added to** the underlying error, never a replacement for it — the cause matters when the failure is expiry or a hostname mismatch rather than an untrusted issuer. And it keys on `SSLError` specifically, **not** its `ConnectionError` parent: advice to consider switching verification off must not print every time the firewall is briefly unreachable, which is how a fail-secure default gets disabled for an unrelated reason. `test_an_ordinary_connection_error_does_not_suggest_disabling_tls` pins that boundary; widening the check to `ConnectionError` fails it.

## Branching and pull requests

`main` is protected: it takes no direct pushes. All work lands through a pull request that squash-merges into one commit, so `main` stays linear.

1. Branch from an up-to-date `main`: `git switch main && git pull && git switch -c type/short-description`. Use `feat/`, `fix/`, `chore/`, `docs/`, or `refactor/` as the prefix.
2. Commit as you go — messy branch commits are fine, squash collapses them.
3. Before pushing, run the compile, lint, audit, test, and build commands from **Commands** above. CI runs the same checks, so running them locally just saves a round trip.
4. Push and open a PR: `git push -u origin HEAD && gh pr create`. Say what changed and why, and note anything you deliberately did not do.
5. Wait for review. Do not merge on the author's behalf unless explicitly asked — the PR exists so a human sees the change before it lands.

Never commit directly to `main`, and never force-push a branch that is under review. If work is already sitting uncommitted on `main`, move it to a branch (`git switch -c type/short-description`) rather than committing it in place.

## Agents and the test-ownership contract

`.claude/agents/` defines six subagents. They exist to keep the invariants above from eroding, so they are committed and reviewed like code — when an invariant changes, the agent that enforces it changes in the same PR.

| Agent | Model | Role |
|---|---|---|
| `planner` | Opus | Designs the change, states the test contract, adjudicates test disputes |
| `tester` | Opus | Writes failing tests first; owns `tests/` |
| `implementer` | Sonnet | Writes production code to satisfy those tests |
| `reviewer` | Opus | Correctness review; audits the contract below |
| `security-reviewer` | Opus | Token, TLS, injection barrier, Docker socket |
| `dependency-triage` | Sonnet | Validates Dependabot PRs locally |

The intended order for a behavior change is **planner → tester → implementer → reviewer**, with `security-reviewer` added whenever the change touches `pfsense.py`, TLS, logging, dependencies, or the Docker/CI surface.

**The contract:** the tester owns everything under `tests/`. The implementer may not create, edit, or delete those files — not to fix a failure, not to soften an assertion, not to add a skip. When the implementer believes a test encodes the wrong requirement it escalates to the planner, which rules one of three ways: the test is right and the implementation must change (the default), the test is wrong and the *tester* revises it, or the plan was ambiguous and the plan changes first. Difficulty satisfying a test is not evidence that the test is wrong.

This matters here because the assertions are deliberately precise — `tests/test_pfsense.py` pins exact `requests` call sequences and kwargs, which is what makes a dropped `/apply` call or a weakened TLS `verify` fail loudly instead of silently. An implementer that can edit the test can erase the safety net rather than satisfy it.

The reviewer enforces this by checking `git diff main...HEAD -- tests/` and confirming any change there traces to a planner ruling. A human working directly is bound by the same rule: change tests deliberately, as a decision, not as a way to get to green.

## Working rules

- Make small, reviewable changes.
- Preserve Docker-based deployment.
- Keep configuration environment-variable driven.
- Treat pfSense API credentials as sensitive.
- Prefer clear error handling around Docker API calls, pfSense API calls, network failures, and malformed labels.
- Run the compile, test, lint, and build commands above after the changes they cover.
- Runtime dependencies are pinned in `requirements.txt`; do not introduce new ones unless explicitly approved.
- The `Dockerfile` copies only `main.py`, `pfsense.py`, and `requirements.txt` — a new runtime module needs a matching `COPY`.
- Keep `README.md`, `docker-compose.yaml`, and `.env.example` aligned with the actual code when env vars or labels change. All three list the settings, so a new variable that lands in only one of them is the normal way this drifts. `.env.example` is the tracked template; `.env` itself is gitignored (`.env`, `.env.*`, with `!.env.example` re-including the template) because the documentation tells operators to keep `PFSENSE_API_TOKEN` there. Do not weaken that negation — a token committed once is a token to rotate on the firewall.

## Style

- Prefer straightforward Python.
- Avoid over-engineering.
- Use explicit names and boring control flow.
- Keep log messages useful but not noisy.

## Release rules

- Document user-facing behavior changes.
- Note changed environment variables, labels, or compose examples.
- Keep release notes in plain Markdown.
