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
.venv/bin/python -m pytest                          # full suite (31 tests)
.venv/bin/python -m pytest tests/test_main.py::test_parse_alias_labels_returns_alias_config   # single test
.venv/bin/python -m pylint main.py pfsense.py       # must stay at 10.00/10
.venv/bin/python -m pip_audit -r requirements.txt --strict       # no known CVEs allowed
.venv/bin/python -m pip_audit -r requirements-dev.txt --strict

docker build -t pfsense-docker-alias .              # required after changing Docker-related files
```

Run pytest as `python -m pytest` from the repo root. There is no `conftest.py`, `pyproject.toml`, or package layout — `main` and `pfsense` are importable only because `python -m` puts the CWD on `sys.path`. Bare `pytest` fails collection with `ModuleNotFoundError: No module named 'pfsense'`.

`pylint` must stay at 10.00/10 — CI fails on any message. Suppressions are local `# pylint: disable=` pragmas at the narrowest scope that works, never a config file: `logging-fstring-interpolation` module-wide in both modules (the codebase logs with f-strings by convention), and `too-many-return-statements` on `add_host_override_alias`, whose seven returns are deliberate guard clauses.

`actionlint` checks the workflow files and is not a pip package — download it when you need it. It shells out to `shellcheck` for `run:` blocks **only if shellcheck is on `PATH`**, and GitHub runners have it while a plain dev box usually does not. Local actionlint without shellcheck is therefore weaker than CI and will miss shell issues that fail the build; install shellcheck before trusting a local pass.

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

CI (`.github/workflows/docker-publish.yml`) runs on every PR and push to `main`: actionlint → compile → pylint → pip-audit → pytest → `docker build` → two container smoke tests. The smoke tests run the built image and assert it exits 1 with a config error when unconfigured, then boots and reaches its event loop when configured. They exist because `docker build` cannot catch a runtime module missing its `COPY` — that image builds cleanly and dies at import. The ghcr.io publish job runs only on tag pushes.

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

### Mutations are always two calls

`add_host_override_alias` and `del_host_override_alias` each perform the mutation, then POST to `/dns_resolver/apply`. Both must succeed to return `True`. Any new mutating method needs the same apply step.

`add_host_override_alias` first calls `find_host_name(alias_fqdn)` to reject an alias already used as a host override or alias anywhere, then resolves the parent host override — the override must already exist in pfSense; this service never creates one.

### Configuration parsing quirks

- `PFSENSE_VERIFY_SSL` is true unless it lowercases to exactly `"false"` (fail-secure). `ADD_ALIASES_ON_STARTUP` is false unless it lowercases to `"true"`.
- The `pfsense.dns.remove_on_stop` label must be the exact lowercase string `"true"` — case-sensitive, unlike the env vars. There is a test pinning this.
- `PFSENSE_CA_BUNDLE` wins over `PFSENSE_VERIFY_SSL`: `verify_ssl = ca_bundle if ca_bundle else verify_ssl`, and the result is passed straight to `requests`' `verify=`.
- Startup sync is additive only — it never prunes stale aliases.

### Validation and logging constraints

`_split_fqdn` requires ≥2 non-empty labels each matching `DNS_LABEL_PATTERN`; it is the injection barrier between container labels and API payloads. Route new FQDN-derived input through it.

Never log API tokens, secrets, full authorization headers, sensitive environment values, or API response bodies. `_handle_api_error` logs the exception and status code but not `response.text`, and `test_http_error_logs_status_without_response_body` enforces it.

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
- Keep `README.md` and `docker-compose.yaml` aligned with the actual code when env vars or labels change.

## Style

- Prefer straightforward Python.
- Avoid over-engineering.
- Use explicit names and boring control flow.
- Keep log messages useful but not noisy.

## Release rules

- Document user-facing behavior changes.
- Note changed environment variables, labels, or compose examples.
- Keep release notes in plain Markdown.
