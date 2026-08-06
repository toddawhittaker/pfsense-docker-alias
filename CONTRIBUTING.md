# Contributing

Thanks for helping out. This file covers how to get set up, what has to pass
before a pull request, and how to test a change against a real pfSense.

`AGENTS.md` is the deeper reference: it explains *why* the failure semantics,
injection barriers and coalescing behave the way they do. Read it before
changing any of them. This file does not repeat it.

## Getting set up

The project is two Python modules with no framework and no package layout.
Python 3.14 matches CI and the runtime image.

```bash
uv venv --python 3.14
uv pip install -r requirements.txt -r requirements-dev.txt
```

## Before you open a pull request

Run these from the repository root. CI runs the same checks, so running them
locally just saves a round trip.

```bash
.venv/bin/python -m py_compile main.py pfsense.py
.venv/bin/python -m pytest --cov --cov-report=term-missing
.venv/bin/python -m pylint main.py pfsense.py
.venv/bin/python -m pip_audit -r requirements.txt --strict
.venv/bin/python -m pip_audit -r requirements-dev.txt --strict
docker build -t pfsense-docker-alias .
```

Run pytest as `python -m pytest`, not bare `pytest`. There is no `conftest.py`
or `pyproject.toml`; `main` and `pfsense` are importable only because `python -m`
puts the working directory on `sys.path`.

A few of these fail in ways worth understanding rather than working around:

- **pylint must stay at 10.00/10.** Suppress with a narrow local
  `# pylint: disable=` pragma when genuinely warranted, never with a config file.
- **Coverage is gated at 80%** and currently sits near 99%. The gate is a floor
  against regression, not a target. Never write a test purely to move the
  number; if something genuinely cannot be covered, exclude it with
  `# pragma: no cover` and say why.
- **`pip-audit --strict` can turn CI red with no code change**, because a new
  CVE was disclosed in a pinned dependency. Fix it by bumping the pin. This
  service ships TLS calls and an API token, and `certifi` is its trust store.

## Branching and pull requests

`main` is protected and takes no direct pushes. Everything lands through a pull
request that squash-merges into one commit.

1. Branch from an up-to-date `main`, prefixing with `feat/`, `fix/`, `chore/`,
   `docs/` or `refactor/`.
2. Commit as you go. Messy branch commits are fine — the squash collapses them.
3. Run the checks above.
4. `git push -u origin HEAD && gh pr create`. Say what changed and why, and note
   anything you deliberately did not do.
5. Wait for review. Don't merge your own pull request unless asked to.

Never force-push a branch that is under review.

## Tests are owned by whoever wrote them

The assertions in `tests/` are deliberately precise. `tests/test_pfsense.py`
pins exact `requests` call sequences and keyword arguments, which is what makes
a dropped `/apply` call or a weakened TLS `verify` fail loudly instead of
silently.

So changing a test is a decision, not a way to get to green. If a test seems to
encode the wrong requirement, say so and get agreement before touching it.
Difficulty satisfying a test is not evidence that the test is wrong. Reviewers
check `git diff main...HEAD -- tests/` for exactly this.

If you are working through the agent workflow described in `AGENTS.md`, this is
a hard rule: the implementer may not edit `tests/` at all, and only the planner
can approve a change to a test the tester already wrote.

## Testing against a real pfSense

The unit suite stubs both Docker and the pfSense API. That is what makes it fast
and precise, but it also means it can only confirm the client matches *our own
idea* of the API. It cannot tell you whether a change actually reaches unbound,
whether a payload field lands where pfSense reads it, or whether a name really
resolves afterwards.

For that, `test-env/` builds a throwaway pfSense virtual machine with the REST
API package installed:

```bash
test-env/bootstrap.sh    # about ten minutes, roughly 6 GB of disk
test-env/smoke.sh        # run the service against it and assert end to end
```

`smoke.sh` starts the service, starts a labelled container, and asserts that the
alias appears, resolves to the right address through the firewall's own
resolver, disappears when the container stops, and that the service is still
running at the end. `test-env/vm.sh reset` rolls back to a clean snapshot in
about a second, so runs are repeatable.

This needs KVM and cannot run on GitHub's runners, so it is not part of CI. It
is worth doing by hand for any change that touches `pfsense.py`, the apply and
coalescing logic, or anything about what actually goes into an API payload.

`test-env/README.md` covers the scripts, the pinned versions, and the handful of
things that will bite you. Two are worth knowing before you start:

- Every request from the host reaches pfSense from a single address, so its
  brute-force protection can lock out SSH, the webGUI and the REST API all at
  once while the serial console still looks healthy. `bootstrap.sh` whitelists
  that address, but it is the first thing to suspect if everything goes quiet.
- Containers cannot reach the VM through QEMU's port forwarding directly; run
  `test-env/relay.sh start` first. `smoke.sh` does this for you.

There is also a much cheaper check that needs no pfSense at all — point the
service at an unresolvable host and watch the retry and failure path, confirming
it logs and keeps running rather than crashing. `AGENTS.md` has the commands
under "Manual end-to-end check".

## House style

- Straightforward Python. Explicit names, boring control flow, no
  over-engineering.
- Keep configuration environment-variable driven, and keep Docker-based
  deployment working.
- Treat pfSense API credentials as sensitive. Never log tokens, authorization
  headers or API response bodies.
- Runtime dependencies are pinned in `requirements.txt`. Don't add one without
  agreement first.
- The `Dockerfile` copies only `main.py`, `pfsense.py` and `requirements.txt`. A
  new runtime module needs a matching `COPY`, or the image builds cleanly and
  dies at import.
- Keep `README.md` and `docker-compose.yaml` aligned with the code when
  environment variables or labels change.
