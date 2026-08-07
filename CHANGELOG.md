# Changelog

This project uses semantic versioning. It is still on `0.x`, which means a minor
release may contain breaking changes — and `v0.2.0` does.

## v0.2.0 — 2026-08-07

The first release since `v0.1.2` (January 2025). Read the breaking changes before
upgrading, especially if you pull the `latest` tag.

### Breaking changes

**1. TLS certificate verification is now on by default.**

`v0.1.2` sent every request to pfSense with certificate verification disabled, with
no way to turn it on. This release verifies by default. Most pfSense installations
use a self-signed certificate, so if yours does, **every API call will fail after
upgrading** until you choose one of the following.

The failure is not silent. The service logs the underlying cause and then names both
settings:

```
ERROR - API call failed during 'get_all_host_overrides': ... certificate verify failed: self-signed certificate
ERROR - TLS certificate verification failed. Mount a CA bundle and set PFSENSE_CA_BUNDLE
        to its path inside the container, or set PFSENSE_VERIFY_SSL=false to skip
        verification entirely, which exposes the API token to anyone able to intercept
        the connection.
```

To keep verification on — recommended — export your pfSense CA certificate, mount it,
and point `PFSENSE_CA_BUNDLE` at it:

```yaml
environment:
  PFSENSE_CA_BUNDLE: "/etc/ssl/certs/pfsense-ca.pem"
volumes:
  - ./pfsense-ca.pem:/etc/ssl/certs/pfsense-ca.pem:ro
```

To restore the old behaviour instead, set `PFSENSE_VERIFY_SSL=false`. This is what
`v0.1.2` did on every request, but understand the trade: this service authenticates
with a pfSense API token, so anyone able to intercept the connection can present any
certificate and collect that token.

**2. Alias and host override names are capped at 253 characters.**

Names longer than RFC 1035's limit are now rejected with a warning instead of being
sent to pfSense. Each dot-separated label is also capped at 63 characters and limited
to letters, digits, and hyphens.

If an over-long alias already exists in pfSense from an earlier version of this
service, **delete it in the pfSense webGUI**, and do not wait. Such an entry is not
harmless leftover config: it makes `unbound-checkconf` fail, so the DNS resolver stops
on its next reload and every name on the firewall stops resolving. This service will
not remove the entry for you, because the same length rule that blocks creating one
also blocks removing it.

### Added

- `pfsense.dns.description` label, setting the alias description shown in the pfSense
  webGUI. Unprintable characters become spaces and the value is capped at 255
  characters.
- `PFSENSE_VERIFY_SSL` (default `true`) and `PFSENSE_CA_BUNDLE` (default unset) to
  control certificate verification. `PFSENSE_CA_BUNDLE` takes precedence. An
  unreadable bundle now stops the service at startup with a clear message rather than
  failing on every request.
- `APPLY_QUIET_SECONDS` (default `10`) and `APPLY_MAX_WAIT_SECONDS` (default `60`) to
  tune how container-event bursts are batched.
- `.env.example`, a documented template for every supported setting. Copy it to `.env`
  and fill it in; `docker compose` reads `.env` automatically. `.env` is now gitignored
  as well — the documentation has always told you to keep `PFSENSE_API_TOKEN` there,
  but nothing previously stopped that file from being committed.

### Fixed

- **A container started with `docker run --rm` now loses its alias when it stops.**
  Docker deletes such a container as it stops, and the service used to read its labels
  back from Docker at that moment. It usually lost that race: twenty containers
  stopping together left nineteen aliases behind. The alias configuration is now
  recorded when the container starts.
- **A burst of container events costs one resolver reload, not one per alias.** A
  `docker compose up` of twenty labelled services previously triggered twenty unbound
  reloads and roughly forty seconds of DNS disruption, with overlapping reloads a
  likely source of dropped updates. It now costs two. A single container start still
  applies immediately.
- **The startup scan applies once** rather than once per alias found.
- **A failed apply no longer strands changes.** A change that reached the pfSense
  configuration while its apply failed used to be forgotten, so nothing retried it and
  the alias never went live. Pending changes are now retried on a later event or at
  shutdown. This applies to the startup scan too: with `ADD_ALIASES_ON_STARTUP=true`,
  a failed startup apply used to leave every alias staged in the configuration with the
  resolver never reloaded, and nothing would retry on an idle host.
- **Applies are confirmed rather than assumed.** pfSense reloads asynchronously, so
  the request returns before the reload finishes. The service now polls until pfSense
  reports the change applied, and reports a failure if it never does.
- **Failed API calls are retried** up to three times for network-level errors.
- **A malformed or unexpected API response no longer stops the service.** An
  unrecognised response body used to raise straight out of the pfSense client and exit
  the container; it is now logged and skipped.
- **Container labels can no longer forge log records.** Externally supplied values are
  escaped before they reach a log message, so a newline in a label cannot fabricate a
  log line. Values are also length-capped.
- **A pfSense API error no longer logs the response body**, which could contain data
  not intended for the log.
- **The API token can no longer be written to the log.** If `PFSENSE_API_TOKEN` had a
  trailing newline or a leading space — what `$(cat /run/secrets/token)` and file-based
  Kubernetes secrets produce — `requests` rejected the header and raised an error with
  the token embedded in its message, which was then logged in cleartext on every single
  API call. Surrounding whitespace is now trimmed at startup, so those tokens simply
  work; anything still malformed exits at startup naming the variable but never the
  value; and that class of error is never logged with its message.
- **Redirects are no longer followed, and a redirected call fails.** `requests` strips
  only the `Authorization` header across a cross-host redirect, so this service's
  `X-API-Key` was being re-sent — a redirect from the firewall's web tier could hand a
  live API token to another host, including over plain HTTP, even with certificate
  verification enabled. pfSense's API does not redirect, so a redirect is now treated
  as a misconfiguration and the call is abandoned.
- **The service survives a SIGTERM with work in flight**, flushing staged changes
  before exit.

### Changed

- Base image moved from `python:3.12-alpine` to `python:3.14-alpine`.
- **pip is removed from the runtime image.** Nothing at run time used it, and it carried
  a vendored dependency manifest that image scanners flagged for packages unreachable
  here — one of them, `setuptools`, was not even installed. The image now scans clean,
  and a container that mounts the Docker socket no longer ships a package installer.
  If you were running `pip` inside this container, it is no longer present.
- The published image is now the exact image CI smoke-tested, rather than a rebuild
  of it, and `:latest` moves only for a plain `vX.Y.Z` tag. A pre-release such as
  `v0.3.0-rc1` publishes under its own tag and leaves `:latest` untouched, so tracking
  `:latest` will not put you on a release candidate.
- Runtime dependencies updated; the pinned set is free of known CVEs as of this
  release, and CI fails on any new advisory.
- Added `CONTRIBUTING.md` and `test-env/`, which builds a throwaway pfSense VM so
  changes can be tested end to end against a real firewall.

## v0.1.2 and earlier

Not documented here. See the commit history.
