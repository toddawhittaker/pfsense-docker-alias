"""
pfSense Docker Alias Updater

This script listens for Docker container start/stop events and dynamically updates
DNS aliases in pfSense based on labels defined in the container configuration.
"""

import os
import sys
import time
import signal
import logging
import docker
import pfsense

# pylint: disable=logging-fstring-interpolation

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

LABEL_DNS_OVERRIDE = "pfsense.dns.override"
LABEL_DNS_ALIAS = "pfsense.dns.alias"
LABEL_DNS_DESCRIPTION = "pfsense.dns.description"
LABEL_DNS_REMOVE_ON_STOP = "pfsense.dns.remove_on_stop"

def _handle_error(error, context=""):
    """
    Logs detailed information about errors.
    :param error: The exception raised.
    :param context: Additional context about the function or operation.
    """
    logger.error(f"Error in {context}: {pfsense.sanitize_for_log(error)}", exc_info=True)

def get_env_var(var_name):
    """Fetch an environment variable and exit if it is not set."""
    value = os.getenv(var_name)
    if not value:
        logger.critical(f"Required environment variable '{var_name}' is not set.")
        sys.exit(1)
    return value

def get_positive_float_env(var_name, default):
    """Read a positive float environment variable, falling back to default if unusable."""
    raw = os.getenv(var_name)
    if raw is None:
        return default

    try:
        value = float(raw)
    except ValueError:
        logger.warning(f"Ignoring invalid {var_name}='{raw}'; using {default}.")
        return default

    if value <= 0:
        logger.warning(f"Ignoring non-positive {var_name}='{raw}'; using {default}.")
        return default

    return value

PFSENSE_HOSTNAME = get_env_var("PFSENSE_HOSTNAME")
# Trim surrounding whitespace from the token. A trailing newline is what
# `$(cat /run/secrets/token)` and a file-based Kubernetes secret both produce, and a
# leading space is an easy compose typo. requests rejects a header value with either,
# raising InvalidHeader with the value embedded in its message -- which is how the token
# used to end up in the log. No API token has meaningful surrounding whitespace, so
# trimming makes the common misconfiguration simply work instead of failing loudly with
# a secret attached. A token malformed some other way is caught below.
PFSENSE_API_TOKEN = get_env_var("PFSENSE_API_TOKEN").strip()
if not PFSENSE_API_TOKEN:
    logger.critical("PFSENSE_API_TOKEN is set but contains only whitespace.")
    sys.exit(1)
if any(not character.isprintable() for character in PFSENSE_API_TOKEN):
    # Never name the value here, only the variable -- reporting a malformed secret must
    # not print it. Trimming above has already removed surrounding whitespace, so what
    # is left is embedded, e.g. a line break in the middle of a pasted token.
    logger.critical(
        "PFSENSE_API_TOKEN contains non-printable characters, such as an embedded "
        "line break. Check how the value is being set. It is not logged."
    )
    sys.exit(1)
PFSENSE_VERIFY_SSL = os.getenv("PFSENSE_VERIFY_SSL", "true").lower() != "false"
PFSENSE_CA_BUNDLE = os.getenv("PFSENSE_CA_BUNDLE")
if PFSENSE_CA_BUNDLE and not os.access(PFSENSE_CA_BUNDLE, os.R_OK):
    # Fail loudly at startup rather than on every request. An unreadable bundle used to
    # surface as an opaque crash loop, which nudged operators toward disabling TLS
    # verification instead of fixing the mount.
    logger.critical(
        f"PFSENSE_CA_BUNDLE '{PFSENSE_CA_BUNDLE}' is not readable. "
        "Check that the CA bundle is mounted into the container at that path."
    )
    sys.exit(1)
ADD_ALIASES_ON_STARTUP = os.getenv("ADD_ALIASES_ON_STARTUP", "false").lower() == "true"
# Coalescing: a burst of container events (a compose up) should cost one reload, not
# one per container. The first change in a quiet period still applies immediately so a
# lone container start is as fast as it ever was.
APPLY_QUIET_SECONDS = get_positive_float_env("APPLY_QUIET_SECONDS", 10.0)
APPLY_MAX_WAIT_SECONDS = get_positive_float_env("APPLY_MAX_WAIT_SECONDS", 60.0)
# How often the event loop regains control to check whether a flush is due.
EVENT_WINDOW_SECONDS = 2.0

# Coalescing state. Elapsed time uses a monotonic clock so a wall-clock adjustment
# cannot strand pending changes.
PENDING_CHANGES = 0
PENDING_SINCE = None
LAST_CHANGE_AT = None
LAST_APPLY_AT = None

# Alias configuration recorded when a container is first seen, keyed by container ID.
# Handling a stop used to depend on reading the container's labels back from Docker,
# which fails for a container run with `docker run --rm`: Docker can delete it before
# the stop event is handled, and the alias was then left behind. Twenty such containers
# stopped together left nineteen aliases orphaned.
KNOWN_ALIASES = {}
# Container IDs are never reused, so nothing here can be evicted by a later start of
# the same container and the table would otherwise grow for the life of the process.
# Entries are also deliberately not dropped on stop: Docker sends both `die` and `stop`
# for one shutdown, and the second event must find the same answer as the first.
KNOWN_ALIASES_MAX = 512

# Initialize Docker client
try:
    client = docker.from_env()
except docker.errors.DockerException as e:
    logger.critical(f"Error initializing Docker client: {pfsense.sanitize_for_log(e)}")
    sys.exit(1)

def add_aliases_on_startup():
    """
    Scan all existing Docker containers and add their aliases if not already added.

    Aliases are staged individually and applied once at the end. Applying per alias
    reloads unbound every time, which takes seconds each and can drop updates when
    reloads overlap.
    """
    logger.info("Scanning existing Docker containers for aliases to add...")
    try:
        containers = client.containers.list()
    except docker.errors.DockerException as e:
        _handle_error(e, "add_aliases_on_startup")
        return

    labeled = 0
    staged = 0

    for container in containers:
        labels = get_container_labels(container)
        alias_config = parse_alias_labels(labels)

        if not alias_config:
            continue

        labeled += 1
        # A container already running when this service starts never produces a start
        # event, so this scan is the only chance to record it for a later stop.
        remember_alias_config(container.id, container.name, alias_config)
        logger.info(
            f"Staging alias '{pfsense.sanitize_for_log(alias_config['alias_fqdn'])}' "
            f"for container '{pfsense.sanitize_for_log(container.name)}'"
        )
        if NAMESERVER.add_host_override_alias(
            alias_config["host_override_fqdn"],
            alias_config["alias_fqdn"],
            alias_config["alias_descr"],
            apply=False
        ):
            staged += 1

    if not labeled:
        logger.info("No aliases found during startup.")
        return

    if not staged:
        logger.warning(
            f"Found {labeled} labeled container(s) but staged no aliases; nothing to apply."
        )
        return

    logger.info(f"Applying {staged} staged alias(es) in a single reload...")
    if not NAMESERVER.apply_changes():
        # Hand the staged changes to the coalescer so a later window tick or the
        # shutdown flush retries the apply. Logging alone left PENDING_CHANGES at 0, and
        # flush_pending_changes() returns at its guard when nothing is pending -- so on
        # an idle host nothing ever retried, and the aliases sat in the configuration
        # with unbound never reloaded. This is the same rule the event path follows:
        # what pfSense actually holds decides, not the return value.
        _record_staged(staged)
        logger.error(
            f"{staged} alias(es) are staged in the pfSense configuration but were not "
            "applied. They will take effect on the next successful apply."
        )

def cleanup(_signum, _frame):
    """Cleanup actions to perform when the script exits."""
    logger.info("Shutting down gracefully...")
    try:
        if NAMESERVER is not None:
            flush_pending_changes(force=True)
    except Exception as e: # pylint: disable=broad-except
        _handle_error(e, "cleanup")

    try:
        client.close()
    except docker.errors.DockerException as e:
        _handle_error(e, "cleanup")
    except Exception as e: # pylint: disable=broad-except
        _handle_error(e, "cleanup")
    sys.exit(0)

# Register signal handlers for graceful shutdown
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)

def get_container_labels(container):
    """Fetch labels from a Docker container."""
    try:
        return container.attrs['Config']['Labels'] or {}
    except (KeyError, TypeError):
        return {}

def parse_alias_labels(labels):
    """Return alias configuration from Docker labels, or None if labels are incomplete."""
    host_override_fqdn = labels.get(LABEL_DNS_OVERRIDE, None)
    if not host_override_fqdn:
        return None

    alias_fqdn = labels.get(LABEL_DNS_ALIAS, None)
    if not alias_fqdn:
        return None

    return {
        "host_override_fqdn": host_override_fqdn,
        "alias_fqdn": alias_fqdn,
        "alias_descr": labels.get(LABEL_DNS_DESCRIPTION, ''),
        "remove_on_stop": labels.get(LABEL_DNS_REMOVE_ON_STOP, None) == "true",
    }

def get_alias_event_action(event_action, labels):
    """Return the alias action and config for a Docker event, or None if no action applies."""
    alias_config = parse_alias_labels(labels)
    if not alias_config:
        return None

    if event_action == 'start':
        return "add", alias_config

    if event_action in ['stop', 'die'] and alias_config["remove_on_stop"]:
        return "remove", alias_config

    return None

def remember_alias_config(container_id, container_name, alias_config):
    """Record a container's alias configuration so a later stop does not need Docker."""
    KNOWN_ALIASES.pop(container_id, None)
    KNOWN_ALIASES[container_id] = (container_name, alias_config)
    while len(KNOWN_ALIASES) > KNOWN_ALIASES_MAX:
        # Dictionaries keep insertion order, so the first key is the oldest entry.
        KNOWN_ALIASES.pop(next(iter(KNOWN_ALIASES)))

def recall_alias_config(container_id, event_action):
    """
    Alias configuration recorded for a container Docker can no longer describe.

    Only a stop is answered from the record. A start event for a container that has
    already gone is genuinely nothing to act on, and treating it as a removal would
    delete an alias in response to the wrong event.
    """
    if event_action not in ['stop', 'die']:
        return None

    remembered = KNOWN_ALIASES.get(container_id)
    if remembered is None:
        return None

    _container_name, alias_config = remembered
    if not alias_config["remove_on_stop"]:
        return None

    return remembered

def _remove_alias_for(container_name, alias_config):
    """Log and dispatch the removal of a stopping container's alias."""
    logger.info(f"Container '{pfsense.sanitize_for_log(container_name)}' is stopping...")
    process_stop_event(alias_config["host_override_fqdn"], alias_config["alias_fqdn"])

def handle_container_event(event):
    """Handle a Docker container start/stop event."""
    container_id = event.get('Actor', {}).get('ID')
    if not container_id:
        logger.warning("Ignoring container event with missing container ID.")
        return

    event_action = event.get('Action')

    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound as e:
        # Expected for a container run with `--rm`, which Docker may delete before this
        # event is handled. Its labels are unreadable now, so fall back to what was
        # recorded when it started rather than leaving the alias behind.
        remembered = recall_alias_config(container_id, event_action)
        if remembered is None:
            logger.warning(f"Container not found: {pfsense.sanitize_for_log(e)}")
            return
        _remove_alias_for(*remembered)
        return
    except docker.errors.DockerException as e:
        _handle_error(e, "handle_container_event")
        return

    labels = get_container_labels(container)

    alias_action = get_alias_event_action(event_action, labels)
    if not alias_action:
        return

    action, alias_config = alias_action

    if action == "add":
        remember_alias_config(container_id, container.name, alias_config)
        logger.info(f"Container '{pfsense.sanitize_for_log(container.name)}' is starting...")
        process_start_event(
            alias_config["host_override_fqdn"],
            alias_config["alias_fqdn"],
            alias_config["alias_descr"]
        )
    elif action == "remove":
        _remove_alias_for(container.name, alias_config)

def should_apply_immediately():
    """
    True when a change can be applied on its own rather than coalesced.

    The first change after a quiet period applies immediately, so a single container
    start is as fast as it was before coalescing. Anything arriving during the burst
    that follows is staged and flushed together.
    """
    if PENDING_CHANGES:
        return False
    return LAST_APPLY_AT is None or time.monotonic() - LAST_APPLY_AT >= APPLY_QUIET_SECONDS

def _record_staged(count=1):
    """Note that `count` changes are staged in pfSense but not yet applied."""
    global PENDING_CHANGES, PENDING_SINCE, LAST_CHANGE_AT  # pylint: disable=global-statement
    PENDING_CHANGES += count
    LAST_CHANGE_AT = time.monotonic()
    if PENDING_SINCE is None:
        PENDING_SINCE = LAST_CHANGE_AT

def _record_applied():
    """Reset coalescing state after changes have been applied."""
    global PENDING_CHANGES, PENDING_SINCE, LAST_CHANGE_AT, LAST_APPLY_AT  # pylint: disable=global-statement
    PENDING_CHANGES = 0
    PENDING_SINCE = None
    LAST_CHANGE_AT = None
    LAST_APPLY_AT = time.monotonic()

def _defer_retry():
    """Push the next flush attempt out a full quiet window after a failed apply."""
    global PENDING_SINCE, LAST_CHANGE_AT  # pylint: disable=global-statement
    LAST_CHANGE_AT = time.monotonic()
    PENDING_SINCE = LAST_CHANGE_AT

def _flush_reason(force):
    """Describe why a flush is due, or None when it is not yet time."""
    if force:
        return "shutdown"
    if time.monotonic() - LAST_CHANGE_AT >= APPLY_QUIET_SECONDS:
        return f"{APPLY_QUIET_SECONDS:g}s without a new event"
    if time.monotonic() - PENDING_SINCE >= APPLY_MAX_WAIT_SECONDS:
        return f"{APPLY_MAX_WAIT_SECONDS:g}s maximum wait"
    return None

def flush_pending_changes(force=False):
    """
    Apply coalesced changes once the quiet window passes, the max wait elapses, or on
    shutdown. Does nothing when no changes are pending.
    """
    if not PENDING_CHANGES:
        return

    reason = _flush_reason(force)
    if reason is None:
        return

    count = PENDING_CHANGES
    logger.info(f"Applying {count} coalesced change(s) after {reason}...")
    if NAMESERVER.apply_changes():
        _record_applied()
        return

    # Keep the changes pending so a later tick or the shutdown flush retries them —
    # clearing the count here discarded them permanently. Push the next attempt out by
    # a full quiet window so a pfSense outage is not retried on every window tick.
    _defer_retry()
    logger.error(
        f"{count} change(s) remain staged in the pfSense configuration and are not live. "
        "Retrying after the quiet period."
    )

def _record_change_outcome(succeeded, mutated):
    """
    Update coalescing state from what pfSense actually holds, not from the return value
    alone.

    A mutation can land in the configuration while its apply fails, which returns False
    even though something is now staged. Trusting the boolean stranded those changes:
    nothing was pending, so nothing ever retried the apply and the alias never went live.

    `mutated` says whether THIS call changed anything, which unapplied_changes cannot:
    that flag is a single boolean and stays True for the whole burst, so a later no-op --
    the second of Docker's die/stop pair, finding the alias already gone -- read as a
    staged change. It inflated the count and restarted the quiet window.
    """
    if not mutated:
        return

    if NAMESERVER.unapplied_changes:
        _record_staged()
    elif succeeded:
        _record_applied()

def process_start_event(host_override_fqdn, alias_fqdn, alias_descr):
    """Process a container start event and add an alias if necessary."""
    immediate = should_apply_immediately()
    before = NAMESERVER.change_count
    succeeded = NAMESERVER.add_host_override_alias(
        host_override_fqdn, alias_fqdn, alias_descr, apply=immediate
    )
    _record_change_outcome(succeeded, NAMESERVER.change_count > before)

def process_stop_event(host_override_fqdn, alias_fqdn):
    """Process a container stop event and remove an alias if necessary."""
    immediate = should_apply_immediately()
    before = NAMESERVER.change_count
    succeeded = NAMESERVER.del_host_override_alias(
        host_override_fqdn, alias_fqdn, apply=immediate
    )
    _record_change_outcome(succeeded, NAMESERVER.change_count > before)

NAMESERVER = None

def iter_events():
    """
    Yield Docker events, with a None tick at every window boundary.

    `client.events()` blocks indefinitely, which would leave nowhere to notice that a
    quiet period has elapsed and pending changes are due. Streaming bounded windows
    hands control back on a fixed cadence without a timer thread, keeping the event
    loop single threaded and the signal handlers simple.

    Windows are contiguous — each starts where the previous ended — so events arriving
    between windows are still delivered. An event landing exactly on a boundary may be
    delivered twice; that is harmless, because adding an existing alias or removing an
    absent one is already detected and logged rather than duplicated.
    """
    since = time.time()
    while True:
        until = time.time() + EVENT_WINDOW_SECONDS
        yield from client.events(since=since, until=until, decode=True)
        since = until
        yield None

def main():
    """Main program loop to listen for Docker events."""
    logger.info("pfsense-docker-alias started")
    global NAMESERVER  # pylint: disable=global-statement
    NAMESERVER = pfsense.PFSense(
        PFSENSE_HOSTNAME,
        PFSENSE_API_TOKEN,
        verify_ssl=PFSENSE_VERIFY_SSL,
        ca_bundle=PFSENSE_CA_BUNDLE
    )

    if ADD_ALIASES_ON_STARTUP:
        add_aliases_on_startup()

    try:
        logger.info("Listening for container start/stop events.")
        for event in iter_events():
            if event is None:
                flush_pending_changes()
            elif (event.get('Type') == 'container'
                  and event.get('Action') in ['start', 'stop', 'die']):
                handle_container_event(event)
    except docker.errors.DockerException as e:
        _handle_error(e, "main")
        raise

def run():
    """Run the service and exit non-zero on unexpected failures."""
    try:
        main()
    except Exception as e:  # pylint: disable=broad-except
        _handle_error(e, "main")
        sys.exit(1)

if __name__ == "__main__":
    run()
