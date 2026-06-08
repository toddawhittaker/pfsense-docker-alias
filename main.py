"""
pfSense Docker Alias Updater

This script listens for Docker container start/stop events and dynamically updates
DNS aliases in pfSense based on labels defined in the container configuration.
"""

import os
import sys
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
    logger.error(f"Error in {context}: {error}", exc_info=True)

def get_env_var(var_name):
    """Fetch an environment variable and exit if it is not set."""
    value = os.getenv(var_name)
    if not value:
        logger.critical(f"Required environment variable '{var_name}' is not set.")
        sys.exit(1)
    return value

PFSENSE_HOSTNAME = get_env_var("PFSENSE_HOSTNAME")
PFSENSE_API_TOKEN = get_env_var("PFSENSE_API_TOKEN")
PFSENSE_VERIFY_SSL = os.getenv("PFSENSE_VERIFY_SSL", "true").lower() != "false"
PFSENSE_CA_BUNDLE = os.getenv("PFSENSE_CA_BUNDLE")
ADD_ALIASES_ON_STARTUP = os.getenv("ADD_ALIASES_ON_STARTUP", "false").lower() == "true"

# Initialize Docker client
try:
    client = docker.from_env()
except docker.errors.DockerException as e:
    logger.critical(f"Error initializing Docker client: {e}")
    sys.exit(1)

def add_aliases_on_startup():
    """Scan all existing Docker containers and add their aliases if not already added."""
    logger.info("Scanning existing Docker containers for aliases to add...")
    try:
        containers = client.containers.list()
    except docker.errors.DockerException as e:
        _handle_error(e, "add_aliases_on_startup")
        return

    found = False

    for container in containers:
        labels = get_container_labels(container)
        alias_config = parse_alias_labels(labels)

        if not alias_config:
            continue

        logger.info(f"Adding alias '{alias_config['alias_fqdn']}' for container '{container.name}'")
        NAMESERVER.add_host_override_alias(
            alias_config["host_override_fqdn"],
            alias_config["alias_fqdn"],
            alias_config["alias_descr"]
        )
        found = True

    if not found:
        logger.info("No aliases found during startup.")

def cleanup(_signum, _frame):
    """Cleanup actions to perform when the script exits."""
    logger.info("Shutting down gracefully...")
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

def handle_container_event(event):
    """Handle a Docker container start/stop event."""
    container_id = event.get('Actor', {}).get('ID')
    if not container_id:
        logger.warning("Ignoring container event with missing container ID.")
        return

    try:
        container = client.containers.get(container_id)
    except docker.errors.NotFound as e:
        logger.warning(f"Container not found: {e}")
        return
    except docker.errors.DockerException as e:
        _handle_error(e, "handle_container_event")
        return

    labels = get_container_labels(container)

    alias_action = get_alias_event_action(event.get('Action'), labels)
    if not alias_action:
        return

    action, alias_config = alias_action

    if action == "add":
        logger.info(f"Container '{container.name}' is starting...")
        process_start_event(
            alias_config["host_override_fqdn"],
            alias_config["alias_fqdn"],
            alias_config["alias_descr"]
        )
    elif action == "remove":
        logger.info(f"Container '{container.name}' is stopping...")
        process_stop_event(alias_config["host_override_fqdn"], alias_config["alias_fqdn"])

def process_start_event(host_override_fqdn, alias_fqdn, alias_descr):
    """Process a container start event and add an alias if necessary."""
    NAMESERVER.add_host_override_alias(host_override_fqdn, alias_fqdn, alias_descr)

def process_stop_event(host_override_fqdn, alias_fqdn):
    """Process a container stop event and remove an alias if necessary."""
    NAMESERVER.del_host_override_alias(host_override_fqdn, alias_fqdn)

NAMESERVER = None

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
        for event in client.events(decode=True):
            if event.get('Type') == 'container' and event.get('Action') in ['start', 'stop', 'die']:
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
