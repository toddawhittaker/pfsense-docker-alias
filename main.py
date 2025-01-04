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

        host_override_fqdn = labels.get("pfsense.dns.override", None)
        if not host_override_fqdn:
            continue

        alias_fqdn = labels.get("pfsense.dns.alias", None)
        if not alias_fqdn:
            continue

        alias_descr = labels.get('pfsense.dns.description', '')
        logger.info(f"Adding alias '{alias_fqdn}' for container '{container.name}'")
        NAMESERVER.add_host_override_alias(host_override_fqdn, alias_fqdn, alias_descr)
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
        return container.attrs['Config']['Labels']
    except KeyError:
        return {}

def handle_container_event(event):
    """Handle a Docker container start/stop event."""
    try:
        container = client.containers.get(event['Actor']['ID'])
    except docker.errors.NotFound as e:
        logger.warning(f"Container not found: {e}")
        return
    except docker.errors.DockerException as e:
        _handle_error(e, "handle_container_event")
        return

    labels = get_container_labels(container)

    host_override_fqdn = labels.get("pfsense.dns.override", None)
    if not host_override_fqdn:
        return

    alias_fqdn = labels.get("pfsense.dns.alias", None)
    if not alias_fqdn:
        return

    alias_descr = labels.get('pfsense.dns.description', '')

    if event['Action'] == 'start':
        logger.info(f"Container '{container.name}' is starting...")
        process_start_event(host_override_fqdn, alias_fqdn, alias_descr)
    elif event['Action'] == 'stop' and labels.get("pfsense.dns.remove_on_stop", None) == "true":
        logger.info(f"Container '{container.name}' is stopping...")
        process_stop_event(host_override_fqdn, alias_fqdn)

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
    NAMESERVER = pfsense.PFSense(PFSENSE_HOSTNAME, PFSENSE_API_TOKEN)

    if ADD_ALIASES_ON_STARTUP:
        add_aliases_on_startup()

    try:
        logger.info("Listening for container start/stop events.")
        for event in client.events(decode=True):
            if event['Type'] == 'container' and event['Action'] in ['start', 'stop']:
                handle_container_event(event)
    except docker.errors.DockerException as e:
        _handle_error(e, "main")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:  # pylint: disable=broad-except
        _handle_error(e, "main")
