"""
pfsense.py

This module provides an abstraction layer for interacting with a pfSense instance via the 
UNOFFICIAL pfSense REST API. It simplifies the management of DNS host overrides and aliases, 
allowing for seamless integration with automated workflows, such as Docker-based environments.

Features:
- Retrieve all host overrides from pfSense.
- Add new DNS aliases to existing host overrides.
- Remove DNS aliases from host overrides.
- Apply DNS changes in pfSense.

The class ensures robust error handling, logs failures without crashing the application, 
and supports secure API interactions using the pfSense API key.

Dependencies:
- Python 3.7 or newer
- Requests library for HTTP requests
- urllib3 for managing secure (self-signed) API interactions

Usage:
- Create an instance of the `PFSense` class by providing the pfSense hostname and API key.
- Use the methods to retrieve host overrides, add aliases, or delete aliases.

Example:
```python
from pfsense import PFSense

# Initialize the PFSense instance
pfsense = PFSense(pfsense_host="pfsense.lab.internal", pfsense_api_key="your_api_key")

# Add an alias to a host override
pfsense.add_host_override_alias(
    host_override_fqdn="example.lab.internal",
    alias_fqdn="alias.lab.internal",
    alias_descr="Alias for testing"
)

# Retrieve all host overrides
host_overrides = pfsense.get_all_host_overrides()

# Delete an alias from a host override
pfsense.del_host_override_alias(
    host_override_fqdn="example.lab.internal",
    alias_fqdn="alias.lab.internal"
)
"""

 # pylint: disable=logging-fstring-interpolation

import logging
import requests
import urllib3

from urllib3.exceptions import InsecureRequestWarning

# Disable insecure (self-signed certs) request warnings
urllib3.disable_warnings(InsecureRequestWarning)

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class PFSense:
    """
    An abstraction of the pfSense server.
    """
    def __init__(self, pfsense_host, pfsense_api_key):
        self.pfsense_host = pfsense_host
        self.pfsense_api_key = pfsense_api_key
        logger.info(f"pfSense host set to {self.pfsense_host}")
        #print(f'pfsense host set to {self.pfsense_host}')

    def _handle_api_error(self, error, context=""):
        """
        Logs detailed information about API errors.
        :param error: The exception raised during the API call.
        :param context: Additional context about the API call.
        """
        logger.error(f"API call failed during '{context}': {error}")
        if isinstance(error, requests.HTTPError):
            logger.error(f"HTTP Status Code: {error.response.status_code}")
            logger.error(f"Response Content: {error.response.text}")

    def get_all_host_overrides(self):
        """Returns all the host overrides defined in pfSense"""
        # Define the headers for authentication
        headers = {
            'X-API-Key': f"{self.pfsense_api_key}",
            'Content-Type': 'application/json'
        }
        # Fetch existing host overrides to find the one to update
        try:
            response = requests.get(
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/host_overrides',
                headers=headers,
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            return response.json().get('data', [])
        except requests.HTTPError as e:
            self._handle_api_error(e, "get_all_host_overrides")
            return []

    def find_host_name(self, fqdn):
        """
        See if this name already exists as a host override or alias
        :parameter fqdn: a fully qualified hostname and domain string
        :return: a host override object representing the host or the alias or None if not found
        """
        host, domain = fqdn.split('.', 1)
        host_overrides = self.get_all_host_overrides()
        for host_override in host_overrides:
            if host_override['host'] == host and host_override['domain'] == domain:
                return host_override
            if self.find_alias_in_host_override(host_override, fqdn) is not None:
                return host_override
        return None

    def find_alias_in_host_override(self, host_override, alias_fqdn):
        """
        See if the alias exists in the given host override
        :parameter host_override: the host override object to search
        :parameter alias_fqdn: a fully qualified hostname and domain string alias
        :return: an alias object if found in the host override or None if not found
        """
        alias_host, alias_domain = alias_fqdn.split('.', 1)

        alias = None
        if 'aliases' in host_override and host_override['aliases']:
            alias = next((al for al in host_override['aliases'] if al['host'] == alias_host and al['domain'] == alias_domain), None)
        return alias

    def add_host_override_alias(self, host_override_fqdn, alias_fqdn, alias_descr=""):
        """
        Adds an alias to an existing host override in pfSense.

        :param host_override_fqdn: The fully qualified domain name of the existing host override.
        :param alias_fqdn: The fully qualified domain name of the alias to add.
        :param alias_descr: Description for the alias (optional).
        :return: True if the alias was added, False otherwise
        """
    
        alias = self.find_host_name(alias_fqdn)
        if alias is not None:
            logger.warning(f"Alias {alias_fqdn} already mapped to {alias['host']}.{alias['domain']}.")
            #print(f'Could not add alias {alias_fqdn} to {host_override_fqdn} because it is already mapped to {alias["host"] + "." + alias["domain"]}.')
            return False

        host_override = self.find_host_name(host_override_fqdn)
        if not host_override:
            logger.warning(f"Host override {host_override_fqdn} not found.")
            #print(f'Could not add alias {alias_fqdn} to {host_override_fqdn} because the host override was not found.')
            return False

        alias_host, alias_domain = alias_fqdn.split('.', 1)
        
        # Define the headers for authentication
        headers = {
            'X-API-Key': f"{self.pfsense_api_key}",
            'Content-Type': 'application/json'
        }

        data = {
            'parent_id': f'{host_override["id"]}',
            'host': f'{alias_host}',
            'domain': f'{alias_domain}',
            'descr': f'{alias_descr}'
        }
        try:
            # Create new alias
            response = requests.post(
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/host_override/alias',
                headers=headers,
                verify=False,
                timeout=10,
                json=data
            )
            response.raise_for_status()

            # Apply changes
            response = requests.post(
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/apply',
                headers=headers,
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            #print(f'Added alias {alias_fqdn} to host override {host_override_fqdn}.')
            logger.info(f"Alias {alias_fqdn} added to host override {host_override_fqdn}.")
            return True

        except requests.HTTPError as e:
            self._handle_api_error(e, "add_host_override_alias")
            return False

    def del_host_override_alias(self, host_override_fqdn, alias_fqdn):
        host_override = self.find_host_name(host_override_fqdn)
        if not host_override:
            logger.warning(f"Host override {host_override_fqdn} not found.")
            #print(f'Could not remove alias {alias_fqdn} from {host_override_fqdn} because the host override was not found.')
            return False
        
        alias = self.find_alias_in_host_override(host_override, alias_fqdn)
        if not alias:
            logger.warning(f"Alias {alias_fqdn} not found in host override {host_override_fqdn}.")
            #print(f'Could not remove alias {alias_fqdn} because is not associated with {host_override_fqdn}.')
            return False
        
        headers = {
            'X-API-Key': f"{self.pfsense_api_key}",
            'Content-Type': 'application/json'
        }

        data = {
            'parent_id': f'{alias["parent_id"]}',
            'id': f'{alias["id"]}',
        }

        try:
            # Remove alias
            response = requests.delete(
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/host_override/alias',
                headers=headers,
                verify=False,
                timeout=10,
                json=data
            )
            response.raise_for_status()

            # Apply changes
            response = requests.post(
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/apply',
                headers=headers,
                verify=False,
                timeout=10
            )
            response.raise_for_status()
            logger.info(f"Alias {alias_fqdn} removed from host override {host_override_fqdn}.")
            #print(f'Removed alias {alias_fqdn} from host override {host_override_fqdn}.')
            return True

        except requests.HTTPError as e:
            self._handle_api_error(e, "del_host_override_alias")
            return False
        