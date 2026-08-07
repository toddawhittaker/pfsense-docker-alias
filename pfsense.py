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
- Python 3.14 in the provided Docker image
- Requests library for HTTP requests
- urllib3 for TLS warning management when verification is explicitly disabled

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
import re
import time
import urllib3
import requests

from urllib3.exceptions import InsecureRequestWarning

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

API_REQUEST_ATTEMPTS = 3
API_RETRY_DELAY_SECONDS = 1
# Applying is asynchronous: the POST returns before unbound has finished
# reloading, so confirm with a bounded GET poll rather than fire-and-forget.
APPLY_POLL_ATTEMPTS = 15
APPLY_POLL_DELAY_SECONDS = 1
DNS_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")

# RFC 1035 bounds a domain name at 255 octets on the wire. In presentation format that
# is 253 characters: each label is preceded by a one-octet length byte instead of a
# dot, so the wire form is sum(len(label) + 1) + 1 (trailing root octet), while the
# presentation form is sum(len(label)) + (count - 1) dots -- exactly two less. A name
# over 253 characters cannot be encoded into a DNS query, so no client could ever
# resolve it; rejecting it costs an operator nothing they could have used.
#
# There is deliberately no separate label-count cap: 253 characters already bounds the
# count at 127 by construction, since ".".join(["a"] * 127) is exactly 253 characters
# (127 single-character labels + 126 dots). DNS_LABEL_PATTERN's 63-character label cap
# does not bound the total; a length check on the joined FQDN is the only thing that does.
MAX_FQDN_CHARS = 253

# 255 is OUR bound, not a limit pfSense is known to enforce on this object. No
# field-length limit for a DNS-resolver host-override alias description was
# determined; reading upstream source established only how the value is rendered
# (services_unbound.php escapes it with htmlspecialchars() for display), not how
# long it may be. A pfSense host-override alias description is free text, not a
# name, so there is no operator-facing reason to bound it tightly -- 255 is
# comfortably under any plausible field limit while still stopping an unbounded
# value from being written into firewall config.
#
# This caps characters, not bytes: 255 emoji is 1020 UTF-8 bytes. If the real
# field is byte-bounded and lower than that, a description this long draws a 4xx
# from pfSense. That degrades the same way any other rejected mutation does:
# raise_for_status() raises, _handle_api_error logs the status without the
# response body, add_host_override_alias returns False, unapplied_changes stays
# False, and the service keeps running. Self-inflicted by the label author, and
# it cannot poison a coalesced batch since a failed add stages nothing.
ALIAS_DESCR_MAX_CHARS = 255

# The injection barrier for logs, as _split_fqdn is for API payloads. Externally
# supplied values (container labels, API responses) must never reach a log call
# unsanitized, or a newline can fabricate a complete, syntactically valid log record.
LOG_VALUE_MAX_CHARS = 512
LOG_TRUNCATION_MARKER = "...(truncated)"


def sanitize_for_log(value):
    """
    Render a value safely for a log message.

    Escapes every non-printable character (including newline, carriage return, and
    line-separator code points) so a hostile value cannot fabricate a log record, then
    truncates. Escaping before truncating matters: truncating first would let a long run
    of control characters expand into several times as much log output after escaping.
    """
    text = value if isinstance(value, str) else str(value)
    escaped = "".join(
        c if c.isprintable() and c != "\\" else c.encode("unicode_escape").decode("ascii")
        for c in text
    )
    if len(escaped) > LOG_VALUE_MAX_CHARS:
        return escaped[:LOG_VALUE_MAX_CHARS] + LOG_TRUNCATION_MARKER
    return escaped


def clean_alias_descr(value):
    """
    Render a value safely for the pfSense alias description field.

    This is the payload barrier for free text, as _split_fqdn is for names -- but it
    REPLACES rather than escapes, and it is not sanitize_for_log(). A description is
    written into the pfSense configuration and shown in the webGUI, so the goal is a
    value that is harmless to store and display, not one that round-trips to the
    original or carries a truncation marker: escaping would put log furniture
    (backslash-n, "...(truncated)") into firewall config, which is worse than the
    problem it would be fixing.

    Every non-printable character (including newline, carriage return, and line
    separator code points) becomes a single space, and the result is capped at
    ALIAS_DESCR_MAX_CHARS with no marker -- truncation here is silent because the
    marker is a log convention, not a fact about stored config. Unlike
    sanitize_for_log(), the replace-then-truncate order here is not load-bearing:
    the replacement is strictly one-to-one, so replacing first and truncating
    first produce the same result.
    """
    text = value if isinstance(value, str) else str(value)
    cleaned = "".join(c if c.isprintable() else " " for c in text)
    return cleaned[:ALIAS_DESCR_MAX_CHARS]


class PFSense:
    """
    An abstraction of the pfSense server.
    """
    def __init__(self, pfsense_host, pfsense_api_key, verify_ssl=True, ca_bundle=None):
        self.pfsense_host = pfsense_host
        self.pfsense_api_key = pfsense_api_key
        self.verify_ssl = ca_bundle if ca_bundle else verify_ssl
        # True whenever a mutation has landed in the pfSense configuration but has not
        # been confirmed applied. Callers use it to keep retrying rather than assuming a
        # False return meant nothing happened.
        self.unapplied_changes = False
        if self.verify_ssl is False:
            urllib3.disable_warnings(InsecureRequestWarning)
        logger.info(f"pfSense host set to {self.pfsense_host}")

    def _split_fqdn(self, fqdn, context):
        """Split a fully qualified domain name into host and domain parts."""
        if not isinstance(fqdn, str):
            logger.warning(f"Invalid FQDN during {context}.")
            return None

        # Checked before the split, not after: a 24 KB label-supplied value would
        # otherwise be exploded into thousands of labels before being rejected.
        if len(fqdn) > MAX_FQDN_CHARS:
            logger.warning(
                f"FQDN '{sanitize_for_log(fqdn)}' exceeds {MAX_FQDN_CHARS} characters "
                f"during {context}."
            )
            return None

        labels = fqdn.split('.')
        if len(labels) < 2 or any(not label for label in labels):
            logger.warning(f"Invalid FQDN '{sanitize_for_log(fqdn)}' during {context}.")
            return None

        if not all(DNS_LABEL_PATTERN.fullmatch(label) for label in labels):
            logger.warning(f"Invalid FQDN label '{sanitize_for_log(fqdn)}' during {context}.")
            return None

        return labels[0], '.'.join(labels[1:])

    def _request(self, method, context, attempts=API_REQUEST_ATTEMPTS, **kwargs):
        """
        Run a pfSense API request with a small retry budget for transient failures.

        :param attempts: How many times to try. Callers that already poll pass 1, so a
            retry budget is not multiplied by a poll budget into a long stall.
        """
        for attempt in range(1, attempts + 1):
            try:
                return method(**kwargs)
            # OSError, not just RequestException: requests raises a bare OSError when
            # `verify` names an unreadable CA bundle. Letting that escape crash-looped
            # the container, which pushed operators toward disabling verification.
            except (requests.RequestException, OSError) as e:
                if attempt == attempts:
                    self._handle_api_error(e, context)
                    return None

                logger.warning(
                    "API call failed during '%s' attempt %s/%s; retrying.",
                    context,
                    attempt,
                    attempts
                )
                time.sleep(API_RETRY_DELAY_SECONDS)

        return None

    def _headers(self):
        """Return the authentication headers for a pfSense API request."""
        return {
            'X-API-Key': f"{self.pfsense_api_key}",
            'Content-Type': 'application/json'
        }

    def apply_changes(self):
        """
        Applies staged DNS resolver changes and waits for the reload to finish.

        pfSense applies changes asynchronously, so the POST returns before unbound has
        reloaded. Poll the apply endpoint until it reports the change as applied rather
        than assuming success, because an unconfirmed reload is indistinguishable from a
        lost update.

        :return: True if the changes were confirmed applied, False otherwise
        """
        headers = self._headers()
        url = f'https://{self.pfsense_host}/api/v2/services/dns_resolver/apply'

        try:
            response = self._request(
                requests.post,
                "apply_changes",
                url=url,
                headers=headers,
                verify=self.verify_ssl,
                timeout=10
            )
            if response is None:
                return False
            response.raise_for_status()
        except requests.RequestException as e:
            self._handle_api_error(e, "apply_changes")
            return False

        for attempt in range(1, APPLY_POLL_ATTEMPTS + 1):
            if self._changes_applied():
                logger.info("DNS resolver changes applied.")
                self.unapplied_changes = False
                return True

            if attempt < APPLY_POLL_ATTEMPTS:
                time.sleep(APPLY_POLL_DELAY_SECONDS)

        logger.error(
            "DNS resolver changes were not confirmed applied after %s attempts. "
            "They remain staged in the pfSense configuration.",
            APPLY_POLL_ATTEMPTS
        )
        return False

    def _changes_applied(self):
        """Return True when pfSense reports the staged DNS resolver changes as applied."""
        try:
            response = self._request(
                requests.get,
                "apply_changes_status",
                attempts=1,
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/apply',
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=10
            )
            if response is None:
                return False
            response.raise_for_status()
            data = response.json().get('data', {})
            return data.get('applied') is True
        except (requests.RequestException, ValueError, AttributeError) as e:
            self._handle_api_error(e, "apply_changes_status")
            return False

    def _handle_api_error(self, error, context=""):
        """
        Logs detailed information about API errors.
        :param error: The exception raised during the API call.
        :param context: Additional context about the API call.
        """
        if isinstance(error, requests.exceptions.InvalidHeader):
            # Do NOT log this exception's message. requests embeds the offending header
            # value in it, and the only header this service sets is the API token, so
            # logging the message prints the token in cleartext -- on every call, since
            # the request fails identically each time. sanitize_for_log does not save
            # us here: it escapes the newline and renders the token characters as-is.
            #
            # main.py trims surrounding whitespace from the token so the common causes
            # (a file-based secret, `$(cat ...)`) never reach this branch at all. This
            # is the second layer, for a token malformed some other way and for any
            # caller constructing PFSense directly.
            logger.error(
                f"API call failed during '{context}': the request headers were "
                "rejected as malformed. Check PFSENSE_API_TOKEN for stray whitespace "
                "or line breaks. The value is not logged."
            )
            return

        logger.error(f"API call failed during '{context}': {sanitize_for_log(error)}")
        if isinstance(error, requests.HTTPError) and error.response is not None:
            # `error.response is not None` is required, not defensive noise: this runs
            # inside an `except` block, so an AttributeError here would escape every
            # handler up to run() and exit the process -- inverting the contract that an
            # API failure logs and returns False rather than killing the service.
            logger.error(f"HTTP Status Code: {error.response.status_code}")
        if isinstance(error, requests.exceptions.SSLError):
            # requests reports the cause accurately but names nothing an operator can
            # set. Verification defaults to on, which this service did not always do,
            # so someone upgrading has no reason to know these settings exist.
            #
            # Deliberately SSLError and not its ConnectionError parent: advice to
            # consider switching verification off must not appear every time the host
            # is simply unreachable. A test pins that boundary.
            logger.error(
                "TLS certificate verification failed. Mount a CA bundle and set "
                "PFSENSE_CA_BUNDLE to its path inside the container, or set "
                "PFSENSE_VERIFY_SSL=false to skip verification entirely, which "
                "exposes the API token to anyone able to intercept the connection."
            )

    def get_all_host_overrides(self):
        """Returns all the host overrides defined in pfSense"""
        # Fetch existing host overrides to find the one to update
        try:
            response = self._request(
                requests.get,
                "get_all_host_overrides",
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/host_overrides',
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=10
            )
            if response is None:
                return []
            response.raise_for_status()
            data = response.json().get('data', [])
        except (requests.RequestException, OSError, ValueError, AttributeError) as e:
            self._handle_api_error(e, "get_all_host_overrides")
            return []

        # Validate the shape here so callers can index safely. An API schema change or
        # a partial object previously raised KeyError/TypeError straight out of this
        # module, which exits the service instead of logging and carrying on.
        if not isinstance(data, list):
            logger.error("Unexpected host override payload; expected a list.")
            return []

        return [entry for entry in data if isinstance(entry, dict)]

    def find_host_name(self, fqdn):
        """
        See if this name already exists as a host override or alias
        :parameter fqdn: a fully qualified hostname and domain string
        :return: a host override object representing the host or the alias or None if not found
        """
        split_fqdn = self._split_fqdn(fqdn, "find_host_name")
        if not split_fqdn:
            return None

        host, domain = split_fqdn
        host_overrides = self.get_all_host_overrides()
        for host_override in host_overrides:
            if host_override.get('host') == host and host_override.get('domain') == domain:
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
        split_fqdn = self._split_fqdn(alias_fqdn, "find_alias_in_host_override")
        if not split_fqdn:
            return None

        alias_host, alias_domain = split_fqdn

        aliases = host_override.get('aliases') or []
        if not isinstance(aliases, list):
            return None

        return next(
            (
                al for al in aliases
                if isinstance(al, dict)
                and al.get('host') == alias_host
                and al.get('domain') == alias_domain
            ),
            None
        )

    def _mutate_alias(self, method, context, data, apply_now):
        """
        Sends a mutating request to the alias endpoint, then applies it unless staging.

        Both public mutators share this shape, and the duplication used to be copied
        between them. Callers still log their own outcome, because the wording differs
        and the staged wording matters: an operator reading "removed" while the name
        still resolves is worse than no message at all.

        The parameter is `apply_now` rather than `apply` only to avoid shadowing the
        builtin in a method that does not need the public signature.

        :param method: The requests function to call, e.g. requests.post.
        :param context: Name used in log messages, normally the calling method's.
        :param data: The JSON body for the request.
        :param apply_now: Apply the change immediately rather than leaving it staged.
        :return: True if the change landed in the pfSense configuration and, when
            apply_now is True, was confirmed live.
        """
        try:
            response = self._request(
                method,
                context,
                url=f'https://{self.pfsense_host}/api/v2/services/dns_resolver/host_override/alias',
                headers=self._headers(),
                verify=self.verify_ssl,
                timeout=10,
                json=data
            )
            if response is None:
                return False
            response.raise_for_status()

        except (requests.RequestException, OSError) as e:
            self._handle_api_error(e, context)
            return False

        # The configuration has now changed whether or not the apply below succeeds.
        # Recording that is what stops a failed apply from stranding the change with
        # nothing tracking it -- main._record_change_outcome() reads this flag, not
        # the boolean returned here.
        self.unapplied_changes = True

        if apply_now and not self.apply_changes():
            return False

        return True

    def add_host_override_alias(self, host_override_fqdn, alias_fqdn, alias_descr="", apply=True):
        # pylint: disable=redefined-builtin
        """
        Adds an alias to an existing host override in pfSense.

        :param host_override_fqdn: The fully qualified domain name of the existing host override.
        :param alias_fqdn: The fully qualified domain name of the alias to add.
        :param alias_descr: Description for the alias (optional).
        :param apply: Apply the change immediately. Pass False when staging several aliases,
            then call apply_changes() once for the batch — each apply reloads unbound and
            takes seconds, so applying per alias is both slow and a source of lost updates.
        :return: True if the alias was added, False otherwise. With apply=False, True means
            the alias is staged in the pfSense configuration but not yet live.
        """
        split_fqdn = self._split_fqdn(alias_fqdn, "add_host_override_alias")
        if not split_fqdn:
            return False

        alias_host, alias_domain = split_fqdn

        alias = self.find_host_name(alias_fqdn)
        if alias is not None:
            logger.warning(
                f"Alias {sanitize_for_log(alias_fqdn)} already mapped to "
                f"{sanitize_for_log(alias.get('host'))}.{sanitize_for_log(alias.get('domain'))}."
            )
            return False

        host_override = self.find_host_name(host_override_fqdn)
        if not host_override:
            logger.warning(f"Host override {sanitize_for_log(host_override_fqdn)} not found.")
            return False

        parent_id = host_override.get("id")
        if parent_id is None:
            logger.error(
                f"Host override {sanitize_for_log(host_override_fqdn)} has no id; "
                "cannot add alias."
            )
            return False

        cleaned_descr = clean_alias_descr(alias_descr)
        if cleaned_descr != f'{alias_descr}':
            logger.warning(
                f"Alias description for {sanitize_for_log(alias_fqdn)} was cleaned "
                "before sending to pfSense; unprintable characters are replaced and "
                f"the description is capped at {ALIAS_DESCR_MAX_CHARS} characters."
            )

        data = {
            'parent_id': f'{parent_id}',
            'host': f'{alias_host}',
            'domain': f'{alias_domain}',
            'descr': cleaned_descr
        }
        if not self._mutate_alias(requests.post, "add_host_override_alias", data, apply):
            return False

        if apply:
            logger.info(
                f"Alias {sanitize_for_log(alias_fqdn)} added to host override "
                f"{sanitize_for_log(host_override_fqdn)}."
            )
        else:
            logger.info(
                f"Alias {sanitize_for_log(alias_fqdn)} staged for host override "
                f"{sanitize_for_log(host_override_fqdn)}."
            )

        return True

    def del_host_override_alias(self, host_override_fqdn, alias_fqdn, apply=True):
        # pylint: disable=redefined-builtin
        """
        Removes an alias from an existing host override in pfSense.

        :param host_override_fqdn: The fully qualified domain name of the existing host override.
        :param alias_fqdn: The fully qualified domain name of the alias to remove.
        :param apply: Apply the change immediately. Pass False when staging several removals,
            then call apply_changes() once for the batch.
        :return: True if the alias was removed, False otherwise. With apply=False, True means
            the removal is staged in the pfSense configuration but not yet live.
        """
        host_override = self.find_host_name(host_override_fqdn)
        if not host_override:
            logger.warning(f"Host override {sanitize_for_log(host_override_fqdn)} not found.")
            return False

        alias = self.find_alias_in_host_override(host_override, alias_fqdn)
        if not alias:
            logger.warning(
                f"Alias {sanitize_for_log(alias_fqdn)} not found in host override "
                f"{sanitize_for_log(host_override_fqdn)}."
            )
            return False

        parent_id = alias.get("parent_id")
        alias_id = alias.get("id")
        if parent_id is None or alias_id is None:
            logger.error(
                f"Alias {sanitize_for_log(alias_fqdn)} is missing an id; cannot remove it."
            )
            return False

        data = {
            'parent_id': f'{parent_id}',
            'id': f'{alias_id}',
        }

        if not self._mutate_alias(requests.delete, "del_host_override_alias", data, apply):
            return False

        if apply:
            logger.info(
                f"Alias {sanitize_for_log(alias_fqdn)} removed from host override "
                f"{sanitize_for_log(host_override_fqdn)}."
            )
        else:
            logger.info(
                f"Alias {sanitize_for_log(alias_fqdn)} staged for removal from "
                f"{sanitize_for_log(host_override_fqdn)}."
            )

        return True
