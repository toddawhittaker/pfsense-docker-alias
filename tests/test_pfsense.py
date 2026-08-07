import requests
import logging

import pfsense
from pfsense import PFSense


class FakeResponse:
    def __init__(self, payload=None, error=None):
        self.payload = payload or {}
        self.error = error
        self.status_code = 500
        self.text = "failure"

    def json(self):
        return self.payload

    def raise_for_status(self):
        if self.error:
            raise self.error


def http_error():
    response = FakeResponse()
    error = requests.HTTPError("request failed")
    error.response = response
    return error


def applied_status_get(applied=True, calls=None):
    """
    A requests.get stand-in for the apply endpoint's status poll.

    The signature is explicit rather than `**_kwargs` on purpose. A helper that swallows
    every kwarg swallowed a hardcoded `verify=False` in _changes_applied() too — mutation
    testing proved the whole suite stayed green. Naming the four kwargs turns a *dropped*
    one into a TypeError at every call site; pass `calls` to catch a *weakened* one.
    """
    def fake_get(url, headers, verify, timeout):
        if calls is not None:
            calls.append(
                {
                    "url": url,
                    "headers": headers,
                    "verify": verify,
                    "timeout": timeout,
                }
            )
        return FakeResponse({"data": {"applied": applied}})

    return fake_get


def log_messages(caplog):
    """The formatted message of each captured record, without any traceback."""
    return [record.getMessage() for record in caplog.records]


def assert_no_forged_log_records(caplog):
    """
    No captured record may contain a raw newline or carriage return.

    caplog.text joins records with newlines, so a substring check on it cannot prove
    single-line-ness — a forged record and a genuine one look identical there. Assert
    per record instead. record.getMessage() excludes exc_info, so a deliberate
    multi-line traceback is not swept up by this check.
    """
    for record in caplog.records:
        message = record.getMessage()
        assert "\n" not in message, message
        assert "\r" not in message, message


def test_get_all_host_overrides_constructs_request(monkeypatch):
    calls = []

    def fake_get(url, headers, verify, timeout):
        calls.append(
            {
                "url": url,
                "headers": headers,
                "verify": verify,
                "timeout": timeout,
            }
        )
        return FakeResponse({"data": [{"host": "caddy", "domain": "lab.internal"}]})

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.get_all_host_overrides() == [{"host": "caddy", "domain": "lab.internal"}]
    assert calls == [
        {
            "url": "https://pfsense.lab.internal/api/v2/services/dns_resolver/host_overrides",
            "headers": {
                "X-API-Key": "secret-token",
                "Content-Type": "application/json",
            },
            "verify": True,
            "timeout": 10,
        }
    ]


def test_get_all_host_overrides_uses_custom_ca_bundle(monkeypatch):
    calls = []

    def fake_get(url, headers, verify, timeout):
        calls.append({"verify": verify})
        return FakeResponse({"data": []})

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "secret-token", ca_bundle="/etc/ssl/pfsense-ca.pem")

    assert client.get_all_host_overrides() == []
    assert calls == [{"verify": "/etc/ssl/pfsense-ca.pem"}]


def test_get_all_host_overrides_can_disable_tls_verification(monkeypatch):
    calls = []

    def fake_get(url, headers, verify, timeout):
        calls.append({"verify": verify})
        return FakeResponse({"data": []})

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "secret-token", verify_ssl=False)

    assert client.get_all_host_overrides() == []
    assert calls == [{"verify": False}]


def test_get_all_host_overrides_returns_empty_list_on_request_errors(monkeypatch):
    monkeypatch.setattr(
        "pfsense.requests.get",
        lambda **_kwargs: FakeResponse(error=http_error()),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.get_all_host_overrides() == []


def test_http_error_logs_status_without_response_body(monkeypatch, caplog):
    response = FakeResponse()
    response.text = "sensitive response body"
    error = requests.HTTPError("request failed")
    error.response = response
    monkeypatch.setattr(
        "pfsense.requests.get",
        lambda **_kwargs: FakeResponse(error=error),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.ERROR):
        assert client.get_all_host_overrides() == []

    assert "HTTP Status Code: 500" in caplog.text
    assert "sensitive response body" not in caplog.text


def test_a_tls_verification_failure_names_the_settings_that_fix_it(monkeypatch, caplog):
    """
    A certificate failure must point at the two settings that resolve it.

    Verification defaults to on, which is a change from this service's own earlier
    behaviour of never verifying. requests reports the cause accurately -- "certificate
    verify failed: self-signed certificate" -- but names nothing an operator can set,
    and someone upgrading has no reason to know PFSENSE_VERIFY_SSL exists, because in
    the version they are upgrading from it did not.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def fake_get(**_kwargs):
        raise requests.exceptions.SSLError(
            "certificate verify failed: self-signed certificate"
        )

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.ERROR):
        assert client.get_all_host_overrides() == []

    hints = [m for m in log_messages(caplog) if "PFSENSE_CA_BUNDLE" in m]
    assert len(hints) == 1
    assert "PFSENSE_VERIFY_SSL" in hints[0]
    # The underlying cause must survive alongside the hint; a hint that replaced the
    # real error would send someone to the wrong setting when the failure is expiry
    # or a hostname mismatch rather than an untrusted issuer.
    assert "certificate verify failed" in caplog.text
    assert "secret-token" not in caplog.text


def test_an_ordinary_connection_error_does_not_suggest_disabling_tls(monkeypatch, caplog):
    """
    The hint is for certificate failures only, and that boundary is the point.

    requests.exceptions.SSLError subclasses ConnectionError, so a check written in the
    wrong order would fire this hint for every unplugged cable and unreachable host.
    Advice to consider turning off certificate validation, printed whenever the network
    hiccups, is how a fail-secure default gets switched off for an unrelated reason.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def fake_get(**_kwargs):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.ERROR):
        assert client.get_all_host_overrides() == []

    assert "PFSENSE_CA_BUNDLE" not in caplog.text
    assert "PFSENSE_VERIFY_SSL" not in caplog.text


def test_a_token_with_a_trailing_newline_never_reaches_the_log(monkeypatch, caplog):
    """
    requests embeds the offending header VALUE in InvalidHeader's message.

    That message is a RequestException, so it lands in _handle_api_error and would be
    logged verbatim -- printing the firewall API token at ERROR on every call, forever,
    because the same request fails identically every time. sanitize_for_log does not
    help: it escapes the newline and renders the token characters as they are.

    A trailing newline is the realistic case, not a contrived one. It is what
    `$(cat /run/secrets/token)` and a file-based Kubernetes secret both produce.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def fake_get(**_kwargs):
        raise requests.exceptions.InvalidHeader(
            "Invalid leading whitespace, reserved character(s), or return character(s) "
            "in header value: 'SUPERSECRETTOKEN\\n'"
        )

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "SUPERSECRETTOKEN\n")

    with caplog.at_level(logging.ERROR):
        assert client.get_all_host_overrides() == []

    assert "SUPERSECRETTOKEN" not in caplog.text


def test_an_invalid_header_error_still_says_what_went_wrong(monkeypatch, caplog):
    """
    Redacting the value must not leave the operator with an unactionable log.

    The whole failure is a malformed token, so the message has to name the variable
    to check. It must do that without quoting the value it is refusing to print.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def fake_get(**_kwargs):
        raise requests.exceptions.InvalidHeader("... in header value: 'SUPERSECRETTOKEN\\n'")

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "SUPERSECRETTOKEN\n")

    with caplog.at_level(logging.ERROR):
        assert client.get_all_host_overrides() == []

    assert "PFSENSE_API_TOKEN" in caplog.text
    assert "SUPERSECRETTOKEN" not in caplog.text


def test_handle_api_error_survives_an_http_error_with_no_response(caplog):
    """
    An HTTPError carrying no response must not raise out of the error handler.

    _handle_api_error runs inside an `except` block, so an AttributeError here escapes
    _request's handler, escapes _mutate_alias's, and reaches run()'s broad handler,
    which exits the process. That inverts the contract that a pfSense API failure logs
    and returns False rather than killing the service.
    """
    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.ERROR):
        client._handle_api_error(  # pylint: disable=protected-access
            requests.HTTPError("no response attached"), "ctx"
        )

    assert "no response attached" in caplog.text
    assert "HTTP Status Code" not in caplog.text


def test_get_all_host_overrides_returns_empty_list_on_network_errors(monkeypatch):
    def fake_get(**_kwargs):
        raise requests.ConnectionError("connection failed")

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.get_all_host_overrides() == []


def test_get_all_host_overrides_retries_transient_network_errors(monkeypatch):
    calls = []
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def fake_get(**_kwargs):
        calls.append("get")
        if len(calls) == 1:
            raise requests.ConnectionError("temporary failure")
        return FakeResponse({"data": [{"host": "caddy", "domain": "lab.internal"}]})

    monkeypatch.setattr("pfsense.requests.get", fake_get)

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.get_all_host_overrides() == [{"host": "caddy", "domain": "lab.internal"}]
    assert calls == ["get", "get"]


def test_get_all_host_overrides_returns_empty_list_on_invalid_json(monkeypatch):
    class InvalidJsonResponse(FakeResponse):
        def json(self):
            raise ValueError("invalid json")

    monkeypatch.setattr(
        "pfsense.requests.get",
        lambda **_kwargs: InvalidJsonResponse(),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.get_all_host_overrides() == []


def test_add_host_override_alias_constructs_alias_and_apply_requests(monkeypatch):
    calls = []

    def fake_post(url, headers, verify, timeout, json=None):
        calls.append(
            {
                "url": url,
                "headers": headers,
                "verify": verify,
                "timeout": timeout,
                "json": json,
            }
        )
        return FakeResponse()

    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token", verify_ssl=False)
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [],
        }
    ]

    assert client.add_host_override_alias(
        "caddy.lab.internal",
        "nginx.lab.internal",
        "nginx service",
    )
    assert calls == [
        {
            "url": "https://pfsense.lab.internal/api/v2/services/dns_resolver/host_override/alias",
            "headers": {
                "X-API-Key": "secret-token",
                "Content-Type": "application/json",
            },
            "verify": False,
            "timeout": 10,
            "json": {
                "parent_id": "12",
                "host": "nginx",
                "domain": "lab.internal",
                "descr": "nginx service",
            },
        },
        {
            "url": "https://pfsense.lab.internal/api/v2/services/dns_resolver/apply",
            "headers": {
                "X-API-Key": "secret-token",
                "Content-Type": "application/json",
            },
            "verify": False,
            "timeout": 10,
            "json": None,
        },
    ]


def test_add_host_override_alias_can_stage_without_applying(monkeypatch):
    posts = []
    gets = []

    monkeypatch.setattr(
        "pfsense.requests.post",
        lambda url, **_kwargs: posts.append(url) or FakeResponse(),
    )
    monkeypatch.setattr(
        "pfsense.requests.get",
        lambda url, **_kwargs: gets.append(url) or FakeResponse(),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    assert client.add_host_override_alias(
        "caddy.lab.internal", "nginx.lab.internal", "nginx service", apply=False
    )

    assert posts == [
        "https://pfsense.lab.internal/api/v2/services/dns_resolver/host_override/alias"
    ]
    assert gets == []


def test_del_host_override_alias_can_stage_without_applying(monkeypatch):
    posts = []

    monkeypatch.setattr("pfsense.requests.delete", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr(
        "pfsense.requests.post",
        lambda url, **_kwargs: posts.append(url) or FakeResponse(),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}
            ],
        }
    ]

    assert client.del_host_override_alias(
        "caddy.lab.internal", "nginx.lab.internal", apply=False
    )
    assert posts == []


def test_add_host_override_alias_returns_false_when_api_post_fails(monkeypatch):
    monkeypatch.setattr(
        "pfsense.requests.post",
        lambda **_kwargs: FakeResponse(error=http_error()),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [],
        }
    ]

    assert not client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal")


def test_add_host_override_alias_returns_false_when_apply_fails(monkeypatch):
    calls = []

    def fake_post(**_kwargs):
        calls.append("post")
        if len(calls) >= 2:
            raise requests.ConnectionError("apply failed")
        return FakeResponse()

    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [],
        }
    ]

    assert not client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal")
    assert calls == ["post", "post", "post", "post"]


def test_add_host_override_alias_returns_false_for_malformed_alias_fqdn(monkeypatch):
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [],
        }
    ]

    assert not client.add_host_override_alias("caddy.lab.internal", "nginx")


def test_add_host_override_alias_rejects_hostile_fqdn_values(monkeypatch):
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [],
        }
    ]

    assert not client.add_host_override_alias("caddy.lab.internal", "bad alias.lab.internal")
    assert not client.add_host_override_alias("caddy.lab.internal", "bad\nalias.lab.internal")
    assert not client.add_host_override_alias("caddy.lab.internal", "bad..alias.lab.internal")
    assert not client.add_host_override_alias("caddy.lab.internal", "-bad.lab.internal")
    assert not client.add_host_override_alias("caddy.lab.internal", "bad-.lab.internal")


def test_del_host_override_alias_constructs_delete_and_apply_requests(monkeypatch):
    delete_calls = []
    post_calls = []

    def fake_delete(url, headers, verify, timeout, json=None):
        delete_calls.append(
            {
                "url": url,
                "headers": headers,
                "verify": verify,
                "timeout": timeout,
                "json": json,
            }
        )
        return FakeResponse()

    def fake_post(url, headers, verify, timeout, json=None):
        post_calls.append(
            {
                "url": url,
                "headers": headers,
                "verify": verify,
                "timeout": timeout,
                "json": json,
            }
        )
        return FakeResponse()

    monkeypatch.setattr("pfsense.requests.delete", fake_delete)
    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token", verify_ssl=False)
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [
                {
                    "id": 34,
                    "parent_id": 12,
                    "host": "nginx",
                    "domain": "lab.internal",
                }
            ],
        }
    ]

    assert client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal")
    assert delete_calls == [
        {
            "url": "https://pfsense.lab.internal/api/v2/services/dns_resolver/host_override/alias",
            "headers": {
                "X-API-Key": "secret-token",
                "Content-Type": "application/json",
            },
            "verify": False,
            "timeout": 10,
            "json": {
                "parent_id": "12",
                "id": "34",
            },
        }
    ]
    assert post_calls == [
        {
            "url": "https://pfsense.lab.internal/api/v2/services/dns_resolver/apply",
            "headers": {
                "X-API-Key": "secret-token",
                "Content-Type": "application/json",
            },
            "verify": False,
            "timeout": 10,
            "json": None,
        }
    ]


def test_del_host_override_alias_returns_false_for_malformed_host_override_fqdn():
    client = PFSense("pfsense.lab.internal", "secret-token")

    assert not client.del_host_override_alias("caddy", "nginx.lab.internal")


def test_del_host_override_alias_returns_false_when_apply_fails(monkeypatch):
    delete_calls = []
    post_calls = []

    def fake_delete(**_kwargs):
        delete_calls.append("delete")
        return FakeResponse()

    def fake_post(**_kwargs):
        post_calls.append("post")
        raise requests.ConnectionError("apply failed")

    monkeypatch.setattr("pfsense.requests.delete", fake_delete)
    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [
                {
                    "id": 34,
                    "parent_id": 12,
                    "host": "nginx",
                    "domain": "lab.internal",
                }
            ],
        }
    ]

    assert not client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal")
    assert delete_calls == ["delete"]
    assert post_calls == ["post", "post", "post"]


def test_split_fqdn_rejects_non_string_input(caplog):
    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        assert client.find_host_name(None) is None
        assert client.find_host_name(12345) is None
        assert client.find_host_name(["nginx", "lab", "internal"]) is None

    assert "Invalid FQDN" in caplog.text


def test_find_alias_in_host_override_rejects_malformed_alias():
    client = PFSense("pfsense.lab.internal", "secret-token")
    host_override = {
        "id": 12,
        "host": "caddy",
        "domain": "lab.internal",
        "aliases": [{"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}],
    }

    assert client.find_alias_in_host_override(host_override, "nginx") is None
    assert client.find_alias_in_host_override(host_override, None) is None


def test_find_alias_in_host_override_handles_override_without_aliases():
    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.find_alias_in_host_override(
        {"id": 12, "host": "caddy", "domain": "lab.internal"}, "nginx.lab.internal"
    ) is None
    assert client.find_alias_in_host_override(
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": None},
        "nginx.lab.internal",
    ) is None


def test_add_host_override_alias_returns_false_when_host_override_missing(caplog):
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: []

    with caplog.at_level(logging.WARNING):
        assert not client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal")

    assert "Host override caddy.lab.internal not found" in caplog.text


def test_add_host_override_alias_refuses_to_shadow_an_existing_name(caplog):
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}
            ],
        }
    ]

    with caplog.at_level(logging.WARNING):
        assert not client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal")

    assert "already mapped" in caplog.text


def test_del_host_override_alias_returns_false_when_alias_missing(caplog):
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    with caplog.at_level(logging.WARNING):
        assert not client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal")

    assert "not found in host override" in caplog.text


def test_del_host_override_alias_returns_false_when_host_override_missing(caplog):
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: []

    with caplog.at_level(logging.WARNING):
        assert not client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal")

    assert "Host override caddy.lab.internal not found" in caplog.text


def test_del_host_override_alias_returns_false_when_delete_fails(monkeypatch):
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        "pfsense.requests.delete",
        lambda **_kwargs: FakeResponse(error=http_error()),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}
            ],
        }
    ]

    assert not client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal")


def test_insecure_warning_suppressed_only_when_verification_disabled(monkeypatch):
    disabled = []
    monkeypatch.setattr(
        "pfsense.urllib3.disable_warnings", lambda category: disabled.append(category)
    )

    PFSense("pfsense.lab.internal", "secret-token")
    assert disabled == []

    PFSense("pfsense.lab.internal", "secret-token", ca_bundle="/etc/ssl/ca.pem")
    assert disabled == []

    PFSense("pfsense.lab.internal", "secret-token", verify_ssl=False)
    assert len(disabled) == 1


def test_add_host_override_alias_returns_false_when_alias_post_exhausts_retries(monkeypatch):
    calls = []
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def always_failing(**_kwargs):
        calls.append("post")
        raise requests.ConnectionError("network down")

    monkeypatch.setattr("pfsense.requests.post", always_failing)

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    assert not client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal")
    assert calls == ["post", "post", "post"]


def test_del_host_override_alias_returns_false_when_delete_exhausts_retries(monkeypatch):
    calls = []
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def always_failing(**_kwargs):
        calls.append("delete")
        raise requests.ConnectionError("network down")

    monkeypatch.setattr("pfsense.requests.delete", always_failing)

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}
            ],
        }
    ]

    assert not client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal")
    assert calls == ["delete", "delete", "delete"]


def test_apply_changes_confirms_the_reload_landed(monkeypatch):
    posts = []
    gets = []

    monkeypatch.setattr(
        "pfsense.requests.post",
        lambda url, **_kwargs: posts.append(url) or FakeResponse(),
    )
    monkeypatch.setattr(
        "pfsense.requests.get",
        lambda url, **_kwargs: gets.append(url) or FakeResponse({"data": {"applied": True}}),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.apply_changes() is True
    assert posts == ["https://pfsense.lab.internal/api/v2/services/dns_resolver/apply"]
    assert gets == ["https://pfsense.lab.internal/api/v2/services/dns_resolver/apply"]


def test_apply_changes_polls_until_pfsense_reports_applied(monkeypatch):
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())

    polls = []

    def slow_apply(**_kwargs):
        polls.append("get")
        return FakeResponse({"data": {"applied": len(polls) >= 3}})

    monkeypatch.setattr("pfsense.requests.get", slow_apply)

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.apply_changes() is True
    assert len(polls) == 3


def test_apply_changes_gives_up_and_reports_changes_still_staged(monkeypatch, caplog):
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get(applied=False))

    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.ERROR):
        assert client.apply_changes() is False

    assert "remain staged" in caplog.text


def test_apply_changes_returns_false_when_the_apply_post_fails(monkeypatch):
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        "pfsense.requests.post",
        lambda **_kwargs: FakeResponse(error=http_error()),
    )
    gets = []
    monkeypatch.setattr(
        "pfsense.requests.get", lambda **_kwargs: gets.append("get") or FakeResponse()
    )

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.apply_changes() is False
    assert gets == []


def test_apply_changes_status_poll_does_not_multiply_the_retry_budget(monkeypatch):
    """A failing status poll must not stack _request retries inside the poll loop."""
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())

    attempts = []

    def unreachable(**_kwargs):
        attempts.append("get")
        raise requests.ConnectionError("unreachable")

    monkeypatch.setattr("pfsense.requests.get", unreachable)

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.apply_changes() is False
    assert len(attempts) == pfsense.APPLY_POLL_ATTEMPTS


def test_apply_changes_treats_a_malformed_status_body_as_not_applied(monkeypatch):
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())

    class InvalidJson(FakeResponse):
        def json(self):
            raise ValueError("not json")

    monkeypatch.setattr("pfsense.requests.get", lambda **_kwargs: InvalidJson())

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.apply_changes() is False


# --- Failures must log and return False, never raise --------------------------


def test_malformed_host_override_payload_does_not_raise(monkeypatch, caplog):
    """
    A well-formed 200 with an unexpected body used to raise KeyError/TypeError straight
    out of this module, which exits the service instead of logging and carrying on.
    """
    client = PFSense("pfsense.lab.internal", "secret-token")

    for payload in (
        {"data": [{"host": "caddy", "domain": "lab.internal"}]},   # no id
        {"data": [{"host": "caddy"}]},                              # no domain
        {"data": {"unexpected": "dict"}},                           # not a list
        {"data": ["a string", 42, None]},                           # not dicts
        {"data": [{"host": "caddy", "domain": "lab.internal", "aliases": "nope"}]},
        {"data": [{"host": "caddy", "domain": "lab.internal", "aliases": [None, 7]}]},
        {"nodata": True},
    ):
        def responder(_payload=payload, **_kwargs):
            return FakeResponse(_payload)

        monkeypatch.setattr("pfsense.requests.get", responder)
        monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
        monkeypatch.setattr("pfsense.requests.delete", lambda **_kwargs: FakeResponse())

        with caplog.at_level(logging.WARNING):
            # The contract is "log and return False", never raise.
            assert client.add_host_override_alias(
                "caddy.lab.internal", "nginx.lab.internal"
            ) is False
            assert client.del_host_override_alias(
                "caddy.lab.internal", "nginx.lab.internal"
            ) is False
            client.find_host_name("caddy.lab.internal")


def test_host_override_without_an_id_is_reported_not_raised(monkeypatch, caplog):
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    with caplog.at_level(logging.ERROR):
        assert not client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal")

    assert "no id" in caplog.text


def test_alias_without_an_id_is_reported_not_raised(monkeypatch, caplog):
    monkeypatch.setattr("pfsense.requests.delete", lambda **_kwargs: FakeResponse())
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [{"host": "nginx", "domain": "lab.internal"}],
        }
    ]

    with caplog.at_level(logging.ERROR):
        assert not client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal")

    assert "missing an id" in caplog.text


def test_an_unreadable_ca_bundle_does_not_escape_as_oserror(monkeypatch):
    """
    requests raises a bare OSError, not a RequestException, when `verify` names an
    unreadable path. Letting it escape crash-looped the container.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    def missing_bundle(**_kwargs):
        raise OSError("Could not find a suitable TLS CA certificate bundle")

    monkeypatch.setattr("pfsense.requests.get", missing_bundle)
    monkeypatch.setattr("pfsense.requests.post", missing_bundle)
    monkeypatch.setattr("pfsense.requests.delete", missing_bundle)

    client = PFSense("pfsense.lab.internal", "secret-token", ca_bundle="/missing/ca.pem")

    assert client.get_all_host_overrides() == []
    assert client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal") is False
    assert client.del_host_override_alias("caddy.lab.internal", "nginx.lab.internal") is False
    assert client.apply_changes() is False


# --- Staged changes stay tracked until confirmed applied ----------------------


def test_a_landed_mutation_marks_unapplied_changes(monkeypatch):
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get(applied=False))
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    assert client.unapplied_changes is False
    # The create lands but the apply never confirms.
    assert client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal") is False
    assert client.unapplied_changes is True


def test_a_landed_mutation_increments_change_count(monkeypatch):
    """
    change_count must move whenever a mutation lands, exactly once per mutation.

    This is the production half of the contract main's coalescer depends on: it compares
    change_count across a call to tell a real mutation from a no-op. unapplied_changes
    cannot answer that, because it saturates at True for the length of a burst.

    Without this test, deleting the increment leaves the whole suite green while
    silently reverting two fixes at once -- every event would look like a no-op, so
    PENDING_CHANGES would never rise, a compose up would go back to one unbound reload
    per container, and a mutation that lands while its apply fails would be stranded
    with nothing pending to retry it.
    """
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get(applied=False))
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    assert client.change_count == 0
    client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal", apply=False)
    assert client.change_count == 1
    client.add_host_override_alias("caddy.lab.internal", "second.lab.internal", apply=False)
    assert client.change_count == 2


def test_a_rejected_mutation_does_not_move_change_count(monkeypatch):
    """
    The other half: a mutation that never reaches pfSense must not look like a change.

    Here the parent host override does not exist, so the method returns False before
    issuing any request. Counting that would make the coalescer treat a no-op as staged
    work -- the exact defect that inflated the pending count during a burst.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: []

    assert client.add_host_override_alias("missing.lab.internal", "nginx.lab.internal") is False
    assert client.change_count == 0
    assert client.unapplied_changes is False


def test_a_confirmed_apply_clears_unapplied_changes(monkeypatch):
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get(applied=True))

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.unapplied_changes = True

    assert client.apply_changes() is True
    assert client.unapplied_changes is False


def test_staging_logs_staged_not_added(monkeypatch, caplog):
    """An operator reading 'removed' must not be told a name is gone while it resolves."""
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.delete", lambda **_kwargs: FakeResponse())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [{"id": 34, "parent_id": 12, "host": "gone", "domain": "lab.internal"}],
        }
    ]

    with caplog.at_level(logging.INFO):
        client.add_host_override_alias(
            "caddy.lab.internal", "nginx.lab.internal", "n", apply=False
        )
        client.del_host_override_alias("caddy.lab.internal", "gone.lab.internal", apply=False)

    assert "staged for host override" in caplog.text
    assert "staged for removal" in caplog.text
    assert "added to host override" not in caplog.text
    assert "removed from host override" not in caplog.text


# --- TLS verification on the apply-status poll --------------------------------


def test_apply_changes_status_poll_constructs_request(monkeypatch):
    """
    The status poll is the newest request site and was the only one with no exact-call
    assertion. Mutation testing proved a hardcoded `verify=False` there passed the whole
    suite — exactly the silent TLS weakening these assertions exist to catch.
    """
    gets = []
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get(calls=gets))

    # A CA bundle path is a verify value that neither True nor False can accidentally
    # match, so "tracks self.verify_ssl" is distinguishable from "equals a constant".
    client = PFSense("pfsense.lab.internal", "secret-token", ca_bundle="/etc/ssl/pfsense-ca.pem")

    assert client.apply_changes() is True
    assert gets == [
        {
            "url": "https://pfsense.lab.internal/api/v2/services/dns_resolver/apply",
            "headers": {
                "X-API-Key": "secret-token",
                "Content-Type": "application/json",
            },
            "verify": "/etc/ssl/pfsense-ca.pem",
            "timeout": 10,
        }
    ]


def test_apply_changes_status_poll_honours_disabled_tls_verification(monkeypatch):
    """With the test above, this pins 'tracks self.verify_ssl', not 'equals a constant'."""
    gets = []
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get(calls=gets))

    client = PFSense("pfsense.lab.internal", "secret-token", verify_ssl=False)

    assert client.apply_changes() is True
    assert [call["verify"] for call in gets] == [False]


# --- Apply confirmation fails closed ------------------------------------------


def test_apply_changes_rejects_a_non_boolean_applied_status(monkeypatch, caplog):
    """
    Only the boolean True confirms a reload.

    bool(data.get('applied')) failed open: the JSON string "false" is truthy, so a
    hostile or buggy response reported the reload as applied. Including "true" and 1
    here makes the strictness deliberate rather than incidental — an unconfirmed reload
    is indistinguishable from a lost update, so it must fail closed.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())

    for status in ("false", "true", 1, 0, "applied", "True", None, {}, []):
        polls = []

        def counting_get(_status=status, _polls=polls, **_kwargs):
            _polls.append("get")
            return FakeResponse({"data": {"applied": _status}})

        monkeypatch.setattr("pfsense.requests.get", counting_get)

        client = PFSense("pfsense.lab.internal", "secret-token")

        caplog.clear()
        with caplog.at_level(logging.ERROR):
            assert client.apply_changes() is False, status

        assert len(polls) == pfsense.APPLY_POLL_ATTEMPTS, status
        assert "remain staged" in caplog.text, status


def test_apply_changes_treats_a_non_dict_data_as_not_applied(monkeypatch):
    """
    A non-dict `data` must degrade to "not applied", never raise out of this module.

    No new guard is needed: response.json().get('data', {}) raises AttributeError for a
    non-dict body and data.get('applied') raises it for None/str/list/int, and
    AttributeError is already caught. This pins that, so the guard cannot be dropped.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())

    for payload in ({"data": None}, {"data": "applied"}, {"data": ["applied"]}, {"data": 1}):
        monkeypatch.setattr(
            "pfsense.requests.get",
            lambda _payload=payload, **_kwargs: FakeResponse(_payload),
        )

        client = PFSense("pfsense.lab.internal", "secret-token")

        assert client.apply_changes() is False, payload


def test_a_string_false_status_keeps_unapplied_changes_set(monkeypatch):
    """
    The invariant a fail-open confirmation actually endangers.

    Clearing unapplied_changes on an unconfirmed reload strands the change: nothing is
    pending, so nothing ever retries the apply and the alias never goes live.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get(applied="false"))

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.unapplied_changes = True

    assert client.apply_changes() is False
    assert client.unapplied_changes is True


# --- sanitize_for_log: the injection barrier for logs --------------------------


def test_sanitize_for_log_escapes_control_characters():
    """Control characters must appear escaped, so no label can fabricate a log record."""
    assert pfsense.sanitize_for_log("a\nb") == "a\\nb"
    assert pfsense.sanitize_for_log("a\rb") == "a\\rb"
    assert pfsense.sanitize_for_log("a\tb") == "a\\tb"
    assert pfsense.sanitize_for_log("a\x00b") == "a\\x00b"
    assert pfsense.sanitize_for_log("a\x1bb") == "a\\x1bb"
    # U+2028/U+2029 break lines for some log viewers even though they are not \n.
    assert pfsense.sanitize_for_log("a\u2028b") == "a\\u2028b"
    assert pfsense.sanitize_for_log("a\u2029b") == "a\\u2029b"
    # Backslash itself escapes, so the mapping is injective: a literal backslash-n
    # cannot be typed to render identically to an escaped newline.
    assert pfsense.sanitize_for_log("a\\nb") == "a\\\\nb"
    assert pfsense.sanitize_for_log("a\\nb") != pfsense.sanitize_for_log("a\nb")


def test_sanitize_for_log_preserves_ordinary_values():
    """
    On printable values the helper is the identity, so operator-facing wording is
    unchanged. That is why no existing assertion moves, and why repr()/!r was rejected.
    """
    assert pfsense.sanitize_for_log("nginx.lab.internal") == "nginx.lab.internal"
    assert pfsense.sanitize_for_log("nginx service") == "nginx service"
    # Printable non-ASCII survives; a blanket unicode_escape would mangle it.
    assert pfsense.sanitize_for_log("café") == "café"
    assert pfsense.sanitize_for_log(None) == "None"
    assert pfsense.sanitize_for_log(12345) == "12345"
    assert pfsense.sanitize_for_log(["nginx", "lab"]) == "['nginx', 'lab']"


def test_sanitize_for_log_truncates_oversized_values():
    """
    Escape first, then truncate.

    Truncating first would let a 512-character control-character run expand to roughly
    3 KB of log, so the all-newlines case is what actually pins the ordering.
    """
    bound = pfsense.LOG_VALUE_MAX_CHARS + len(pfsense.LOG_TRUNCATION_MARKER)

    plain = pfsense.sanitize_for_log("a" * 10000)
    assert len(plain) == bound
    assert plain.endswith(pfsense.LOG_TRUNCATION_MARKER)
    # Count the leading run rather than every "a": the marker contains one of its own.
    assert plain.startswith("a" * pfsense.LOG_VALUE_MAX_CHARS)
    assert not plain.startswith("a" * (pfsense.LOG_VALUE_MAX_CHARS + 1))

    newlines = pfsense.sanitize_for_log("\n" * 10000)
    assert len(newlines) == bound
    assert "\n" not in newlines
    assert newlines.startswith("\\n")
    assert newlines.endswith(pfsense.LOG_TRUNCATION_MARKER)


# --- Log forgery: labels and API payloads are untrusted at every log site ------

# The proof of concept from the 2026-08-01 review, confirmed by execution. It splits
# into six NON-EMPTY labels, so it survives the label-count check and is rejected by
# DNS_LABEL_PATTERN instead. The two rejection branches therefore need different
# inputs — feeding this one to both makes the label-count test pass vacuously.
FORGED_LABEL_FQDN = (
    "a.b\n2026-08-01 21:00:00 - INFO - "
    "Alias attacker.lab.internal added to host override parent.lab.internal"
)
FORGED_LABEL_FQDN_ESCAPED = (
    "a.b\\n2026-08-01 21:00:00 - INFO - "
    "Alias attacker.lab.internal added to host override parent.lab.internal"
)

# One label, no dot: this is what reaches the label-count rejection.
FORGED_COUNT_FQDN = "a\n2026-08-02 12:00:00 - INFO - forged"
FORGED_COUNT_FQDN_ESCAPED = "a\\n2026-08-02 12:00:00 - INFO - forged"


def test_invalid_fqdn_warning_cannot_forge_a_log_record(caplog):
    """The label-count rejection logs the value it just rejected; it must escape it."""
    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        assert client.find_host_name(FORGED_COUNT_FQDN) is None

    assert_no_forged_log_records(caplog)
    rejected = [m for m in log_messages(caplog) if "Invalid FQDN" in m]
    assert len(rejected) == 1
    # The evidence survives: escaped, not stripped.
    assert FORGED_COUNT_FQDN_ESCAPED in rejected[0]


def test_invalid_fqdn_label_warning_cannot_forge_a_log_record(caplog):
    """
    The label-pattern rejection is where most hostile input actually lands.

    It used to drop the value entirely — a lossy workaround for this very risk. With
    escaping it can log the value again, which is what an operator needs to act.
    """
    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        assert client.find_host_name(FORGED_LABEL_FQDN) is None

    assert_no_forged_log_records(caplog)
    rejected = [m for m in log_messages(caplog) if "Invalid FQDN" in m]
    assert len(rejected) == 1
    assert FORGED_LABEL_FQDN_ESCAPED in rejected[0]


def test_host_override_not_found_warning_cannot_forge_a_log_record(caplog):
    """Both mutators log the parent FQDN before anything has validated it."""
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: []
    hostile_parent = "caddy.lab.internal\n2026-08-02 12:00:00 - INFO - forged"
    escaped_parent = "caddy.lab.internal\\n2026-08-02 12:00:00 - INFO - forged"

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias(hostile_parent, "nginx.lab.internal") is False
        assert client.del_host_override_alias(hostile_parent, "nginx.lab.internal") is False

    assert_no_forged_log_records(caplog)
    not_found = [m for m in log_messages(caplog) if "Host override" in m and "not found" in m]
    assert len(not_found) == 2
    for message in not_found:
        assert escaped_parent in message


def test_alias_not_found_warning_cannot_forge_a_log_record(caplog):
    """The removal path logs the alias FQDN after _split_fqdn has already rejected it."""
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]
    hostile_alias = "nginx\n2026-08-02 12:00:00 - INFO - forged.lab.internal"
    escaped_alias = "nginx\\n2026-08-02 12:00:00 - INFO - forged.lab.internal"

    with caplog.at_level(logging.WARNING):
        assert client.del_host_override_alias("caddy.lab.internal", hostile_alias) is False

    assert_no_forged_log_records(caplog)
    missing = [m for m in log_messages(caplog) if "not found in host override" in m]
    assert len(missing) == 1
    assert escaped_alias in missing[0]


def test_already_mapped_warning_escapes_api_supplied_values(caplog):
    """
    Second-order forgery: the values here come from the pfSense API response, not from
    a container label, and API responses are untrusted input too.

    Reaching this branch needs find_host_name to resolve via the ALIAS match, so the
    override's own host/domain must not match while one of its aliases does.
    """
    hostile_host = "caddy\n2026-08-02 12:00:00 - INFO - forged"
    hostile_domain = "lab.internal\r2026-08-02 12:00:00 - INFO - forged"
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": hostile_host,
            "domain": hostile_domain,
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}
            ],
        }
    ]

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal") is False

    assert_no_forged_log_records(caplog)
    mapped = [m for m in log_messages(caplog) if "already mapped" in m]
    assert len(mapped) == 1
    assert "caddy\\n2026-08-02 12:00:00 - INFO - forged" in mapped[0]
    assert "lab.internal\\r2026-08-02 12:00:00 - INFO - forged" in mapped[0]


def test_already_mapped_warning_survives_an_override_without_host_keys(caplog):
    """
    find_host_name returns an override whenever one of its *aliases* matches, regardless
    of that override's own keys, so indexing alias['host'] here raised KeyError straight
    out of this module — past main()'s except clause and into sys.exit(1). API failures
    log and return False; they never raise.
    """
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}
            ],
        }
    ]

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal") is False

    assert "already mapped" in caplog.text


def test_valid_fqdn_log_wording_is_unchanged(caplog):
    """
    Sanitizing a clean value must be the identity, wording included.

    This is the defense against repr()/!r being reintroduced: quoting and reformatting
    every FQDN would change what operators read for the overwhelmingly common case.
    """
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: []

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal") is False

    assert "Host override caddy.lab.internal not found." in log_messages(caplog)


def test_api_error_log_cannot_forge_a_log_record(monkeypatch, caplog):
    """
    A requests exception carries off-box string data, so this log site is not internal.

    The HTTP reason phrase comes straight off the wire: http.client parses
    `HTTP/1.1 500 Internal\\x1b[31mError\\x07` into r.reason verbatim, and that text
    reaches the exception message. Anyone who can answer as the pfSense host — or sit
    in front of it — can therefore fabricate a log record from an error path.
    """
    hostile = "upstream said: boom\n2026-08-02 12:00:00 - INFO - forged"
    response = FakeResponse()
    error = requests.HTTPError(hostile)
    error.response = response

    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.get", lambda **_kwargs: FakeResponse(error=error))

    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.ERROR):
        assert client.get_all_host_overrides() == []

    assert_no_forged_log_records(caplog)
    failed = [m for m in log_messages(caplog) if "API call failed" in m]
    assert len(failed) == 1
    # We escape, we do not discard: the diagnostic text an operator needs survives.
    assert "\\n" in failed[0]
    assert "upstream said: boom" in failed[0]
    assert "forged" in failed[0]
    # The status code is an int from requests' own parser, not wire string data, so it
    # is not sanitized and its wording is unchanged.
    assert "HTTP Status Code: 500" in caplog.text


# --- Sanitization is bounded, and applies to the log only ----------------------


# Lengths that straddle the 253-character presentation-format bound. Three 63-character
# labels plus their three dots come to 192, so the final label decides the total; every
# label in all four is individually valid, which is the whole point — label validity has
# never bounded the total.
FQDN_252 = ".".join(["a" * 63] * 3 + ["a" * 60])
FQDN_253 = ".".join(["a" * 63] * 3 + ["a" * 61])
FQDN_254 = ".".join(["a" * 63] * 3 + ["a" * 62])
# 40 labels of 60 characters: 2439 characters, every label valid.
FQDN_HUGE = ".".join(["a" * 60] * 40)
# What _split_fqdn must return as the domain half of each.
FQDN_253_DOMAIN = ".".join(["a" * 63] * 2 + ["a" * 61])
FQDN_254_DOMAIN = ".".join(["a" * 63] * 2 + ["a" * 62])


def test_a_maximal_length_fqdn_reaches_the_payload_byte_for_byte(monkeypatch, caplog):
    """
    Sanitization is a *rendering* step and the length cap is a *validation* step;
    neither may alter the value that goes into the API payload.

    An FQDN of exactly MAX_FQDN_CHARS is the longest value that can legitimately reach
    the payload, so it is where a cap implemented as truncation — or a payload value
    routed through sanitize_for_log() — would show up: pfSense would get an alias whose
    name is not the name the operator asked for. At 253 characters the value is also
    under LOG_VALUE_MAX_CHARS, so the accepted case carries no truncation marker
    anywhere, in the payload or in the log.
    """
    posts = []

    def fake_post(url, headers, verify, timeout, json=None):
        posts.append({"url": url, "json": json})
        return FakeResponse()

    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    with caplog.at_level(logging.INFO):
        assert client.add_host_override_alias("caddy.lab.internal", FQDN_253) is True

    added = [m for m in log_messages(caplog) if "added to host override" in m]
    assert len(added) == 1
    # An accepted value renders verbatim: no escaping, no truncation, no marker.
    assert FQDN_253 in added[0]
    assert added[0].count(pfsense.LOG_TRUNCATION_MARKER) == 0

    # The load-bearing assertion: the alias-creation payload is byte-for-byte the
    # validated value, with no marker, no escape, and no truncation.
    alias_post = posts[0]
    assert alias_post["url"] == (
        "https://pfsense.lab.internal/api/v2/services/dns_resolver/host_override/alias"
    )
    assert alias_post["json"] == {
        "parent_id": "12",
        "host": "a" * 63,
        "domain": FQDN_253_DOMAIN,
        "descr": "",
    }
    assert f'{alias_post["json"]["host"]}.{alias_post["json"]["domain"]}' == FQDN_253
    assert pfsense.LOG_TRUNCATION_MARKER not in alias_post["json"]["domain"]
    assert "\\" not in alias_post["json"]["domain"]


def test_already_mapped_warning_truncates_oversized_api_values(caplog):
    """
    Two of the three values on this line are unbounded, and both must be capped.

    The host and domain come from the pfSense API response, which can return anything —
    nothing in this service bounds them, so they need the per-value cap. The third value,
    the label-supplied alias_fqdn, used to be unbounded too and this test used to pin all
    three; the 253-character bound in _split_fqdn now rejects an over-long alias before
    execution ever reaches this line, so the alias here is a validated one. That
    label-supplied-unbounded property now lives in
    test_an_oversized_fqdn_is_truncated_in_the_rejection_log.

    Requiring two markers pins each API value independently: the cap is per value, not
    per message, and removing the call from either half drops the count to 1. Capping the
    whole message would make each value's rendering depend on its neighbours and break
    the exact-wording guarantee, which holds here too — the bounded alias renders
    unchanged on the same line as two truncations.
    """
    # The alias branch of find_host_name resolves the parent, so the override's own
    # oversized name lands on the line beside the alias that matched.
    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "c" * 5000,
            "domain": "d" * 5000,
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "nginx", "domain": "lab.internal"}
            ],
        }
    ]

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias("caddy.lab.internal", "nginx.lab.internal") is False

    assert_no_forged_log_records(caplog)
    mapped = [m for m in log_messages(caplog) if "already mapped" in m]
    assert len(mapped) == 1
    assert mapped[0].count(pfsense.LOG_TRUNCATION_MARKER) == 2
    assert len(mapped[0]) < 2 * pfsense.LOG_VALUE_MAX_CHARS + 200
    assert "nginx.lab.internal" in mapped[0]
    assert "c" * 5000 not in mapped[0]
    assert "d" * 5000 not in mapped[0]
    # The evidence survives for both truncated values.
    assert "c" * 100 in mapped[0]
    assert "d" * 100 in mapped[0]


# --- The payload barrier is bounded --------------------------------------------


def warning_messages(caplog):
    """The formatted message of each captured record at WARNING or above."""
    return [
        record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING
    ]


def test_split_fqdn_accepts_an_fqdn_at_the_length_limit(caplog):
    """
    Exactly MAX_FQDN_CHARS is legal, so the comparison is `>`, not `>=`.

    RFC 1035 bounds the presentation form at 253 characters, and this value is the
    longest legal one. An off-by-one here rejects a name pfSense would happily hold.
    """
    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        result = client._split_fqdn(FQDN_253, "add_host_override_alias")

    assert pfsense.MAX_FQDN_CHARS == 253
    assert len(FQDN_253) == pfsense.MAX_FQDN_CHARS
    assert len(FQDN_253_DOMAIN) == 189
    assert result == ("a" * 63, FQDN_253_DOMAIN)
    assert warning_messages(caplog) == []


def test_split_fqdn_accepts_an_fqdn_one_character_under_the_limit(caplog):
    """The ordinary side of the boundary: under the cap is unaffected by the cap."""
    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        result = client._split_fqdn(FQDN_252, "add_host_override_alias")

    assert len(FQDN_252) == pfsense.MAX_FQDN_CHARS - 1
    assert result == ("a" * 63, ".".join(["a" * 63] * 2 + ["a" * 60]))
    assert warning_messages(caplog) == []


def test_split_fqdn_rejects_an_fqdn_one_character_over_the_limit(caplog):
    """
    One character over is rejected, and says so distinguishably.

    Every label here is valid, which is the finding: DNS_LABEL_PATTERN caps a label at
    63 characters and nothing caps the count, so all-valid labels can add up to any
    length at all. The rejection wording has to be tellable apart from the two existing
    "Invalid FQDN" branches — a test that cannot say which branch fired cannot prove the
    length check exists rather than some other rule catching the value by accident.
    """
    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        result = client._split_fqdn(FQDN_254, "add_host_override_alias")

    assert len(FQDN_254) == pfsense.MAX_FQDN_CHARS + 1
    assert result is None
    warnings = warning_messages(caplog)
    assert len(warnings) == 1
    assert "exceeds 253 characters" in warnings[0]
    assert "add_host_override_alias" in warnings[0]


def test_an_oversized_alias_is_rejected_before_any_request_is_made(monkeypatch):
    """
    Rejection means no request at all, not a shortened one.

    This is the test that fails if the bound is implemented as truncation: truncating a
    2439-character FQDN to 253 would create a real alias under a name nobody asked for,
    which is worse than the unbounded payload it was meant to fix. Nothing may be sent,
    and nothing may be left staged for a later apply to push live.
    """
    posts = []
    gets = []
    deletes = []

    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        "pfsense.requests.post",
        lambda url, **_kwargs: posts.append(url) or FakeResponse(),
    )
    monkeypatch.setattr(
        "pfsense.requests.get",
        lambda url, **_kwargs: gets.append(url) or FakeResponse(),
    )
    monkeypatch.setattr(
        "pfsense.requests.delete",
        lambda url, **_kwargs: deletes.append(url) or FakeResponse(),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")

    assert client.add_host_override_alias("caddy.lab.internal", FQDN_HUGE) is False
    assert posts == []
    assert gets == []
    assert deletes == []
    assert client.unapplied_changes is False


def test_an_oversized_fqdn_is_truncated_in_the_rejection_log(monkeypatch, caplog):
    """
    The rejection branch logs the value it just rejected, so the log cap must hold here.

    An over-long FQDN is exactly the value a hostile or careless label can make
    arbitrarily large, and under --restart=always the rejection repeats on every start.
    Bounding the payload does not bound the log: the two caps are separate, and this is
    the case that needs both.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", lambda **_kwargs: FakeResponse())

    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias("caddy.lab.internal", FQDN_HUGE) is False

    assert_no_forged_log_records(caplog)
    warnings = warning_messages(caplog)
    assert len(warnings) == 1
    assert pfsense.LOG_TRUNCATION_MARKER in warnings[0]
    assert len(warnings[0]) < pfsense.LOG_VALUE_MAX_CHARS + 200
    assert FQDN_HUGE not in warnings[0]
    # The evidence survives: an operator can still see what was asked for.
    assert "a" * 60 in warnings[0]


def test_an_oversized_host_override_fqdn_is_rejected(monkeypatch):
    """
    The parent FQDN crosses the same boundary as the alias and gets the same rule.

    The parent is never written into a payload as a name — it is resolved to an id — but
    it is matched against every host override, and an unbounded value has no business
    getting that far. The override below deliberately exists under the oversized name,
    so only the length check can stop this.
    """
    posts = []

    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr(
        "pfsense.requests.post",
        lambda url, **_kwargs: posts.append(url) or FakeResponse(),
    )
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "a" * 63, "domain": FQDN_254_DOMAIN, "aliases": []}
    ]

    assert client.add_host_override_alias(FQDN_254, "nginx.lab.internal") is False
    assert posts == []


def test_an_oversized_alias_cannot_be_removed_and_says_so(monkeypatch, caplog):
    """
    An ACCEPTED REGRESSION, pinned here so nobody "fixes" it by accident.

    One validation rule guards both directions. An over-long alias created before this
    bound existed — or created by hand in the webGUI — can therefore no longer be removed
    by this service: the removal path routes the same FQDN through the same _split_fqdn
    and gets the same rejection. The remedy is one delete in the pfSense webGUI.

    The alternative, validating only on the way in, means the removal path takes an
    unbounded value from a container label and matches it against the config, which is
    the barrier having a hole in it in one direction. A single rule that is occasionally
    inconvenient beats two rules that disagree. Do not add a "removals are exempt" branch
    to make this test pass; it is asserting the refusal, not tolerating it.
    """
    deletes = []

    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())
    monkeypatch.setattr(
        "pfsense.requests.delete",
        lambda url, **_kwargs: deletes.append(url) or FakeResponse(),
    )

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {
            "id": 12,
            "host": "caddy",
            "domain": "lab.internal",
            "aliases": [
                {"id": 34, "parent_id": 12, "host": "a" * 63, "domain": FQDN_254_DOMAIN}
            ],
        }
    ]

    with caplog.at_level(logging.WARNING):
        assert client.del_host_override_alias("caddy.lab.internal", FQDN_254) is False

    assert deletes == []
    oversized = [m for m in warning_messages(caplog) if "exceeds 253 characters" in m]
    assert len(oversized) == 1


# --- Descriptions are cleaned, not rejected, and never escaped ------------------


def test_clean_alias_descr_replaces_unprintable_characters():
    """
    It REPLACES; it does not escape. This is not sanitize_for_log.

    A description is written into the pfSense configuration and shown in the webGUI, so
    the goal is a value that is harmless to store and display, not one that round-trips
    to the original. Escaping a newline to a literal backslash-n would put log furniture
    into firewall config; replacing it with a space leaves something an operator reads
    without noticing anything happened.
    """
    result = pfsense.clean_alias_descr("web\nserver\r\nprod")

    assert result == "web server  prod"
    assert "\n" not in result
    assert "\\n" not in result


def test_clean_alias_descr_truncates_at_the_cap():
    """
    Truncation is silent: no marker, because the marker is a log convention.

    LOG_TRUNCATION_MARKER exists to tell an operator reading a log line that they are
    seeing part of a value. Writing it into a firewall config field instead invents a
    description that claims something about its own provenance, in data pfSense keeps.
    """
    result = pfsense.clean_alias_descr("a" * 10000)

    assert result == "a" * pfsense.ALIAS_DESCR_MAX_CHARS
    assert pfsense.ALIAS_DESCR_MAX_CHARS == 255
    assert pfsense.LOG_TRUNCATION_MARKER not in result


def test_clean_alias_descr_leaves_an_ordinary_description_unchanged():
    """
    The common case is the identity, em dash included.

    str.isprintable() is the rule, not an ASCII allowlist: a description is free text a
    human wrote, and mangling accents, currency symbols, or punctuation would be a
    visible regression for a value that was never a threat.
    """
    assert pfsense.clean_alias_descr("My nginx webserver — prod") == "My nginx webserver — prod"


def test_an_oversized_description_is_truncated_in_the_payload_not_rejected(monkeypatch):
    """
    The asymmetry with the FQDN rule, stated as a test.

    A wrong FQDN is a wrong DNS record, so an over-long one is rejected. A wrong
    description is cosmetic, so an over-long one is trimmed and the alias is still
    created — refusing to create DNS because a label had a chatty description would be
    the barrier causing the outage it exists to prevent. The name fields are untouched.
    """
    posts = []

    def fake_post(url, headers, verify, timeout, json=None):
        posts.append({"url": url, "json": json})
        return FakeResponse()

    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    assert client.add_host_override_alias(
        "caddy.lab.internal", "nginx.lab.internal", "x" * 10000
    ) is True
    assert posts[0]["json"]["descr"] == "x" * 255
    assert posts[0]["json"]["host"] == "nginx"
    assert posts[0]["json"]["domain"] == "lab.internal"


def test_a_hostile_description_cannot_forge_a_log_record_or_reach_the_payload_raw(
    monkeypatch, caplog
):
    """
    The description label never passed either barrier: not _split_fqdn, not the log.

    pfsense.dns.description is attacker-controlled in exactly the way the alias label is,
    and it went into the API payload untouched. A newline in it is a forged log record on
    any line that echoes it and an unexpected control character in stored config.
    """
    posts = []

    def fake_post(url, headers, verify, timeout, json=None):
        posts.append({"url": url, "json": json})
        return FakeResponse()

    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    with caplog.at_level(logging.INFO):
        assert client.add_host_override_alias(
            "caddy.lab.internal",
            "nginx.lab.internal",
            "ok\n2026-08-02 12:00:00 - INFO - forged",
        ) is True

    descr = posts[0]["json"]["descr"]
    assert "ok" in descr
    assert "forged" in descr
    assert "\n" not in descr
    assert "\\n" not in descr
    assert_no_forged_log_records(caplog)


def test_a_cleaned_description_is_reported_once(caplog, monkeypatch):
    """
    Silently rewriting operator-supplied config is how a mystery starts.

    One warning, naming the alias so the operator knows which container to fix. Once, not
    once per label and not on every event: the message is diagnostic, not a running
    commentary, and it must stay on a single line like every other log call here.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias(
            "caddy.lab.internal", "nginx.lab.internal", "x" * 10000
        ) is True

    cleaned = [m for m in warning_messages(caplog) if "was cleaned" in m]
    assert len(cleaned) == 1
    assert "nginx.lab.internal" in cleaned[0]
    assert "\n" not in cleaned[0]


def test_an_unchanged_description_logs_no_warning(caplog, monkeypatch):
    """
    The warning is conditional on the value actually changing.

    Warning unconditionally would fire on every ordinary alias, and a warning that always
    fires is one an operator learns to scroll past — including the time it meant
    something.
    """
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", lambda **_kwargs: FakeResponse())
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    with caplog.at_level(logging.INFO):
        assert client.add_host_override_alias(
            "caddy.lab.internal", "nginx.lab.internal", "nginx service"
        ) is True

    assert [m for m in log_messages(caplog) if "was cleaned" in m] == []


# --- Each warning reports the cap it actually enforces --------------------------
#
# The tests above grep for "exceeds 253 characters" and read ALIAS_DESCR_MAX_CHARS,
# which pins the LITERAL in the message and the VALUE of the constant — but not the tie
# between them. Nothing there fails if a message advertises one number while the code
# enforces another. Asserting f"capped at {pfsense.ALIAS_DESCR_MAX_CHARS} characters"
# would be a tautology as long as the constant is still 255: the interpolated and the
# hardcoded message are the same string. The only non-tautological form is to move the
# constant and check that the enforced behavior and the reported number move with it.


def test_the_description_cap_warning_reports_the_enforced_cap(monkeypatch, caplog):
    """
    The number in the warning must be the number the code enforced, not a copy of it.

    A warning that says "capped at 255" while the code truncates at 64 sends an operator
    to count characters against a limit that is not the limit, and the log is the only
    place the truncation is visible at all — pfSense just holds the shortened value. This
    is the same class of defect either cap could develop; the FQDN side avoids it by
    interpolating its constant, and this side must do the same rather than stay correct
    by coincidence.
    """
    posts = []

    def fake_post(url, headers, verify, timeout, json=None):
        posts.append({"url": url, "json": json})
        return FakeResponse()

    monkeypatch.setattr(pfsense, "ALIAS_DESCR_MAX_CHARS", 64)
    monkeypatch.setattr("pfsense.time.sleep", lambda _seconds: None)
    monkeypatch.setattr("pfsense.requests.post", fake_post)
    monkeypatch.setattr("pfsense.requests.get", applied_status_get())

    client = PFSense("pfsense.lab.internal", "secret-token")
    client.get_all_host_overrides = lambda: [
        {"id": 12, "host": "caddy", "domain": "lab.internal", "aliases": []}
    ]

    with caplog.at_level(logging.WARNING):
        assert client.add_host_override_alias(
            "caddy.lab.internal", "nginx.lab.internal", "x" * 500
        ) is True

    # The cap moved, so the enforcement moved with it.
    assert posts[0]["json"]["descr"] == "x" * 64
    cleaned = [m for m in warning_messages(caplog) if "was cleaned" in m]
    assert len(cleaned) == 1
    assert "64" in cleaned[0]
    # The load-bearing assertion: a hardcoded 255 in the message survives every other
    # check in this suite, because every other check runs with the cap set to 255.
    assert "255" not in cleaned[0]


def test_the_fqdn_rejection_warning_reports_the_enforced_cap(monkeypatch, caplog):
    """
    The same tie on the FQDN side, which is correct today by construction rather than
    by test.

    This one passes as written, and that is the point: the pair exists so neither cap
    depends on nobody having made the copy-paste mistake yet. Pinning only the side that
    lost leaves the other free to regress in exactly the way this one just did.
    """
    monkeypatch.setattr(pfsense, "MAX_FQDN_CHARS", 20)

    client = PFSense("pfsense.lab.internal", "secret-token")

    with caplog.at_level(logging.WARNING):
        result = client._split_fqdn("a" * 15 + ".lab.internal", "unit")

    assert result is None
    warnings = warning_messages(caplog)
    assert len(warnings) == 1
    assert "exceeds 20 characters" in warnings[0]
    assert "unit" in warnings[0]
    assert "253" not in warnings[0]
