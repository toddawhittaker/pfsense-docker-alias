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


def applied_status_get(applied=True):
    """A requests.get stand-in for the apply endpoint's status poll."""
    return lambda **_kwargs: FakeResponse({"data": {"applied": applied}})


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
