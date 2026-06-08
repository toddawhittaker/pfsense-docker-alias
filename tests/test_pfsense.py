import requests

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
            "verify": False,
            "timeout": 10,
        }
    ]


def test_get_all_host_overrides_returns_empty_list_on_http_error(monkeypatch):
    monkeypatch.setattr(
        "pfsense.requests.get",
        lambda **_kwargs: FakeResponse(error=http_error()),
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

    client = PFSense("pfsense.lab.internal", "secret-token")
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
