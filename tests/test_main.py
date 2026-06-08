import importlib
import sys
import types


class DockerException(Exception):
    pass


class DockerNotFound(DockerException):
    pass


class FakeDockerClient:
    def __init__(self):
        self.containers = types.SimpleNamespace(get=self.get_container, list=lambda: [])
        self.container = None
        self.closed = False

    def get_container(self, _container_id):
        return self.container

    def events(self, decode=True):
        assert decode is True
        return iter(())

    def close(self):
        self.closed = True


def load_main(monkeypatch, verify_ssl=None, ca_bundle=None):
    fake_client = FakeDockerClient()
    fake_docker = types.SimpleNamespace(
        from_env=lambda: fake_client,
        errors=types.SimpleNamespace(DockerException=DockerException, NotFound=DockerNotFound),
    )

    monkeypatch.setenv("PFSENSE_HOSTNAME", "pfsense.lab.internal")
    monkeypatch.setenv("PFSENSE_API_TOKEN", "test-token")
    if verify_ssl is None:
        monkeypatch.delenv("PFSENSE_VERIFY_SSL", raising=False)
    else:
        monkeypatch.setenv("PFSENSE_VERIFY_SSL", verify_ssl)

    if ca_bundle is None:
        monkeypatch.delenv("PFSENSE_CA_BUNDLE", raising=False)
    else:
        monkeypatch.setenv("PFSENSE_CA_BUNDLE", ca_bundle)

    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    sys.modules.pop("main", None)

    module = importlib.import_module("main")
    return module, fake_client


def test_parse_alias_labels_returns_alias_config(monkeypatch):
    main, _fake_client = load_main(monkeypatch)

    alias_config = main.parse_alias_labels(
        {
            "pfsense.dns.override": "caddy.lab.internal",
            "pfsense.dns.alias": "nginx.lab.internal",
            "pfsense.dns.description": "nginx service",
            "pfsense.dns.remove_on_stop": "true",
        }
    )

    assert alias_config == {
        "host_override_fqdn": "caddy.lab.internal",
        "alias_fqdn": "nginx.lab.internal",
        "alias_descr": "nginx service",
        "remove_on_stop": True,
    }


def test_tls_verification_env_defaults_to_true_and_only_false_disables(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    assert main.PFSENSE_VERIFY_SSL is True

    main, _fake_client = load_main(monkeypatch, verify_ssl="not-a-bool")
    assert main.PFSENSE_VERIFY_SSL is True

    main, _fake_client = load_main(monkeypatch, verify_ssl="false")
    assert main.PFSENSE_VERIFY_SSL is False


def test_parse_alias_labels_ignores_incomplete_labels(monkeypatch):
    main, _fake_client = load_main(monkeypatch)

    assert main.parse_alias_labels({}) is None
    assert main.parse_alias_labels({"pfsense.dns.override": "caddy.lab.internal"}) is None
    assert main.parse_alias_labels({"pfsense.dns.alias": "nginx.lab.internal"}) is None


def test_get_alias_event_action_handles_start_and_stop(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    labels = {
        "pfsense.dns.override": "caddy.lab.internal",
        "pfsense.dns.alias": "nginx.lab.internal",
        "pfsense.dns.remove_on_stop": "true",
    }

    start_action = main.get_alias_event_action("start", labels)
    stop_action = main.get_alias_event_action("stop", labels)

    assert start_action[0] == "add"
    assert start_action[1]["alias_fqdn"] == "nginx.lab.internal"
    assert stop_action[0] == "remove"
    assert stop_action[1]["host_override_fqdn"] == "caddy.lab.internal"


def test_get_alias_event_action_requires_exact_remove_on_stop_value(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    labels = {
        "pfsense.dns.override": "caddy.lab.internal",
        "pfsense.dns.alias": "nginx.lab.internal",
        "pfsense.dns.remove_on_stop": "True",
    }

    assert main.get_alias_event_action("stop", labels) is None


def test_handle_container_event_dispatches_start(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    calls = []
    fake_client.container = types.SimpleNamespace(
        name="nginx",
        attrs={
            "Config": {
                "Labels": {
                    "pfsense.dns.override": "caddy.lab.internal",
                    "pfsense.dns.alias": "nginx.lab.internal",
                    "pfsense.dns.description": "nginx service",
                }
            }
        },
    )
    monkeypatch.setattr(
        main,
        "process_start_event",
        lambda host_override, alias, description: calls.append((host_override, alias, description)),
    )

    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    assert calls == [("caddy.lab.internal", "nginx.lab.internal", "nginx service")]


def test_handle_container_event_dispatches_stop_when_enabled(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    calls = []
    fake_client.container = types.SimpleNamespace(
        name="nginx",
        attrs={
            "Config": {
                "Labels": {
                    "pfsense.dns.override": "caddy.lab.internal",
                    "pfsense.dns.alias": "nginx.lab.internal",
                    "pfsense.dns.remove_on_stop": "true",
                }
            }
        },
    )
    monkeypatch.setattr(
        main,
        "process_stop_event",
        lambda host_override, alias: calls.append((host_override, alias)),
    )

    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "stop"})

    assert calls == [("caddy.lab.internal", "nginx.lab.internal")]
