import importlib
import logging
import sys
import time
import types

import pfsense


class DockerException(Exception):
    pass


class DockerNotFound(DockerException):
    pass


class FakeDockerClient:
    def __init__(self):
        self.containers = types.SimpleNamespace(get=self.get_container, list=lambda: [])
        self.container = None
        self.closed = False
        self.event_windows = []

    def get_container(self, _container_id):
        return self.container

    def events(self, since=None, until=None, decode=True):
        assert decode is True
        self.event_windows.append((since, until))
        return iter(())

    def close(self):
        self.closed = True


def load_main(monkeypatch, verify_ssl=None, ca_bundle=None, add_on_startup=None):
    fake_client = FakeDockerClient()
    fake_docker = types.SimpleNamespace(
        from_env=lambda: fake_client,
        errors=types.SimpleNamespace(DockerException=DockerException, NotFound=DockerNotFound),
    )

    monkeypatch.setenv("PFSENSE_HOSTNAME", "pfsense.lab.internal")
    monkeypatch.setenv("PFSENSE_API_TOKEN", "test-token")
    if add_on_startup is None:
        monkeypatch.delenv("ADD_ALIASES_ON_STARTUP", raising=False)
    else:
        monkeypatch.setenv("ADD_ALIASES_ON_STARTUP", add_on_startup)
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


def test_get_container_labels_returns_empty_dict_for_null_labels(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    container = types.SimpleNamespace(attrs={"Config": {"Labels": None}})

    assert main.get_container_labels(container) == {}


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


def test_get_alias_event_action_handles_die_as_remove(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    labels = {
        "pfsense.dns.override": "caddy.lab.internal",
        "pfsense.dns.alias": "nginx.lab.internal",
        "pfsense.dns.remove_on_stop": "true",
    }

    action = main.get_alias_event_action("die", labels)

    assert action[0] == "remove"
    assert action[1]["alias_fqdn"] == "nginx.lab.internal"


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


def test_handle_container_event_ignores_missing_container_id(monkeypatch, caplog):
    main, _fake_client = load_main(monkeypatch)

    with caplog.at_level(logging.WARNING):
        main.handle_container_event({"Actor": {}, "Action": "start"})

    assert "missing container ID" in caplog.text


def test_main_loop_ignores_malformed_events(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    handled_events = []
    monkeypatch.setattr(
        main,
        "iter_events",
        lambda: iter(
            [
                {},
                {"Type": "container"},
                {"Type": "network", "Action": "start"},
                {"Type": "container", "Action": "start"},
                {"Type": "container", "Action": "die"},
            ]
        ),
    )
    monkeypatch.setattr(main, "handle_container_event", handled_events.append)

    main.main()

    assert handled_events == [
        {"Type": "container", "Action": "start"},
        {"Type": "container", "Action": "die"},
    ]


def test_main_loop_flushes_pending_changes_on_a_window_tick(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    flushes = []
    monkeypatch.setattr(
        main,
        "iter_events",
        lambda: iter([{"Type": "container", "Action": "start"}, None, None]),
    )
    monkeypatch.setattr(main, "handle_container_event", lambda _event: None)
    monkeypatch.setattr(main, "flush_pending_changes", lambda: flushes.append("flush"))

    main.main()

    assert flushes == ["flush", "flush"]


def test_main_loop_reraises_docker_event_errors(monkeypatch):
    main, _fake_client = load_main(monkeypatch)

    def fail_events():
        raise DockerException("event stream failed")

    monkeypatch.setattr(main, "iter_events", fail_events)

    try:
        main.main()
    except DockerException:
        pass
    else:
        raise AssertionError("main() did not raise DockerException")


def test_add_aliases_on_startup_adds_labeled_running_containers(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    calls = []
    fake_client.containers.list = lambda: [
        types.SimpleNamespace(
            id="id-nginx",
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
        ),
        types.SimpleNamespace(
            id="id-unlabeled", name="unlabeled", attrs={"Config": {"Labels": {}}}
        ),
    ]
    applies = []
    main.NAMESERVER = types.SimpleNamespace(
        add_host_override_alias=lambda host_override, alias, description, apply: calls.append(
            (host_override, alias, description, apply)
        )
        or True,
        apply_changes=lambda: applies.append("apply") or True,
    )

    main.add_aliases_on_startup()

    assert calls == [("caddy.lab.internal", "nginx.lab.internal", "nginx service", False)]
    assert applies == ["apply"]


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


def test_handle_container_event_dispatches_die_when_remove_on_stop_enabled(monkeypatch):
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

    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "die"})

    assert calls == [("caddy.lab.internal", "nginx.lab.internal")]


def test_run_exits_nonzero_on_unexpected_exception(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    monkeypatch.setattr(main, "main", lambda: (_ for _ in ()).throw(RuntimeError("boom")))

    try:
        main.run()
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("run() did not exit")


# --- Startup and shutdown contracts -----------------------------------------


def test_get_env_var_exits_when_required_value_missing(monkeypatch, caplog):
    main, _fake_client = load_main(monkeypatch)
    monkeypatch.delenv("DEFINITELY_NOT_SET", raising=False)

    with caplog.at_level(logging.CRITICAL):
        try:
            main.get_env_var("DEFINITELY_NOT_SET")
        except SystemExit as exc:
            assert exc.code == 1
        else:
            raise AssertionError("get_env_var did not exit")

    assert "DEFINITELY_NOT_SET" in caplog.text


def test_import_exits_when_required_env_var_missing(monkeypatch):
    fake_client = FakeDockerClient()
    fake_docker = types.SimpleNamespace(
        from_env=lambda: fake_client,
        errors=types.SimpleNamespace(DockerException=DockerException, NotFound=DockerNotFound),
    )
    monkeypatch.delenv("PFSENSE_HOSTNAME", raising=False)
    monkeypatch.setenv("PFSENSE_API_TOKEN", "test-token")
    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    sys.modules.pop("main", None)

    try:
        importlib.import_module("main")
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("import did not exit")
    finally:
        sys.modules.pop("main", None)


def test_import_exits_when_docker_client_cannot_initialize(monkeypatch):
    def unavailable():
        raise DockerException("cannot connect to docker daemon")

    fake_docker = types.SimpleNamespace(
        from_env=unavailable,
        errors=types.SimpleNamespace(DockerException=DockerException, NotFound=DockerNotFound),
    )
    monkeypatch.setenv("PFSENSE_HOSTNAME", "pfsense.lab.internal")
    monkeypatch.setenv("PFSENSE_API_TOKEN", "test-token")
    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    sys.modules.pop("main", None)

    try:
        importlib.import_module("main")
    except SystemExit as exc:
        assert exc.code == 1
    else:
        raise AssertionError("import did not exit")
    finally:
        sys.modules.pop("main", None)


def test_import_exits_when_the_ca_bundle_is_not_readable(monkeypatch, caplog, tmp_path, capsys):
    """
    An unreadable PFSENSE_CA_BUNDLE must fail loudly at startup, not per request.

    This path used to surface as an opaque crash loop out of `requests` — a bare
    OSError on every call — which pushed operators toward turning TLS verification
    off to get the service running. The message therefore has to name the path so
    the fix is obvious. It is deliberately *not* sanitized: the value comes from
    whoever configures the service, who already owns the process, so escaping it
    would defend against nobody. See AGENTS.md, "Exclusions".
    """
    missing = tmp_path / "no-such-ca.pem"

    with caplog.at_level(logging.CRITICAL):
        try:
            load_main(monkeypatch, ca_bundle=str(missing))
        except SystemExit as exc:
            assert exc.code == 1
        else:
            raise AssertionError("import did not exit")

    critical = [m for m in log_messages(caplog) if "is not readable" in m]
    assert len(critical) == 1
    assert str(missing) in critical[0]
    # The remedy belongs in the message; an operator seeing only "not readable" has
    # no reason to suspect a missing bind mount.
    assert "mounted into the container" in critical[0]
    # Never print the token while reporting a configuration error.
    assert "test-token" not in caplog.text
    assert "test-token" not in capsys.readouterr().err


def test_a_readable_ca_bundle_starts_normally(monkeypatch, tmp_path):
    """
    The startup check rejects an *unreadable* bundle, not the mere presence of one.

    Without this, inverting the condition in main.py would still leave the test
    above green while making every custom CA bundle fatal.
    """
    bundle = tmp_path / "ca.pem"
    bundle.write_text("-- not a real certificate --\n")

    main, _fake_client = load_main(monkeypatch, verify_ssl="false", ca_bundle=str(bundle))

    assert main.PFSENSE_CA_BUNDLE == str(bundle)
    # PFSENSE_CA_BUNDLE wins over PFSENSE_VERIFY_SSL: main passes both down and
    # PFSense resolves the precedence, so main must not drop the bundle here.
    assert main.PFSENSE_VERIFY_SSL is False


def _load_main_with_token(monkeypatch, token):
    """Import main with a specific PFSENSE_API_TOKEN, returning the module."""
    fake_client = FakeDockerClient()
    fake_docker = types.SimpleNamespace(
        from_env=lambda: fake_client,
        errors=types.SimpleNamespace(DockerException=DockerException, NotFound=DockerNotFound),
    )
    monkeypatch.setenv("PFSENSE_HOSTNAME", "pfsense.lab.internal")
    monkeypatch.setenv("PFSENSE_API_TOKEN", token)
    monkeypatch.delenv("ADD_ALIASES_ON_STARTUP", raising=False)
    monkeypatch.delenv("PFSENSE_VERIFY_SSL", raising=False)
    monkeypatch.delenv("PFSENSE_CA_BUNDLE", raising=False)
    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    sys.modules.pop("main", None)
    return importlib.import_module("main")


def test_surrounding_whitespace_is_trimmed_from_the_token(monkeypatch):
    """
    A trailing newline must not break the service, because it is the common case.

    `$(cat /run/secrets/token)` and a file-based Kubernetes secret both produce one.
    requests rejects such a header value and embeds it in the exception message, which
    is how the token used to reach the log. No API token has meaningful surrounding
    whitespace, so trimming is the fix that keeps a working deployment working.
    """
    main = _load_main_with_token(monkeypatch, "  tok-abc123\n")

    assert main.PFSENSE_API_TOKEN == "tok-abc123"


def test_a_whitespace_only_token_exits_at_startup(monkeypatch, caplog):
    with caplog.at_level(logging.CRITICAL):
        try:
            _load_main_with_token(monkeypatch, "   \n")
        except SystemExit as exc:
            assert exc.code == 1
        else:
            raise AssertionError("import did not exit")

    assert "only whitespace" in caplog.text


def test_a_token_with_an_embedded_line_break_exits_without_logging_it(monkeypatch, caplog):
    """
    Rejecting a malformed secret must not print the secret while doing so.

    Trimming handles surrounding whitespace, so what reaches here is embedded -- a line
    break in the middle of a pasted token. The message names the variable, never the
    value, which is the whole point of failing here rather than at the request.
    """
    with caplog.at_level(logging.CRITICAL):
        try:
            _load_main_with_token(monkeypatch, "SUPERSECRET\nTOKEN")
        except SystemExit as exc:
            assert exc.code == 1
        else:
            raise AssertionError("import did not exit")

    assert "PFSENSE_API_TOKEN" in caplog.text
    assert "SUPERSECRET" not in caplog.text
    assert "non-printable" in caplog.text


def test_cleanup_closes_client_and_exits_zero(monkeypatch):
    main, fake_client = load_main(monkeypatch)

    try:
        main.cleanup(15, None)
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("cleanup did not exit")

    assert fake_client.closed is True


def test_cleanup_still_exits_zero_when_close_fails(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)

    def failing_close():
        raise DockerException("close failed")

    fake_client.close = failing_close

    with caplog.at_level(logging.ERROR):
        try:
            main.cleanup(15, None)
        except SystemExit as exc:
            assert exc.code == 0
        else:
            raise AssertionError("cleanup did not exit")

    assert "cleanup" in caplog.text


def test_cleanup_survives_unexpected_close_error(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)

    def failing_close():
        raise RuntimeError("something unexpected")

    fake_client.close = failing_close

    with caplog.at_level(logging.ERROR):
        try:
            main.cleanup(15, None)
        except SystemExit as exc:
            assert exc.code == 0
        else:
            raise AssertionError("cleanup did not exit")

    assert "cleanup" in caplog.text


# --- Resilience: one bad container must not kill the service -----------------


def test_get_container_labels_handles_malformed_attrs(monkeypatch):
    main, _fake_client = load_main(monkeypatch)

    assert main.get_container_labels(types.SimpleNamespace(attrs={})) == {}
    assert main.get_container_labels(types.SimpleNamespace(attrs={"Config": None})) == {}
    assert main.get_container_labels(types.SimpleNamespace(attrs=None)) == {}


def test_handle_container_event_survives_missing_container(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)

    def gone(_container_id):
        raise DockerNotFound("no such container")

    fake_client.containers.get = gone

    with caplog.at_level(logging.WARNING):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    assert "Container not found" in caplog.text


def test_handle_container_event_survives_docker_error(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)

    def unavailable(_container_id):
        raise DockerException("daemon unavailable")

    fake_client.containers.get = unavailable

    with caplog.at_level(logging.ERROR):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    assert "handle_container_event" in caplog.text


def test_handle_container_event_ignores_unlabeled_container(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    calls = []
    fake_client.container = types.SimpleNamespace(
        name="plain", attrs={"Config": {"Labels": {}}}
    )
    monkeypatch.setattr(main, "process_start_event", lambda *a: calls.append(a))

    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    assert calls == []


def test_get_alias_event_action_ignores_unrelated_actions(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    labels = {
        "pfsense.dns.override": "caddy.lab.internal",
        "pfsense.dns.alias": "nginx.lab.internal",
        "pfsense.dns.remove_on_stop": "true",
    }

    assert main.get_alias_event_action("restart", labels) is None
    assert main.get_alias_event_action("start", {}) is None


def test_add_aliases_on_startup_survives_docker_error(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)
    calls = []

    def unavailable():
        raise DockerException("daemon unavailable")

    fake_client.containers.list = unavailable
    main.NAMESERVER = types.SimpleNamespace(
        add_host_override_alias=lambda *args: calls.append(args)
    )

    with caplog.at_level(logging.ERROR):
        main.add_aliases_on_startup()

    assert calls == []
    assert "add_aliases_on_startup" in caplog.text


def test_add_aliases_on_startup_reports_when_nothing_labeled(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)
    fake_client.containers.list = lambda: [
        types.SimpleNamespace(name="plain", attrs={"Config": {"Labels": {}}})
    ]
    main.NAMESERVER = types.SimpleNamespace(add_host_override_alias=lambda *args: None)

    with caplog.at_level(logging.INFO):
        main.add_aliases_on_startup()

    assert "No aliases found during startup" in caplog.text


# --- Dispatch and wiring -----------------------------------------------------


def test_process_events_delegate_to_nameserver(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    added = []
    removed = []
    # change_count increments on a mutation that lands, as the real PFSense does. The
    # coalescer compares it across the call to tell a real change from a no-op, so a
    # fake that never moves it would model a service that never changes anything.
    nameserver = types.SimpleNamespace(unapplied_changes=False, change_count=0)

    def add(host, alias, descr, apply):
        added.append((host, alias, descr, apply))
        nameserver.change_count += 1
        return True

    def remove(host, alias, apply):
        removed.append((host, alias, apply))
        nameserver.change_count += 1
        return True

    nameserver.add_host_override_alias = add
    nameserver.del_host_override_alias = remove
    main.NAMESERVER = nameserver

    main.process_start_event("caddy.lab.internal", "nginx.lab.internal", "nginx service")
    main.process_stop_event("caddy.lab.internal", "nginx.lab.internal")

    # The first change in a quiet period applies immediately; the second coalesces
    # because an apply just happened.
    assert added == [("caddy.lab.internal", "nginx.lab.internal", "nginx service", True)]
    assert removed == [("caddy.lab.internal", "nginx.lab.internal", False)]


def test_main_runs_startup_scan_only_when_enabled(monkeypatch):
    main, _fake_client = load_main(monkeypatch, add_on_startup="true")
    scanned = []
    monkeypatch.setattr(main, "iter_events", lambda: iter(()))
    monkeypatch.setattr(main, "add_aliases_on_startup", lambda: scanned.append(True))

    main.main()

    assert scanned == [True]

    main, _fake_client = load_main(monkeypatch)
    scanned = []
    monkeypatch.setattr(main, "iter_events", lambda: iter(()))
    monkeypatch.setattr(main, "add_aliases_on_startup", lambda: scanned.append(True))

    main.main()

    assert scanned == []


# --- Startup batching: one reload, not one per alias --------------------------


def _labeled_container(name, alias):
    return types.SimpleNamespace(
        id=f"id-{name}",
        name=name,
        attrs={
            "Config": {
                "Labels": {
                    "pfsense.dns.override": "caddy.lab.internal",
                    "pfsense.dns.alias": alias,
                    "pfsense.dns.description": f"{name} service",
                }
            }
        },
    )


def _recording_nameserver(staged, applies, add_result=True, apply_result=True):
    nameserver = RecordingNameserver(apply_result=apply_result, mutation_result=add_result)
    real_add = nameserver.add_host_override_alias
    real_apply = nameserver.apply_changes

    def add(host_override, alias, description, apply):
        staged.append((alias, apply))
        return real_add(host_override, alias, description, apply)

    def apply_changes():
        applies.append("apply")
        return real_apply()

    nameserver.add_host_override_alias = add
    nameserver.apply_changes = apply_changes
    return nameserver


def test_startup_scan_applies_once_for_many_aliases(monkeypatch):
    """The regression this change exists for: N aliases must cost one reload, not N."""
    main, fake_client = load_main(monkeypatch)
    staged = []
    applies = []
    fake_client.containers.list = lambda: [
        _labeled_container(f"svc{i}", f"svc{i}.lab.internal") for i in range(20)
    ]
    main.NAMESERVER = _recording_nameserver(staged, applies)

    main.add_aliases_on_startup()

    assert len(staged) == 20
    assert all(apply is False for _alias, apply in staged)
    assert applies == ["apply"]


def test_startup_scan_does_not_apply_when_nothing_was_staged(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    staged = []
    applies = []
    fake_client.containers.list = lambda: [
        types.SimpleNamespace(name="plain", attrs={"Config": {"Labels": {}}})
    ]
    main.NAMESERVER = _recording_nameserver(staged, applies)

    main.add_aliases_on_startup()

    assert staged == []
    assert applies == []


def test_startup_scan_does_not_apply_when_every_stage_failed(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)
    staged = []
    applies = []
    fake_client.containers.list = lambda: [
        _labeled_container("svc0", "svc0.lab.internal"),
        _labeled_container("svc1", "svc1.lab.internal"),
    ]
    main.NAMESERVER = _recording_nameserver(staged, applies, add_result=False)

    with caplog.at_level(logging.WARNING):
        main.add_aliases_on_startup()

    assert len(staged) == 2
    assert applies == []
    # Labeled-but-unstaged must not be reported as "no aliases found" — that
    # hid a real failure while looking like an idle startup.
    assert "Found 2 labeled container(s)" in caplog.text
    assert "No aliases found during startup" not in caplog.text


def test_startup_scan_reports_staged_aliases_when_the_apply_fails(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)
    staged = []
    applies = []
    fake_client.containers.list = lambda: [
        _labeled_container("svc0", "svc0.lab.internal"),
        _labeled_container("svc1", "svc1.lab.internal"),
    ]
    main.NAMESERVER = _recording_nameserver(staged, applies, apply_result=False)

    with caplog.at_level(logging.ERROR):
        main.add_aliases_on_startup()

    assert applies == ["apply"]
    assert "2 alias(es) are staged" in caplog.text
    assert "next successful apply" in caplog.text


def test_a_failed_startup_apply_stays_pending_and_is_retried(monkeypatch):
    """
    A failed startup apply must leave the coalescer holding the work.

    The event path already does this -- a mutation can land while its apply fails, and
    unapplied_changes rather than the return value is what says so. The startup scan
    only logged. PENDING_CHANGES stayed 0, and flush_pending_changes() returns
    immediately when nothing is pending, so neither a window tick nor the shutdown
    flush ever retried: the aliases sat in config.xml with unbound never reloaded, and
    on an idle host no name resolved until something unrelated happened to trigger an
    apply.
    """
    main, fake_client = load_main(monkeypatch)
    staged = []
    applies = []
    fake_client.containers.list = lambda: [
        _labeled_container("svc0", "svc0.lab.internal"),
        _labeled_container("svc1", "svc1.lab.internal"),
    ]
    nameserver = _recording_nameserver(staged, applies, apply_result=False)
    main.NAMESERVER = nameserver

    main.add_aliases_on_startup()

    assert len(staged) == 2
    assert applies == ["apply"]
    # The failure is tracked, not just logged.
    assert main.PENDING_CHANGES == 2
    assert main.PENDING_SINCE is not None

    # A later flush must actually retry it. Without the fix there is nothing to retry,
    # because PENDING_CHANGES is 0 and flush_pending_changes() returns at its guard.
    nameserver.apply_result = True
    main.flush_pending_changes(force=True)

    assert applies == ["apply", "apply"]
    assert main.PENDING_CHANGES == 0


# --- Coalescing: a burst costs one reload, a lone start stays fast -------------


class RecordingNameserver:
    """
    Counts applies, distinguishing immediate ones from coalesced flushes.

    Mirrors the real PFSense contract: a mutation that lands sets unapplied_changes,
    and only a confirmed apply clears it. Modelling that is what lets these tests catch
    a change that stages successfully but fails to apply.
    """

    def __init__(self, apply_result=True, mutation_result=True):
        self.staged = []
        self.immediate_applies = 0
        self.flush_applies = 0
        self.apply_result = apply_result
        self.mutation_result = mutation_result
        self.unapplied_changes = False
        # Monotonic count of mutations that actually landed. unapplied_changes is a
        # boolean and saturates, so it cannot tell "this call changed something" from
        # "something was already staged" once a burst is under way.
        self.change_count = 0

    def _mutate(self, alias, apply):
        self.staged.append((alias, apply))
        if not self.mutation_result:
            return False

        self.unapplied_changes = True
        self.change_count += 1
        if not apply:
            return True

        self.immediate_applies += 1
        if not self.apply_result:
            return False

        self.unapplied_changes = False
        return True

    def add_host_override_alias(self, _host_override, alias, _descr, apply):
        return self._mutate(alias, apply)

    def del_host_override_alias(self, _host_override, alias, apply):
        return self._mutate(alias, apply)

    def apply_changes(self):
        self.flush_applies += 1
        if not self.apply_result:
            return False
        self.unapplied_changes = False
        return True

    @property
    def total_applies(self):
        return self.immediate_applies + self.flush_applies


def test_a_lone_container_start_applies_immediately(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver

    main.process_start_event("caddy.lab.internal", "svc.lab.internal", "svc")

    assert nameserver.staged == [("svc.lab.internal", True)]
    assert nameserver.immediate_applies == 1
    assert main.PENDING_CHANGES == 0


def test_a_burst_of_starts_costs_two_applies_not_twenty(monkeypatch):
    """The regression this change exists for: a compose up must not reload per service."""
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver

    for i in range(20):
        main.process_start_event("caddy.lab.internal", f"svc{i}.lab.internal", "svc")

    # The first applied on its own; the remaining 19 are staged and still pending.
    assert nameserver.immediate_applies == 1
    assert main.PENDING_CHANGES == 19
    assert [apply for _alias, apply in nameserver.staged] == [True] + [False] * 19

    # A window tick after the quiet period flushes all 19 in one apply.
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 0.0)
    main.flush_pending_changes()

    assert nameserver.flush_applies == 1
    assert nameserver.total_applies == 2
    assert main.PENDING_CHANGES == 0


def test_pending_changes_are_not_flushed_before_the_quiet_period(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "APPLY_MAX_WAIT_SECONDS", 3600.0)

    main.process_start_event("caddy.lab.internal", "a.lab.internal", "a")
    main.process_start_event("caddy.lab.internal", "b.lab.internal", "b")
    main.flush_pending_changes()

    assert nameserver.flush_applies == 0
    assert main.PENDING_CHANGES == 1


def test_max_wait_forces_a_flush_when_events_keep_arriving(monkeypatch):
    """Continuous churn under the quiet threshold must not starve the apply forever."""
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "APPLY_MAX_WAIT_SECONDS", 0.0)

    main.process_start_event("caddy.lab.internal", "a.lab.internal", "a")
    main.process_start_event("caddy.lab.internal", "b.lab.internal", "b")
    main.flush_pending_changes()

    assert nameserver.flush_applies == 1
    assert main.PENDING_CHANGES == 0


def test_flush_is_a_noop_when_nothing_is_pending(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver

    main.flush_pending_changes()
    main.flush_pending_changes(force=True)

    assert nameserver.flush_applies == 0


def test_shutdown_flushes_pending_changes(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "APPLY_MAX_WAIT_SECONDS", 3600.0)

    main.process_start_event("caddy.lab.internal", "a.lab.internal", "a")
    main.process_start_event("caddy.lab.internal", "b.lab.internal", "b")
    assert main.PENDING_CHANGES == 1

    try:
        main.cleanup(15, None)
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("cleanup did not exit")

    # Staged changes must not be abandoned on SIGTERM.
    assert nameserver.flush_applies == 1
    assert fake_client.closed is True


def test_shutdown_before_nameserver_exists_does_not_crash(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    main.NAMESERVER = None

    try:
        main.cleanup(15, None)
    except SystemExit as exc:
        assert exc.code == 0
    else:
        raise AssertionError("cleanup did not exit")

    assert fake_client.closed is True


def test_a_failed_flush_keeps_changes_pending_for_retry(monkeypatch, caplog):
    """
    A failed apply must not discard the pending count.

    Clearing it stranded the changes: the shutdown flush had nothing left to retry, so
    aliases sat in the pfSense configuration and never went live.
    """
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver(apply_result=False)
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)

    main.process_start_event("caddy.lab.internal", "a.lab.internal", "a")
    main.process_start_event("caddy.lab.internal", "b.lab.internal", "b")
    # Both are pending: the first because its immediate apply failed, the second
    # because it was coalesced behind it.
    assert main.PENDING_CHANGES == 2

    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 0.0)
    with caplog.at_level(logging.ERROR):
        main.flush_pending_changes()

    assert "remain staged" in caplog.text
    assert main.PENDING_CHANGES == 2

    # And they are still there for the shutdown flush to retry.
    nameserver.apply_result = True
    main.flush_pending_changes(force=True)
    assert main.PENDING_CHANGES == 0
    assert nameserver.unapplied_changes is False


def test_a_stranded_change_is_retried_rather_than_lost(monkeypatch):
    """
    A mutation that lands but fails to apply must stay tracked.

    The mutator returns False in that case, which previously read as "nothing happened",
    so nothing was pending and the alias never went live.
    """
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver(apply_result=False)
    main.NAMESERVER = nameserver

    main.process_start_event("caddy.lab.internal", "svc.lab.internal", "svc")

    # The create landed even though the apply did not confirm.
    assert nameserver.unapplied_changes is True
    assert main.PENDING_CHANGES == 1

    # pfSense recovers; shutdown flushes the stranded change.
    nameserver.apply_result = True
    main.flush_pending_changes(force=True)

    assert nameserver.flush_applies == 1
    assert nameserver.unapplied_changes is False
    assert main.PENDING_CHANGES == 0


def test_a_failed_flush_defers_the_next_attempt(monkeypatch):
    """A pfSense outage must not be retried on every two-second window tick."""
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver(apply_result=False)
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "APPLY_MAX_WAIT_SECONDS", 3600.0)

    main.process_start_event("caddy.lab.internal", "a.lab.internal", "a")
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 0.0)
    main.flush_pending_changes()
    assert nameserver.flush_applies == 1

    # Timers were pushed out, so an immediate second tick does not retry.
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    main.flush_pending_changes()
    assert nameserver.flush_applies == 1
    assert main.PENDING_CHANGES == 1


def test_iter_events_yields_a_tick_after_each_window(monkeypatch):
    main, fake_client = load_main(monkeypatch)
    windows = []

    def fake_events(since=None, until=None, decode=True):
        assert decode is True
        windows.append((since, until))
        return iter([{"Type": "container", "Action": "start", "n": len(windows)}])

    fake_client.events = fake_events

    events = main.iter_events()
    collected = [next(events) for _ in range(4)]

    assert collected[0]["n"] == 1
    assert collected[1] is None
    assert collected[2]["n"] == 2
    assert collected[3] is None
    # Windows must be contiguous so events between them are not dropped.
    assert windows[1][0] == windows[0][1]


# --- Coalescing configuration -------------------------------------------------


def test_quiet_window_is_configurable(monkeypatch):
    monkeypatch.setenv("APPLY_QUIET_SECONDS", "2.5")
    monkeypatch.setenv("APPLY_MAX_WAIT_SECONDS", "30")
    main, _fake_client = load_main(monkeypatch)

    assert main.APPLY_QUIET_SECONDS == 2.5
    assert main.APPLY_MAX_WAIT_SECONDS == 30.0


def test_unusable_coalescing_config_falls_back_to_defaults(monkeypatch, caplog):
    main, _fake_client = load_main(monkeypatch)

    with caplog.at_level(logging.WARNING):
        assert main.get_positive_float_env("SOME_WINDOW", 10.0) == 10.0

        monkeypatch.setenv("SOME_WINDOW", "not-a-number")
        assert main.get_positive_float_env("SOME_WINDOW", 10.0) == 10.0

        monkeypatch.setenv("SOME_WINDOW", "0")
        assert main.get_positive_float_env("SOME_WINDOW", 10.0) == 10.0

        monkeypatch.setenv("SOME_WINDOW", "-5")
        assert main.get_positive_float_env("SOME_WINDOW", 10.0) == 10.0

    assert "invalid" in caplog.text
    assert "non-positive" in caplog.text


def test_shutdown_survives_a_failing_flush(monkeypatch, caplog):
    main, fake_client = load_main(monkeypatch)

    def exploding_apply():
        raise RuntimeError("apply blew up")

    main.NAMESERVER = types.SimpleNamespace(apply_changes=exploding_apply)
    monkeypatch.setattr(main, "PENDING_CHANGES", 1)
    monkeypatch.setattr(main, "LAST_CHANGE_AT", 0.0)
    monkeypatch.setattr(main, "PENDING_SINCE", 0.0)

    with caplog.at_level(logging.ERROR):
        try:
            main.cleanup(15, None)
        except SystemExit as exc:
            assert exc.code == 0
        else:
            raise AssertionError("cleanup did not exit")

    # A broken flush must not block shutdown or leave the client open.
    assert "cleanup" in caplog.text
    assert fake_client.closed is True


def test_a_failed_add_stages_nothing(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    applies = []
    main.NAMESERVER = types.SimpleNamespace(
        unapplied_changes=False,
        # Never moves, because neither mutator changes anything -- which is the point.
        change_count=0,
        add_host_override_alias=lambda *_args, **_kwargs: False,
        del_host_override_alias=lambda *_args, **_kwargs: False,
        apply_changes=lambda: applies.append("apply") or True,
    )
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "LAST_APPLY_AT", time.monotonic())

    main.process_start_event("caddy.lab.internal", "a.lab.internal", "a")
    main.process_stop_event("caddy.lab.internal", "b.lab.internal")

    assert main.PENDING_CHANGES == 0
    assert applies == []


def test_a_no_op_removal_during_a_burst_does_not_inflate_the_pending_count(monkeypatch):
    """
    Docker emits both `die` and `stop` for one shutdown. The second finds the alias
    already gone, so the mutator returns False without touching pfSense.

    unapplied_changes is a single boolean that saturates: once anything is staged it
    stays True, so reading it alone counted that no-op as a staged change. A
    `docker compose down` of twenty services then reported roughly 38 coalesced
    changes for 19 real removals.
    """
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "LAST_APPLY_AT", time.monotonic())

    main.process_stop_event("caddy.lab.internal", "a.lab.internal")
    assert main.PENDING_CHANGES == 1

    # The second event for the same container: nothing left to remove.
    nameserver.mutation_result = False
    main.process_stop_event("caddy.lab.internal", "a.lab.internal")

    assert main.PENDING_CHANGES == 1


def test_a_no_op_event_does_not_hold_the_quiet_window_open(monkeypatch):
    """
    A no-op must not restart the coalescing clock.

    A container in a restart loop emitting repeated die/stop for an already-removed
    alias would otherwise keep pushing LAST_CHANGE_AT forward, delaying a genuinely
    pending change from the 10s quiet window out to the 60s maximum wait.
    """
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "LAST_APPLY_AT", time.monotonic())

    main.process_stop_event("caddy.lab.internal", "a.lab.internal")
    change_at = main.LAST_CHANGE_AT

    nameserver.mutation_result = False
    main.process_stop_event("caddy.lab.internal", "a.lab.internal")

    assert main.LAST_CHANGE_AT == change_at


def test_a_coalesced_removal_is_staged_like_an_addition(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "LAST_APPLY_AT", time.monotonic())

    main.process_stop_event("caddy.lab.internal", "gone.lab.internal")

    assert nameserver.staged == [("gone.lab.internal", False)]
    assert main.PENDING_CHANGES == 1


# --- Log forgery: anyone who can start a container controls these values -------


def log_messages(caplog):
    """The formatted message of each captured record, without any traceback."""
    return [record.getMessage() for record in caplog.records]


def assert_no_forged_log_records(caplog):
    """
    No captured record may contain a raw newline or carriage return.

    caplog.text joins records with newlines, so a substring check on it cannot prove
    single-line-ness — a forged record and a genuine one look identical there. Assert
    per record instead. record.getMessage() excludes exc_info, so _handle_error's
    deliberate multi-line traceback is not swept up by this check.
    """
    for record in caplog.records:
        message = record.getMessage()
        assert "\n" not in message, message
        assert "\r" not in message, message


def test_startup_staging_log_cannot_be_forged_by_a_label(monkeypatch, caplog):
    """
    The startup scan logs the alias label and the container name before pfSense has
    seen either. A newline in one fabricates a complete, syntactically valid record.
    """
    main, fake_client = load_main(monkeypatch)
    staged = []
    applies = []
    hostile_alias = (
        "svc\n2026-08-02 12:00:00 - INFO - "
        "Alias attacker.lab.internal added to host override parent.lab.internal"
    )
    escaped_alias = (
        "svc\\n2026-08-02 12:00:00 - INFO - "
        "Alias attacker.lab.internal added to host override parent.lab.internal"
    )
    hostile_name = "svc\r2026-08-02 12:00:00 - INFO - forged"
    escaped_name = "svc\\r2026-08-02 12:00:00 - INFO - forged"
    fake_client.containers.list = lambda: [_labeled_container(hostile_name, hostile_alias)]
    main.NAMESERVER = _recording_nameserver(staged, applies)

    with caplog.at_level(logging.INFO):
        main.add_aliases_on_startup()

    assert_no_forged_log_records(caplog)
    staging = [m for m in log_messages(caplog) if "Staging alias" in m]
    assert len(staging) == 1
    # Both values on the line are attacker supplied, and the evidence survives escaped.
    assert escaped_alias in staging[0]
    assert escaped_name in staging[0]


def test_container_start_and_stop_logs_cannot_be_forged_by_a_container_name(
    monkeypatch, caplog
):
    """A container name is chosen by whoever starts the container, and is logged raw."""
    main, fake_client = load_main(monkeypatch)
    hostile_name = "nginx\n2026-08-02 12:00:00 - INFO - Alias attacker.lab.internal added"
    escaped_name = "nginx\\n2026-08-02 12:00:00 - INFO - Alias attacker.lab.internal added"
    fake_client.container = types.SimpleNamespace(
        name=hostile_name,
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
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)
    monkeypatch.setattr(main, "process_stop_event", lambda *_args: None)

    with caplog.at_level(logging.INFO):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "stop"})

    assert_no_forged_log_records(caplog)
    messages = log_messages(caplog)
    assert f"Container '{escaped_name}' is starting..." in messages
    assert f"Container '{escaped_name}' is stopping..." in messages


def test_container_not_found_warning_cannot_be_forged(monkeypatch, caplog):
    """The Docker exception text carries the container id taken from the event."""
    main, fake_client = load_main(monkeypatch)
    hostile = "no such container: abc\n2026-08-02 12:00:00 - INFO - forged"
    escaped = "no such container: abc\\n2026-08-02 12:00:00 - INFO - forged"

    def gone(_container_id):
        raise DockerNotFound(hostile)

    fake_client.containers.get = gone

    with caplog.at_level(logging.WARNING):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    assert_no_forged_log_records(caplog)
    missing = [m for m in log_messages(caplog) if "Container not found" in m]
    assert len(missing) == 1
    assert escaped in missing[0]


def test_handle_error_escapes_the_message_but_keeps_the_traceback(monkeypatch, caplog):
    """
    The escape must not become a global "strip newlines" scrubber.

    _handle_error logs with exc_info=True on purpose; that traceback is multi-line and
    must stay multi-line. Only the interpolated message is attacker influenced.
    """
    main, _fake_client = load_main(monkeypatch)
    hostile = "boom\n2026-08-02 12:00:00 - INFO - Alias attacker.lab.internal added"
    escaped = "boom\\n2026-08-02 12:00:00 - INFO - Alias attacker.lab.internal added"

    with caplog.at_level(logging.ERROR):
        try:
            raise RuntimeError(hostile)
        except RuntimeError as error:
            main._handle_error(error, "handle_container_event")

    assert_no_forged_log_records(caplog)
    record = caplog.records[-1]
    assert escaped in record.getMessage()
    # The developer-supplied context is untouched, and the traceback survives.
    assert "Error in handle_container_event:" in record.getMessage()
    assert record.exc_info is not None
    assert "Traceback" in caplog.text


def test_oversized_label_values_are_truncated_in_logs(monkeypatch, caplog):
    """A megabyte-long label must not become a megabyte of log."""
    main, fake_client = load_main(monkeypatch)
    oversized = "a" * 10000
    fake_client.container = types.SimpleNamespace(
        name=oversized,
        attrs={
            "Config": {
                "Labels": {
                    "pfsense.dns.override": "caddy.lab.internal",
                    "pfsense.dns.alias": "nginx.lab.internal",
                }
            }
        },
    )
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)

    with caplog.at_level(logging.INFO):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    starting = [m for m in log_messages(caplog) if "is starting" in m]
    assert len(starting) == 1
    assert "a" * pfsense.LOG_VALUE_MAX_CHARS in starting[0]
    assert "a" * (pfsense.LOG_VALUE_MAX_CHARS + 1) not in starting[0]
    assert starting[0].count(pfsense.LOG_TRUNCATION_MARKER) == 1


def test_docker_client_init_failure_log_cannot_forge_a_log_record(monkeypatch, caplog):
    """
    An import-time log site is testable, and this one is enforced rather than assumed.

    caplog attaches to the root logger before the test body runs, so records emitted
    while `main` is being imported are captured like any other. The Docker daemon's
    error text is off-box string data, which makes this a real forgery site, not a
    provably-no-op one.
    """
    hostile = "boom\n2026-08-02 12:00:00 - INFO - forged"

    def unavailable():
        raise DockerException(hostile)

    fake_docker = types.SimpleNamespace(
        from_env=unavailable,
        errors=types.SimpleNamespace(DockerException=DockerException, NotFound=DockerNotFound),
    )
    monkeypatch.setenv("PFSENSE_HOSTNAME", "pfsense.lab.internal")
    monkeypatch.setenv("PFSENSE_API_TOKEN", "test-token")
    monkeypatch.delenv("ADD_ALIASES_ON_STARTUP", raising=False)
    monkeypatch.delenv("PFSENSE_VERIFY_SSL", raising=False)
    monkeypatch.delenv("PFSENSE_CA_BUNDLE", raising=False)
    monkeypatch.setitem(sys.modules, "docker", fake_docker)
    # A module whose import raises is removed from sys.modules by the import machinery,
    # so `main` is left unimported here and later load_main() calls are unaffected.
    sys.modules.pop("main", None)

    with caplog.at_level(logging.CRITICAL):
        try:
            importlib.import_module("main")
        except SystemExit as exc:
            # The escape must not disturb the import-time exit contract: CI's container
            # smoke test asserts the image exits 1 when it cannot reach Docker.
            assert exc.code == 1
        else:
            raise AssertionError("import did not exit")

    assert_no_forged_log_records(caplog)
    critical = [m for m in log_messages(caplog) if "Error initializing Docker client" in m]
    assert len(critical) == 1
    assert "\\n" in critical[0]
    assert "boom" in critical[0]
    assert "forged" in critical[0]
    assert "Error initializing Docker client" in caplog.text


# --- Remembering aliases so a deleted container can still be cleaned up -------


def _remembering_container(container_id, name, alias, remove_on_stop=True):
    labels = {
        "pfsense.dns.override": "caddy.lab.internal",
        "pfsense.dns.alias": alias,
    }
    if remove_on_stop:
        labels["pfsense.dns.remove_on_stop"] = "true"
    return types.SimpleNamespace(
        id=container_id,
        name=name,
        attrs={"Config": {"Labels": labels}},
    )


def _container_is_gone(fake_client):
    def gone(_container_id):
        raise DockerNotFound("no such container")

    fake_client.containers.get = gone


def test_a_deleted_container_still_loses_its_alias_on_stop(monkeypatch):
    """
    A container run with `docker run --rm` is often deleted before its stop event is
    handled, so its labels can no longer be read back from Docker. The alias must
    still be removed, from what was recorded when the container started.
    """
    main, fake_client = load_main(monkeypatch)
    removals = []
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)
    monkeypatch.setattr(
        main,
        "process_stop_event",
        lambda host_override, alias: removals.append((host_override, alias)),
    )

    fake_client.container = _remembering_container("abc123", "nginx", "nginx.lab.internal")
    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    _container_is_gone(fake_client)
    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "stop"})

    assert removals == [("caddy.lab.internal", "nginx.lab.internal")]


def test_a_burst_of_deleted_containers_removes_every_alias(monkeypatch):
    """
    The regression this exists for. Twenty `--rm` containers stopped together left
    nineteen aliases behind against a real pfSense, because Docker won the race to
    delete each container before its stop event was handled.
    """
    main, fake_client = load_main(monkeypatch)
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)
    removals = []
    monkeypatch.setattr(
        main, "process_stop_event", lambda _host_override, alias: removals.append(alias)
    )

    for index in range(20):
        fake_client.container = _remembering_container(
            f"id-{index}", f"svc{index}", f"svc{index}.lab.internal"
        )
        main.handle_container_event({"Actor": {"ID": f"id-{index}"}, "Action": "start"})

    _container_is_gone(fake_client)
    for index in range(20):
        main.handle_container_event({"Actor": {"ID": f"id-{index}"}, "Action": "stop"})

    assert removals == [f"svc{index}.lab.internal" for index in range(20)]


def test_a_container_never_seen_starting_still_reports_not_found(monkeypatch, caplog):
    """Nothing was recorded, so there is nothing to fall back to — say so and move on."""
    main, fake_client = load_main(monkeypatch)
    removals = []
    monkeypatch.setattr(
        main, "process_stop_event", lambda host_override, alias: removals.append((host_override, alias))
    )
    _container_is_gone(fake_client)

    with caplog.at_level(logging.WARNING):
        main.handle_container_event({"Actor": {"ID": "never-seen"}, "Action": "stop"})

    assert removals == []
    assert "Container not found" in caplog.text


def test_a_deleted_container_without_remove_on_stop_keeps_its_alias(monkeypatch, caplog):
    """Falling back to a recorded configuration must still honour the opt-in label."""
    main, fake_client = load_main(monkeypatch)
    removals = []
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)
    monkeypatch.setattr(
        main, "process_stop_event", lambda host_override, alias: removals.append((host_override, alias))
    )

    fake_client.container = _remembering_container(
        "abc123", "nginx", "nginx.lab.internal", remove_on_stop=False
    )
    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    _container_is_gone(fake_client)
    with caplog.at_level(logging.WARNING):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "stop"})

    assert removals == []
    assert "Container not found" in caplog.text


def test_a_missing_container_on_a_start_event_is_not_treated_as_a_stop(monkeypatch, caplog):
    """A recorded alias is a fallback for stopping, never a reason to remove on start."""
    main, fake_client = load_main(monkeypatch)
    removals = []
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)
    monkeypatch.setattr(
        main, "process_stop_event", lambda host_override, alias: removals.append((host_override, alias))
    )

    fake_client.container = _remembering_container("abc123", "nginx", "nginx.lab.internal")
    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    _container_is_gone(fake_client)
    with caplog.at_level(logging.WARNING):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    assert removals == []
    assert "Container not found" in caplog.text


def test_the_remembered_alias_table_is_bounded(monkeypatch):
    """
    Container IDs are never reused, so entries would otherwise accumulate for the
    lifetime of the process. The oldest are dropped once the table is full.
    """
    main, fake_client = load_main(monkeypatch)
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)

    overflow = main.KNOWN_ALIASES_MAX + 5
    for index in range(overflow):
        fake_client.container = _remembering_container(
            f"id-{index}", f"svc{index}", f"svc{index}.lab.internal"
        )
        main.handle_container_event({"Actor": {"ID": f"id-{index}"}, "Action": "start"})

    assert len(main.KNOWN_ALIASES) == main.KNOWN_ALIASES_MAX
    assert "id-0" not in main.KNOWN_ALIASES
    assert f"id-{overflow - 1}" in main.KNOWN_ALIASES


def test_both_die_and_stop_remove_the_alias_for_a_deleted_container(monkeypatch, caplog):
    """
    Docker sends `die` AND `stop` for one shutdown, so the record must survive the first.

    This is the reason recall_alias_config reads the table with .get() rather than
    .pop(). Dropping the entry on the first event would make the second log
    "Container not found" for a container that was handled correctly a moment earlier.
    A mutation to .pop() passed the whole suite before this test existed, because no
    other test sends two stop events for one container ID.
    """
    main, fake_client = load_main(monkeypatch)
    removals = []
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)
    monkeypatch.setattr(
        main, "process_stop_event", lambda _host_override, alias: removals.append(alias)
    )

    fake_client.container = _remembering_container("abc123", "nginx", "nginx.lab.internal")
    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "start"})

    _container_is_gone(fake_client)
    with caplog.at_level(logging.WARNING):
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "die"})
        main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "stop"})

    assert removals == ["nginx.lab.internal", "nginx.lab.internal"]
    assert "Container not found" not in caplog.text


def test_re_recording_a_container_makes_it_the_newest_entry(monkeypatch):
    """
    remember_alias_config deletes before reinserting, so a re-recorded container counts
    as newest for eviction.

    Eviction relies on dictionaries preserving insertion order. Without the delete, a
    long-lived container that keeps being re-recorded would keep its original position
    and be evicted ahead of entries younger than it. Removing the pop passed the whole
    suite before this test existed, because no other test re-records an ID.
    """
    main, fake_client = load_main(monkeypatch)
    monkeypatch.setattr(main, "process_start_event", lambda *_args: None)

    def start(index):
        fake_client.container = _remembering_container(
            f"id-{index}", f"svc{index}", f"svc{index}.lab.internal"
        )
        main.handle_container_event({"Actor": {"ID": f"id-{index}"}, "Action": "start"})

    for index in range(main.KNOWN_ALIASES_MAX):
        start(index)
    assert len(main.KNOWN_ALIASES) == main.KNOWN_ALIASES_MAX

    # Re-record the oldest entry. It must move to the newest position.
    start(0)
    # One more start overflows the table by one, evicting whatever is oldest.
    start(main.KNOWN_ALIASES_MAX)

    assert len(main.KNOWN_ALIASES) == main.KNOWN_ALIASES_MAX
    # id-0 was refreshed, so id-1 is now the oldest and is the one to go.
    assert "id-0" in main.KNOWN_ALIASES
    assert "id-1" not in main.KNOWN_ALIASES


def test_startup_scan_remembers_aliases_for_containers_it_did_not_see_start(monkeypatch):
    """
    A container already running when this service starts never produces a start event,
    so the startup scan is the only chance to record it.
    """
    main, fake_client = load_main(monkeypatch)
    fake_client.containers.list = lambda: [
        _remembering_container("abc123", "nginx", "nginx.lab.internal")
    ]
    main.NAMESERVER = types.SimpleNamespace(
        add_host_override_alias=lambda *_args, **_kwargs: True,
        apply_changes=lambda: True,
    )
    main.add_aliases_on_startup()

    removals = []
    monkeypatch.setattr(
        main, "process_stop_event", lambda host_override, alias: removals.append((host_override, alias))
    )
    _container_is_gone(fake_client)

    main.handle_container_event({"Actor": {"ID": "abc123"}, "Action": "stop"})

    assert removals == [("caddy.lab.internal", "nginx.lab.internal")]
