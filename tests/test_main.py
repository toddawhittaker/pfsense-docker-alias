import importlib
import logging
import sys
import time
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
        types.SimpleNamespace(name="unlabeled", attrs={"Config": {"Labels": {}}}),
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
    main.NAMESERVER = types.SimpleNamespace(
        unapplied_changes=False,
        add_host_override_alias=lambda host, alias, descr, apply: added.append(
            (host, alias, descr, apply)
        )
        or True,
        del_host_override_alias=lambda host, alias, apply: removed.append((host, alias, apply))
        or True,
    )

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

    def _mutate(self, alias, apply):
        self.staged.append((alias, apply))
        if not self.mutation_result:
            return False

        self.unapplied_changes = True
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


def test_a_coalesced_removal_is_staged_like_an_addition(monkeypatch):
    main, _fake_client = load_main(monkeypatch)
    nameserver = RecordingNameserver()
    main.NAMESERVER = nameserver
    monkeypatch.setattr(main, "APPLY_QUIET_SECONDS", 3600.0)
    monkeypatch.setattr(main, "LAST_APPLY_AT", time.monotonic())

    main.process_stop_event("caddy.lab.internal", "gone.lab.internal")

    assert nameserver.staged == [("gone.lab.internal", False)]
    assert main.PENDING_CHANGES == 1
