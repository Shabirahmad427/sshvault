from __future__ import annotations

import copy
import unittest

from sshvault_core import (
    LOCAL_FORWARDING_STATUSES,
    LocalForwardingSession,
    SessionController,
    SessionLifecycleState,
)


def _rule(
    rule_id: str,
    *,
    enabled: bool = True,
    kind: str = "Local",
    listen_host: str = "127.0.0.1",
    listen_port: int = 8000,
    destination_host: str = "destination.example",
    destination_port: int = 80,
) -> dict:
    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "type": kind,
        "bind_address": listen_host,
        "bind_port": listen_port,
        "destination_host": destination_host,
        "destination_port": destination_port,
    }


class _Listener:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _Starter:
    def __init__(self, failing_ports: set[int] | None = None) -> None:
        self.failing_ports = failing_ports or set()
        self.rules: list[dict] = []
        self.listeners: dict[str, _Listener] = {}

    def __call__(self, running) -> None:
        rule = dict(running.rule)
        self.rules.append(rule)
        if int(rule["bind_port"]) in self.failing_ports:
            raise OSError("listener unavailable")
        listener = _Listener()
        running.runtime.listener = listener
        self.listeners[str(rule["rule_id"])] = listener


class ServicesLocalForwardingTests(unittest.TestCase):
    def test_status_contract_is_exact(self) -> None:
        self.assertEqual(
            LOCAL_FORWARDING_STATUSES,
            ("Stopped", "Starting", "Active", "Failed"),
        )

    def test_enabled_local_rule_starts_and_disabled_rule_stays_stopped(self) -> None:
        starter = _Starter()
        service = LocalForwardingSession(
            "session",
            object(),
            [_rule("enabled"), _rule("disabled", enabled=False, listen_port=8001)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("enabled"), "Active")
        self.assertEqual(service.status("disabled"), "Stopped")
        self.assertEqual([rule["rule_id"] for rule in starter.rules], ["enabled"])

    def test_listener_and_destination_values_come_from_snapshot_rule(self) -> None:
        starter = _Starter()
        service = LocalForwardingSession(
            "session",
            object(),
            [
                _rule(
                    "mapped",
                    listen_host="127.0.0.2",
                    listen_port=8123,
                    destination_host="database.internal",
                    destination_port=5432,
                )
            ],
            starter,
        )
        service.start_enabled()
        started = starter.rules[0]
        self.assertEqual((started["bind_address"], started["bind_port"]), ("127.0.0.2", 8123))
        self.assertEqual(
            (started["destination_host"], started["destination_port"]),
            ("database.internal", 5432),
        )

    def test_duplicate_active_listener_is_rejected_per_rule(self) -> None:
        starter = _Starter()
        service = LocalForwardingSession(
            "session",
            object(),
            [
                _rule("first"),
                _rule("duplicate", destination_host="other.example", destination_port=443),
            ],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("first"), "Active")
        self.assertEqual(service.status("duplicate"), "Failed")
        self.assertIn("already uses", service.records["duplicate"].error)
        self.assertEqual(len(starter.rules), 1)

    def test_failed_rule_does_not_disconnect_session_or_block_other_rule(self) -> None:
        controller = SessionController()
        session = controller.create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        starter = _Starter({8000})
        service = LocalForwardingSession(
            session.session_id,
            object(),
            [_rule("failed"), _rule("healthy", listen_port=8001)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("failed"), "Failed")
        self.assertEqual(service.status("healthy"), "Active")
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_logout_stops_all_current_session_listeners(self) -> None:
        starter = _Starter()
        service = LocalForwardingSession(
            "session",
            object(),
            [_rule("one"), _rule("two", listen_port=8001)],
            starter,
        )
        service.start_enabled()
        service.stop_all()
        self.assertTrue(service.closed)
        self.assertEqual(service.status("one"), "Stopped")
        self.assertEqual(service.status("two"), "Stopped")
        self.assertTrue(all(listener.closed == 1 for listener in starter.listeners.values()))
        service.stop_all()
        self.assertTrue(all(listener.closed == 1 for listener in starter.listeners.values()))

    def test_stopping_one_controller_leaves_the_other_active(self) -> None:
        first_starter, second_starter = _Starter(), _Starter()
        first = LocalForwardingSession("first", object(), [_rule("first")], first_starter)
        second = LocalForwardingSession(
            "second",
            object(),
            [_rule("second", listen_port=8001)],
            second_starter,
        )
        first.start_enabled()
        second.start_enabled()
        first.stop_all()
        self.assertEqual(first.status("first"), "Stopped")
        self.assertEqual(second.status("second"), "Active")
        self.assertEqual(first_starter.listeners["first"].closed, 1)
        self.assertEqual(second_starter.listeners["second"].closed, 0)

    def test_active_runtime_uses_immutable_session_snapshot(self) -> None:
        profile = {
            "id": "profile",
            "name": "Profile",
            "host": "host.example",
            "port": 22,
            "user": "alice",
            "auth_method": "agent",
            "tunnel_options": {"rules": [_rule("snapshot")]},
        }
        session = SessionController().create_session(profile)
        starter = _Starter()
        rules = session.profile_snapshot["tunnel_options"]["rules"]
        service = LocalForwardingSession(session.session_id, object(), rules, starter)
        profile["tunnel_options"]["rules"][0]["destination_host"] = "edited.example"
        service.start_enabled()
        self.assertEqual(starter.rules[0]["destination_host"], "destination.example")
        self.assertEqual(
            session.profile_snapshot["tunnel_options"]["rules"][0]["destination_host"],
            "destination.example",
        )
        self.assertNotEqual(service.rules, copy.deepcopy(profile["tunnel_options"]["rules"]))

    def test_remote_and_dynamic_rules_are_not_started(self) -> None:
        starter = _Starter()
        service = LocalForwardingSession(
            "session",
            object(),
            [
                _rule("remote", kind="Remote"),
                _rule(
                    "dynamic",
                    kind="SOCKS",
                    listen_port=1080,
                    destination_host="",
                    destination_port=0,
                ),
            ],
            starter,
        )
        service.start_enabled()
        self.assertEqual(starter.rules, [])
        self.assertEqual(service.status("remote"), "Stopped")
        self.assertEqual(service.status("dynamic"), "Stopped")


if __name__ == "__main__":
    unittest.main()
