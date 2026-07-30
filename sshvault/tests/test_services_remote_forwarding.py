from __future__ import annotations

import unittest

from sshvault_core import (
    REMOTE_FORWARDING_STATUSES,
    RemoteForwardingSession,
    RunningTunnel,
    SessionController,
    SessionLifecycleState,
    TunnelRuntime,
    start_remote_forwarding_listener,
)


def _rule(
    rule_id: str,
    *,
    enabled: bool = True,
    kind: str = "Remote",
    listen_host: str = "127.0.0.1",
    listen_port: int = 9000,
    destination_host: str = "local.example",
    destination_port: int = 8080,
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
            raise OSError("remote listener unavailable")
        listener = _Listener()
        running.runtime.listener = listener
        self.listeners[str(rule["rule_id"])] = listener


class _Transport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, int, object]] = []
        self.cancellations: list[tuple[str, int]] = []

    def request_port_forward(self, host: str, port: int, handler=None) -> int:
        self.requests.append((host, port, handler))
        return port

    def cancel_port_forward(self, host: str, port: int) -> None:
        self.cancellations.append((host, port))


class ServicesRemoteForwardingTests(unittest.TestCase):
    def test_status_contract_is_exact(self) -> None:
        self.assertEqual(
            REMOTE_FORWARDING_STATUSES,
            ("Stopped", "Starting", "Active", "Failed"),
        )

    def test_enabled_remote_rule_starts_and_disabled_rule_stays_stopped(self) -> None:
        starter = _Starter()
        service = RemoteForwardingSession(
            "session",
            object(),
            [_rule("enabled"), _rule("disabled", enabled=False, listen_port=9001)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("enabled"), "Active")
        self.assertEqual(service.status("disabled"), "Stopped")
        self.assertEqual([rule["rule_id"] for rule in starter.rules], ["enabled"])

    def test_remote_bind_and_destination_values_come_from_rule(self) -> None:
        starter = _Starter()
        service = RemoteForwardingSession(
            "session",
            object(),
            [
                _rule(
                    "mapped",
                    listen_host="0.0.0.0",
                    listen_port=9222,
                    destination_host="127.0.0.2",
                    destination_port=22,
                )
            ],
            starter,
        )
        service.start_enabled()
        started = starter.rules[0]
        self.assertEqual((started["bind_address"], started["bind_port"]), ("0.0.0.0", 9222))
        self.assertEqual(
            (started["destination_host"], started["destination_port"]),
            ("127.0.0.2", 22),
        )

    def test_transport_request_and_logout_cancellation_use_remote_bind(self) -> None:
        transport = _Transport()
        rule = _rule("transport", listen_host="localhost", listen_port=9443)
        running = RunningTunnel(rule, TunnelRuntime(), "starting")
        start_remote_forwarding_listener(running, transport)
        self.assertEqual(len(transport.requests), 1)
        host, port, handler = transport.requests[0]
        self.assertEqual((host, port), ("localhost", 9443))
        self.assertTrue(callable(handler))
        running.runtime.stop()
        self.assertEqual(transport.cancellations, [("localhost", 9443)])
        running.runtime.stop()
        self.assertEqual(transport.cancellations, [("localhost", 9443)])

    def test_duplicate_remote_listener_is_rejected(self) -> None:
        starter = _Starter()
        service = RemoteForwardingSession(
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

    def test_failed_rule_keeps_session_connected_and_starts_other_rule(self) -> None:
        controller = SessionController()
        session = controller.create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        starter = _Starter({9000})
        service = RemoteForwardingSession(
            session.session_id,
            object(),
            [_rule("failed"), _rule("healthy", listen_port=9001)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("failed"), "Failed")
        self.assertEqual(service.status("healthy"), "Active")
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_logout_stops_only_current_session_remote_forwards(self) -> None:
        first_starter, second_starter = _Starter(), _Starter()
        first = RemoteForwardingSession("first", object(), [_rule("first")], first_starter)
        second = RemoteForwardingSession(
            "second",
            object(),
            [_rule("second", listen_port=9001)],
            second_starter,
        )
        first.start_enabled()
        second.start_enabled()
        first.stop_all()
        self.assertEqual(first.status("first"), "Stopped")
        self.assertEqual(second.status("second"), "Active")
        self.assertEqual(first_starter.listeners["first"].closed, 1)
        self.assertEqual(second_starter.listeners["second"].closed, 0)
        first.stop_all()
        self.assertEqual(first_starter.listeners["first"].closed, 1)

    def test_active_remote_forward_uses_session_snapshot(self) -> None:
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
        service = RemoteForwardingSession(
            session.session_id,
            object(),
            session.profile_snapshot["tunnel_options"]["rules"],
            starter,
        )
        profile["tunnel_options"]["rules"][0]["destination_host"] = "edited.example"
        service.start_enabled()
        self.assertEqual(starter.rules[0]["destination_host"], "local.example")
        self.assertEqual(
            session.profile_snapshot["tunnel_options"]["rules"][0]["destination_host"],
            "local.example",
        )

    def test_local_and_dynamic_rules_are_not_started(self) -> None:
        starter = _Starter()
        service = RemoteForwardingSession(
            "session",
            object(),
            [
                _rule("local", kind="Local"),
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
        self.assertEqual(service.status("local"), "Stopped")
        self.assertEqual(service.status("dynamic"), "Stopped")


if __name__ == "__main__":
    unittest.main()
