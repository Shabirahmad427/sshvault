from __future__ import annotations

import unittest

from sshvault_core import (
    DYNAMIC_FORWARDING_STATUSES,
    DynamicForwardingSession,
    ProfileError,
    SessionController,
    SessionLifecycleState,
    open_socks5_connect_channel,
)


def _rule(
    rule_id: str,
    *,
    enabled: bool = True,
    kind: str = "SOCKS",
    listen_host: str = "127.0.0.1",
    listen_port: int = 1080,
) -> dict:
    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "type": kind,
        "bind_address": listen_host,
        "bind_port": listen_port,
        "destination_host": "",
        "destination_port": 0,
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
            raise OSError("SOCKS listener unavailable")
        listener = _Listener()
        running.runtime.listener = listener
        self.listeners[str(rule["rule_id"])] = listener


class _RoutingTransport:
    def __init__(self, channel=None) -> None:
        self.calls: list[tuple[str, tuple[str, int], tuple[str, int]]] = []
        self.channel = channel if channel is not None else object()

    def open_channel(self, kind: str, target: tuple[str, int], origin: tuple[str, int]):
        self.calls.append((kind, target, origin))
        return self.channel


class ServicesDynamicForwardingTests(unittest.TestCase):
    def test_status_contract_is_exact(self) -> None:
        self.assertEqual(
            DYNAMIC_FORWARDING_STATUSES,
            ("Stopped", "Starting", "Active", "Failed"),
        )

    def test_enabled_dynamic_rule_starts_and_disabled_rule_stays_stopped(self) -> None:
        starter = _Starter()
        service = DynamicForwardingSession(
            "session",
            object(),
            [_rule("enabled"), _rule("disabled", enabled=False, listen_port=1081)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("enabled"), "Active")
        self.assertEqual(service.status("disabled"), "Stopped")
        self.assertEqual([rule["rule_id"] for rule in starter.rules], ["enabled"])

    def test_correct_bind_address_comes_from_session_rule(self) -> None:
        starter = _Starter()
        service = DynamicForwardingSession(
            "session",
            object(),
            [_rule("mapped", listen_host="127.0.0.2", listen_port=1180)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(
            (starter.rules[0]["bind_address"], starter.rules[0]["bind_port"]),
            ("127.0.0.2", 1180),
        )
        self.assertEqual(starter.rules[0]["destination_host"], "")
        self.assertEqual(starter.rules[0]["destination_port"], 0)

    def test_socks5_connect_routes_through_existing_transport(self) -> None:
        channel = object()
        transport = _RoutingTransport(channel)
        request = b"\x05\x01\x00\x03\x0cexample.test\x00\x16"
        result = open_socks5_connect_channel(
            request,
            transport,
            ("127.0.0.1", 40000),
        )
        self.assertIs(result, channel)
        self.assertEqual(
            transport.calls,
            [("direct-tcpip", ("example.test", 22), ("127.0.0.1", 40000))],
        )

    def test_only_connect_is_accepted(self) -> None:
        transport = _RoutingTransport()
        origin = ("127.0.0.1", 40000)
        for command in (2, 3):
            with self.subTest(command=command), self.assertRaisesRegex(ProfileError, "CONNECT"):
                open_socks5_connect_channel(
                    bytes([5, command, 0, 1, 127, 0, 0, 1, 0, 22]),
                    transport,
                    origin,
                )
        self.assertEqual(transport.calls, [])

    def test_duplicate_dynamic_listener_is_rejected(self) -> None:
        starter = _Starter()
        service = DynamicForwardingSession(
            "session",
            object(),
            [_rule("first"), _rule("duplicate")],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("first"), "Active")
        self.assertEqual(service.status("duplicate"), "Failed")
        self.assertIn("already uses", service.records["duplicate"].error)
        self.assertEqual(len(starter.rules), 1)

    def test_failed_rule_does_not_disconnect_or_block_other_rule(self) -> None:
        controller = SessionController()
        session = controller.create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        starter = _Starter({1080})
        service = DynamicForwardingSession(
            session.session_id,
            object(),
            [_rule("failed"), _rule("healthy", listen_port=1081)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("failed"), "Failed")
        self.assertEqual(service.status("healthy"), "Active")
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_logout_cleanup_is_idempotent_and_controller_scoped(self) -> None:
        first_starter, second_starter = _Starter(), _Starter()
        first = DynamicForwardingSession("first", object(), [_rule("first")], first_starter)
        second = DynamicForwardingSession(
            "second",
            object(),
            [_rule("second", listen_port=1081)],
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

    def test_active_dynamic_forward_uses_session_snapshot(self) -> None:
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
        service = DynamicForwardingSession(
            session.session_id,
            object(),
            session.profile_snapshot["tunnel_options"]["rules"],
            starter,
        )
        profile["tunnel_options"]["rules"][0]["bind_port"] = 2080
        service.start_enabled()
        self.assertEqual(starter.rules[0]["bind_port"], 1080)
        self.assertEqual(
            session.profile_snapshot["tunnel_options"]["rules"][0]["bind_port"],
            1080,
        )


if __name__ == "__main__":
    unittest.main()
