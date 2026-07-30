from __future__ import annotations

import unittest

from sshvault_core import (
    DynamicForwardingSession,
    HTTPForwardingSession,
    LocalForwardingSession,
    RemoteForwardingSession,
    SessionController,
    SessionLifecycleState,
    X11ForwardingSession,
    open_http_connect_channel,
    open_socks5_connect_channel,
)


def _rule(rule_id: str, kind: str, port: int, *, enabled: bool = True) -> dict:
    destination_free = kind in {"SOCKS", "HTTP"}
    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "type": kind,
        "bind_address": "127.0.0.1",
        "bind_port": port,
        "destination_host": "" if destination_free else f"{kind.casefold()}.internal",
        "destination_port": 0 if destination_free else 443,
    }


def _profile(profile_id: str, offset: int = 0) -> dict:
    return {
        "id": profile_id,
        "name": profile_id,
        "host": "ssh.example",
        "port": 22,
        "user": "alice",
        "auth_method": "agent",
        "terminal_options": {
            "x11_forwarding": True,
            "x11_trusted": False,
            "x11_display": ":0",
        },
        "tunnel_options": {
            "rules": [
                _rule("local", "Local", 8100 + offset),
                _rule("remote", "Remote", 8200 + offset),
                _rule("socks", "SOCKS", 1080 + offset),
                _rule("http", "HTTP", 8800 + offset),
            ]
        },
    }


class _Listener:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _Starter:
    def __init__(self, failing_ids: set[str] | None = None) -> None:
        self.failing_ids = failing_ids or set()
        self.rules: list[dict] = []
        self.listeners: dict[str, _Listener] = {}

    def __call__(self, running) -> None:
        rule = dict(running.rule)
        rule_id = str(rule["rule_id"])
        self.rules.append(rule)
        if rule_id in self.failing_ids:
            raise OSError("private service failure")
        listener = _Listener()
        running.runtime.listener = listener
        self.listeners[rule_id] = listener


class _X11Channel:
    def __init__(self) -> None:
        self.requests: list[dict[str, object]] = []

    def request_x11(self, **kwargs: object) -> None:
        self.requests.append(kwargs)


class _RoutingTransport:
    def __init__(self) -> None:
        self.channel = object()
        self.calls: list[tuple[str, tuple[str, int], tuple[str, int]]] = []

    def open_channel(self, kind: str, target: tuple[str, int], origin: tuple[str, int]):
        self.calls.append((kind, target, origin))
        return self.channel


def _services(session_id: str, profile_snapshot: dict, starter: _Starter):
    rules = profile_snapshot["tunnel_options"]["rules"]
    transport = object()
    return (
        LocalForwardingSession(session_id, transport, rules, starter),
        RemoteForwardingSession(session_id, transport, rules, starter),
        DynamicForwardingSession(session_id, transport, rules, starter),
        HTTPForwardingSession(session_id, transport, rules, starter),
        X11ForwardingSession(
            session_id,
            profile_snapshot["terminal_options"],
            {},
        ),
    )


class ServicesPhaseTwoIntegrationTests(unittest.TestCase):
    def test_all_phase_two_services_start_and_route_on_existing_transport(self) -> None:
        controller = SessionController()
        record = controller.create_session(_profile("controller"))
        record.state = SessionLifecycleState.CONNECTED
        starter = _Starter()
        local, remote, dynamic, http, x11 = _services(
            record.session_id,
            record.profile_snapshot,
            starter,
        )
        for service in (local, remote, dynamic, http):
            service.start_enabled()
        x11_channel = _X11Channel()
        self.assertTrue(x11.request_for_channel(x11_channel))
        self.assertEqual(local.status("local"), "Active")
        self.assertEqual(remote.status("remote"), "Active")
        self.assertEqual(dynamic.status("socks"), "Active")
        self.assertEqual(http.status("http"), "Active")
        self.assertEqual(x11.status, "Active")

        routing = _RoutingTransport()
        origin = ("127.0.0.1", 45000)
        socks_request = b"\x05\x01\x00\x03\x0cexample.test\x01\xbb"
        http_request = b"CONNECT example.test:443 HTTP/1.1\r\n\r\n"
        self.assertIs(open_socks5_connect_channel(socks_request, routing, origin), routing.channel)
        self.assertIs(open_http_connect_channel(http_request, routing, origin), routing.channel)
        self.assertEqual(
            routing.calls,
            [
                ("direct-tcpip", ("example.test", 443), origin),
                ("direct-tcpip", ("example.test", 443), origin),
            ],
        )
        self.assertIs(record.state, SessionLifecycleState.CONNECTED)

    def test_one_failed_service_does_not_disconnect_or_stop_other_services(self) -> None:
        controller = SessionController()
        record = controller.create_session(_profile("failure"))
        record.state = SessionLifecycleState.CONNECTED
        starter = _Starter({"http"})
        local, remote, dynamic, http, x11 = _services(
            record.session_id,
            record.profile_snapshot,
            starter,
        )
        for service in (local, remote, dynamic, http):
            service.start_enabled()
        self.assertTrue(x11.request_for_channel(_X11Channel()))
        self.assertEqual(http.status("http"), "Failed")
        self.assertEqual(local.status("local"), "Active")
        self.assertEqual(remote.status("remote"), "Active")
        self.assertEqual(dynamic.status("socks"), "Active")
        self.assertEqual(x11.status, "Active")
        self.assertIs(record.state, SessionLifecycleState.CONNECTED)

    def test_logout_is_controller_scoped_and_services_use_session_snapshots(self) -> None:
        controller = SessionController()
        first_profile = _profile("first")
        second_profile = _profile("second", 100)
        first_record = controller.create_session(first_profile)
        second_record = controller.create_session(second_profile)
        first_record.state = second_record.state = SessionLifecycleState.CONNECTED
        first_starter, second_starter = _Starter(), _Starter()
        first = _services(first_record.session_id, first_record.profile_snapshot, first_starter)
        second = _services(second_record.session_id, second_record.profile_snapshot, second_starter)

        first_profile["tunnel_options"]["rules"][0]["bind_port"] = 9999
        first_profile["terminal_options"]["x11_forwarding"] = False
        for service in (*first[:4], *second[:4]):
            service.start_enabled()
        self.assertTrue(first[4].request_for_channel(_X11Channel()))
        self.assertTrue(second[4].request_for_channel(_X11Channel()))
        self.assertEqual(first_starter.rules[0]["bind_port"], 8100)
        self.assertEqual(first_record.profile_snapshot["tunnel_options"]["rules"][0]["bind_port"], 8100)

        for service in first[:4]:
            service.stop_all()
        first[4].close()
        self.assertTrue(all(service.closed for service in first))
        self.assertTrue(all(not service.closed for service in second))
        self.assertTrue(all(service.active_rule_ids() for service in second[:4]))
        self.assertEqual(second[4].status, "Active")
        self.assertTrue(all(listener.closed == 1 for listener in first_starter.listeners.values()))
        self.assertTrue(all(listener.closed == 0 for listener in second_starter.listeners.values()))
        self.assertIs(second_record.state, SessionLifecycleState.CONNECTED)


if __name__ == "__main__":
    unittest.main()
