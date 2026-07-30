from __future__ import annotations

import unittest

from sshvault_core import (
    HTTP_FORWARDING_STATUSES,
    HTTPConnectRequestError,
    HTTPForwardingSession,
    SessionController,
    SessionLifecycleState,
    open_http_connect_channel,
    parse_http_connect_request,
)


def _rule(
    rule_id: str,
    *,
    enabled: bool = True,
    listen_host: str = "127.0.0.1",
    listen_port: int = 8080,
) -> dict:
    return {
        "rule_id": rule_id,
        "enabled": enabled,
        "type": "HTTP",
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
            raise OSError("private listener failure")
        listener = _Listener()
        running.runtime.listener = listener
        self.listeners[str(rule["rule_id"])] = listener


class _Transport:
    def __init__(self, channel=None, *, fail: bool = False) -> None:
        self.channel = object() if channel is None else channel
        self.fail = fail
        self.calls: list[tuple[str, tuple[str, int], tuple[str, int]]] = []

    def open_channel(self, kind: str, target: tuple[str, int], origin: tuple[str, int]):
        self.calls.append((kind, target, origin))
        if self.fail:
            raise OSError("private routing failure")
        return self.channel


class ServicesHTTPForwardingTests(unittest.TestCase):
    def test_status_contract_and_enabled_disabled_rules(self) -> None:
        self.assertEqual(
            HTTP_FORWARDING_STATUSES,
            ("Stopped", "Starting", "Active", "Failed"),
        )
        starter = _Starter()
        service = HTTPForwardingSession(
            "session",
            object(),
            [_rule("enabled"), _rule("disabled", enabled=False, listen_port=8081)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("enabled"), "Active")
        self.assertEqual(service.status("disabled"), "Stopped")
        self.assertEqual([rule["rule_id"] for rule in starter.rules], ["enabled"])

    def test_successful_connect_routes_through_existing_transport(self) -> None:
        channel = object()
        transport = _Transport(channel)
        request = b"CONNECT example.test:443 HTTP/1.1\r\nHost: example.test:443\r\n\r\n"
        self.assertEqual(parse_http_connect_request(request), ("example.test", 443))
        self.assertIs(
            open_http_connect_channel(request, transport, ("127.0.0.1", 45000)),
            channel,
        )
        self.assertEqual(
            transport.calls,
            [("direct-tcpip", ("example.test", 443), ("127.0.0.1", 45000))],
        )

    def test_malformed_connect_request_returns_bad_request(self) -> None:
        malformed = b"CONNECT example.test HTTP/1.1\r\n\r\n"
        with self.assertRaises(HTTPConnectRequestError) as raised:
            parse_http_connect_request(malformed)
        self.assertEqual(raised.exception.status_code, 400)
        self.assertTrue(raised.exception.response().startswith(b"HTTP/1.1 400 Bad Request"))

    def test_unsupported_http_methods_are_rejected_without_routing(self) -> None:
        transport = _Transport()
        request = b"GET http://example.test/ HTTP/1.1\r\nHost: example.test\r\n\r\n"
        with self.assertRaises(HTTPConnectRequestError) as raised:
            open_http_connect_channel(request, transport, ("127.0.0.1", 45000))
        self.assertEqual(raised.exception.status_code, 405)
        self.assertIn(b"Allow: CONNECT", raised.exception.response())
        self.assertEqual(transport.calls, [])

    def test_duplicate_listener_is_rejected(self) -> None:
        starter = _Starter()
        service = HTTPForwardingSession(
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

    def test_listener_failure_isolated_from_ssh_session(self) -> None:
        controller = SessionController()
        session = controller.create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        starter = _Starter({8080})
        service = HTTPForwardingSession(
            session.session_id,
            object(),
            [_rule("failed"), _rule("healthy", listen_port=8081)],
            starter,
        )
        service.start_enabled()
        self.assertEqual(service.status("failed"), "Failed")
        self.assertEqual(service.status("healthy"), "Active")
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_logout_cleanup_and_controller_isolation(self) -> None:
        first_starter, second_starter = _Starter(), _Starter()
        first = HTTPForwardingSession("first", object(), [_rule("first")], first_starter)
        second = HTTPForwardingSession(
            "second",
            object(),
            [_rule("second", listen_port=8081)],
            second_starter,
        )
        first.start_enabled()
        second.start_enabled()
        first.stop_all()
        first.stop_all()
        self.assertEqual(first.status("first"), "Stopped")
        self.assertEqual(second.status("second"), "Active")
        self.assertEqual(first_starter.listeners["first"].closed, 1)
        self.assertEqual(second_starter.listeners["second"].closed, 0)

    def test_runtime_uses_session_snapshot(self) -> None:
        profile = {
            "id": "profile",
            "name": "HTTP proxy",
            "host": "host.example",
            "port": 22,
            "user": "alice",
            "auth_method": "agent",
            "tunnel_options": {"rules": [_rule("snapshot")]},
        }
        session = SessionController().create_session(profile)
        starter = _Starter()
        service = HTTPForwardingSession(
            session.session_id,
            object(),
            session.profile_snapshot["tunnel_options"]["rules"],
            starter,
        )
        profile["tunnel_options"]["rules"][0]["bind_port"] = 9080
        service.start_enabled()
        self.assertEqual(starter.rules[0]["bind_port"], 8080)
        self.assertEqual(
            session.profile_snapshot["tunnel_options"]["rules"][0]["bind_port"],
            8080,
        )


if __name__ == "__main__":
    unittest.main()
