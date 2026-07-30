from __future__ import annotations

import copy
import unittest

from sshvault_core import (
    SessionController,
    SessionLifecycleState,
    X11_FORWARDING_OPTION_LABELS,
    X11ForwardingSession,
    build_native_ssh_argv,
    default_profile_sections,
)


class _Channel:
    def __init__(self, *, fail: bool = False) -> None:
        self.fail = fail
        self.requests: list[dict[str, object]] = []

    def request_x11(self, **kwargs: object) -> None:
        if self.fail:
            raise OSError("private server detail")
        self.requests.append(kwargs)


def _profile(*, enabled: bool = False, trusted: bool = False, display: str = "") -> dict:
    return {
        "id": "x11-profile",
        "name": "X11",
        "host": "host.example",
        "port": 22,
        "user": "alice",
        "auth_method": "agent",
        "terminal_options": {
            "terminal_type": "xterm-256color",
            "x11_forwarding": enabled,
            "x11_trusted": trusted,
            "x11_display": display,
        },
    }


def _connected(controller: SessionController, profile: dict):
    record = controller.create_session(profile)
    controller.begin_connection(record.session_id)
    for state in (
        SessionLifecycleState.RESOLVING,
        SessionLifecycleState.CONNECTING_HOST,
        SessionLifecycleState.VERIFYING_HOST_KEY,
        SessionLifecycleState.AUTHENTICATING,
        SessionLifecycleState.CONNECTED,
    ):
        controller.transition(record.session_id, state)
    return record


class ServicesX11ForwardingTests(unittest.TestCase):
    def test_settings_contract_and_disabled_default(self) -> None:
        self.assertEqual(
            X11_FORWARDING_OPTION_LABELS,
            ("Enable X11 forwarding", "Trusted forwarding", "X11 display"),
        )
        options = default_profile_sections()["terminal_options"]
        self.assertFalse(options["x11_forwarding"])
        self.assertFalse(options["x11_trusted"])
        self.assertEqual(options["x11_display"], "")
        service = X11ForwardingSession("session", options, {"DISPLAY": ":0"})
        self.assertFalse(service.request_for_channel(_Channel()))
        self.assertEqual(service.status, "Stopped")

    def test_enabled_request_uses_display_screen(self) -> None:
        service = X11ForwardingSession(
            "session",
            _profile(enabled=True, display="localhost:10.2")["terminal_options"],
            {},
        )
        channel = _Channel()
        self.assertTrue(service.request_for_channel(channel))
        self.assertEqual(
            channel.requests,
            [{"screen_number": 2, "single_connection": False}],
        )
        self.assertEqual(service.status, "Active")
        self.assertEqual(service.request_count, 1)

    def test_trusted_and_untrusted_forwarding_are_preserved(self) -> None:
        trusted = X11ForwardingSession(
            "trusted",
            _profile(enabled=True, trusted=True, display=":0")["terminal_options"],
            {},
        )
        untrusted = X11ForwardingSession(
            "untrusted",
            _profile(enabled=True, trusted=False, display=":0")["terminal_options"],
            {},
        )
        trusted.request_for_channel(_Channel())
        untrusted.request_for_channel(_Channel())
        self.assertTrue(trusted.last_request["trusted"])
        self.assertFalse(untrusted.last_request["trusted"])
        self.assertIn("-Y", build_native_ssh_argv(_profile(enabled=True, trusted=True)))
        self.assertIn("-X", build_native_ssh_argv(_profile(enabled=True, trusted=False)))

    def test_empty_profile_display_falls_back_to_local_display(self) -> None:
        service = X11ForwardingSession(
            "session",
            _profile(enabled=True)["terminal_options"],
            {"DISPLAY": ":7.1"},
        )
        channel = _Channel()
        self.assertTrue(service.request_for_channel(channel))
        self.assertEqual(service.display, ":7.1")
        self.assertEqual(channel.requests[0]["screen_number"], 1)

    def test_request_failure_is_sanitized_and_keeps_session_resources(self) -> None:
        controller = SessionController()
        record = _connected(controller, _profile(enabled=True, display=":0"))
        controller.register_sftp_view(record.session_id, "sftp-view")
        controller.register_tunnel(record.session_id, "tunnel")
        service = X11ForwardingSession(
            record.session_id,
            record.profile_snapshot["terminal_options"],
            {},
        )
        self.assertFalse(service.request_for_channel(_Channel(fail=True)))
        self.assertEqual(service.error, "X11 forwarding request failed.")
        self.assertNotIn("private server detail", service.error)
        current = controller.get(record.session_id)
        self.assertIs(current.state, SessionLifecycleState.CONNECTED)
        self.assertEqual(current.sftp_view_ids, {"sftp-view"})
        self.assertEqual(current.tunnel_ids, {"tunnel"})

    def test_cleanup_and_controller_isolation(self) -> None:
        options = _profile(enabled=True, display=":0")["terminal_options"]
        first = X11ForwardingSession("first", options, {})
        second = X11ForwardingSession("second", options, {})
        first.request_for_channel(_Channel())
        second.request_for_channel(_Channel())
        first.close()
        first.close()
        self.assertTrue(first.closed)
        self.assertEqual(first.status, "Stopped")
        self.assertFalse(second.closed)
        self.assertEqual(second.status, "Active")

    def test_active_session_uses_immutable_options_snapshot(self) -> None:
        profile = _profile(enabled=True, trusted=True, display=":4")
        controller = SessionController()
        record = controller.create_session(profile)
        service = X11ForwardingSession(
            record.session_id,
            record.profile_snapshot["terminal_options"],
            {},
        )
        working = copy.deepcopy(profile)
        working["terminal_options"]["x11_forwarding"] = False
        working["terminal_options"]["x11_trusted"] = False
        working["terminal_options"]["x11_display"] = ":9"
        self.assertTrue(service.enabled)
        self.assertTrue(service.trusted)
        self.assertEqual(service.display, ":4")
        self.assertTrue(record.profile_snapshot["terminal_options"]["x11_forwarding"])
        self.assertEqual(record.profile_snapshot["terminal_options"]["x11_display"], ":4")


if __name__ == "__main__":
    unittest.main()
