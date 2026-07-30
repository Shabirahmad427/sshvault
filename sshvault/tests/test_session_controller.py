"""Display-free Milestone A lifecycle tests."""

from __future__ import annotations

import unittest

from sshvault_core import SessionController, SessionLifecycleState


def profile(name: str = "One") -> dict:
    return {
        "id": "123e4567-e89b-12d3-a456-426614174000",
        "name": name,
        "host": "one.example",
        "port": 22,
        "user": "alice",
        "auth_method": "agent",
    }


class SessionControllerTests(unittest.TestCase):
    def test_sessions_have_unique_identity_and_copied_secret_free_snapshot(self) -> None:
        controller = SessionController()
        source = profile() | {"password": "never-store"}
        first, second = controller.create_session(source), controller.create_session(source)
        source["host"] = "changed.example"
        self.assertNotEqual(first.session_id, second.session_id)
        self.assertEqual(first.profile_id, second.profile_id)
        self.assertEqual(first.profile_snapshot["host"], "one.example")
        self.assertNotIn("password", first.profile_snapshot)
        self.assertEqual(len(controller.for_profile(first.profile_id)), 2)

    def test_valid_transitions_and_invalid_transition_rejection(self) -> None:
        controller = SessionController()
        session = controller.create_session(profile())
        self.assertTrue(controller.begin_connection(session.session_id))
        for state in (
            SessionLifecycleState.RESOLVING,
            SessionLifecycleState.CONNECTING_HOST,
            SessionLifecycleState.VERIFYING_HOST_KEY,
            SessionLifecycleState.AUTHENTICATING,
            SessionLifecycleState.CONNECTED,
        ):
            controller.transition(session.session_id, state)
        with self.assertRaises(ValueError):
            controller.transition(session.session_id, SessionLifecycleState.VALIDATING)
        self.assertTrue(controller.disconnect(session.session_id))
        self.assertFalse(controller.disconnect(session.session_id))

    def test_tool_ownership_is_independent(self) -> None:
        controller = SessionController()
        session = controller.create_session(profile())
        controller.register_terminal(session.session_id, "term-1")
        controller.register_sftp_view(session.session_id, "sftp-1")
        controller.register_tunnel(session.session_id, "tunnel-1")
        controller.unregister_terminal(session.session_id, "term-1")
        current = controller.get(session.session_id)
        self.assertEqual(current.terminal_ids, set())
        self.assertEqual(current.sftp_view_ids, {"sftp-1"})
        self.assertEqual(current.tunnel_ids, {"tunnel-1"})
