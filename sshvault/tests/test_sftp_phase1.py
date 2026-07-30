from __future__ import annotations

import unittest

from sshvault_core import SessionController, SessionLifecycleState, StartupActionCoordinator, validate_profile


class SFTPPhaseOneTests(unittest.TestCase):
    def test_snapshot_and_view_registration_are_isolated(self) -> None:
        profile = validate_profile(
            {
                "id": "sftp",
                "host": "example.org",
                "user": "alice",
                "sftp_options": {"initial_remote_directory": "/one"},
            },
            check_key_exists=False,
        )
        controller = SessionController()
        record = controller.create_session(profile)
        profile["sftp_options"]["initial_remote_directory"] = "/two"
        self.assertEqual(record.profile_snapshot["sftp_options"]["initial_remote_directory"], "/one")
        controller.register_sftp_view(record.session_id, "view-1")
        controller.register_sftp_view(record.session_id, "view-2")
        controller.unregister_sftp_view(record.session_id, "view-1")
        self.assertEqual(record.sftp_view_ids, {"view-2"})

    def test_only_connected_sessions_are_eligible_for_sftp_actions(self) -> None:
        controller = SessionController()
        record = controller.create_session({"host": "example.org", "user": "alice"})
        self.assertIs(record.state, SessionLifecycleState.DISCONNECTED)
        controller.begin_connection(record.session_id)
        self.assertIsNot(record.state, SessionLifecycleState.CONNECTED)

    def test_on_login_sftp_action_runs_once_per_generation(self) -> None:
        calls: list[str] = []
        actions = StartupActionCoordinator({"sftp": lambda: calls.append("view")})
        actions.run({"open_sftp": True}, 1)
        actions.run({"open_sftp": True}, 1)
        self.assertEqual(calls, ["view"])

    def test_disabled_sftp_action_opens_no_view(self) -> None:
        calls: list[str] = []
        StartupActionCoordinator({"sftp": lambda: calls.append("view")}).run({"open_sftp": False}, 1)
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
