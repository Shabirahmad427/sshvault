from __future__ import annotations

import unittest

from sshvault_core import (
    APPLICATION_STARTUP_OPTION_LABELS,
    LOGOUT_OPTION_LABELS,
    OPTIONS_GROUPS,
    POST_LOGIN_OPTION_LABELS,
    SessionController,
    StartupActionCoordinator,
    normalized_launch_preferences,
    validate_profile,
    validate_settings,
)


class OptionsTabContractTests(unittest.TestCase):
    def test_exact_groups_and_labels(self) -> None:
        self.assertEqual(OPTIONS_GROUPS, ("On successful login", "Application startup", "On logout"))
        self.assertEqual(
            POST_LOGIN_OPTION_LABELS,
            ("Open Terminal", "Open SFTP", "Start enabled services", "Run configured startup commands"),
        )
        self.assertEqual(
            APPLICATION_STARTUP_OPTION_LABELS,
            (
                "Load last selected profile",
                "Log in automatically",
                "Restore previous sessions",
                "Restore window position",
            ),
        )
        self.assertEqual(
            LOGOUT_OPTION_LABELS,
            (
                "Close terminal windows",
                "Close SFTP windows",
                "Stop enabled services",
                "Ask before cancelling active transfers",
            ),
        )

    def test_passive_profile_option_defaults(self) -> None:
        preferences = normalized_launch_preferences(None)
        self.assertEqual(
            preferences,
            {
                "open_terminal": False,
                "open_sftp": False,
                "start_enabled_services": False,
                "run_startup_commands": False,
                "startup_command": "",
            },
        )
        profile = validate_profile({"host": "host.example", "user": "alice"}, check_key_exists=False)
        self.assertEqual(profile["launch_preferences"], preferences)

    def test_application_startup_defaults_are_passive(self) -> None:
        settings = validate_settings({})
        self.assertTrue(settings["load_last_selected_profile"])
        self.assertFalse(settings["login_automatically_on_start"])
        self.assertFalse(settings["restore_previous_sessions_on_start"])
        self.assertTrue(settings["restore_window_position"])

    def test_post_login_order_and_exactly_once(self) -> None:
        calls: list[str] = []
        coordinator = StartupActionCoordinator(
            {
                "tunnels": lambda: calls.append("services"),
                "command": lambda _data: calls.append("command"),
                "terminal": lambda: calls.append("terminal"),
                "sftp": lambda: calls.append("sftp"),
            }
        )
        preferences = {
            "start_enabled_services": True,
            "run_startup_commands": True,
            "startup_command": "echo ready",
            "open_terminal": True,
            "open_sftp": True,
        }
        coordinator.run(preferences, 7)
        coordinator.run(preferences, 7)  # duplicate CONNECTED callback
        self.assertEqual(calls, ["services", "command", "terminal", "sftp"])

    def test_disabled_or_failed_connection_has_no_post_login_actions(self) -> None:
        calls: list[str] = []
        coordinator = StartupActionCoordinator({"terminal": lambda: calls.append("terminal")})
        coordinator.run(normalized_launch_preferences({}), 1)
        self.assertEqual(calls, [])

    def test_session_snapshot_keeps_connection_options_isolated(self) -> None:
        profile = validate_profile(
            {
                "id": "profile-a",
                "host": "host.example",
                "user": "alice",
                "launch_preferences": {"open_terminal": True},
                "connection_options": {"stop_enabled_services": True},
            },
            check_key_exists=False,
        )
        session = SessionController().create_session(profile)
        profile["launch_preferences"]["open_terminal"] = False
        profile["connection_options"]["stop_enabled_services"] = False
        self.assertTrue(session.profile_snapshot["launch_preferences"]["open_terminal"])
        self.assertTrue(session.profile_snapshot["connection_options"]["stop_enabled_services"])


if __name__ == "__main__":
    unittest.main()
