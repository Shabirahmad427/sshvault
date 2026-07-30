from __future__ import annotations

import unittest

from sshvault_core import (
    SessionController,
    SessionLifecycleState,
    TERMINAL_BACKENDS,
    TERMINAL_BELLS,
    TERMINAL_COLOR_THEMES,
    TERMINAL_CURSOR_SHAPES,
    TERMINAL_GROUPS,
    build_native_ssh_argv,
    default_profile_sections,
    terminal_key_sequence,
    validate_profile,
)


class TerminalTabContractTests(unittest.TestCase):
    def test_exact_group_and_choice_contract(self) -> None:
        self.assertEqual(TERMINAL_GROUPS, ("Terminal Emulation", "Appearance", "Session Behavior", "Terminal Actions"))
        self.assertEqual(TERMINAL_BACKENDS, ("Automatic", "Native VTE", "Legacy"))
        self.assertEqual(TERMINAL_BELLS, ("System bell", "Visual bell", "Disabled"))
        self.assertEqual(TERMINAL_CURSOR_SHAPES, ("Block", "I-Beam", "Underline"))
        self.assertEqual(TERMINAL_COLOR_THEMES, ("System", "Light", "Dark"))

    def test_terminal_defaults_are_passive_and_native_ready(self) -> None:
        options = default_profile_sections()["terminal_options"]
        self.assertEqual(options["terminal_type"], "xterm-256color")
        self.assertEqual(options["scrollback"], 10000)
        self.assertFalse(options["agent_forwarding"])
        self.assertFalse(options["x11_forwarding"])
        self.assertFalse(options["close_on_logout"])
        self.assertFalse(options["scroll_on_output"])
        self.assertTrue(options["scroll_on_keystroke"])

    def test_clauberh_native_argv_uses_session_target_and_selected_flags(self) -> None:
        argv = build_native_ssh_argv(
            {
                "name": "clauberh",
                "host": "coaraci.ifi.unicamp.br",
                "port": 22,
                "user": "clauberh",
                "auth_method": "agent",
                "proxy_jump": "sahmaddo@gate.ifi.unicamp.br",
                "terminal_options": {
                    "terminal_type": "xterm-256color",
                    "agent_forwarding": True,
                    "x11_forwarding": True,
                    "startup_command": "uptime",
                },
            }
        )
        self.assertEqual(argv[:6], ["ssh", "-tt", "-p", "22", "-J", "sahmaddo@gate.ifi.unicamp.br"])
        self.assertIn("SetEnv=TERM=xterm-256color", argv)
        self.assertIn("-A", argv)
        self.assertIn("-X", argv)
        self.assertEqual(argv[-2:], ["clauberh@coaraci.ifi.unicamp.br", "uptime"])
        self.assertNotIn("clauberh", argv[:-2])

    def test_no_forwarding_flags_or_secret_in_default_argv(self) -> None:
        argv = build_native_ssh_argv(
            {"host": "example.org", "port": 22, "user": "alice", "auth_method": "password", "password": "secret"}
        )
        self.assertNotIn("-A", argv)
        self.assertNotIn("-X", argv)
        self.assertNotIn("secret", argv)

    def test_terminal_options_are_copied_into_session_snapshot(self) -> None:
        profile = validate_profile(
            {
                "id": "profile-terminal",
                "host": "example.org",
                "user": "alice",
                "terminal_options": {"font_size": 14, "scrollback": 20000},
            },
            check_key_exists=False,
        )
        session = SessionController().create_session(profile)
        profile["terminal_options"]["font_size"] = 6
        self.assertEqual(session.profile_snapshot["terminal_options"]["font_size"], 14)

    def test_session_state_drives_terminal_action_availability(self) -> None:
        controller = SessionController()
        record = controller.create_session({"host": "example.org", "user": "alice"})
        self.assertIs(record.state, SessionLifecycleState.DISCONNECTED)
        controller.begin_connection(record.session_id)
        self.assertIsNot(
            controller.state if hasattr(controller, "state") else record.state, SessionLifecycleState.CONNECTED
        )
        controller.transition(record.session_id, SessionLifecycleState.RESOLVING)
        controller.transition(record.session_id, SessionLifecycleState.CONNECTING_HOST)
        controller.transition(record.session_id, SessionLifecycleState.VERIFYING_HOST_KEY)
        controller.transition(record.session_id, SessionLifecycleState.AUTHENTICATING)
        controller.transition(record.session_id, SessionLifecycleState.CONNECTED)
        self.assertIs(controller.get(record.session_id).state, SessionLifecycleState.CONNECTED)

    def test_native_selection_shortcuts_do_not_turn_ctrl_c_into_copy(self) -> None:
        self.assertEqual(terminal_key_sequence("c", "c", 0x0004), "\x03")
        self.assertEqual(terminal_key_sequence("Insert", "Insert", 0x0004), "\x1b[2~")


if __name__ == "__main__":
    unittest.main()
