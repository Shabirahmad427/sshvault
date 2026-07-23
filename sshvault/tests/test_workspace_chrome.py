"""Display-free workspace connection-chrome state tests."""

from __future__ import annotations

import unittest

from sshvault_core import WorkspaceChromeState


class WorkspaceChromeStateTests(unittest.TestCase):
    def test_initial_disconnected_state_and_connect_button(self) -> None:
        state = WorkspaceChromeState()
        self.assertEqual(state.status, "disconnected")
        self.assertEqual(state.connect_button, ("Connect", True))
        self.assertFalse(state.connection_tools_enabled)

    def test_connecting_prevents_duplicate_attempts_and_disables_tools(self) -> None:
        state = WorkspaceChromeState()
        state.transition("connecting")
        self.assertEqual(state.connect_button, ("Connecting…", False))
        self.assertFalse(state.connection_tools_enabled)
        with self.assertRaises(ValueError):
            state.transition("connecting")

    def test_connected_and_disconnect_transitions(self) -> None:
        state = WorkspaceChromeState()
        state.transition("connecting")
        state.transition("connected")
        self.assertEqual(state.connect_button, ("Disconnect", True))
        self.assertTrue(state.connection_tools_enabled)
        state.transition("disconnecting")
        self.assertEqual(state.connect_button, ("Disconnecting…", False))
        state.transition("disconnected")
        self.assertFalse(state.connection_tools_enabled)

    def test_failure_message_is_redacted_and_can_reconnect(self) -> None:
        state = WorkspaceChromeState()
        state.transition("connecting")
        state.transition("failed", "password=hunter2")
        self.assertEqual(state.status, "failed")
        self.assertNotIn("hunter2", state.message)
        self.assertEqual(state.connect_button, ("Connect", True))
        state.transition("connecting")

    def test_selected_tab_is_preserved_by_state(self) -> None:
        state = WorkspaceChromeState(selected_tab="SFTP")
        state.transition("connecting")
        state.transition("connected")
        self.assertEqual(state.selected_tab, "SFTP")
