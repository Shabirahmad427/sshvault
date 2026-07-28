"""Display-free terminal lifecycle and safety tests."""

from __future__ import annotations

import unittest

from sshvault_core import (
    TerminalPanelState,
    terminal_key_sequence,
    application_shortcut_allowed,
    confirm_multiline_paste_enabled,
    redact_secrets,
)


class TerminalPanelStateTests(unittest.TestCase):
    def test_lifecycle_and_stale_output_suppression(self) -> None:
        state = TerminalPanelState()
        first = state.begin()
        self.assertEqual(state.status, "connecting")
        self.assertTrue(state.connected(first))
        self.assertTrue(state.accepts_output(first))
        second = state.begin(reconnecting=True)
        self.assertEqual(state.status, "reconnecting")
        self.assertFalse(state.accepts_output(first))
        self.assertTrue(state.connected(second))
        self.assertTrue(state.ended(second))
        self.assertEqual(state.status, "session ended")

    def test_bounded_scrollback_follow_and_clear_policy(self) -> None:
        state = TerminalPanelState(max_scrollback_lines=3)
        self.assertEqual(state.trim_scrollback(["1", "2", "3", "4"]), ["2", "3", "4"])
        self.assertTrue(state.follow_output)
        state.follow_output = False
        self.assertFalse(state.follow_output)
        state.note_output()
        self.assertTrue(state.unseen_output)
        state.jump_to_bottom()
        self.assertTrue(state.follow_output)
        self.assertFalse(state.unseen_output)

    def test_paste_confirmation_and_secret_safe_diagnostics(self) -> None:
        self.assertFalse(TerminalPanelState.requires_paste_confirmation("ls -la"))
        self.assertTrue(TerminalPanelState.requires_paste_confirmation("one\ntwo"))
        self.assertNotIn("secret", str(redact_secrets("password=secret")))
        self.assertTrue(confirm_multiline_paste_enabled(None))
        self.assertTrue(confirm_multiline_paste_enabled({"confirm_multiline_paste": "bad"}))
        self.assertTrue(confirm_multiline_paste_enabled({"confirm_multiline_paste": True}))
        self.assertFalse(confirm_multiline_paste_enabled({"confirm_multiline_paste": False}))

    def test_resize_small_widgets_and_shortcut_suppression(self) -> None:
        self.assertEqual(TerminalPanelState.terminal_size(0, 0, 8, 16), (1, 1))
        self.assertEqual(TerminalPanelState.terminal_size(808, 324, 8, 16), (100, 20))
        self.assertFalse(application_shortcut_allowed("TerminalWidget"))

    def test_terminal_key_translation_is_remote_only(self) -> None:
        self.assertEqual(terminal_key_sequence("Up"), "\x1b[A")
        self.assertEqual(terminal_key_sequence("Up", application_cursor=True), "\x1bOA")
        self.assertEqual(terminal_key_sequence("Left", state=0x0004), "\x1b[1;5D")
        self.assertEqual(terminal_key_sequence("Home"), "\x1b[H")
        self.assertEqual(terminal_key_sequence("End"), "\x1b[F")
        self.assertEqual(terminal_key_sequence("Delete"), "\x1b[3~")
        self.assertEqual(terminal_key_sequence("BackSpace"), "\x7f")
        self.assertEqual(terminal_key_sequence("Insert"), "\x1b[2~")
        self.assertEqual(terminal_key_sequence("F12"), "\x1b[24~")
        self.assertEqual(terminal_key_sequence("a", "a", 0x0004), "\x01")
        self.assertEqual(terminal_key_sequence("x", "x", 0x0008), "\x1bx")
