"""Recorded-stream terminal tests; no Tk display or SSH server is required."""

from __future__ import annotations

import codecs
import re
import unittest

import pyte

from sshvault_core import TerminalPanelState, terminal_key_sequence


class _Screen(pyte.Screen):
    def __init__(self, columns, lines, scrollback):
        super().__init__(columns, lines)
        self._scrollback = scrollback

    def index(self):
        top, bottom = self.margins or (0, self.lines - 1)
        if self.cursor.y == bottom and top == 0:
            self._scrollback.append(self.line(0))
        super().index()

    def line(self, row):
        return "".join(self.buffer[row][col].data for col in range(self.columns)).rstrip()


class FakePTY:
    """Minimal recorded-byte terminal model matching the widget's pyte path."""

    _controls = ("\x1b[?47h", "\x1b[?47l", "\x1b[?1047h", "\x1b[?1047l", "\x1b[?1049h", "\x1b[?1049l")

    def __init__(self, columns=12, rows=3):
        self.columns, self.rows = columns, rows
        self.scrollback = []
        self.normal = _Screen(columns, rows, self.scrollback)
        self.screen = self.normal
        self.stream = pyte.Stream(self.screen)
        self.alternate = None
        self.alternate_active = False
        self.decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self.control_tail = ""
        self.generation = 1
        self.closed = False
        self.outbound = []

    def feed_bytes(self, data, generation=1):
        if self.closed or generation != self.generation:
            return
        self.feed_text(self.decoder.decode(data))

    def feed_text(self, data):
        data = self.control_tail + data
        self.control_tail = ""
        marker = data.rfind("\x1b[?")
        if (
            marker >= 0
            and data[marker:] not in self._controls
            and any(item.startswith(data[marker:]) for item in self._controls)
        ):
            self.control_tail, data = data[marker:], data[:marker]
        for part in re.split(r"(\x1b\[\?(?:47|1047|1049)[hl])", data):
            if part in {"\x1b[?47h", "\x1b[?1047h", "\x1b[?1049h"}:
                self.alternate = _Screen(self.columns, self.rows, [])
                self.screen, self.alternate_active = self.alternate, True
                self.stream.attach(self.screen)
            elif part in {"\x1b[?47l", "\x1b[?1047l", "\x1b[?1049l"}:
                self.screen, self.alternate_active = self.normal, False
                self.stream.attach(self.screen)
            elif part:
                self.stream.feed(part)

    def resize(self, columns, rows, generation=1):
        if generation != self.generation:
            return
        self.columns, self.rows = columns, rows
        self.normal.resize(lines=rows, columns=columns)
        if self.alternate is not None:
            self.alternate.resize(lines=rows, columns=columns)

    def send(self, text):
        self.outbound.append(text.encode("utf-8"))

    def close(self):
        self.closed = True
        self.generation += 1


class FakePTYTerminalTests(unittest.TestCase):
    def test_middle_editing_and_history_are_remote_sequences(self):
        pty = FakePTY()
        for key in ("Left", "BackSpace", "Delete", "Up", "Down", "Home", "End"):
            pty.send(terminal_key_sequence(key))
        self.assertEqual(pty.outbound, [b"\x1b[D", b"\x7f", b"\x1b[3~", b"\x1b[A", b"\x1b[B", b"\x1b[H", b"\x1b[F"])

    def test_line_diff_cr_progress_clear_and_erase(self):
        pty = FakePTY()
        pty.feed_text("abcdef\rxy")
        self.assertEqual(pty.screen.line(0), "xycdef")
        pty.feed_text("\x1b[K")
        self.assertEqual(pty.screen.line(0), "xy")
        pty.feed_text("\x1b[2J")
        self.assertEqual(pty.screen.line(0), "")

    def test_wrapping_and_rapid_redraws(self):
        pty = FakePTY(columns=4, rows=2)
        pty.feed_text("abcdef")
        self.assertEqual((pty.screen.line(0), pty.screen.line(1)), ("abcd", "ef"))
        for number in range(50):
            pty.feed_text(f"\r{number:02d}\x1b[K")
        self.assertEqual(pty.screen.line(1), "49")

    def test_split_utf8_and_ansi_are_buffered(self):
        pty = FakePTY()
        encoded = "é".encode()
        pty.feed_bytes(encoded[:1])
        pty.feed_bytes(encoded[1:])
        pty.feed_bytes(b"\x1b[31")
        pty.feed_bytes(b"mR\x1b[0m")
        self.assertEqual(pty.screen.line(0), "éR")
        self.assertEqual(pty.screen.buffer[0][1].fg, "red")

    def test_scrollback_only_on_live_screen_exit(self):
        pty = FakePTY(columns=8, rows=2)
        pty.feed_text("one\r\ntwo\r\nthree")
        self.assertEqual(pty.scrollback, ["one"])

    def test_alternate_isolation_cursor_restore_and_cycles(self):
        pty = FakePTY()
        pty.feed_text("normal")
        before = (pty.normal.cursor.x, pty.normal.cursor.y)
        pty.feed_bytes(b"\x1b[?10")
        pty.feed_bytes(b"49halt")
        self.assertTrue(pty.alternate_active)
        self.assertEqual(pty.screen.line(0), "alt")
        pty.feed_text("\x1b[?1049l")
        self.assertFalse(pty.alternate_active)
        self.assertEqual(pty.normal.line(0), "normal")
        self.assertEqual((pty.normal.cursor.x, pty.normal.cursor.y), before)
        for _ in range(3):
            pty.feed_text("\x1b[?1049hx\x1b[?1049l")
        self.assertEqual(pty.normal.line(0), "normal")

    def test_resize_normal_alternate_scrollback_and_stale_callback(self):
        pty = FakePTY(columns=5, rows=2)
        pty.feed_text("one\r\ntwo\r\nthree")
        saved = list(pty.scrollback)
        pty.resize(8, 4)
        self.assertEqual((pty.normal.columns, pty.normal.lines), (8, 4))
        self.assertEqual(pty.scrollback, saved)
        pty.feed_text("\x1b[?1049h")
        pty.resize(6, 3)
        self.assertEqual((pty.alternate.columns, pty.alternate.lines), (6, 3))
        pty.resize(99, 99, generation=0)
        self.assertEqual((pty.normal.columns, pty.normal.lines), (6, 3))

    def test_paste_modes_and_close_suppress_stale_output(self):
        state = TerminalPanelState()
        state.follow_output = False
        state.note_output()
        self.assertTrue(state.unseen_output)
        state.jump_to_bottom()
        self.assertFalse(state.unseen_output)
        pty = FakePTY()
        pty.feed_bytes(b"old")
        pty.close()
        pty.feed_bytes(b"new")
        self.assertEqual(pty.screen.line(0), "old")
