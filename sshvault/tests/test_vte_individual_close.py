from __future__ import annotations

import unittest
import threading
import time
import json
from pathlib import Path
from unittest.mock import Mock, patch

from sshvault_core import TransferScheduler, VTEAvailability, VTETerminalBackend
from sshvault_vte_helper import (
    NATIVE_VTE_CLOSE_TAB_LABEL,
    _dispatch_terminal_keypress,
    _read_control_messages,
    _terminal_tab_label,
    _terminal_shortcut_action,
)


class _Widget:
    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.children: list[object] = []
        self.callback = None
        self.tooltip = ""

    def set_relief(self, _relief: object) -> None:
        pass

    def set_focus_on_click(self, _enabled: bool) -> None:
        pass

    def set_tooltip_text(self, text: str) -> None:
        self.tooltip = text

    def connect(self, _signal: str, callback: object) -> None:
        self.callback = callback

    def pack_start(self, widget: object, _expand: bool, _fill: bool, _padding: int) -> None:
        self.children.append(widget)

    def show_all(self) -> None:
        pass


class _Gtk:
    class Orientation:
        HORIZONTAL = "horizontal"

    class ReliefStyle:
        NONE = "none"

    Box = _Widget
    Label = _Widget
    Button = _Widget


class _KeyWidget:
    def __init__(self, *, selection: bool = False) -> None:
        self.selection = selection
        self.copy_count = 0
        self.paste_count = 0

    def get_has_selection(self) -> bool:
        return self.selection

    def copy_clipboard(self) -> None:
        self.copy_count += 1

    def paste_clipboard(self) -> None:
        self.paste_count += 1


class _NonBlockingSocket:
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = list(chunks)
        self.recv_calls = 0

    def recv(self, _size: int) -> bytes:
        self.recv_calls += 1
        if not self.chunks:
            raise BlockingIOError
        return self.chunks.pop(0)


class NativeVTEIndividualCloseTests(unittest.TestCase):
    def test_copy_paste_and_selection_shortcuts_remain_native(self) -> None:
        self.assertEqual(_terminal_shortcut_action(True, True, ord("C"), True), "copy")
        self.assertEqual(_terminal_shortcut_action(True, True, ord("V"), False), "paste")
        self.assertEqual(_terminal_shortcut_action(True, False, 65379, True), "copy")
        self.assertEqual(_terminal_shortcut_action(False, True, 65379, False), "paste")
        self.assertIsNone(_terminal_shortcut_action(True, False, ord("c"), True))

    def test_keyboard_input_is_dispatched_immediately_to_native_vte(self) -> None:
        widget = _KeyWidget()
        event = Mock(state=0, keyval=ord("x"))
        self.assertFalse(_dispatch_terminal_keypress(widget, event))
        self.assertEqual((widget.copy_count, widget.paste_count), (0, 0))

    def test_available_helper_messages_are_batched_in_one_read_wakeup(self) -> None:
        messages = [
            {"type": "focus_tab", "request_id": "one"},
            {"type": "list_terminals", "request_id": "two"},
        ]
        wire = b"".join((json.dumps(message).encode() + b"\n") for message in messages)
        connection = _NonBlockingSocket([wire[:17], wire[17:]])
        pending, decoded, connected = _read_control_messages(connection, b"")  # type: ignore[arg-type]
        self.assertEqual(decoded, messages)
        self.assertEqual(pending, b"")
        self.assertTrue(connected)
        self.assertEqual(connection.recv_calls, 3)

    def test_native_vte_has_no_duplicate_resize_or_focus_forwarding(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "sshvault_vte_helper.py").read_text(encoding="utf-8")
        self.assertNotIn('connect("focus-in-event"', source)
        self.assertNotIn('connect("size-allocate"', source)
        self.assertNotIn("timeout_add", source)

    def test_vte_control_remains_responsive_while_sftp_worker_lock_is_held(self) -> None:
        scheduler = TransferScheduler(lambda: Mock())
        lock_held = threading.Event()
        release = threading.Event()

        def hold_sftp_lock() -> None:
            with scheduler._condition:
                lock_held.set()
                release.wait(1)

        worker = threading.Thread(target=hold_sftp_lock)
        worker.start()
        self.assertTrue(lock_held.wait(1))
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._connection = Mock()
        with (
            patch("sshvault_core.uuid4", return_value="vte-request"),
            patch.object(
                backend,
                "_receive",
                return_value={"type": "response", "request_id": "vte-request", "ok": True},
            ),
        ):
            started = time.monotonic()
            response = backend._request("list_terminals")
        release.set()
        worker.join(1)
        self.assertTrue(response and response["ok"])
        self.assertLess(time.monotonic() - started, 0.1)

    def test_visible_tab_close_control_targets_only_its_tab(self) -> None:
        closed: list[str] = []
        label = _terminal_tab_label(
            _Gtk,
            "sahmaddo (2)",
            lambda _button: closed.append("second"),
        )
        close_button = label.children[1]
        self.assertEqual(close_button.kwargs["label"], "×")
        self.assertEqual(close_button.tooltip, NATIVE_VTE_CLOSE_TAB_LABEL)
        close_button.callback(close_button)
        self.assertEqual(closed, ["second"])

    def test_backend_close_removes_one_terminal_and_preserves_sibling(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {
            "first": {"terminal_id": "first"},
            "second": {"terminal_id": "second"},
        }
        backend.last_terminal_id = "second"
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        with (
            patch("sshvault_core.threading.Thread") as thread,
        ):
            self.assertTrue(backend.close_terminal("first"))
        thread.assert_called_once()
        thread.return_value.start.assert_called_once_with()
        self.assertNotIn("first", backend._terminals)
        self.assertIn("second", backend._terminals)
        self.assertEqual(backend.last_terminal_id, "second")

    def test_closing_terminal_returns_before_slow_ipc_reply(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {"terminal": {"terminal_id": "terminal"}}
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        finished = threading.Event()
        reaped = threading.Event()
        backend._process.wait.side_effect = lambda timeout: reaped.set()

        def slow_request(*_args, **_kwargs):
            time.sleep(0.2)
            finished.set()

        with patch.object(backend, "_request", side_effect=slow_request):
            started = time.monotonic()
            self.assertTrue(backend.close_terminal("terminal"))
            self.assertLess(time.monotonic() - started, 0.1)
            self.assertTrue(finished.wait(1))
            self.assertTrue(reaped.wait(1))


if __name__ == "__main__":
    unittest.main()
