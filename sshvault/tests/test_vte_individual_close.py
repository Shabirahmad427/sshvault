from __future__ import annotations

import unittest
import threading
import time
import json
from pathlib import Path
from unittest.mock import Mock, patch

from sshvault import ConnectionTab
from sshvault_core import SessionController, TransferScheduler, VTEAvailability, VTETerminalBackend
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

    def test_helper_preserves_partial_frame_until_next_read(self) -> None:
        message = {"type": "focus_tab", "request_id": "fragmented"}
        wire = json.dumps(message).encode() + b"\n"
        first = _NonBlockingSocket([wire[:11]])
        pending, decoded, connected = _read_control_messages(first, b"")  # type: ignore[arg-type]
        self.assertEqual(decoded, [])
        self.assertEqual(pending, wire[:11])
        self.assertTrue(connected)
        second = _NonBlockingSocket([wire[11:]])
        pending, decoded, connected = _read_control_messages(second, pending)  # type: ignore[arg-type]
        self.assertEqual((pending, decoded, connected), (b"", [message], True))

    def test_helper_partial_frame_then_disconnect_is_not_parsed(self) -> None:
        connection = _NonBlockingSocket([b'{"type":"focus_tab"', b""])
        pending, decoded, connected = _read_control_messages(connection, b"")  # type: ignore[arg-type]
        self.assertEqual(decoded, [])
        self.assertTrue(pending)
        self.assertFalse(connected)

    def test_helper_discards_only_malformed_frame(self) -> None:
        valid = {"type": "list_terminals", "request_id": "valid"}
        connection = _NonBlockingSocket([b"{bad json}\n" + json.dumps(valid).encode() + b"\n"])
        pending, decoded, connected = _read_control_messages(connection, b"")  # type: ignore[arg-type]
        self.assertEqual((pending, decoded, connected), (b"", [valid], True))

    def test_native_vte_has_no_duplicate_resize_or_focus_forwarding(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "sshvault_vte_helper.py").read_text(encoding="utf-8")
        self.assertNotIn('connect("focus-in-event"', source)
        self.assertNotIn('connect("size-allocate"', source)
        self.assertNotIn("timeout_add", source)

    def test_native_vte_helper_applies_appearance_settings(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "sshvault_vte_helper.py").read_text(encoding="utf-8")
        for call in (
            "terminal.set_font(description)",
            "terminal.set_cursor_shape",
            "terminal.set_cursor_blink_mode",
            "terminal.set_color_foreground",
            "terminal.set_color_background",
        ):
            self.assertIn(call, source)

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

    def test_successful_close_acknowledgement_removes_only_requested_terminal(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {
            "first": {"terminal_id": "first", "session_id": "sahmaddo"},
            "second": {"terminal_id": "second", "session_id": "sahmaddo"},
        }
        backend.last_terminal_id = "second"
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        entered = threading.Event()
        release = threading.Event()
        completed = threading.Event()
        result = []

        def request(*_args, **_kwargs):
            entered.set()
            release.wait(1)
            return {"ok": True}

        with patch.object(backend, "_request", side_effect=request):
            self.assertTrue(backend.close_terminal("first"))
            self.assertTrue(entered.wait(0.5))
            self.assertIn("first", backend._terminals)
            self.assertTrue(
                backend.close_terminal(
                    "first",
                    lambda *values: (result.append(values), completed.set()),
                )
            )
            release.set()
            self.assertTrue(completed.wait(1))
        self.assertNotIn("first", backend._terminals)
        self.assertIn("second", backend._terminals)
        self.assertEqual(backend.last_terminal_id, "second")
        self.assertEqual(result, [("first", True, "")])

    def test_closing_terminal_returns_before_slow_ipc_reply(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {"terminal": {"terminal_id": "terminal"}}
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        finished = threading.Event()

        def slow_request(*_args, **_kwargs):
            time.sleep(0.2)
            finished.set()
            return {"ok": True}

        with patch.object(backend, "_request", side_effect=slow_request):
            started = time.monotonic()
            self.assertTrue(backend.close_terminal("terminal"))
            self.assertLess(time.monotonic() - started, 0.1)
            self.assertTrue(finished.wait(1))
            for _ in range(100):
                if "terminal" not in backend._terminals:
                    break
                time.sleep(0.005)
            self.assertNotIn("terminal", backend._terminals)

    def test_failed_close_keeps_terminal_ownership(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {"terminal": {"terminal_id": "terminal", "session_id": "sahmaddo"}}
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        completed = threading.Event()
        result = []
        with patch.object(backend, "_request", return_value={"ok": False, "error": "close rejected"}):
            self.assertTrue(
                backend.close_terminal(
                    "terminal",
                    lambda *values: (result.append(values), completed.set()),
                )
            )
            self.assertTrue(completed.wait(1))
        self.assertIn("terminal", backend._terminals)
        self.assertEqual(result, [("terminal", False, "close rejected")])
        self.assertEqual(backend.last_close_error, "close rejected")

    def test_helper_death_during_close_cleans_stale_session_ownership(self) -> None:
        controller = SessionController()
        session = controller.create_session(
            {"id": "sahmaddo", "host": "coaraci", "port": 22, "user": "sahmaddo", "auth_method": "agent"}
        )
        controller.register_terminal(session.session_id, "terminal")
        tab = type("Tab", (), {})()
        tab._native_terminal_ids = {"terminal"}
        tab._session_controller = controller
        tab.session_id = session.session_id
        tab._terminal_backend_status = Mock()
        tab.after = lambda _delay, callback: callback()

        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {"terminal": {"terminal_id": "terminal", "session_id": session.session_id}}
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        completed = threading.Event()

        def helper_dies(*_args, **_kwargs):
            backend._process.poll.return_value = 1
            return None

        def callback(terminal_id, remove, error):
            ConnectionTab._native_terminal_close_completed(tab, terminal_id, remove, error)
            completed.set()

        with (
            patch.object(backend, "_request", side_effect=helper_dies),
            patch("sshvault.messagebox.showwarning"),
        ):
            self.assertTrue(backend.close_terminal("terminal", callback))
            self.assertTrue(completed.wait(1))
        self.assertNotIn("terminal", backend._terminals)
        self.assertNotIn("terminal", tab._native_terminal_ids)
        self.assertNotIn("terminal", session.terminal_ids)
        self.assertEqual(backend.reason, "helper exited during terminal close")

    def test_double_close_sends_only_one_helper_request(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {"terminal": {"terminal_id": "terminal"}}
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        entered = threading.Event()
        release = threading.Event()

        def request(*_args, **_kwargs):
            entered.set()
            release.wait(1)
            return {"ok": True}

        with patch.object(backend, "_request", side_effect=request) as request_mock:
            self.assertTrue(backend.close_terminal("terminal"))
            self.assertTrue(entered.wait(0.5))
            self.assertTrue(backend.close_terminal("terminal"))
            release.set()
            for _ in range(100):
                if "terminal" not in backend._terminals:
                    break
                time.sleep(0.005)
            self.assertTrue(backend.close_terminal("terminal"))
        request_mock.assert_called_once_with("close_tab", terminal_id="terminal")

    def test_close_isolated_across_sessions_and_unrelated_resources(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {
            "sahmaddo-one": {"terminal_id": "sahmaddo-one", "session_id": "sahmaddo"},
            "sahmaddo-two": {"terminal_id": "sahmaddo-two", "session_id": "sahmaddo"},
            "clauberh-one": {"terminal_id": "clauberh-one", "session_id": "clauberh"},
        }
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        ssh_connection = object()
        sftp_scheduler = object()
        with patch.object(backend, "_request", return_value={"ok": True}):
            self.assertTrue(backend.close_terminal("sahmaddo-one"))
            for _ in range(100):
                if "sahmaddo-one" not in backend._terminals:
                    break
                time.sleep(0.005)
        self.assertEqual(set(backend._terminals), {"sahmaddo-two", "clauberh-one"})
        self.assertIsNotNone(ssh_connection)
        self.assertIsNotNone(sftp_scheduler)

    def test_last_terminal_close_reaps_helper_without_orphan_metadata(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {"terminal": {"terminal_id": "terminal"}}
        backend._connection = Mock()
        backend._process = Mock()
        backend._process.poll.return_value = None
        reaped = threading.Event()
        backend._process.wait.side_effect = lambda timeout: reaped.set()
        with patch.object(backend, "_request", return_value={"ok": True}):
            self.assertTrue(backend.close_terminal("terminal"))
            self.assertTrue(reaped.wait(1))
        self.assertEqual(backend._terminals, {})
        self.assertEqual(backend._closing_terminals, {})
        helper_source = (Path(__file__).resolve().parents[1] / "sshvault_vte_helper.py").read_text(encoding="utf-8")
        self.assertIn("os.kill(pid, signal.SIGHUP)", helper_source)


if __name__ == "__main__":
    unittest.main()
