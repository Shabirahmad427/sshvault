from __future__ import annotations

import unittest
from unittest.mock import patch

from sshvault_core import VTEAvailability, VTETerminalBackend
from sshvault_vte_helper import (
    NATIVE_VTE_CLOSE_TAB_LABEL,
    _terminal_tab_label,
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


class NativeVTEIndividualCloseTests(unittest.TestCase):
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
        with (
            patch.object(backend, "_start", return_value=True),
            patch.object(
                backend,
                "_request",
                return_value={"type": "response", "ok": True},
            ) as request,
        ):
            self.assertTrue(backend.close_terminal("first"))
        request.assert_called_once_with("close_tab", terminal_id="first")
        self.assertNotIn("first", backend._terminals)
        self.assertIn("second", backend._terminals)
        self.assertEqual(backend.last_terminal_id, "second")


if __name__ == "__main__":
    unittest.main()
