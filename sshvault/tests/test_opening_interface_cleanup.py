from __future__ import annotations

import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import patch

from sshvault import (
    CONTROLLER_BOTTOM_ACTIONS,
    CONTROLLER_CONFIG_TABS,
    CONTROLLER_PROFILE_ACTIONS,
    SSHVaultApp,
    _ConnectionViewRegistry,
    _ProfileSelectionModel,
)
from sshvault_core import VTEAvailability
from sshvault_core import SessionLifecycleState


class _Vault:
    def __init__(self) -> None:
        self.entries = [
            {
                "id": "profile-id",
                "name": "Example",
                "host": "host.example",
                "port": 22,
                "user": "alice",
                "auth_method": "agent",
            }
        ]


def _descendants(widget: tk.Misc) -> list[tk.Misc]:
    result: list[tk.Misc] = []
    for child in widget.winfo_children():
        result.append(child)
        result.extend(_descendants(child))
    return result


class OpeningInterfaceCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            with (
                patch("sshvault.Vault", _Vault),
                patch("sshvault.detect_vte_backend", return_value=VTEAvailability(False, reason="test")),
                patch.object(SSHVaultApp, "_restore_session", lambda _self: None),
            ):
                self.app = SSHVaultApp()
            self.app.update_idletasks()
        except tk.TclError as exc:
            self.skipTest(f"Tk display unavailable: {exc}")

    def tearDown(self) -> None:
        if hasattr(self, "app"):
            self.app.destroy()

    def test_left_profile_rail_is_the_only_profile_action_area(self) -> None:
        widgets = _descendants(self.app)
        self.assertEqual(
            tuple(self.app._toolbar_buttons),
            CONTROLLER_PROFILE_ACTIONS,
        )
        self.assertEqual(
            [str(button.cget("text")).split("  ", 1)[-1] for button in self.app._toolbar_buttons.values()],
            list(CONTROLLER_PROFILE_ACTIONS),
        )
        self.assertTrue(self.app._profile_rail.winfo_ismapped())
        self.assertFalse(hasattr(self.app, "_profile_toolbar"))
        self.assertFalse(hasattr(self.app, "_profile_selector"))
        self.assertEqual(
            [
                widget
                for widget in widgets
                if isinstance(widget, ttk.Combobox) and widget.master is self.app._profile_rail
            ],
            [],
        )

    def test_single_connection_action_exit_status_and_log(self) -> None:
        widgets = _descendants(self.app)
        buttons = [widget for widget in widgets if isinstance(widget, (tk.Button, ttk.Button))]
        connection_buttons = [widget for widget in buttons if str(widget.cget("text")) in {"Log in", "Log out"}]
        exit_buttons = [widget for widget in buttons if str(widget.cget("text")) == "Exit"]
        self.assertEqual(connection_buttons, [self.app._connection_action_button])
        self.assertEqual(exit_buttons, [self.app._exit_button])
        self.assertEqual(CONTROLLER_BOTTOM_ACTIONS, ("Log in / Log out", "Exit"))
        status_labels = [
            widget
            for widget in widgets
            if isinstance(widget, tk.Label) and str(widget.cget("textvariable")) == str(self.app._controller_status)
        ]
        self.assertEqual(status_labels, [self.app._controller_status_label])
        self.assertEqual([widget for widget in widgets if isinstance(widget, tk.Text)], [self.app._controller_log])

    def test_no_controller_strip_or_attached_legacy_sidebar(self) -> None:
        widgets = _descendants(self.app)
        self.assertIsNone(self.app._application_statusbar)
        self.assertIsInstance(self.app._tree, _ProfileSelectionModel)
        self.assertIsInstance(self.app._conn_notebook, _ConnectionViewRegistry)
        self.assertFalse(hasattr(self.app, "_sessions_tree"))
        self.assertIsNone(self.app._connection_view_host)
        labels = [str(widget.cget("text")) for widget in widgets if isinstance(widget, (tk.Label, ttk.Label))]
        self.assertNotIn("Saved SSH connections", labels)
        self.assertNotIn("Active Sessions", labels)
        notebooks = [widget for widget in widgets if isinstance(widget, ttk.Notebook)]
        self.assertEqual(notebooks, [self.app._control_notebook])

    def test_exact_tab_order_and_login_column_layout(self) -> None:
        self.assertEqual(
            tuple(self.app._control_notebook.tab(tab, "text") for tab in self.app._control_notebook.tabs()),
            CONTROLLER_CONFIG_TABS,
        )
        login_groups = {
            str(child.cget("text")): child
            for child in self.app._control_pages["Login"].winfo_children()
            if isinstance(child, ttk.LabelFrame)
        }
        self.assertEqual(set(login_groups), {"Server", "Authentication", "Host Key", "Proxy"})
        self.assertEqual(int(login_groups["Server"].grid_info()["column"]), 0)
        self.assertEqual(int(login_groups["Proxy"].grid_info()["column"]), 0)
        self.assertEqual(int(login_groups["Host Key"].grid_info()["column"]), 0)
        self.assertEqual(int(login_groups["Authentication"].grid_info()["column"]), 1)

    def test_bottom_controls_remain_visible_at_supported_sizes(self) -> None:
        for geometry in ("1050x720", "900x620"):
            with self.subTest(geometry=geometry):
                self.app.geometry(geometry)
                self.app.update_idletasks()
                bottom = self.app._controller_bottom_bar
                self.assertTrue(bottom.winfo_ismapped())
                self.assertLessEqual(bottom.winfo_y() + bottom.winfo_height(), self.app.winfo_height())
                self.assertTrue(self.app._controller_log_frame.winfo_ismapped())
                self.assertLess(
                    self.app._control_notebook.winfo_y(),
                    self.app._controller_log_frame.winfo_y(),
                )

    def test_profile_selection_is_passive(self) -> None:
        self.app.profile_dirty = False
        self.assertTrue(self.app._select_profile_from_rail("profile-id"))
        self.assertEqual(self.app.selected_profile_id, "profile-id")
        self.assertFalse(self.app.profile_dirty)
        self.assertIsInstance(self.app.working_profile["port"], int)
        self.assertEqual(len(self.app._session_controller.sessions), 0)

    def test_switching_profiles_keeps_first_session_connected(self) -> None:
        second = {
            "id": "second-profile-id",
            "name": "Second",
            "host": "second.example",
            "port": 22,
            "user": "bob",
            "auth_method": "agent",
        }
        self.app._vault.entries.append(second)
        self.app._refresh_list()
        first_record = self.app._session_controller.create_session(self.app._vault.entries[0])
        first_record.state = SessionLifecycleState.CONNECTED
        self.app._selected_session_id = first_record.session_id

        self.assertTrue(self.app._select_profile_from_rail("second-profile-id"))

        self.assertEqual(first_record.state, SessionLifecycleState.CONNECTED)
        self.assertIsNone(self.app._selected_session_id)
        self.assertEqual(self.app._connection_action_button.cget("text"), "Log in")
        self.assertEqual(len(self.app._session_controller.sessions), 1)

    def test_loading_connected_profiles_selects_each_own_session(self) -> None:
        second = {
            "id": "second-profile-id",
            "name": "Second",
            "host": "second.example",
            "port": 22,
            "user": "bob",
            "auth_method": "agent",
        }
        self.app._vault.entries.append(second)
        self.app._refresh_list()
        first = self.app._session_controller.create_session(self.app._vault.entries[0])
        second_record = self.app._session_controller.create_session(second)
        first.state = SessionLifecycleState.CONNECTED
        second_record.state = SessionLifecycleState.CONNECTED

        self.assertTrue(self.app._select_profile_from_rail("profile-id"))
        self.assertEqual(self.app._selected_session_id, first.session_id)
        self.assertEqual(self.app._connection_action_button.cget("text"), "Log out")

        self.assertTrue(self.app._select_profile_from_rail("second-profile-id"))
        self.assertEqual(self.app._selected_session_id, second_record.session_id)
        self.assertEqual(first.state, SessionLifecycleState.CONNECTED)
        self.assertEqual(second_record.state, SessionLifecycleState.CONNECTED)


if __name__ == "__main__":
    unittest.main()
