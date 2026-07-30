from __future__ import annotations

import unittest
from unittest.mock import patch

from sshvault import ConnectionTab, SSHVaultApp
from sshvault_core import SessionController


class _Value:
    def __init__(self) -> None:
        self.value = ""

    def set(self, value: str) -> None:
        self.value = value


class _Notebook:
    def __init__(self) -> None:
        self.tabs: list[object] = []

    def add(self, tab: object, text: str) -> None:
        self.tabs.append((tab, text))

    def select(self, _tab: object) -> None:
        pass


class _ConnectionTab:
    def __init__(self, _parent: object, entry: dict, **kwargs: object) -> None:
        self._entry = entry
        self.session_id = kwargs["session_id"]
        self.started = False

    def start_connection(self) -> None:
        self.started = True


class FinalIntegrationRegressionTests(unittest.TestCase):
    def test_transient_download_directory_does_not_enter_session_snapshot(self) -> None:
        profile = {
            "id": "profile-id",
            "name": "Profile",
            "host": "host.example",
            "port": 22,
            "user": "alice",
            "auth_method": "agent",
        }
        app = type("AppHarness", (), {})()
        app._vault = type("VaultHarness", (), {"entries": [profile]})()
        app._status_var = _Value()
        app._runtime_settings = {
            "connection_timeout": 15,
            "download_directory": "/tmp/downloads",
        }
        app._session_controller = SessionController()
        app._conn_notebook = _Notebook()
        app._conn_tabs = {}
        app._session_serial = 0
        app._selected_session_id = None
        app._update_statusbar = lambda: None
        app._refresh_sessions = lambda: None

        with patch("sshvault.ConnectionTab", _ConnectionTab):
            SSHVaultApp._connect_by_idx(app, 0)

        self.assertEqual(len(app._session_controller.sessions), 1)
        record = next(iter(app._session_controller.sessions.values()))
        tab = app._conn_tabs[record.session_id]
        self.assertNotIn("default_download_directory", record.profile_snapshot)
        self.assertEqual(tab._entry["default_download_directory"], "/tmp/downloads")
        self.assertTrue(tab.started)

    def test_logout_disconnects_without_permanently_shutting_down_tab(self) -> None:
        calls: list[str] = []
        record = type(
            "Record",
            (),
            {
                "session_id": "session-id",
                "profile_snapshot": {"connection_options": {}},
            },
        )()
        tab = type(
            "Tab",
            (),
            {
                "_disconnect": lambda _self: calls.append("disconnect"),
                "shutdown": lambda _self: calls.append("shutdown"),
            },
        )()
        app = type("AppHarness", (), {})()
        app._selected_session_record = lambda: record
        app._conn_tabs = {"session-id": tab}
        app._refresh_action_states = lambda: None

        SSHVaultApp._logout_selected_session(app)

        self.assertEqual(calls, ["disconnect"])

    def test_explicit_reconnect_starts_fresh_generation_after_logout(self) -> None:
        calls: list[str] = []
        controller = type(
            "ReconnectHarness",
            (),
            {
                "new_session": lambda _self: calls.append("new_session"),
                "reconnect_now": lambda _self: calls.append("reconnect_now"),
            },
        )()
        tab = type("ConnectionHarness", (), {"_reconnect_controller": controller})()

        ConnectionTab._reconnect_now(tab)

        self.assertEqual(calls, ["new_session", "reconnect_now"])


if __name__ == "__main__":
    unittest.main()
