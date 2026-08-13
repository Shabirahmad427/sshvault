from __future__ import annotations

import unittest
from unittest.mock import patch

from sshvault import ConnectionInfoPanel, ConnectionTab, SSHVaultApp
from sshvault_core import SessionController, SessionLifecycleState


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


class _InfoKey:
    def get_name(self):
        return "ssh-ed25519"

    def get_fingerprint(self):
        return bytes.fromhex("00112233")


class _InfoTransport:
    local_cipher = "aes256-gcm"
    local_mac = "hmac-sha2-256"
    local_compression = "none"
    remote_version = "SSH-2.0-current"

    def is_active(self):
        return True

    def get_remote_server_key(self):
        return _InfoKey()


class _InfoClient:
    def __init__(self, transport=None):
        self.transport = transport or _InfoTransport()
        self.closed = False

    def get_transport(self):
        return self.transport

    def close(self):
        self.closed = True


class _InfoPanel:
    def __init__(self, client):
        self._client = client
        self.profile = None
        self.state_provider = None
        self.rebinds = []

    def rebind(self, client, profile, state_provider):
        self._client = client
        self.profile = profile
        self.state_provider = state_provider
        self.rebinds.append(client)


class _InfoTabHarness:
    _rebind_connection_info = ConnectionTab._rebind_connection_info

    def __init__(self, session_id, client):
        self.session_id = session_id
        self._info_panel = _InfoPanel(client)
        self.profile = {"host": "coaraci.ifi.unicamp.br", "user": session_id}

    def _session_profile_snapshot(self):
        return self.profile

    def _connection_info_state(self):
        return SessionLifecycleState.CONNECTED


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
                "_disconnect": lambda _self, logout_preferences=None: calls.append("disconnect"),
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

    def test_manual_and_automatic_reconnect_rebind_existing_connection_info_panel(self) -> None:
        for reconnect_kind in ("manual", "automatic"):
            with self.subTest(reconnect_kind=reconnect_kind):
                old, new = _InfoClient(), _InfoClient()
                tab = _InfoTabHarness("sahmaddo", old)
                panel = tab._info_panel
                tab._rebind_connection_info(new)
                self.assertIs(tab._info_panel, panel)
                self.assertIs(panel._client, new)
                self.assertEqual(panel.rebinds, [new])

    def test_old_client_close_does_not_break_rebound_connection_info(self) -> None:
        old, new = _InfoClient(), _InfoClient()
        tab = _InfoTabHarness("sahmaddo", old)
        tab._rebind_connection_info(new)
        old.close()
        details = ConnectionInfoPanel.connection_details(
            tab._info_panel._client,
            tab._info_panel.profile,
            tab._info_panel.state_provider(),
        )
        self.assertTrue(old.closed)
        self.assertEqual(details["Session state"], "Connected")
        self.assertEqual(details["Host"], "coaraci.ifi.unicamp.br")
        self.assertEqual(details["User"], "sahmaddo")
        self.assertEqual(details["Transport status"], "Active")
        self.assertEqual(details["Cipher"], "aes256-gcm")
        self.assertEqual(details["Server host key"], "ssh-ed25519")

    def test_connection_info_rebind_is_session_isolated(self) -> None:
        sahmaddo_old, clauberh_client = _InfoClient(), _InfoClient()
        sahmaddo = _InfoTabHarness("sahmaddo", sahmaddo_old)
        clauberh = _InfoTabHarness("clauberh", clauberh_client)
        sahmaddo_new = _InfoClient()
        sahmaddo._rebind_connection_info(sahmaddo_new)
        self.assertIs(sahmaddo._info_panel._client, sahmaddo_new)
        self.assertIs(clauberh._info_panel._client, clauberh_client)
        self.assertEqual(clauberh._info_panel.rebinds, [])


if __name__ == "__main__":
    unittest.main()
