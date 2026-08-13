"""Regression coverage for passive session recovery and native terminal IPC."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sshvault import SSHVaultApp
from sshvault_core import (
    ProfileStore,
    SecretStore,
    SessionController,
    SessionLifecycleState,
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    VTEAvailability,
    VTETerminalBackend,
    session_resource_title,
)


class _Status:
    def set(self, _value: str) -> None:
        pass


class _Vault:
    def __init__(self) -> None:
        self.entries = [
            {"id": "one", "name": "One", "host": "one.example", "port": 22, "user": "alice"},
            {"id": "two", "name": "Two", "host": "two.example", "port": 22, "user": "bob"},
        ]


class _App:
    _restore_session = SSHVaultApp._restore_session
    _restore_previous_sessions = SSHVaultApp._restore_previous_sessions

    def __init__(self) -> None:
        self._vault = _Vault()
        self._runtime_settings = {"restore_previous_sessions_on_start": True}
        self._conn_tabs = {}
        self._status_var = _Status()
        self.connected: list[int] = []

    def _connect_by_idx(self, index: int) -> None:
        self.connected.append(index)


class ProfileSessionSeparationTests(unittest.TestCase):
    def test_malformed_or_unclean_snapshot_never_changes_profile_store(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            vault_path, session_path = Path(directory) / "vault.json", Path(directory) / "session.json"
            profile = {"name": "One", "host": "one.example", "port": 22, "user": "alice", "auth_method": "agent"}
            store = ProfileStore(vault_path, SecretStore(None))
            store.add(profile)
            before = vault_path.read_bytes()
            session_path.write_text('{"clean_shutdown":false,"profile_ids":["missing"]}', encoding="utf-8")
            app = _App()
            with patch("sshvault.SESSION_FILE", session_path):
                app._restore_session()
            self.assertEqual(vault_path.read_bytes(), before)
            self.assertEqual(len(store.entries), 1)

    def test_index_snapshot_maps_to_ids_without_connecting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Path(directory) / "session.json"
            session.write_text(json.dumps({"clean_shutdown": True, "open_indices": [1, 99]}), encoding="utf-8")
            app = _App()
            with patch("sshvault.SESSION_FILE", session):
                app._restore_session()
            self.assertEqual(app.connected, [])
            self.assertEqual(app._pending_restore_profile_ids, ["two"])
            self.assertTrue(Path(directory, "session.pre-id-migration.json").exists())


class NativeTerminalProtocolTests(unittest.TestCase):
    def test_explicit_open_commands_keep_unique_terminal_ids(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        replies = iter(
            (
                {"ok": True, "terminal_id": "a", "window_id": "w1"},
                {"ok": True, "terminal_id": "b", "window_id": "w1"},
                {"ok": True, "terminal_id": "c", "window_id": "w2"},
            )
        )
        with patch.object(backend, "_start", return_value=True), patch.object(backend, "_request", side_effect=replies):
            profile = {"name": "One", "host": "one.example", "port": 22, "user": "alice", "auth_method": "agent"}
            self.assertTrue(backend.open_terminal_tab(profile))
            self.assertTrue(backend.open_terminal_tab(profile))
            self.assertTrue(backend.open_terminal_window(profile))
        self.assertEqual(set(backend._terminals), {"a", "b", "c"})
        self.assertEqual(backend._terminals["a"]["window_id"], backend._terminals["b"]["window_id"])
        self.assertNotEqual(backend._terminals["b"]["window_id"], backend._terminals["c"]["window_id"])


class _OwnedPanel:
    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self.opened = 0

    def _show_transfer_manager(self) -> None:
        self.opened += 1


class _OwnedTab:
    def __init__(self, session_id: str, controller: SessionController) -> None:
        self.session_id = session_id
        self.controller = controller
        self.terminals: list[str] = []
        self._sftp_panel = _OwnedPanel(session_id)
        self.disconnected = 0

    def _open_terminal(self) -> None:
        terminal_id = f"{self.session_id}:{len(self.terminals) + 1}"
        self.terminals.append(terminal_id)
        self.controller.register_terminal(self.session_id, terminal_id)

    def _disconnect(self) -> None:
        self.disconnected += 1
        self.controller.disconnect(self.session_id, "test logout")


class _Scheduler:
    def __init__(self) -> None:
        self.invalidated = 0
        self.stopped = 0

    def invalidate_session(self, fail_active: bool = False) -> None:
        self.invalidated += int(fail_active)

    def shutdown(self) -> None:
        self.stopped += 1


class _Channel:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


class _Service:
    def __init__(self) -> None:
        self.stopped = 0

    def active_rule_ids(self) -> list[str]:
        return []

    def stop_all(self) -> None:
        self.stopped += 1


class _IsolationApp:
    _selected_session_record = SSHVaultApp._selected_session_record
    _open_selected_session_terminal = SSHVaultApp._open_selected_session_terminal
    _open_selected_session_sftp = SSHVaultApp._open_selected_session_sftp
    _open_transfer_manager = SSHVaultApp._open_transfer_manager
    _logout_selected_session = SSHVaultApp._logout_selected_session
    _stop_sftp_resources_for_session = SSHVaultApp._stop_sftp_resources_for_session
    _stop_local_forwarding_for_session = SSHVaultApp._stop_local_forwarding_for_session

    def __init__(self) -> None:
        self._session_controller = SessionController()
        profiles = (
            {
                "id": "sahmaddo",
                "name": "sahmaddo",
                "host": "coaraci.example",
                "port": 22,
                "user": "sahmaddo",
                "auth_method": "agent",
            },
            {
                "id": "clauberh",
                "name": "clauberh",
                "host": "coaraci.example",
                "port": 22,
                "user": "clauberh",
                "auth_method": "agent",
            },
        )
        records = [self._session_controller.create_session(profile) for profile in profiles]
        for record in records:
            record.state = SessionLifecycleState.CONNECTED
        self.records = {record.profile_id: record for record in records}
        self._conn_tabs = {
            record.session_id: _OwnedTab(record.session_id, self._session_controller) for record in records
        }
        self._selected_session_id = records[0].session_id
        self.sftp_opens: list[tuple[str, str]] = []
        self._sftp_transfer_schedulers: dict[str, _Scheduler] = {}
        self._sftp_browser_clients = SFTPBrowserRegistry()
        self._local_forwarding_services: dict[str, _Service] = {}

    def select(self, profile_id: str) -> None:
        self._selected_session_id = self.records[profile_id].session_id

    def _open_sftp_placeholder(self, record) -> str:
        view_id = f"{record.session_id}:sftp:{len(record.sftp_view_ids) + 1}"
        self._session_controller.register_sftp_view(record.session_id, view_id)
        self.sftp_opens.append((record.session_id, view_id))
        return view_id

    def _close_sftp_views_for_session(self, _session_id: str) -> None:
        pass

    def _stop_remote_forwarding_for_session(self, _session_id: str) -> None:
        pass

    def _stop_dynamic_forwarding_for_session(self, _session_id: str) -> None:
        pass

    def _stop_http_forwarding_for_session(self, _session_id: str) -> None:
        pass

    def _stop_x11_forwarding_for_session(self, _session_id: str) -> None:
        pass

    def _refresh_action_states(self) -> None:
        pass

    def _refresh_services_tab(self) -> None:
        pass


class CompleteMultiSessionIsolationTests(unittest.TestCase):
    def test_both_profiles_are_connected_simultaneously(self) -> None:
        app = _IsolationApp()
        self.assertEqual({record.state for record in app.records.values()}, {SessionLifecycleState.CONNECTED})
        self.assertEqual(len(app._conn_tabs), 2)

    def test_terminal_open_uses_selected_session_id(self) -> None:
        app = _IsolationApp()
        for profile_id in ("sahmaddo", "clauberh"):
            app.select(profile_id)
            app._open_selected_session_terminal()
        for record in app.records.values():
            self.assertEqual(app._conn_tabs[record.session_id].terminals, [f"{record.session_id}:1"])

    def test_multiple_terminals_remain_owned_after_profile_switch(self) -> None:
        app = _IsolationApp()
        app.select("sahmaddo")
        app._open_selected_session_terminal()
        app._open_selected_session_terminal()
        owned = list(app._conn_tabs[app.records["sahmaddo"].session_id].terminals)
        app.select("clauberh")
        app._open_selected_session_terminal()
        self.assertEqual(app._conn_tabs[app.records["sahmaddo"].session_id].terminals, owned)
        self.assertTrue(all(item.startswith(app.records["sahmaddo"].session_id) for item in owned))

    def test_multiple_sftp_windows_use_selected_session_id(self) -> None:
        app = _IsolationApp()
        app.select("sahmaddo")
        app._open_selected_session_sftp()
        app._open_selected_session_sftp()
        app.select("clauberh")
        app._open_selected_session_sftp()
        self.assertEqual([owner for owner, _ in app.sftp_opens], [
            app.records["sahmaddo"].session_id,
            app.records["sahmaddo"].session_id,
            app.records["clauberh"].session_id,
        ])

    def test_transfer_manager_uses_only_selected_session(self) -> None:
        app = _IsolationApp()
        app.select("clauberh")
        app._open_transfer_manager()
        sahmaddo = app._conn_tabs[app.records["sahmaddo"].session_id]._sftp_panel
        clauberh = app._conn_tabs[app.records["clauberh"].session_id]._sftp_panel
        self.assertEqual((sahmaddo.opened, clauberh.opened), (0, 1))

    def test_logout_closes_only_selected_session_resources(self) -> None:
        app = _IsolationApp()
        channels = {record.session_id: _Channel() for record in app.records.values()}
        schedulers = {record.session_id: _Scheduler() for record in app.records.values()}
        app._sftp_transfer_schedulers.update(schedulers)
        for session_id, channel in channels.items():
            app._sftp_browser_clients.register(session_id, "view", SFTPBrowserClient(channel))
        app.select("sahmaddo")
        app._logout_selected_session()
        sahmaddo_id, clauberh_id = (app.records[name].session_id for name in ("sahmaddo", "clauberh"))
        self.assertEqual((channels[sahmaddo_id].closed, channels[clauberh_id].closed), (1, 0))
        self.assertEqual((schedulers[sahmaddo_id].stopped, schedulers[clauberh_id].stopped), (1, 0))
        self.assertEqual(app.records["clauberh"].state, SessionLifecycleState.CONNECTED)

    def test_services_are_stopped_by_session_id(self) -> None:
        app = _IsolationApp()
        services = {record.session_id: _Service() for record in app.records.values()}
        app._local_forwarding_services.update(services)
        sahmaddo_id, clauberh_id = (app.records[name].session_id for name in ("sahmaddo", "clauberh"))
        app._stop_local_forwarding_for_session(sahmaddo_id)
        self.assertEqual((services[sahmaddo_id].stopped, services[clauberh_id].stopped), (1, 0))
        self.assertIn(clauberh_id, app._local_forwarding_services)

    def test_terminal_and_sftp_titles_identify_owner(self) -> None:
        profile = {"user": "clauberh", "host": "coaraci.example"}
        self.assertEqual(session_resource_title("Terminal", profile), "Terminal — clauberh@coaraci")
        self.assertEqual(session_resource_title("SFTP", profile), "SFTP — clauberh@coaraci")
