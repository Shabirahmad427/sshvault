"""Regression coverage for passive session recovery and native terminal IPC."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sshvault import SSHVaultApp
from sshvault_core import ProfileStore, SecretStore, VTEAvailability, VTETerminalBackend


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
