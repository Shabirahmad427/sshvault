"""Startup restoration is intentionally passive unless explicitly enabled."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sshvault import SSHVaultApp


class _Status:
    def __init__(self) -> None:
        self.value = ""

    def set(self, value: str) -> None:
        self.value = value


class _Vault:
    def __init__(self) -> None:
        self.entries = [{"host": "one.example", "port": 22, "user": "alice"}]


class _App:
    _restore_session = SSHVaultApp._restore_session
    _restore_previous_sessions = SSHVaultApp._restore_previous_sessions

    def __init__(self, enabled: bool = False) -> None:
        self._vault = _Vault()
        self._runtime_settings = {"restore_previous_sessions_on_start": enabled}
        self._conn_tabs = {}
        self._status_var = _Status()
        self.connected: list[int] = []

    def _connect_by_idx(self, index: int) -> None:
        self.connected.append(index)


class StartupRestoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.session = Path(self.tmp.name) / "session.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_saved_open_session_does_not_connect_by_default(self) -> None:
        self.session.write_text(json.dumps({"clean_shutdown": True, "open_indices": [0]}))
        app = _App()
        with patch("sshvault.SESSION_FILE", self.session):
            app._restore_session()
        self.assertEqual(app.connected, [])
        self.assertEqual(app._pending_restore_indices, [0])

    def test_setting_cannot_reintroduce_automatic_restore(self) -> None:
        self.session.write_text(json.dumps({"clean_shutdown": True, "open_indices": [0]}))
        app = _App(enabled=True)
        with patch("sshvault.SESSION_FILE", self.session):
            app._restore_session()
        self.assertEqual(app.connected, [])
        self.assertEqual(app._pending_restore_indices, [0])

    def test_unclean_or_legacy_session_file_is_not_restored(self) -> None:
        self.session.write_text(json.dumps([0]))
        app = _App(enabled=True)
        with patch("sshvault.SESSION_FILE", self.session):
            app._restore_session()
        self.assertEqual(app.connected, [])
