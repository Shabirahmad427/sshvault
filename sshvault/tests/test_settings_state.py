from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sshvault_core import (
    ProfileError,
    atomic_json_write,
    confirm_delete_enabled,
    confirm_overwrite_enabled,
    validate_settings,
)


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "settings.json"

    def tearDown(self):
        self.tmp.cleanup()

    def test_defaults_valid_booleans_unknown_and_secrets(self):
        self.assertEqual(validate_settings({})["scrollback_limit"], 5000)
        got = validate_settings(
            {"scrollback_limit": "6000", "connection_timeout": "20", "confirm_delete": 0, "future": 1}
        )
        self.assertEqual(
            (got["scrollback_limit"], got["connection_timeout"], got["confirm_delete"], got["future"]),
            (6000, 20, False, 1),
        )
        for raw in ({"scrollback_limit": 1}, {"connection_timeout": 999}, {"password": "x"}):
            with self.assertRaises(ProfileError):
                validate_settings(raw)

    def test_atomic_save_and_failure_preserves_previous(self):
        atomic_json_write(self.path, validate_settings({"scrollback_limit": 6000}))
        before = self.path.read_text()
        self.assertEqual(json.loads(before)["scrollback_limit"], 6000)
        with patch("sshvault_core.os.replace", side_effect=OSError("disk")):
            with self.assertRaises(OSError):
                atomic_json_write(self.path, {"scrollback_limit": 7000})
        self.assertEqual(self.path.read_text(), before)

    def test_delete_confirmation_safe_defaults(self):
        self.assertTrue(confirm_delete_enabled(None))
        self.assertTrue(confirm_delete_enabled({"confirm_delete": "bad"}))
        self.assertTrue(confirm_delete_enabled({"confirm_delete": True}))
        self.assertFalse(confirm_delete_enabled({"confirm_delete": False}))

    def test_overwrite_confirmation_safe_defaults(self):
        self.assertTrue(confirm_overwrite_enabled(None))
        self.assertTrue(confirm_overwrite_enabled({"confirm_overwrite": "bad"}))
        self.assertTrue(confirm_overwrite_enabled({"confirm_overwrite": True}))
        self.assertFalse(confirm_overwrite_enabled({"confirm_overwrite": False}))
