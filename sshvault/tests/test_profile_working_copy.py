"""B1 profile-copy invariants, exercised without a Tk display."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from sshvault_core import ProfileStore, SecretStore


def profile(name: str) -> dict:
    return {"name": name, "host": "host.example", "port": 22, "user": "alice", "auth_method": "agent", "tags": ["x"]}


class ProfileWorkingCopyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.store = ProfileStore(Path(self.tmp.name) / "vault.json", SecretStore(None))
        self.saved = self.store.add(profile("One"))

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_copy_isolated_until_atomic_update(self) -> None:
        working = copy.deepcopy(self.saved)
        working["host"] = "changed.example"
        working["tags"].append("y")
        self.assertEqual(self.store.entries[0]["host"], "host.example")
        self.store.update(0, working)
        self.assertEqual(self.store.entries[0]["id"], self.saved["id"])
        self.assertEqual(self.store.entries[0]["host"], "changed.example")

    def test_save_as_and_duplicate_have_new_ids(self) -> None:
        saved_as = self.store.add(dict(profile("Two"), host="two.example"))
        duplicate = self.store.add(dict(profile("One Copy"), host="copy.example"))
        self.assertNotEqual(self.saved["id"], saved_as["id"])
        self.assertNotEqual(saved_as["id"], duplicate["id"])

    def test_delete_does_not_mutate_external_session_snapshot(self) -> None:
        snapshot = copy.deepcopy(self.saved)
        self.store.delete(0)
        self.assertEqual(snapshot["name"], "One")
        self.assertEqual(self.store.entries, [])
