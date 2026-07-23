from __future__ import annotations
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from sshvault_core import (
    ProfileError,
    ProfileStore,
    SecretStore,
    SCHEMA_VERSION,
    build_import_preview,
    ImportDecisionModel,
)


class Keyring:
    def get_password(self, *a):
        return None

    def set_password(self, *a):
        pass

    def delete_password(self, *a):
        pass


def p(name="One", host="one.test", user="dev", **changes):
    value = {
        "name": name,
        "host": host,
        "port": 22,
        "user": user,
        "auth_method": "agent",
        "key_path": "",
        "tags": [],
        "notes": "",
    }
    value.update(changes)
    return value


class ImportExportTests(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory()
        self.root = Path(self.t.name)
        self.store = ProfileStore(self.root / "vault.json", SecretStore(Keyring()))
        self.store.add(p())

    def tearDown(self):
        self.t.cleanup()

    def write(self, profiles, version=SCHEMA_VERSION):
        path = self.root / "in.json"
        path.write_text(json.dumps({"version": version, "profiles": profiles}))
        return path

    def test_valid_secret_free_import_and_export(self):
        s = self.store.import_profiles(self.write([p("Two", "two.test")]))
        self.assertEqual(s.imported, 1)
        out = self.root / "out.json"
        self.store.export(out)
        self.assertNotIn("password", out.read_text())

    def test_schema_secret_and_collision_decisions(self):
        with self.assertRaises(ProfileError):
            self.store.import_profiles(self.write([], 99))
        self.assertEqual(self.store.import_profiles(self.write([dict(p(), password="x")])).failed, 1)
        self.assertEqual(self.store.import_profiles(self.write([p()]), {0: "skip"}).skipped, 1)
        self.assertEqual(self.store.import_profiles(self.write([p()]), {0: "rename"}).renamed, 1)
        self.assertEqual(self.store.import_profiles(self.write([p(notes="new")]), {0: "replace"}).replaced, 1)
        self.assertTrue(list(self.root.glob("vault.pre-import.*.json")))

    def test_preview_rows_hide_secrets_and_mark_collisions(self):
        rows = build_import_preview(
            [p("Two", "two.test"), p(), dict(p(), password="x"), {"host": ""}], self.store.entries
        )
        self.assertEqual([r.status for r in rows], ["Ready", "Collision", "Invalid", "Invalid"])
        self.assertIsNone(rows[2].profile)

    def test_decision_model_defaults_rename_replace_and_summary(self):
        rows = build_import_preview(
            [p("One", "other.test"), p("Two", "two.test"), dict(p(), password="x")], self.store.entries
        )
        model = ImportDecisionModel(rows, self.store.entries)
        self.assertEqual(model.decisions[0], "skip")
        model.decisions[0] = "rename"
        model.rename_names[0] = model.default_rename(rows[0])
        self.assertFalse(model.errors())
        self.assertEqual(model.mapping()[0], "rename")
        self.assertEqual((model.summary().renamed, model.summary().imported, model.summary().failed), (1, 1, 1))

    def test_decision_model_ready_invalid_and_skip_rows(self):
        rows = build_import_preview([p("Two", "two.test"), p(), dict(p(), token="secret")], self.store.entries)
        model = ImportDecisionModel(rows, self.store.entries)
        self.assertEqual(model.decisions[1], "skip")
        self.assertEqual(model.to_import_mapping(), {0: "import", 1: "skip"})
        self.assertEqual(model.eligible_count(), 1)
        self.assertFalse(model.errors())
        self.assertIsNone(rows[2].profile)

    def test_rename_validation_rejects_blank_existing_and_duplicate_names(self):
        self.store.add(p("Taken", "taken.test"))
        rows = build_import_preview([p("One", "other.test"), p("Taken", "another.test")], self.store.entries)
        model = ImportDecisionModel(rows, self.store.entries)
        for row in rows:
            model.decisions[row.index] = "rename"
        model.rename_names[0] = ""
        self.assertIn(0, model.errors())
        model.rename_names[0] = "Shared"
        model.rename_names[1] = "shared"
        self.assertIn(1, model.errors())
        model.rename_names[0] = "One"
        self.assertIn(0, model.errors())

    def test_rename_rejects_duplicate_identity_and_replace_requires_exact_target(self):
        rows = build_import_preview([p("Different name", "one.test"), p(notes="replacement")], self.store.entries)
        model = ImportDecisionModel(rows, self.store.entries)
        model.decisions[0] = "rename"
        model.rename_names[0] = "New name"
        self.assertIn(0, model.errors())
        model.decisions[1] = "replace"
        model.replace_targets[1] = "not-a-profile"
        self.assertIn(1, model.errors())
        model.replace_targets[1] = self.store.entries[0]["id"]
        self.assertNotIn(1, model.errors())

    def test_mixed_decisions_mapping_summary_and_custom_rename(self):
        self.store.add(p("Taken", "taken.test"))
        rows = build_import_preview(
            [p("One", "other.test"), p("Taken", "another.test"), p("Ready", "ready.test"), dict(p(), password="x")],
            self.store.entries,
        )
        model = ImportDecisionModel(rows, self.store.entries)
        model.decisions[0] = "rename"
        model.rename_names[0] = "Imported One"
        model.decisions[1] = "replace"
        model.replace_targets[1] = self.store.entries[1]["id"]
        self.assertFalse(model.errors())
        self.assertEqual(model.to_import_mapping(), {0: "rename", 1: "replace", 2: "import"})
        self.assertEqual(model.rename_mapping(), {0: "Imported One"})
        self.assertEqual(model.replace_mapping(), {1: self.store.entries[1]["id"]})
        summary = model.summary()
        self.assertEqual((summary.imported, summary.renamed, summary.replaced, summary.failed), (1, 1, 1, 1))
        result = self.store.import_profiles(
            self.write(
                [p("One", "other.test"), p("Taken", "another.test"), p("Ready", "ready.test"), dict(p(), password="x")]
            ),
            model.to_import_mapping(),
            model.rename_mapping(),
            model.replace_mapping(),
        )
        self.assertEqual((result.imported, result.renamed, result.replaced, result.failed), (1, 1, 1, 1))
        self.assertIn("Imported One", [entry["name"] for entry in self.store.entries])

    def test_selected_and_all_exports_are_versioned_secret_free(self):
        self.store.add(p("Two", "two.test"))
        selected = self.root / "selected.json"
        all_profiles = self.root / "all.json"
        selected_profile = dict(self.store.entries[0], password="not-exported", token="not-exported")
        self.assertEqual(self.store.export(selected, [selected_profile]), 1)
        payload = json.loads(selected.read_text())
        self.assertEqual(payload["version"], SCHEMA_VERSION)
        self.assertEqual(len(payload["profiles"]), 1)
        self.assertEqual(payload["profiles"][0]["name"], "One")
        self.assertNotIn("password", selected.read_text())
        self.assertNotIn("token", selected.read_text())
        before = [dict(item) for item in self.store.entries]
        self.assertEqual(self.store.export(all_profiles), 2)
        self.assertEqual(len(json.loads(all_profiles.read_text())["profiles"]), 2)
        self.assertEqual(self.store.entries, before)

    def test_export_overwrite_requires_approval_and_failure_preserves_original(self):
        target = self.root / "existing.json"
        target.write_text("original", encoding="utf-8")
        with self.assertRaises(ProfileError):
            self.store.export(target)
        self.assertEqual(target.read_text(encoding="utf-8"), "original")
        with patch("sshvault_core.atomic_json_write", side_effect=OSError("write failed")):
            with self.assertRaises(OSError):
                self.store.export(target, overwrite=True)
        self.assertEqual(target.read_text(encoding="utf-8"), "original")
        self.assertEqual(self.store.export(target, overwrite=True), 1)
        self.assertEqual(json.loads(target.read_text())["version"], SCHEMA_VERSION)

    def test_timestamped_secret_free_backups_are_unique(self):
        self.store.entries[0]["password"] = "not-exported"
        first, count = self.store.create_backup()
        second, count2 = self.store.create_backup()
        self.assertEqual((count, count2), (1, 1))
        self.assertNotEqual(first, second)
        self.assertTrue(first.name.startswith("vault.backup."))
        self.assertEqual(json.loads(first.read_text())["version"], SCHEMA_VERSION)
        self.assertNotIn("password", first.read_text())

    def test_restore_preview_rejects_bad_schema_and_secrets(self):
        good = self.write([p("Restored", "restore.test")])
        preview = self.store.preview_restore(good)
        self.assertEqual(
            (
                preview.schema_version,
                preview.profile_count,
                preview.valid_profiles,
                preview.invalid_profiles,
                preview.conflicts,
            ),
            (SCHEMA_VERSION, 1, 1, 0, 0),
        )
        conflict = self.write([p("A", "a.test"), p("A", "other.test"), {"host": ""}])
        preview = self.store.preview_restore(conflict)
        self.assertEqual((preview.valid_profiles, preview.invalid_profiles, preview.conflicts), (1, 1, 1))
        with self.assertRaises(ProfileError):
            self.store.preview_restore(self.write([], 99))
        with self.assertRaises(ProfileError):
            self.store.preview_restore(self.write([dict(p(), token="secret")]))
        malformed = self.root / "bad.json"
        malformed.write_text("not json")
        with self.assertRaises(ProfileError):
            self.store.preview_restore(malformed)

    def test_restore_is_atomic_and_creates_pre_restore_backup(self):
        source = self.write([p("Restored", "restore.test"), {"host": ""}])
        summary = self.store.restore_backup(source)
        self.assertEqual((summary.restored, summary.skipped, summary.failed), (1, 0, 1))
        self.assertIsNotNone(summary.backup_path)
        self.assertTrue(summary.backup_path.exists())
        self.assertEqual([entry["name"] for entry in self.store.entries], ["Restored"])
        original = [dict(entry) for entry in self.store.entries]
        with patch.object(self.store, "save", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.store.restore_backup(source)
        self.assertEqual(self.store.entries, original)
        self.assertTrue(list((self.root / "backups").glob("vault.pre-restore.*.json")))
