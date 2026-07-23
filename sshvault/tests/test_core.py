"""Pure unit tests for sshvault_core: no home directory, network, or real keyring."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sshvault_core import (
    ProfileError,
    ProfileStore,
    SecretStore,
    connection_kwargs,
    redact_secrets,
    validate_port,
    validate_profile,
)


class FakeKeyring:
    def __init__(self, fail: str = "") -> None:
        self.values: dict[tuple[str, str], str] = {}
        self.fail = fail

    def get_password(self, service: str, identifier: str) -> str | None:
        if self.fail == "get":
            raise RuntimeError("backend down")
        return self.values.get((service, identifier))

    def set_password(self, service: str, identifier: str, secret: str) -> None:
        if self.fail == "set":
            raise PermissionError("access denied")
        self.values[(service, identifier)] = secret

    def delete_password(self, service: str, identifier: str) -> None:
        if self.fail == "delete":
            raise RuntimeError("backend down")
        self.values.pop((service, identifier), None)


def profile(**changes: object) -> dict[str, object]:
    value: dict[str, object] = {
        "name": "Example",
        "host": "example.test",
        "port": 22,
        "user": "dev",
        "auth_method": "agent",
        "key_path": "",
        "tags": ["test"],
        "notes": "",
    }
    value.update(changes)
    return value


class CoreTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.path = self.root / "nested" / "vault.json"
        self.backend = FakeKeyring()
        self.secrets = SecretStore(self.backend)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self) -> ProfileStore:
        return ProfileStore(self.path, self.secrets)


class ValidationTests(CoreTestCase):
    def test_valid_password_and_agent_profiles(self) -> None:
        password = validate_profile(profile(auth_method="password"))
        agent = validate_profile(profile(auth_method="agent"))
        self.assertEqual(password["auth_method"], "password")
        self.assertEqual(agent["auth_method"], "agent")

    def test_valid_key_profile(self) -> None:
        key = self.root / "id_test"
        key.write_text("not a real key")
        result = validate_profile(profile(auth_method="key", key_path=str(key)))
        self.assertEqual(result["key_path"], str(key))

    def test_name_is_deterministically_normalized_to_host(self) -> None:
        self.assertEqual(validate_profile(profile(name="   "))["name"], "example.test")

    def test_missing_host_and_username_are_rejected(self) -> None:
        for invalid in (profile(host=""), profile(user=""), profile(user="bad user")):
            with self.assertRaises(ProfileError):
                validate_profile(invalid)

    def test_invalid_port_values_are_rejected(self) -> None:
        for value in (0, -1, 65536, "abc", 22.5, True, False, None):
            with self.assertRaises(ProfileError, msg=str(value)):
                validate_port(value)

    def test_key_auth_requires_a_path_and_auth_method_is_limited(self) -> None:
        with self.assertRaises(ProfileError):
            validate_profile(profile(auth_method="key", key_path=""))
        with self.assertRaises(ProfileError):
            validate_profile(profile(auth_method="certificate"))

    def test_whitespace_tags_notes_and_unknown_fields(self) -> None:
        result = validate_profile(profile(host=" host.test ", user=" dev ", tags=" one, two, one ", notes=" note "))
        self.assertEqual(result["host"], "host.test")
        self.assertEqual(result["tags"], ["one", "two"])
        self.assertEqual(result["notes"], " note ")
        with self.assertRaises(ProfileError):
            validate_profile(profile(unexpected="no"))
        with self.assertRaises(ProfileError):
            validate_profile(profile(private_key="private key contents"))


class DuplicateTests(CoreTestCase):
    def test_empty_store_and_duplicate_identity(self) -> None:
        store = self.store()
        self.assertEqual(store.entries, [])
        store.add(profile())
        with self.assertRaisesRegex(ProfileError, "same host"):
            store.add(profile(name="Another"))

    def test_names_are_forbidden_case_insensitively(self) -> None:
        store = self.store()
        store.add(profile(name="Production"))
        with self.assertRaisesRegex(ProfileError, "names must be unique"):
            store.add(profile(name="Production", host="different.test"))
        with self.assertRaisesRegex(ProfileError, "names must be unique"):
            store.add(profile(name="production", host="other.test"))

    def test_edit_excludes_itself_but_rejects_renamed_duplicate(self) -> None:
        store = self.store()
        store.add(profile(name="One"))
        store.add(profile(name="Two", host="two.test"))
        store.update(0, profile(name="One", notes="changed"))
        with self.assertRaises(ProfileError):
            store.update(1, profile(name="one", host="two.test"))


class SerializationAndStorageTests(CoreTestCase):
    def test_round_trip_unicode_empty_optional_and_no_secrets(self) -> None:
        store = self.store()
        added = store.add(profile(name="研究服务器", tags=["科学", "prod"], notes="Δοκιμή", password="not-saved"))
        content = self.path.read_text(encoding="utf-8")
        self.assertIn("研究服务器", content)
        self.assertNotIn("not-saved", content)
        self.assertNotIn('"password"', content)
        self.assertNotIn("passphrase", content)
        self.assertNotIn("private key contents", content)
        loaded = ProfileStore(self.path, self.secrets)
        self.assertEqual(loaded.entries[0]["name"], added["name"])
        self.assertEqual(loaded.entries[0]["startup_command"], "")

    def test_atomic_write_creates_parent_permissions_and_cleans_temp_file(self) -> None:
        store = self.store()
        store.add(profile())
        self.assertTrue(self.path.exists())
        self.assertEqual(
            self.path.stat().st_mode & 0o777, 0o600
        )  # Unix assertion; Windows does not enforce POSIX modes.
        self.assertEqual(list(self.path.parent.glob(".vault.json.*")), [])

    def test_failed_replace_preserves_existing_vault_and_cleans_temp_file(self) -> None:
        store = self.store()
        store.add(profile())
        before = self.path.read_text()
        with patch("sshvault_core.os.replace", side_effect=OSError("disk failure")):
            with self.assertRaises(OSError):
                store.save()
        self.assertEqual(self.path.read_text(), before)
        self.assertEqual(list(self.path.parent.glob(".vault.json.*")), [])

    def test_export_never_overwrites(self) -> None:
        store = self.store()
        store.add(profile())
        destination = self.root / "profiles.json"
        store.export(destination)
        with self.assertRaises(ProfileError):
            store.export(destination)

    def test_backups_are_unique(self) -> None:
        store = self.store()
        store.add(profile())
        first = store._backup("manual")  # uniqueness is a storage invariant.
        second = store._backup("manual")
        self.assertNotEqual(first, second)
        self.assertTrue(first.exists() and second.exists())


class MigrationTests(CoreTestCase):
    def test_legacy_migration_moves_secrets_and_is_idempotent(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(
            json.dumps(
                [
                    dict(profile(name="Legacy", password="legacy-secret")),
                    dict(profile(name="Key", host="key.test", auth_method="key", key_path="/missing")),
                    {"name": "Broken", "host": "bad host", "user": "dev"},
                ]
            )
        )
        store = ProfileStore(self.path, self.secrets)
        report = store.migration_report
        self.assertEqual(report.migrated_profiles, 2)
        self.assertEqual(report.skipped_profiles, 1)
        self.assertEqual(report.secrets_moved, 1)
        self.assertIsNotNone(report.backup_path)
        self.assertEqual(self.secrets.get(store.entries[0]["id"]), "legacy-secret")
        self.assertNotIn("legacy-secret", self.path.read_text())
        again = ProfileStore(self.path, self.secrets)
        self.assertIsNone(again.migration_report.backup_path)

    def test_unavailable_keyring_reports_recovery_without_plaintext_fallback(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text(json.dumps([dict(profile(password="legacy-secret"))]))
        store = ProfileStore(self.path, SecretStore(None))
        self.assertEqual(store.migration_report.secrets_not_moved, 1)
        self.assertIn("could not be moved", store.migration_notice)
        self.assertNotIn("legacy-secret", self.path.read_text())

    def test_malformed_top_level_and_future_schema_are_not_changed(self) -> None:
        self.path.parent.mkdir(parents=True)
        self.path.write_text("not json")
        with self.assertRaises(ProfileError):
            ProfileStore(self.path, self.secrets)
        self.assertEqual(self.path.read_text(), "not json")
        self.path.write_text(json.dumps({"version": 99, "profiles": []}))
        with self.assertRaises(ProfileError):
            ProfileStore(self.path, self.secrets)
        self.assertEqual(json.loads(self.path.read_text())["version"], 99)


class SecretAndRedactionTests(CoreTestCase):
    def test_keyring_store_read_delete_missing_and_errors(self) -> None:
        secrets = SecretStore(self.backend)
        secrets.set("profile-id", "value")
        self.assertEqual(secrets.get("profile-id"), "value")
        self.assertNotIn("value", "profile-id")
        secrets.delete("profile-id")
        self.assertIsNone(secrets.get("profile-id"))
        with self.assertRaises(ProfileError):
            SecretStore(FakeKeyring("set")).set("id", "secret")
        with self.assertRaises(ProfileError):
            SecretStore(FakeKeyring("get")).get("id")

    def test_redaction_keeps_safe_diagnostics(self) -> None:
        value = {
            "hostname": "server.test",
            "port": 2222,
            "username": "dev",
            "fingerprint": "SHA256:public",
            "Password": "pw",
            "token": "abc",
            "nested": ["passphrase=hush", ("Authorization: Bearer xyz",)],
        }
        redacted = redact_secrets(value)
        self.assertEqual(redacted["hostname"], "server.test")
        self.assertEqual(redacted["Password"], "[REDACTED]")
        self.assertIn("[REDACTED]", redacted["nested"][0])
        self.assertIn("[REDACTED]", redact_secrets(RuntimeError("token=abc")))
        pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----"
        self.assertEqual(redact_secrets(pem), "[REDACTED PRIVATE KEY]")


class ConnectionParameterTests(CoreTestCase):
    def test_authentication_parameter_construction(self) -> None:
        password = connection_kwargs(validate_profile(profile(auth_method="password")), "pw")
        self.assertEqual(password["password"], "pw")
        self.assertFalse(password["look_for_keys"])
        agent = connection_kwargs(
            validate_profile(profile(auth_method="agent", port=2200, timeout=30, compression=True))
        )
        self.assertEqual((agent["port"], agent["timeout"], agent["compress"]), (2200, 30, True))
        self.assertNotIn("host_key_policy", agent)
        key = self.root / "id_test"
        key.write_text("private key contents")
        key_kwargs = connection_kwargs(validate_profile(profile(auth_method="key", key_path=str(key))))
        self.assertEqual(key_kwargs["key_filename"], str(key))
        self.assertNotIn("password", key_kwargs)
        with self.assertRaises(ProfileError):
            connection_kwargs(validate_profile(profile(auth_method="password")))
