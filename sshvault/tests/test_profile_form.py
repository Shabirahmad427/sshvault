"""Display-free editor-state tests; no Tk, network, or real keyring."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from sshvault_core import ProfileError, ProfileFormState, ProfileStore, SecretStore


class FakeKeyring:
    def __init__(self) -> None:
        self.values: dict[tuple[str, str], str] = {}

    def get_password(self, service: str, ident: str) -> str | None:
        return self.values.get((service, ident))

    def set_password(self, service: str, ident: str, secret: str) -> None:
        self.values[(service, ident)] = secret

    def delete_password(self, service: str, ident: str) -> None:
        self.values.pop((service, ident), None)


def data(**changes: object) -> dict[str, object]:
    result: dict[str, object] = {
        "name": "Demo",
        "host": "demo.test",
        "port": "22",
        "user": "dev",
        "auth_method": "agent",
        "key_path": "",
        "tags": "one, two, one",
        "notes": "line one\nline two",
    }
    result.update(changes)
    return result


class ProfileFormTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "vault.json"
        self.keyring = FakeKeyring()
        self.store = ProfileStore(self.path, SecretStore(self.keyring))

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_authentication_visibility_and_valid_agent_profile(self) -> None:
        state = ProfileFormState(data())
        self.assertEqual(state.auth_field_visibility(), {"password": False, "key_path": False, "passphrase": False})
        self.assertTrue(state.can_save)

    def test_password_profile_excludes_secrets(self) -> None:
        state = ProfileFormState(data(auth_method="password", password="pw", passphrase="never"), password="pw")
        profile = state.clean_profile()
        self.assertEqual(state.auth_field_visibility()["password"], True)
        self.assertNotIn("password", profile)
        self.assertNotIn("passphrase", profile)

    def test_key_profile_requires_existing_regular_file(self) -> None:
        key = Path(self.temp.name) / "id_demo"
        key.write_text("test")
        state = ProfileFormState(data(auth_method="key", key_path=str(key)), passphrase="secret")
        self.assertTrue(state.can_save)
        self.assertTrue(state.auth_field_visibility()["key_path"])
        self.assertFalse(ProfileFormState(data(auth_method="key", key_path="missing")).can_save)

    def test_invalid_required_fields_disable_save(self) -> None:
        for changes in ({"port": "0"}, {"host": ""}, {"user": ""}, {"auth_method": "unsupported"}):
            self.assertFalse(ProfileFormState(data(**changes)).can_save)

    def test_store_secret_replace_remove_and_duplicate_rejection(self) -> None:
        added = self.store.add(data(auth_method="password"), "old")
        self.assertEqual(self.keyring.get_password("sshvault", added["id"]), "old")
        self.store.update(0, data(auth_method="password", notes="edited without replacing"))
        self.assertEqual(self.keyring.get_password("sshvault", added["id"]), "old")
        self.store.update(0, data(auth_method="password", notes="changed"), "new")
        self.assertEqual(self.keyring.get_password("sshvault", added["id"]), "new")
        self.store.update(0, data(auth_method="agent"), remove_password=True)
        self.assertIsNone(self.keyring.get_password("sshvault", added["id"]))
        with self.assertRaises(ProfileError):
            self.store.add(data(name="demo", host="other.test"))
        with self.assertRaises(ProfileError):
            self.store.add(data(name="Different"))

    def test_failed_persistence_keeps_original_entry(self) -> None:
        original = self.store.add(data())
        from unittest.mock import patch

        with patch("sshvault_core.os.replace", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                self.store.update(0, data(notes="not saved"))
        self.assertEqual(self.store.entries[0], original)
