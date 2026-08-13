from __future__ import annotations

import ast
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from sshvault import ConnectionTab, LOGIN_AUTH_METHODS, PROXY_AUTH_METHODS, SSHVaultApp
from sshvault_core import (
    ProfileStore,
    SecretStore,
    SessionController,
    build_native_ssh_argv,
    connection_kwargs,
    proxy_jump_target,
    validate_profile,
)


class _Var:
    def __init__(self, value="") -> None:
        self.value = value

    def get(self):
        return self.value

    def set(self, value) -> None:
        self.value = value


class _Keyring:
    def __init__(self) -> None:
        self.values = {}

    def get_password(self, service, profile_id):
        return self.values.get((service, profile_id))

    def set_password(self, service, profile_id, secret):
        self.values[(service, profile_id)] = secret

    def delete_password(self, service, profile_id):
        self.values.pop((service, profile_id), None)


def _profile() -> dict:
    return validate_profile(
        {
            "id": "destination",
            "name": "Destination",
            "host": "coaraci.example",
            "port": 22,
            "user": "clauberh",
            "auth_method": "agent",
        },
        check_key_exists=False,
    )


class _LoginHarness:
    _login_field_changed = SSHVaultApp._login_field_changed
    _login_password_changed = SSHVaultApp._login_password_changed
    recalculate_profile_dirty = SSHVaultApp.recalculate_profile_dirty
    update_working_profile_field = SSHVaultApp.update_working_profile_field

    def __init__(self) -> None:
        self.loaded_profile_snapshot = _profile()
        self.working_profile = copy.deepcopy(self.loaded_profile_snapshot)
        self.profile_dirty = False
        self.profile_validation_errors = []
        self._working_profile_password = ""
        self._working_profile_password_changed = False
        self._login_refreshing = False
        self._login_password_var = _Var()
        self._login_vars = {
            "auth_method": _Var("SSH Agent"),
            "proxy_type": _Var("None"),
            "proxy_host": _Var(),
            "proxy_port": _Var("22"),
            "proxy_user": _Var(),
            "proxy_auth_method": _Var("SSH Agent"),
        }

    def _refresh_profile_heading(self):
        return None

    def _refresh_action_states(self):
        return None

    def _sync_login_visibility(self):
        return None

    def _validate_working_profile(self):
        try:
            validate_profile(self.working_profile, check_key_exists=False)
        except Exception as exc:
            self.profile_validation_errors = [str(exc)]
            return False
        self.profile_validation_errors = []
        return True


class _VaultAdapter:
    def __init__(self, store: ProfileStore) -> None:
        self.store = store
        self.entries = store.entries

    def update(self, index, profile, password=None, remove_password=False):
        self.store.update(index, profile, password, remove_password=remove_password)
        self.entries = self.store.entries


class LoginBindingTests(unittest.TestCase):
    def test_one_effective_save_path_persists_and_clears_dirty_state(self):
        source_path = Path(__file__).resolve().parents[1] / "sshvault.py"
        module = ast.parse(source_path.read_text(encoding="utf-8"))
        app_class = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "SSHVaultApp")
        saves = [
            node
            for node in app_class.body
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "_save_working_profile"
        ]
        self.assertEqual(len(saves), 1)
        self.assertNotIn("Milestone B placeholder", ast.get_source_segment(source_path.read_text(), saves[0]) or "")

        with tempfile.TemporaryDirectory() as root:
            store = ProfileStore(Path(root, "vault.json"), SecretStore(_Keyring()))
            saved = store.add(_profile())
            app = _LoginHarness()
            app._vault = _VaultAdapter(store)
            app.selected_profile_id = saved["id"]
            app._save_working_profile = SSHVaultApp._save_working_profile.__get__(app)
            app._refresh_list = lambda: None
            app.working_profile["notes"] = "persisted through canonical save"
            app.recalculate_profile_dirty()
            self.assertTrue(app.profile_dirty)
            app._save_working_profile()
            reloaded = ProfileStore(Path(root, "vault.json"), SecretStore(_Keyring()))
            self.assertEqual(reloaded.entries[0]["notes"], "persisted through canonical save")
            self.assertFalse(app.profile_dirty)
            self.assertEqual(app.loaded_profile_snapshot, app.working_profile)

    def test_only_supported_destination_and_jump_methods_are_exposed(self):
        self.assertEqual(tuple(LOGIN_AUTH_METHODS), ("SSH Agent", "Private Key", "Password"))
        self.assertEqual(tuple(PROXY_AUTH_METHODS), ("SSH Agent", "Password"))
        self.assertNotIn("Keyboard Interactive", LOGIN_AUTH_METHODS)
        self.assertNotIn("OpenSSH Config", LOGIN_AUTH_METHODS)

    def test_destination_agent_and_password_selection_update_working_copy_and_dirty_state(self):
        app = _LoginHarness()
        app._login_vars["auth_method"].set("Password")
        app._login_field_changed("auth_method")
        self.assertEqual(app.working_profile["auth_method"], "password")
        self.assertTrue(app.profile_dirty)
        app._login_vars["auth_method"].set("SSH Agent")
        app._login_field_changed("auth_method")
        self.assertEqual(app.working_profile["auth_method"], "agent")
        self.assertFalse(app.profile_dirty)

    def test_password_is_staged_outside_profile_and_reaches_auth_backend(self):
        app = _LoginHarness()
        app._login_vars["auth_method"].set("Password")
        app._login_field_changed("auth_method")
        app._login_password_var.set("destination-secret")
        app._login_password_changed()
        self.assertEqual(app._working_profile_password, "destination-secret")
        self.assertNotIn("password", app.working_profile)
        kwargs = connection_kwargs(app.working_profile, app._working_profile_password)
        self.assertEqual(kwargs["password"], "destination-secret")
        self.assertFalse(kwargs["allow_agent"])

    def test_password_save_reload_uses_secret_store_and_never_profile_json(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "vault.json")
            keyring = _Keyring()
            store = ProfileStore(path, SecretStore(keyring))
            saved = store.add(dict(_profile(), auth_method="password"), "destination-secret")
            payload = path.read_text(encoding="utf-8")
            self.assertNotIn("destination-secret", payload)
            self.assertNotIn("password", json.loads(payload)["profiles"][0])
            reloaded = ProfileStore(path, SecretStore(keyring))
            self.assertEqual(reloaded.entries[0]["auth_method"], "password")
            self.assertEqual(reloaded.secret_store.get(saved["id"]), "destination-secret")

    def test_visible_password_is_committed_through_existing_secure_store(self):
        with tempfile.TemporaryDirectory() as root:
            keyring = _Keyring()
            store = ProfileStore(Path(root, "vault.json"), SecretStore(keyring))
            saved = store.add(_profile())
            app = _LoginHarness()
            app._vault = _VaultAdapter(store)
            app.selected_profile_id = saved["id"]
            app._save_working_profile = SSHVaultApp._save_working_profile.__get__(app)
            app._refresh_list = lambda: None
            app._login_vars["auth_method"].set("Password")
            app._login_field_changed("auth_method")
            app._login_password_var.set("destination-secret")
            app._login_password_changed()
            app._save_working_profile()
            self.assertEqual(store.secret_store.get(saved["id"]), "destination-secret")
            self.assertNotIn("password", store.entries[0])

    def test_proxy_fields_and_authentication_update_working_profile(self):
        app = _LoginHarness()
        app._login_vars["proxy_type"].set("SSH ProxyJump")
        app._login_vars["proxy_host"].set("gate.example")
        app._login_vars["proxy_port"].set("2200")
        app._login_vars["proxy_user"].set("sahmaddo")
        app._login_vars["proxy_auth_method"].set("Password")
        app._login_field_changed("proxy_auth_method")
        options = app.working_profile["login_options"]
        self.assertEqual(
            (
                options["proxy_jump_enabled"],
                options["proxy_jump_host"],
                options["proxy_jump_port"],
                options["proxy_jump_user"],
                options["proxy_jump_auth_method"],
            ),
            (True, "gate.example", "2200", "sahmaddo", "password"),
        )
        self.assertEqual(app.working_profile["proxy_jump"], "sahmaddo@gate.example:2200")
        self.assertTrue(app.profile_dirty)

    def test_disabling_proxy_removes_target_but_preserves_unrelated_login_settings(self):
        app = _LoginHarness()
        app.working_profile["login_options"]["timeout"] = 77
        app._login_vars["proxy_type"].set("None")
        app._login_field_changed("proxy_type")
        self.assertEqual(app.working_profile["proxy_jump"], "")
        self.assertEqual(app.working_profile["login_options"]["timeout"], 77)

    def test_proxy_save_reload_and_active_session_snapshot_isolation(self):
        original = _profile()
        active = SessionController().create_session(original)
        edited = copy.deepcopy(original)
        edited["login_options"].update(
            {
                "proxy_jump_enabled": True,
                "proxy_jump_host": "gate.example",
                "proxy_jump_port": 2200,
                "proxy_jump_user": "sahmaddo",
                "proxy_jump_auth_method": "agent",
            }
        )
        normalized = validate_profile(edited, check_key_exists=False)
        self.assertEqual(normalized["proxy_jump"], "sahmaddo@gate.example:2200")
        self.assertEqual(active.profile_snapshot["proxy_jump"], "")
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "vault.json")
            store = ProfileStore(path, SecretStore(None))
            store.add(normalized)
            reloaded = ProfileStore(path, SecretStore(None)).entries[0]
            self.assertEqual(reloaded["login_options"]["proxy_jump_host"], "gate.example")
            self.assertEqual(proxy_jump_target(reloaded["login_options"]), "sahmaddo@gate.example:2200")

    def test_jump_agent_is_independent_from_destination_password_or_agent(self):
        jump = {
            "proxy_jump_enabled": True,
            "proxy_jump_host": "gate.example",
            "proxy_jump_port": 22,
            "proxy_jump_user": "sahmaddo",
            "proxy_jump_auth_method": "agent",
        }
        for destination_auth, password in (("password", "destination-secret"), ("agent", None)):
            with self.subTest(destination_auth=destination_auth):
                destination = validate_profile(
                    dict(_profile(), auth_method=destination_auth, login_options=jump),
                    check_key_exists=False,
                )
                destination_kwargs = connection_kwargs(destination, password)
                self.assertEqual(destination["login_options"]["proxy_jump_auth_method"], "agent")
                self.assertEqual(destination_kwargs["allow_agent"], destination_auth == "agent")
                self.assertEqual("password" in destination_kwargs, destination_auth == "password")

    def test_runtime_jump_agent_remains_independent_from_destination_auth(self):
        class Transport:
            def open_channel(self, *_args):
                return object()

        class Client:
            def get_transport(self):
                return Transport()

        captured = []

        class Manager:
            def __init__(self, *_args):
                pass

            def connect(self, profile, _trust, password, **_kwargs):
                captured.append((profile, password))
                return Client()

        class Terminal:
            def write(self, *_args):
                pass

        for destination_auth in ("password", "agent"):
            destination = validate_profile(
                dict(
                    _profile(),
                    auth_method=destination_auth,
                    login_options={
                        "proxy_jump_enabled": True,
                        "proxy_jump_host": "gate.example",
                        "proxy_jump_port": 22,
                        "proxy_jump_user": "sahmaddo",
                        "proxy_jump_auth_method": "agent",
                    },
                ),
                check_key_exists=False,
            )
            tab = type(
                "Tab",
                (),
                {
                    "_session_profile_snapshot": lambda self, value=destination: value,
                    "after": lambda self, _delay, callback: callback(),
                    "_terminal": Terminal(),
                    "_vault_entries": [],
                    "_entry": {},
                    "_trust_broker": type("Trust", (), {"request": lambda self, _request: None})(),
                    "_report_agent_authentication": lambda self, _event: None,
                    "_session_generation": 1,
                    "_proxy_context": None,
                },
            )()
            with patch("sshvault.SSHConnectionManager", Manager):
                ConnectionTab._make_proxy_sock(tab, destination["proxy_jump"], destination["host"], 22, 1)
            jump_profile, jump_password = captured[-1]
            self.assertEqual(jump_profile["auth_method"], "agent")
            self.assertIsNone(jump_password)
            kwargs = connection_kwargs(destination, "destination-secret" if destination_auth == "password" else None)
            self.assertEqual(kwargs["allow_agent"], destination_auth == "agent")

    def test_clauberh_proxyjump_uses_destination_not_profile_name(self):
        profile = {
            "name": "clauberh",
            "host": "coaraci.ifi.unicamp.br",
            "port": 22,
            "user": "clauberh",
            "auth_method": "agent",
            "proxy_jump": "sahmaddo@gate.ifi.unicamp.br",
        }
        argv = build_native_ssh_argv(profile)
        self.assertIn("clauberh@coaraci.ifi.unicamp.br", argv)
        self.assertEqual(argv[argv.index("-J") + 1], "sahmaddo@gate.ifi.unicamp.br")

    def test_password_is_not_in_native_argv(self):
        argv = build_native_ssh_argv(
            {"host": "example.org", "port": 22, "user": "alice", "auth_method": "password", "password": "secret"}
        )
        self.assertNotIn("secret", argv)
        self.assertNotIn("secret", json.dumps(_profile()))
