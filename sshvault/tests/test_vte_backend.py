"""Display-free native VTE backend policy tests."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from sshvault_core import (
    ProfileError,
    VTEAvailability,
    VTETerminalBackend,
    build_native_ssh_argv,
    detect_vte_backend,
    vte_agent_diagnostics,
    vte_inherited_environment,
)


class NativeVTEBackendTests(unittest.TestCase):
    def _profile(self) -> dict:
        return {"host": "example.org", "user": "alice", "port": 2222, "auth_method": "agent"}

    def test_agent_argv_has_no_password_or_identity(self) -> None:
        profile = self._profile() | {"password": "never-exposed"}
        argv = build_native_ssh_argv(profile)
        self.assertEqual(
            argv[:7], ["ssh", "-tt", "-p", "2222", "-o", "SetEnv=TERM=xterm-256color", "alice@example.org"]
        )
        self.assertNotIn("never-exposed", argv)
        self.assertNotIn("-i", argv)
        self.assertNotIn("StrictHostKeyChecking=no", argv)

    def test_clauberh_profile_maps_to_the_canonical_openssh_command(self) -> None:
        argv = build_native_ssh_argv(
            {
                "name": "clauberh",
                "host": "coaraci.ifi.unicamp.br",
                "user": "clauberh",
                "port": 22,
                "proxy_jump": "sahmaddo@gate.ifi.unicamp.br",
                "auth_method": "agent",
            }
        )
        self.assertEqual(
            argv,
            [
                "ssh",
                "-tt",
                "-p",
                "22",
                "-J",
                "sahmaddo@gate.ifi.unicamp.br",
                "-o",
                "SetEnv=TERM=xterm-256color",
                "clauberh@coaraci.ifi.unicamp.br",
            ],
        )

    def test_explicit_key_is_restricted_to_that_identity(self) -> None:
        with patch("sshvault_core.Path.is_file", return_value=True):
            argv = build_native_ssh_argv(self._profile() | {"auth_method": "key", "key_path": "/keys/id"})
        self.assertIn("-i", argv)
        self.assertIn("IdentitiesOnly=yes", argv)

    def test_invalid_untrusted_options_are_rejected(self) -> None:
        with self.assertRaises(ProfileError):
            build_native_ssh_argv(self._profile() | {"host": "bad host"})
        with self.assertRaises(ProfileError):
            build_native_ssh_argv(self._profile() | {"proxy_jump": "jump;rm"})
        with self.assertRaises(ProfileError):
            build_native_ssh_argv(self._profile() | {"port": 0})

    def test_vte_detection_uses_safe_fallback(self) -> None:
        with (
            patch("sshvault_core.platform.system", return_value="Linux"),
            patch("sshvault_core._gi_probe", return_value=False),
        ):
            result = detect_vte_backend()
        self.assertFalse(result.available)
        self.assertIn("python3-gi", result.reason)
        self.assertEqual(VTEAvailability(True, "/usr/bin/python3").interpreter, "/usr/bin/python3")

    def test_system_python_is_selected_when_current_interpreter_lacks_vte(self) -> None:
        with (
            patch("sshvault_core.platform.system", return_value="Linux"),
            patch("sshvault_core._gi_probe", return_value=True) as probe,
        ):
            result = detect_vte_backend()
        self.assertTrue(result.available)
        self.assertEqual(result.interpreter, "/usr/bin/python3")
        probe.assert_called_once_with("/usr/bin/python3")

    def test_backend_never_claims_native_before_handshake(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        self.assertEqual(backend.status, "Legacy terminal — VTE helper failed: helper exited early")

    def test_missing_helper_has_visible_fallback_reason(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        with patch.object(backend, "_helper_path", return_value=Path("/missing/helper.py")):
            self.assertFalse(backend.ensure_ready())
        self.assertEqual(backend.status, "Legacy terminal — VTE helper failed: helper module missing")

    def test_helper_script_is_present_in_the_project_for_wheel_packaging(self) -> None:
        helper = Path(__file__).resolve().parents[1] / "sshvault_vte_helper.py"
        self.assertTrue(helper.is_file())
        self.assertIn("def probe()", helper.read_text(encoding="utf-8"))

    def test_runtime_environment_includes_display_and_agent_variables(self) -> None:
        parent = {
            "DISPLAY": ":1",
            "WAYLAND_DISPLAY": "wayland-0",
            "XAUTHORITY": "/tmp/auth",
            "DBUS_SESSION_BUS_ADDRESS": "unix:path=/tmp/bus",
            "XDG_RUNTIME_DIR": "/run/user/1",
            "SSH_AUTH_SOCK": "/tmp/agent",
            "SSH_AGENT_PID": "9",
            "LC_ALL": "C",
            "HOME": "/home/a",
        }
        environment = vte_inherited_environment(parent)
        self.assertTrue(all(name in environment for name in parent))

    def test_agent_and_session_environment_propagates_without_secrets(self) -> None:
        parent = {
            "SSH_AUTH_SOCK": "/run/user/1000/agent.sock",
            "SSH_AGENT_PID": "123",
            "HOME": "/home/alice",
            "USER": "alice",
            "LOGNAME": "alice",
            "PATH": "/usr/bin",
            "LANG": "pt_BR.UTF-8",
            "LC_CTYPE": "pt_BR.UTF-8",
            "DISPLAY": ":0",
            "PASSWORD": "must-not-pass",
        }
        helper_environment = vte_inherited_environment(parent)
        self.assertEqual(helper_environment["SSH_AUTH_SOCK"], parent["SSH_AUTH_SOCK"])
        self.assertEqual(helper_environment["LC_CTYPE"], parent["LC_CTYPE"])
        self.assertNotIn("PASSWORD", helper_environment)
        self.assertEqual(vte_inherited_environment(helper_environment), helper_environment)

    def test_no_agent_is_safe_and_diagnostics_do_not_reveal_socket(self) -> None:
        self.assertNotIn("SSH_AUTH_SOCK", vte_inherited_environment({"HOME": "/tmp"}))
        diagnostics = vte_agent_diagnostics({"HOME": "/tmp"})
        self.assertEqual(diagnostics, {"agent_socket_present": False, "agent_socket_exists": False})
