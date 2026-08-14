"""Display-free native VTE backend policy tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
import subprocess
from unittest.mock import Mock, patch

from sshvault_core import (
    ProfileError,
    SessionController,
    SessionLifecycleState,
    VTEAvailability,
    VTETerminalBackend,
    build_native_ssh_argv,
    detect_vte_backend,
    vte_agent_diagnostics,
    vte_inherited_environment,
)


class _ChunkedControlSocket:
    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.sent = []
        self.timeouts = []

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def recv(self, size):
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
            return chunk[:size]
        return chunk

    def sendall(self, payload):
        self.sent.append(payload)


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
        unavailable = VTEAvailability(
            False,
            "/usr/bin/python3",
            "System Python cannot import VTE 2.91.",
            True,
            False,
            "Namespace Vte not available",
        )
        with (
            patch("sshvault_core.platform.system", return_value="Linux"),
            patch("sshvault_core._probe_vte_interpreter", return_value=unavailable),
        ):
            result = detect_vte_backend()
        self.assertFalse(result.available)
        self.assertTrue(result.gi_available)
        self.assertFalse(result.vte_available)
        self.assertIn("Namespace Vte not available", result.error)
        self.assertEqual(VTEAvailability(True, "/usr/bin/python3").interpreter, "/usr/bin/python3")

    def test_system_python_is_selected_when_current_interpreter_lacks_vte(self) -> None:
        available = VTEAvailability(True, "/usr/bin/python3", gi_available=True, vte_available=True)
        with (
            patch("sshvault_core.platform.system", return_value="Linux"),
            patch("sshvault_core._probe_vte_interpreter", return_value=available) as probe,
        ):
            result = detect_vte_backend()
        self.assertTrue(result.available)
        self.assertEqual(result.interpreter, "/usr/bin/python3")
        probe.assert_called_once_with("/usr/bin/python3")

    def test_miniconda_main_process_reports_system_python_vte_helper(self) -> None:
        availability = VTEAvailability(True, "/usr/bin/python3", gi_available=True, vte_available=True)
        with patch("sshvault_core.sys.executable", "/home/alice/miniconda3/bin/python"):
            diagnostics = availability.diagnostics()
        self.assertIn("Main Python: /home/alice/miniconda3/bin/python", diagnostics)
        self.assertIn("VTE Python: /usr/bin/python3", diagnostics)
        self.assertIn("GI available: yes", diagnostics)
        self.assertIn("VTE 2.91 available: yes", diagnostics)

    def test_gi_unavailable_diagnostics_include_sanitized_error(self) -> None:
        availability = VTEAvailability(
            False,
            "/usr/bin/python3",
            "System Python cannot import GI.",
            False,
            False,
            "No module named gi",
        )
        diagnostics = availability.diagnostics("/opt/conda/bin/python")
        self.assertIn("GI available: no", diagnostics)
        self.assertIn("VTE 2.91 available: no", diagnostics)
        self.assertIn("Import error: No module named gi", diagnostics)

    def test_backend_never_claims_native_before_handshake(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        self.assertEqual(backend.status, "Native VTE unavailable: helper exited")

    def test_json_response_split_across_multiple_reads(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        wire = json.dumps({"type": "response", "request_id": "split", "ok": True}).encode() + b"\n"
        backend._connection = _ChunkedControlSocket([wire[:5], wire[5:19], wire[19:]])  # type: ignore[assignment]
        self.assertEqual(backend._receive(1), {"type": "response", "request_id": "split", "ok": True})

    def test_response_larger_than_4096_bytes(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        expected = {"type": "response", "request_id": "large", "value": "x" * 9000}
        wire = json.dumps(expected).encode() + b"\n"
        backend._connection = _ChunkedControlSocket([wire[:4096], wire[4096:8192], wire[8192:]])  # type: ignore[assignment]
        self.assertEqual(backend._receive(1), expected)

    def test_two_responses_received_together_are_preserved(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        first = {"type": "response", "request_id": "one", "ok": True}
        second = {"type": "response", "request_id": "two", "ok": True}
        wire = b"".join(json.dumps(item).encode() + b"\n" for item in (first, second))
        backend._connection = _ChunkedControlSocket([wire])  # type: ignore[assignment]
        self.assertEqual(backend._receive(1), first)
        self.assertEqual(backend._receive(1), second)

    def test_partial_response_followed_by_disconnect_fails_safely(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._connection = _ChunkedControlSocket([b'{"type":"response"', b""])  # type: ignore[assignment]
        self.assertIsNone(backend._receive(1))
        self.assertEqual(backend._receive_buffer, bytearray())

    def test_malformed_response_fails_only_its_frame(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        valid = {"type": "response", "request_id": "next", "ok": True}
        wire = b"{malformed}\n" + json.dumps(valid).encode() + b"\n"
        backend._connection = _ChunkedControlSocket([wire])  # type: ignore[assignment]
        self.assertIsNone(backend._receive(1))
        self.assertEqual(backend._receive(1), valid)

    def test_rejected_open_does_not_close_unrelated_live_terminals(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._process = Mock()
        backend._process.poll.return_value = None
        backend._terminals = {"existing": {"terminal_id": "existing", "session_id": "other"}}
        with (
            patch.object(backend, "_start", return_value=True),
            patch.object(backend, "_request", return_value=None),
            patch.object(backend, "close") as close,
        ):
            self.assertFalse(backend.open_terminal_tab(self._profile()))
        close.assert_not_called()
        self.assertIn("existing", backend._terminals)

    def test_buffered_responses_keep_multiple_vte_tabs_independent(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {
            "sahmaddo-tab": {"terminal_id": "sahmaddo-tab", "session_id": "sahmaddo"},
            "clauberh-tab": {"terminal_id": "clauberh-tab", "session_id": "clauberh"},
        }
        responses = (
            {"type": "response", "request_id": "request-one", "ok": True},
            {"type": "response", "request_id": "request-two", "ok": True},
        )
        wire = b"".join(json.dumps(item).encode() + b"\n" for item in responses)
        backend._connection = _ChunkedControlSocket([wire])  # type: ignore[assignment]
        with patch("sshvault_core.uuid4", side_effect=("request-one", "request-two")):
            self.assertTrue(backend._request("focus_tab", terminal_id="sahmaddo-tab")["ok"])
            self.assertTrue(backend._request("focus_tab", terminal_id="clauberh-tab")["ok"])
        self.assertEqual(set(backend._terminals), {"sahmaddo-tab", "clauberh-tab"})

    def test_vte_request_propagates_appearance_term_and_initial_command(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        profile = self._profile() | {
            "_session_id": "sahmaddo-session",
            "terminal_options": {
                "backend": "Native VTE",
                "font": "Fira Code",
                "font_size": 14,
                "cursor_shape": "Underline",
                "cursor_blink": False,
                "foreground": "#aabbcc",
                "background": "#112233",
                "terminal_type": "screen-256color",
                "startup_command": "whoami",
            },
        }
        with (
            patch.object(backend, "_start", return_value=True),
            patch.object(
                backend,
                "_request",
                return_value={"ok": True, "terminal_id": "one", "window_id": "window", "warnings": []},
            ) as request,
        ):
            self.assertTrue(backend.open_terminal_tab(profile))
        payload = request.call_args.kwargs
        self.assertEqual(payload["session_id"], "sahmaddo-session")
        self.assertEqual(payload["terminal_options"]["font"], "Fira Code")
        self.assertEqual(payload["terminal_options"]["cursor_shape"], "Underline")
        self.assertEqual(payload["terminal_options"]["foreground"], "#aabbcc")
        self.assertIn("SetEnv=TERM=screen-256color", payload["argv"])
        self.assertEqual(payload["argv"][-1], "whoami")
        self.assertEqual(backend._terminals["one"]["terminal_options"]["background"], "#112233")

    def test_missing_helper_has_visible_fallback_reason(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        with patch.object(backend, "_helper_path", return_value=Path("/missing/helper.py")):
            self.assertFalse(backend.ensure_ready())
        self.assertEqual(backend.status, "Native VTE unavailable: helper module missing")

    def test_helper_script_is_present_in_the_project_for_wheel_packaging(self) -> None:
        helper = Path(__file__).resolve().parents[1] / "sshvault_vte_helper.py"
        self.assertTrue(helper.is_file())
        source = helper.read_text(encoding="utf-8")
        self.assertIn("def probe()", source)
        self.assertNotIn("import paramiko", source)
        self.assertNotIn("import sshvault_core", source)

    def test_helper_failure_does_not_restart_or_disconnect_ssh(self) -> None:
        controller = SessionController()
        session = controller.create_session(self._profile())
        session.state = SessionLifecycleState.CONNECTED
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        backend._terminals = {"terminal": {"terminal_id": "terminal"}}
        backend._process = Mock()
        backend._process.poll.return_value = 1
        with patch.object(backend, "_start") as start:
            self.assertEqual(backend.list_terminals(), [])
        start.assert_not_called()
        self.assertEqual(backend.status, "Native VTE unavailable: helper exited")
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_close_reaps_helper_after_forced_kill(self) -> None:
        backend = VTETerminalBackend(VTEAvailability(True, "/usr/bin/python3"))
        process = Mock()
        process.poll.return_value = None
        process.wait.side_effect = [subprocess.TimeoutExpired("vte", 1), 0]
        backend._process = process
        backend.close()
        process.terminate.assert_called_once_with()
        process.kill.assert_called_once_with()
        self.assertEqual(process.wait.call_count, 2)

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
