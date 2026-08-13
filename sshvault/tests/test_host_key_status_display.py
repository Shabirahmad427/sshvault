"""F11 real, session-owned host-key status regressions."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import paramiko

from sshvault import ConnectionTab, SSHVaultApp
from sshvault_core import (
    HOST_KEY_POLICY_DISPLAY,
    HostKeySessionStatus,
    SessionController,
    SessionLifecycleState,
)
from sshvault_security import (
    InteractiveHostKeyPolicy,
    KnownHostsStore,
    SSHConnectionManager,
    TrustDecision,
    sha256_fingerprint,
)


class _Variable:
    def __init__(self) -> None:
        self.value = ""

    def set(self, value) -> None:
        self.value = value


class _Transport:
    def __init__(self, key) -> None:
        self.key = key
        self.sock = None

    def get_remote_server_key(self):
        return self.key

    def set_keepalive(self, _interval):
        return None


class _Client:
    def __init__(self, key) -> None:
        self.transport = _Transport(key)

    def load_host_keys(self, _path):
        return None

    def set_missing_host_key_policy(self, _policy):
        return None

    def connect(self, **_kwargs):
        return None

    def get_transport(self):
        return self.transport

    def close(self):
        return None


class _DisplayHarness:
    _refresh_host_key_status = SSHVaultApp._refresh_host_key_status

    def __init__(self, controller, selected) -> None:
        self._session_controller = controller
        self._selected_session_id = selected
        self._host_key_vars = {key: _Variable() for key in ("policy", "source", "destination", "proxy")}

    def _selected_session_record(self):
        return self._session_controller.get(self._selected_session_id)


def _profile(profile_id, user, *, proxy=""):
    return {
        "id": profile_id,
        "name": user,
        "host": "coaraci.ifi.unicamp.br",
        "port": 22,
        "user": user,
        "auth_method": "password",
        "proxy_jump": proxy,
    }


class HostKeyStatusDisplayTests(unittest.TestCase):
    def test_known_verified_key_records_algorithm_sha256_result_and_host(self) -> None:
        key = paramiko.RSAKey.generate(1024)
        with tempfile.TemporaryDirectory() as root:
            manager = SSHConnectionManager(KnownHostsStore(Path(root, "known_hosts")), "coaraci.example", 22)
            with patch("sshvault_security.paramiko.SSHClient", return_value=_Client(key)):
                manager.connect(_profile("profile", "user"), lambda _request: TrustDecision.CANCEL, "password")
        status = manager.last_host_key_verification
        self.assertIsNotNone(status)
        self.assertEqual(status.hostname, "coaraci.example")
        self.assertEqual(status.algorithm, key.get_name())
        self.assertEqual(status.fingerprint, sha256_fingerprint(key))
        self.assertEqual(status.verification_result, "Verified against known hosts")
        self.assertNotIn(key.asbytes().hex(), status.display())

    def test_unknown_key_status_records_explicit_decision(self) -> None:
        key = paramiko.RSAKey.generate(1024)
        with tempfile.TemporaryDirectory() as root:
            manager = SSHConnectionManager(KnownHostsStore(Path(root, "known_hosts")), "unknown.example", 22)
            policy = InteractiveHostKeyPolicy(
                manager,
                _profile("profile", "user"),
                lambda _request: TrustDecision.TRUST_ONCE,
            )
            policy.missing_host_key(Mock(), "unknown.example", key)
        status = manager.last_host_key_verification
        self.assertEqual(status.verification_result, "Unknown key trusted once")
        self.assertEqual(status.fingerprint, sha256_fingerprint(key))

    def test_changed_key_is_recorded_as_rejected(self) -> None:
        controller = SessionController()
        session = controller.create_session(_profile("profile", "user"))
        request = type(
            "Changed",
            (),
            {
                "host_role": "Destination host",
                "hostname": "coaraci.example",
                "key_type": "ssh-ed25519",
                "received_fingerprint": "SHA256:received",
            },
        )()
        tab = type("Tab", (), {"_session_controller": controller, "session_id": session.session_id})()
        tab._record_host_key_verification = lambda status: controller.record_host_key_status(session.session_id, status)
        ConnectionTab._record_changed_host_key(tab, request)
        status = session.host_key_statuses["Destination host"]
        self.assertEqual((status.fingerprint, status.verification_result), ("SHA256:received", "Changed key rejected"))
        self.assertFalse(status.connected)

    def test_proxy_and_destination_fingerprints_remain_separate(self) -> None:
        controller = SessionController()
        session = controller.create_session(_profile("profile", "user", proxy="jump@gate"))
        controller.record_host_key_status(
            session.session_id,
            HostKeySessionStatus("Jump host", "gate", "ssh-ed25519", "SHA256:jump", "Verified"),
        )
        controller.record_host_key_status(
            session.session_id,
            HostKeySessionStatus("Destination host", "coaraci", "ssh-rsa", "SHA256:dest", "Verified"),
        )
        app = _DisplayHarness(controller, session.session_id)
        app._refresh_host_key_status()
        self.assertIn("SHA256:jump", app._host_key_vars["proxy"].value)
        self.assertNotIn("SHA256:dest", app._host_key_vars["proxy"].value)
        self.assertIn("SHA256:dest", app._host_key_vars["destination"].value)
        self.assertEqual(app._host_key_vars["policy"].value, HOST_KEY_POLICY_DISPLAY)

    def test_disconnect_preserves_fingerprint_and_marks_status(self) -> None:
        controller = SessionController()
        session = controller.create_session(_profile("profile", "user"))
        controller.record_host_key_status(
            session.session_id,
            HostKeySessionStatus("Destination host", "coaraci", "ssh-ed25519", "SHA256:key", "Verified"),
        )
        controller.mark_host_keys_disconnected(session.session_id)
        self.assertIn("SHA256:key", session.host_key_statuses["Destination host"].display())
        self.assertIn("disconnected", session.host_key_statuses["Destination host"].display())

    def test_sessions_display_only_their_own_fingerprints(self) -> None:
        controller = SessionController()
        first = controller.create_session(_profile("sahmaddo", "sahmaddo"))
        second = controller.create_session(_profile("clauberh", "clauberh"))
        first.state = second.state = SessionLifecycleState.CONNECTED
        controller.record_host_key_status(
            first.session_id,
            HostKeySessionStatus("Destination host", "coaraci", "ssh-ed25519", "SHA256:sahmaddo", "Verified"),
        )
        controller.record_host_key_status(
            second.session_id,
            HostKeySessionStatus("Destination host", "coaraci", "ssh-ed25519", "SHA256:clauberh", "Verified"),
        )
        app = _DisplayHarness(controller, first.session_id)
        app._refresh_host_key_status()
        self.assertIn("SHA256:sahmaddo", app._host_key_vars["destination"].value)
        self.assertNotIn("SHA256:clauberh", app._host_key_vars["destination"].value)
        app._selected_session_id = second.session_id
        app._refresh_host_key_status()
        self.assertIn("SHA256:clauberh", app._host_key_vars["destination"].value)
        self.assertNotIn("SHA256:sahmaddo", app._host_key_vars["destination"].value)


if __name__ == "__main__":
    unittest.main()
