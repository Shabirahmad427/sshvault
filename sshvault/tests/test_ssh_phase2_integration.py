from __future__ import annotations

import copy
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

from sshvault_core import (
    ProfileError,
    SessionController,
    SSH_CIPHER_CHOICES,
    SSH_HOST_KEY_CHOICES,
    SSH_KEY_EXCHANGE_CHOICES,
    SSH_MAC_CHOICES,
    set_working_ssh_preference,
)
from sshvault_security import KnownHostsStore, SSHConnectionManager


def _profile(identifier: str, host: str, **preferences: object) -> dict:
    profile = {
        "id": identifier,
        "name": identifier,
        "host": host,
        "port": 22,
        "user": "alice",
        "auth_method": "agent",
    }
    for key, value in preferences.items():
        set_working_ssh_preference(profile, key, value)
    return profile


class _Socket:
    def __init__(self) -> None:
        self.options: list[tuple[int, int, int]] = []

    def setsockopt(self, level: int, option: int, value: int) -> None:
        self.options.append((level, option, value))


class _SecurityOptions:
    def __init__(self) -> None:
        self.kex = tuple(SSH_KEY_EXCHANGE_CHOICES[1:])
        self.key_types = tuple(SSH_HOST_KEY_CHOICES[1:])
        self.ciphers = tuple(SSH_CIPHER_CHOICES[1:])
        self.digests = tuple(SSH_MAC_CHOICES[1:])


class _Transport:
    def __init__(self, sock: _Socket, **_kwargs: object) -> None:
        self.sock = sock
        self.options = _SecurityOptions()
        self.keepalive: int | None = None
        self.closed = False

    def get_security_options(self) -> _SecurityOptions:
        return self.options

    def set_keepalive(self, interval: int) -> None:
        self.keepalive = interval

    def close(self) -> None:
        self.closed = True


class _Client:
    def __init__(self) -> None:
        self.socket = _Socket()
        self.transport = _Transport(self.socket)
        self.connect_kwargs: dict[str, object] = {}
        self.closed = False

    def set_missing_host_key_policy(self, _policy: object) -> None:
        pass

    def load_host_keys(self, _path: str) -> None:
        pass

    def connect(self, **kwargs: object) -> None:
        self.connect_kwargs = dict(kwargs)
        factory = kwargs.get("transport_factory")
        if callable(factory):
            self.transport = factory(self.socket)

    def get_transport(self) -> _Transport:
        return self.transport

    def close(self) -> None:
        self.closed = True


class SSHPhaseTwoIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.known_hosts = KnownHostsStore(Path(self.temp.name) / "known_hosts")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _connect(self, profile: dict, client: _Client) -> SSHConnectionManager:
        manager = SSHConnectionManager(self.known_hosts, profile["host"], profile["port"])
        with (
            patch("sshvault_security.paramiko.SSHClient", return_value=client),
            patch("sshvault_security.paramiko.Transport", _Transport),
        ):
            manager.connect(profile, lambda _request: None)
        return manager

    def test_transport_receives_compression_keepalive_and_algorithms(self) -> None:
        profile = _profile(
            "configured",
            "configured.example",
            compression=True,
            tcp_keepalive=True,
            keepalive_interval=19,
            maximum_missed_keepalives=6,
            preferred_key_exchange=SSH_KEY_EXCHANGE_CHOICES[-1],
            preferred_host_key=SSH_HOST_KEY_CHOICES[-1],
            preferred_cipher=SSH_CIPHER_CHOICES[-1],
            preferred_mac=SSH_MAC_CHOICES[-1],
        )
        client = _Client()
        self._connect(profile, client)
        self.assertTrue(client.connect_kwargs["compress"])
        self.assertEqual(client.transport.keepalive, 19)
        self.assertEqual(client.transport.sshvault_maximum_missed_keepalives, 6)
        self.assertIn(
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            client.socket.options,
        )
        self.assertEqual(client.transport.options.kex[0], SSH_KEY_EXCHANGE_CHOICES[-1])
        self.assertEqual(client.transport.options.key_types[0], SSH_HOST_KEY_CHOICES[-1])
        self.assertEqual(client.transport.options.ciphers[0], SSH_CIPHER_CHOICES[-1])
        self.assertEqual(client.transport.options.digests[0], SSH_MAC_CHOICES[-1])

    def test_automatic_omits_factory_and_preserves_backend_algorithm_order(self) -> None:
        profile = _profile("automatic", "automatic.example")
        client = _Client()
        defaults = copy.deepcopy(client.transport.options.__dict__)
        self._connect(profile, client)
        self.assertNotIn("transport_factory", client.connect_kwargs)
        self.assertEqual(client.transport.options.__dict__, defaults)

    def test_jump_destination_and_active_snapshot_remain_independent(self) -> None:
        jump = _profile(
            "jump",
            "jump.example",
            compression=True,
            keepalive_interval=9,
            preferred_cipher=SSH_CIPHER_CHOICES[1],
        )
        final = _profile(
            "final",
            "final.example",
            compression=False,
            keepalive_interval=31,
            preferred_cipher=SSH_CIPHER_CHOICES[-1],
        )
        record = SessionController().create_session(final)
        working = copy.deepcopy(final)
        set_working_ssh_preference(working, "compression", True)
        set_working_ssh_preference(working, "keepalive_interval", 88)
        jump_client = _Client()
        final_client = _Client()
        managers = [
            SSHConnectionManager(self.known_hosts, jump["host"], jump["port"]),
            SSHConnectionManager(
                self.known_hosts,
                record.profile_snapshot["host"],
                record.profile_snapshot["port"],
            ),
        ]
        with (
            patch(
                "sshvault_security.paramiko.SSHClient",
                side_effect=[jump_client, final_client],
            ),
            patch("sshvault_security.paramiko.Transport", _Transport),
        ):
            managers[0].connect(jump, lambda _request: None)
            managers[1].connect(record.profile_snapshot, lambda _request: None)
        self.assertTrue(jump_client.connect_kwargs["compress"])
        self.assertFalse(final_client.connect_kwargs["compress"])
        self.assertEqual(jump_client.transport.keepalive, 9)
        self.assertEqual(final_client.transport.keepalive, 31)
        self.assertEqual(jump_client.transport.options.ciphers[0], SSH_CIPHER_CHOICES[1])
        self.assertEqual(final_client.transport.options.ciphers[0], SSH_CIPHER_CHOICES[-1])

    def test_invalid_runtime_preference_fails_before_backend_connection(self) -> None:
        profile = _profile("invalid", "invalid.example")
        set_working_ssh_preference(profile, "preferred_cipher", SSH_CIPHER_CHOICES[1])
        profile["connection_options"]["ssh_preferences"]["preferred_cipher"] = "unsupported"
        before = copy.deepcopy(profile)
        client = _Client()
        manager = SSHConnectionManager(self.known_hosts, profile["host"], profile["port"])
        with patch("sshvault_security.paramiko.SSHClient", return_value=client):
            with self.assertRaisesRegex(ProfileError, "Unsupported"):
                manager.connect(profile, lambda _request: None)
        self.assertFalse(client.connect_kwargs)
        self.assertTrue(client.closed)
        self.assertEqual(profile, before)


if __name__ == "__main__":
    unittest.main()
