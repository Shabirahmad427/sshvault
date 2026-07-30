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
    friendly_connection_error,
    set_working_ssh_preference,
    ssh_runtime_preferences,
)
from sshvault_security import (
    KnownHostsStore,
    SSHConnectionManager,
    preferred_transport_factory,
    request_agent_forwarding,
)


def _profile(**preferences: object) -> dict:
    profile = {
        "id": "runtime-profile",
        "name": "Runtime profile",
        "host": "destination.example",
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


class _Transport:
    def __init__(self) -> None:
        self.sock = _Socket()
        self.keepalive: int | None = None

    def set_keepalive(self, interval: int) -> None:
        self.keepalive = interval


class _Client:
    def __init__(self) -> None:
        self.transport = _Transport()
        self.connect_kwargs: dict = {}
        self.closed = False

    def load_host_keys(self, _path: str) -> None:
        pass

    def set_missing_host_key_policy(self, _policy: object) -> None:
        pass

    def connect(self, **kwargs: object) -> None:
        self.connect_kwargs = dict(kwargs)

    def get_transport(self) -> _Transport:
        return self.transport

    def close(self) -> None:
        self.closed = True


class _SecurityOptions:
    def __init__(self) -> None:
        self.kex = tuple(SSH_KEY_EXCHANGE_CHOICES[1:])
        self.key_types = tuple(SSH_HOST_KEY_CHOICES[1:])
        self.ciphers = tuple(SSH_CIPHER_CHOICES[1:])
        self.digests = tuple(SSH_MAC_CHOICES[1:])


class _AlgorithmTransport:
    def __init__(self, _sock: object, **_kwargs: object) -> None:
        self.options = _SecurityOptions()
        self.closed = False

    def get_security_options(self) -> _SecurityOptions:
        return self.options

    def close(self) -> None:
        self.closed = True


class SSHPhaseTwoRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.known_hosts = KnownHostsStore(Path(self.temp.name) / "known_hosts")

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_all_runtime_values_reach_connection_and_transport(self) -> None:
        profile = _profile(
            compression=True,
            tcp_keepalive=True,
            keepalive_interval=27,
            maximum_missed_keepalives=5,
            agent_forwarding=True,
            preferred_key_exchange=SSH_KEY_EXCHANGE_CHOICES[1],
            preferred_host_key=SSH_HOST_KEY_CHOICES[1],
            preferred_cipher=SSH_CIPHER_CHOICES[1],
            preferred_mac=SSH_MAC_CHOICES[1],
        )
        client = _Client()
        manager = SSHConnectionManager(self.known_hosts, profile["host"], profile["port"])
        with patch("sshvault_security.paramiko.SSHClient", return_value=client):
            result = manager.connect(profile, lambda _request: None)

        self.assertIs(result, client)
        self.assertTrue(client.connect_kwargs["compress"])
        self.assertIn("transport_factory", client.connect_kwargs)
        self.assertEqual(client.transport.keepalive, 27)
        self.assertEqual(client.transport.sshvault_maximum_missed_keepalives, 5)
        self.assertIn(
            (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1),
            client.transport.sock.options,
        )
        self.assertTrue(manager.last_runtime_preferences.agent_forwarding)

    def test_automatic_algorithms_are_omitted_and_keep_backend_defaults(self) -> None:
        profile = _profile()
        client = _Client()
        manager = SSHConnectionManager(self.known_hosts, profile["host"], profile["port"])
        with patch("sshvault_security.paramiko.SSHClient", return_value=client):
            manager.connect(profile, lambda _request: None)
        self.assertNotIn("transport_factory", client.connect_kwargs)
        self.assertEqual(
            ssh_runtime_preferences(profile).algorithm_preferences,
            {},
        )

    def test_explicit_algorithms_are_preferred_without_removing_fallbacks(self) -> None:
        runtime = ssh_runtime_preferences(
            _profile(
                preferred_key_exchange=SSH_KEY_EXCHANGE_CHOICES[-1],
                preferred_host_key=SSH_HOST_KEY_CHOICES[-1],
                preferred_cipher=SSH_CIPHER_CHOICES[-1],
                preferred_mac=SSH_MAC_CHOICES[-1],
            )
        )
        with patch(
            "sshvault_security.paramiko.Transport",
            _AlgorithmTransport,
        ):
            transport = preferred_transport_factory(runtime)(object())
        self.assertEqual(transport.options.kex[0], SSH_KEY_EXCHANGE_CHOICES[-1])
        self.assertEqual(transport.options.key_types[0], SSH_HOST_KEY_CHOICES[-1])
        self.assertEqual(transport.options.ciphers[0], SSH_CIPHER_CHOICES[-1])
        self.assertEqual(transport.options.digests[0], SSH_MAC_CHOICES[-1])
        self.assertEqual(
            set(transport.options.ciphers),
            set(SSH_CIPHER_CHOICES[1:]),
        )

    def test_concrete_backend_rejection_closes_transport_safely(self) -> None:
        runtime = ssh_runtime_preferences(_profile(preferred_cipher=SSH_CIPHER_CHOICES[1]))

        class UnsupportedOptions(_SecurityOptions):
            def __init__(self) -> None:
                super().__init__()
                self.ciphers = ("backend-only-cipher",)

        class UnsupportedTransport(_AlgorithmTransport):
            latest: UnsupportedTransport | None = None

            def __init__(self, sock: object, **kwargs: object) -> None:
                super().__init__(sock, **kwargs)
                self.options = UnsupportedOptions()
                UnsupportedTransport.latest = self

        with patch(
            "sshvault_security.paramiko.Transport",
            UnsupportedTransport,
        ):
            with self.assertRaisesRegex(ProfileError, "unsupported"):
                preferred_transport_factory(runtime)(object())
        self.assertTrue(UnsupportedTransport.latest.closed)

    def test_jump_and_final_hosts_keep_independent_runtime_preferences(self) -> None:
        jump = _profile(
            compression=True,
            keepalive_interval=10,
            preferred_cipher=SSH_CIPHER_CHOICES[1],
        )
        jump.update(id="jump", host="jump.example", user="jumper")
        final = _profile(
            compression=False,
            keepalive_interval=40,
            preferred_cipher=SSH_CIPHER_CHOICES[-1],
        )
        clients = [_Client(), _Client()]
        managers = [
            SSHConnectionManager(self.known_hosts, jump["host"], jump["port"]),
            SSHConnectionManager(self.known_hosts, final["host"], final["port"]),
        ]
        with patch(
            "sshvault_security.paramiko.SSHClient",
            side_effect=clients,
        ):
            managers[0].connect(jump, lambda _request: None)
            managers[1].connect(final, lambda _request: None)
        self.assertTrue(clients[0].connect_kwargs["compress"])
        self.assertFalse(clients[1].connect_kwargs["compress"])
        self.assertEqual(clients[0].transport.keepalive, 10)
        self.assertEqual(clients[1].transport.keepalive, 40)
        self.assertEqual(
            managers[0].last_runtime_preferences.preferred_cipher,
            SSH_CIPHER_CHOICES[1],
        )
        self.assertEqual(
            managers[1].last_runtime_preferences.preferred_cipher,
            SSH_CIPHER_CHOICES[-1],
        )

    def test_session_snapshot_is_immutable_runtime_source(self) -> None:
        saved = _profile(
            compression=True,
            keepalive_interval=15,
            preferred_mac=SSH_MAC_CHOICES[1],
        )
        record = SessionController().create_session(saved)
        working = copy.deepcopy(saved)
        set_working_ssh_preference(working, "compression", False)
        set_working_ssh_preference(working, "keepalive_interval", 90)
        set_working_ssh_preference(working, "preferred_mac", SSH_MAC_CHOICES[-1])
        runtime = ssh_runtime_preferences(record.profile_snapshot)
        self.assertTrue(runtime.compression)
        self.assertEqual(runtime.keepalive_interval, 15)
        self.assertEqual(runtime.preferred_mac, SSH_MAC_CHOICES[1])

    def test_unsupported_runtime_preference_fails_without_profile_mutation(self) -> None:
        profile = _profile()
        set_working_ssh_preference(profile, "preferred_cipher", SSH_CIPHER_CHOICES[1])
        profile["connection_options"]["ssh_preferences"]["preferred_cipher"] = "not-supported"
        before = copy.deepcopy(profile)
        client = _Client()
        manager = SSHConnectionManager(self.known_hosts, profile["host"], profile["port"])
        with patch("sshvault_security.paramiko.SSHClient", return_value=client):
            with self.assertRaisesRegex(ProfileError, "Unsupported"):
                manager.connect(profile, lambda _request: None)
        self.assertTrue(client.closed)
        self.assertEqual(profile, before)
        self.assertEqual(
            friendly_connection_error(ProfileError("Unsupported SSH cipher preference.")),
            "The selected SSH runtime preference is unsupported by this backend.",
        )

    def test_agent_forwarding_is_requested_only_when_enabled(self) -> None:
        channel = object()
        handler = object()
        with patch(
            "sshvault_security.paramiko.agent.AgentRequestHandler",
            return_value=handler,
        ) as request:
            self.assertIs(
                request_agent_forwarding(channel, _profile(agent_forwarding=True)),
                handler,
            )
            self.assertIsNone(request_agent_forwarding(channel, _profile(agent_forwarding=False)))
        request.assert_called_once_with(channel)


if __name__ == "__main__":
    unittest.main()
