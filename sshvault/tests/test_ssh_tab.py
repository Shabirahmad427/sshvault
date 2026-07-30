from __future__ import annotations

import copy
import unittest

import paramiko

from sshvault_core import (
    ProfileError,
    SessionController,
    SSH_CIPHER_CHOICES,
    SSH_HOST_KEY_CHOICES,
    SSH_KEY_EXCHANGE_CHOICES,
    SSH_MAC_CHOICES,
    SSH_SETTING_LABELS,
    build_native_ssh_argv,
    default_ssh_preferences,
    set_working_ssh_preference,
    ssh_preferences_from_profile,
    validate_profile,
    validate_ssh_preferences,
)


def _profile() -> dict:
    return {
        "id": "ssh-profile",
        "name": "SSH profile",
        "host": "host.example",
        "port": 22,
        "user": "alice",
        "auth_method": "agent",
    }


class SSHPhaseOneTests(unittest.TestCase):
    def test_control_contract_and_defaults(self) -> None:
        self.assertEqual(
            SSH_SETTING_LABELS,
            (
                "Enable compression",
                "TCP keepalive",
                "Keepalive interval",
                "Maximum missed keepalives",
                "Agent forwarding",
                "Preferred key-exchange algorithm",
                "Preferred host-key algorithm",
                "Preferred cipher",
                "Preferred MAC",
            ),
        )
        self.assertEqual(
            default_ssh_preferences(),
            {
                "compression": False,
                "tcp_keepalive": False,
                "keepalive_interval": 0,
                "maximum_missed_keepalives": 3,
                "agent_forwarding": False,
                "preferred_key_exchange": "Automatic",
                "preferred_host_key": "Automatic",
                "preferred_cipher": "Automatic",
                "preferred_mac": "Automatic",
            },
        )

    def test_dropdowns_are_automatic_first_and_backend_supported(self) -> None:
        choices = (
            (SSH_KEY_EXCHANGE_CHOICES, paramiko.Transport._preferred_kex),
            (SSH_HOST_KEY_CHOICES, paramiko.Transport._preferred_keys),
            (SSH_CIPHER_CHOICES, paramiko.Transport._preferred_ciphers),
            (SSH_MAC_CHOICES, paramiko.Transport._preferred_macs),
        )
        for displayed, supported in choices:
            with self.subTest(displayed=displayed):
                self.assertEqual(displayed[0], "Automatic")
                self.assertTrue(set(displayed[1:]).issubset(set(supported)))

    def test_keepalive_validation_accepts_boundaries(self) -> None:
        for interval in (0, 3600):
            for missed in (1, 20):
                with self.subTest(interval=interval, missed=missed):
                    result = validate_ssh_preferences(
                        {
                            "keepalive_interval": interval,
                            "maximum_missed_keepalives": missed,
                        }
                    )
                    self.assertEqual(result["keepalive_interval"], interval)
                    self.assertEqual(result["maximum_missed_keepalives"], missed)

    def test_keepalive_validation_rejects_invalid_values(self) -> None:
        for key, value in (
            ("keepalive_interval", -1),
            ("keepalive_interval", 3601),
            ("keepalive_interval", "invalid"),
            ("maximum_missed_keepalives", 0),
            ("maximum_missed_keepalives", 21),
            ("maximum_missed_keepalives", 1.5),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(ProfileError):
                validate_ssh_preferences({key: value})

    def test_unsupported_algorithms_are_rejected(self) -> None:
        for key in (
            "preferred_key_exchange",
            "preferred_host_key",
            "preferred_cipher",
            "preferred_mac",
        ):
            with self.subTest(key=key), self.assertRaisesRegex(ProfileError, "Unsupported"):
                validate_ssh_preferences({key: "unsupported-algorithm"})
        profile = _profile()
        set_working_ssh_preference(
            profile,
            "preferred_cipher",
            "unsupported-algorithm",
        )
        with self.assertRaisesRegex(ProfileError, "Unsupported"):
            validate_profile(profile, check_key_exists=False)

    def test_editing_updates_only_working_copy_and_dirty_semantics(self) -> None:
        stored = _profile()
        loaded = copy.deepcopy(stored)
        working = copy.deepcopy(stored)
        self.assertEqual(working, loaded)
        set_working_ssh_preference(working, "tcp_keepalive", True)
        self.assertNotEqual(working, loaded)
        self.assertNotIn("ssh_preferences", stored.get("connection_options", {}))
        set_working_ssh_preference(working, "tcp_keepalive", False)
        expected = copy.deepcopy(loaded)
        set_working_ssh_preference(expected, "tcp_keepalive", False)
        self.assertEqual(working, expected)

    def test_active_session_snapshot_isolated_from_working_edits(self) -> None:
        profile = _profile()
        set_working_ssh_preference(profile, "preferred_cipher", "aes256-ctr")
        session = SessionController().create_session(profile)
        working = copy.deepcopy(profile)
        set_working_ssh_preference(working, "preferred_cipher", "aes128-ctr")
        set_working_ssh_preference(working, "compression", True)
        self.assertEqual(
            ssh_preferences_from_profile(session.profile_snapshot)["preferred_cipher"],
            "aes256-ctr",
        )
        self.assertFalse(ssh_preferences_from_profile(session.profile_snapshot)["compression"])

    def test_phase_one_preferences_are_not_applied_to_runtime_argv(self) -> None:
        profile = _profile()
        set_working_ssh_preference(profile, "compression", True)
        set_working_ssh_preference(profile, "agent_forwarding", True)
        argv = build_native_ssh_argv(profile)
        self.assertNotIn("-C", argv)
        self.assertNotIn("-A", argv)


if __name__ == "__main__":
    unittest.main()
