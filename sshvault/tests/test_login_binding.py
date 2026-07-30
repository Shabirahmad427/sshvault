import unittest
from sshvault_core import build_native_ssh_argv


class LoginBindingTests(unittest.TestCase):
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
