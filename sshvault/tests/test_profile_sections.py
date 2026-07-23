import unittest

from sshvault_core import (
    ProfileError,
    validate_environment,
    validate_profile,
    validate_tunnel_rules,
)


class ProfileSectionTests(unittest.TestCase):
    def profile(self):
        return {"name": "Work", "host": "host.test", "port": 22, "user": "dev", "auth_method": "agent"}

    def test_old_profile_gets_idempotent_defaults(self):
        first = validate_profile(self.profile())
        second = validate_profile(first)
        self.assertEqual(first["terminal_options"], second["terminal_options"])
        self.assertEqual(first["sftp_options"], second["sftp_options"])

    def test_environment_names_and_values(self):
        self.assertEqual(validate_environment({"BUILD_MODE": 3}), {"BUILD_MODE": "3"})
        with self.assertRaises(ProfileError):
            validate_environment({"bad-name": "x"})

    def test_tunnel_rules_have_stable_ids_and_socks_shape(self):
        rules = validate_tunnel_rules([{"type": "SOCKS", "bind_port": 1080}])
        self.assertTrue(rules[0]["rule_id"])
        self.assertEqual(rules[0]["destination_host"], "")
        self.assertEqual(rules[0]["rule_id"], validate_tunnel_rules(rules)[0]["rule_id"])

    def test_enabled_bind_conflicts_are_rejected(self):
        with self.assertRaises(ProfileError):
            validate_tunnel_rules([{"type": "SOCKS", "bind_port": 1080}, {"type": "SOCKS", "bind_port": 1080}])


if __name__ == "__main__":
    unittest.main()
