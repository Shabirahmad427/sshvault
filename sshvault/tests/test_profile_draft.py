import unittest

from sshvault_core import ProfileDraft, ProfileError, validate_proxy_chain


class ProfileDraftTests(unittest.TestCase):
    def profile(self, name="Work", proxy_jump=""):
        return {
            "id": name,
            "name": name,
            "host": f"{name.lower()}.test",
            "port": 22,
            "user": "dev",
            "auth_method": "agent",
            "proxy_jump": proxy_jump,
        }

    def test_draft_isolated_and_duplicate_clears_secrets(self):
        draft = ProfileDraft.from_profile(dict(self.profile(), password="secret"))
        draft.set_value("host", "changed.test")
        self.assertNotEqual(draft.values["host"], "work.test")
        duplicate = draft.duplicate()
        self.assertTrue(duplicate.values["id"] != draft.values["id"])
        self.assertEqual(duplicate.password, "")
        self.assertNotIn("password", duplicate.values)

    def test_name_collision_and_tunnel_issue(self):
        draft = ProfileDraft.from_profile(self.profile())
        self.assertTrue(draft.issues([self.profile("Work")], editing_id="Other"))
        draft.values["tunnel_options"] = {
            "rules": [{"type": "SOCKS", "bind_port": 1080}, {"type": "SOCKS", "bind_port": 1080}]
        }
        self.assertTrue(any(issue.tab == "Tunnels" for issue in draft.issues()))

    def test_proxy_self_missing_and_cycle(self):
        profiles = [self.profile("A", "B"), self.profile("B", "A")]
        with self.assertRaises(ProfileError):
            validate_proxy_chain(profiles[0], profiles)
        with self.assertRaises(ProfileError):
            validate_proxy_chain(self.profile("A", "Missing"), [self.profile("A")])
        with self.assertRaises(ProfileError):
            validate_proxy_chain(self.profile("A", "A"), [self.profile("A")])


if __name__ == "__main__":
    unittest.main()
