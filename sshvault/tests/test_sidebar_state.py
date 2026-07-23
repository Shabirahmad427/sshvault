"""Display-free profile sidebar state tests."""

from __future__ import annotations

import unittest

from sshvault_core import ProfileSidebarState, application_shortcut_allowed


def profile(identifier: str, name: str, host: str, user: str, **changes: object) -> dict[str, object]:
    data: dict[str, object] = {
        "id": identifier,
        "name": name,
        "host": host,
        "user": user,
        "port": 22,
        "auth_method": "agent",
        "tags": [],
        "notes": "",
    }
    data.update(changes)
    return data


class ProfileSidebarStateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.profiles = [
            profile("1", "Zulu", "zulu.example", "ops", tags=["production"], notes="primary database"),
            profile("2", "Alpha", "alpha.example", "dev", tags=["staging"], notes="nightly jobs"),
            profile("3", "Bravo", "bravo.example", "admin", tags=["archive"], notes="legacy host"),
        ]

    def test_searches_all_supported_fields_case_insensitively(self) -> None:
        for query, expected in (
            ("zulu", ["1"]),
            ("ALPHA.EXAMPLE", ["2"]),
            ("OPS", ["1"]),
            ("production", ["1"]),
            ("nightly", ["2"]),
        ):
            state = ProfileSidebarState(self.profiles, query=query)
            self.assertEqual([item["id"] for item in state.visible_profiles()], expected)

    def test_clear_search_empty_result_and_stored_order(self) -> None:
        state = ProfileSidebarState(self.profiles, query="missing")
        self.assertEqual(state.visible_profiles(), [])
        self.assertEqual(state.empty_state(), "No profiles match your search.")
        state.query = ""
        self.assertEqual(len(state.visible_profiles()), 3)
        self.assertEqual([item["id"] for item in self.profiles], ["1", "2", "3"])

    def test_sorting_does_not_mutate_storage(self) -> None:
        expected = {"Name": ["2", "3", "1"], "Hostname": ["2", "3", "1"], "Username": ["3", "2", "1"]}
        for kind, identifiers in expected.items():
            state = ProfileSidebarState(self.profiles, sort_by=kind)
            self.assertEqual([item["id"] for item in state.visible_profiles()], identifiers)
        self.assertEqual([item["id"] for item in self.profiles], ["1", "2", "3"])

    def test_selected_profile_and_actions_survive_filter_when_visible(self) -> None:
        state = ProfileSidebarState(self.profiles, selected_id="2")
        self.assertEqual(
            state.action_enabled(), {"connect": True, "edit": True, "duplicate": True, "delete": True, "export": True}
        )
        state.query = "alpha"
        self.assertEqual(state.selected_profile()["id"], "2")
        state.query = "zulu"
        self.assertEqual(state.selected_profile()["id"], "2")
        state.selected_id = None
        self.assertFalse(any(state.action_enabled().values()))

    def test_selected_profile_can_differ_from_connected_profile(self) -> None:
        state = ProfileSidebarState(self.profiles, selected_id="2")
        self.assertTrue(state.selected_differs_from(self.profiles[0]))
        self.assertFalse(state.selected_differs_from(self.profiles[1]))

    def test_duplicate_name_is_unique(self) -> None:
        state = ProfileSidebarState(self.profiles)
        self.assertEqual(state.duplicate_name(self.profiles[0]), "Zulu Copy")
        state.profiles.append(profile("4", "Zulu Copy", "other.example", "root"))
        self.assertEqual(state.duplicate_name(self.profiles[0]), "Zulu Copy 2")

    def test_duplicate_copy_excludes_secrets(self) -> None:
        source = dict(self.profiles[0], password="password", passphrase="passphrase")
        duplicate = {key: value for key, value in source.items() if key not in {"id", "password", "passphrase"}}
        self.assertNotIn("password", duplicate)
        self.assertNotIn("passphrase", duplicate)
        self.assertNotIn("id", duplicate)

    def test_empty_state_and_shortcut_suppression(self) -> None:
        self.assertEqual(ProfileSidebarState([]).empty_state(), "No saved profiles yet. Add a profile to begin.")
        for widget in ("Entry", "Text", "TEntry", "TCombobox", "TerminalWidget"):
            self.assertFalse(application_shortcut_allowed(widget))
        self.assertTrue(application_shortcut_allowed("Treeview"))
