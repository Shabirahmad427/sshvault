from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sshvault_core import (
    LocalBrowserEntry,
    ProfileError,
    SFTPViewNavigationState,
    initial_local_browser_path,
    list_local_browser_entries,
    normalize_local_path,
    sort_browser_entries,
    update_browser_sort,
)


class LocalPaneTests(unittest.TestCase):
    def test_configured_initial_path_and_invalid_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            configured = Path(root, "configured")
            configured.mkdir()
            self.assertEqual(initial_local_browser_path(str(configured), root), str(configured))
            self.assertEqual(initial_local_browser_path(str(Path(root, "missing")), root), root)

    def test_back_forward_up_home_and_refresh(self) -> None:
        state = SFTPViewNavigationState(local_current_path="/one/two")
        self.assertTrue(state.navigate_new("/three", False))
        self.assertTrue(state.navigate_back(False))
        self.assertEqual(state.local_current_path, "/one/two")
        self.assertTrue(state.navigate_forward(False))
        self.assertEqual(state.local_current_path, "/three")
        self.assertTrue(state.navigate_up(False))
        self.assertEqual(state.local_current_path, "/")
        self.assertTrue(state.navigate_home("/home/test", False))
        history = (list(state.local_back_history), list(state.local_forward_history))
        self.assertEqual(state.refresh(False), "/home/test")
        self.assertEqual(history, (state.local_back_history, state.local_forward_history))

    def test_path_entry_normalization_and_navigation(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            target = Path(root, "target")
            target.mkdir()
            entered = normalize_local_path(f"{root}/target/../target")
            self.assertEqual([entry.name for entry in list_local_browser_entries(entered)], [])
            state = SFTPViewNavigationState(local_current_path=root)
            self.assertTrue(state.navigate_new(entered, False))
            self.assertEqual(state.local_current_path, str(target))

    def test_invalid_path_preserves_current_path_history_and_listing(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            Path(root, "visible").write_text("x")
            before = list_local_browser_entries(root)
            state = SFTPViewNavigationState(local_current_path=root)
            history = (list(state.local_back_history), list(state.local_forward_history))
            with self.assertRaisesRegex(ProfileError, "Local directory not found"):
                list_local_browser_entries(str(Path(root, "missing")))
            self.assertEqual(state.local_current_path, root)
            self.assertEqual(history, (state.local_back_history, state.local_forward_history))
            self.assertEqual(before, list_local_browser_entries(root))

    def test_hidden_file_filtering(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            Path(root, ".hidden").write_text("x")
            Path(root, "visible").write_text("x")
            self.assertEqual([entry.name for entry in list_local_browser_entries(root)], ["visible"])
            self.assertEqual(
                [entry.name for entry in list_local_browser_entries(root, show_hidden=True)],
                [".hidden", "visible"],
            )

    def test_heading_sort_toggle_and_supported_columns(self) -> None:
        entries = [
            LocalBrowserEntry("b", "/b", False, False, 20, 2, "File", "0o644"),
            LocalBrowserEntry("a", "/a", False, False, 10, 1, "File", "0o600"),
            LocalBrowserEntry("dir", "/dir", True, False, 0, 0, "Directory", "0o755"),
        ]
        state = SFTPViewNavigationState()
        update_browser_sort(state, "name")
        self.assertTrue(state.local_sort_descending)
        self.assertEqual([item.name for item in sort_browser_entries(entries, "name", True)], ["dir", "b", "a"])
        for column in ("size", "modified", "type", "permissions"):
            update_browser_sort(state, column)
            self.assertEqual(state.local_sort_column, column)
            self.assertFalse(state.local_sort_descending)
            self.assertTrue(sort_browser_entries(entries, column, False)[0].is_directory)


if __name__ == "__main__":
    unittest.main()
