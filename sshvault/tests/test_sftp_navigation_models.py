import tempfile
import unittest
from pathlib import Path

from sshvault_core import (
    SFTPBrowserClient,
    SFTPViewNavigationState,
    list_local_browser_entries,
    list_remote_browser_entries,
    sort_browser_entries,
)


class _Attr:
    def __init__(self, name, mode=0o100644, size=1, owner=1000):
        self.filename, self.st_mode, self.st_size, self.st_mtime, self.st_uid = name, mode, size, 1, owner


class _Remote:
    def __init__(self, items=None, error=None):
        self.items, self.error = items or [], error

    def listdir_attr(self, path):
        if self.error:
            raise self.error
        return self.items

    def normalize(self, path):
        return "/home/alice" if path == "." else path

    def stat(self, path):
        return None

    def close(self):
        pass


class NavigationModelTests(unittest.TestCase):
    def test_local_listing_filters_hidden_and_directories_first(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "dir").mkdir()
            Path(root, "file").write_text("x")
            Path(root, ".hidden").write_text("x")
            entries = list_local_browser_entries(root)
            self.assertEqual([entry.name for entry in entries], ["dir", "file"])

    def test_generations_are_per_view(self):
        first, second = SFTPViewNavigationState(), SFTPViewNavigationState()
        generation = first.next_generation(True)
        self.assertTrue(first.generation_current(generation, True))
        self.assertFalse(second.generation_current(generation, True))

    def test_history_back_forward_and_refresh(self):
        state = SFTPViewNavigationState(local_current_path="/a")
        state.navigate_new("/b", False)
        state.navigate_new("/c", False)
        self.assertTrue(state.navigate_back(False))
        self.assertEqual(state.local_current_path, "/b")
        self.assertTrue(state.navigate_forward(False))
        self.assertEqual(state.refresh(False), "/c")

    def test_remote_listing_filters_and_orders(self):
        client = SFTPBrowserClient(_Remote([_Attr("file"), _Attr("dir", 0o040755), _Attr(".hidden")]))
        entries = list_remote_browser_entries(client, "")
        self.assertEqual([item.name for item in entries], ["dir", "file"])
        self.assertEqual(entries[0].permissions, "0o755")

    def test_remote_error_mapping(self):
        with self.assertRaisesRegex(Exception, "Remote directory not found"):
            list_remote_browser_entries(SFTPBrowserClient(_Remote(error=FileNotFoundError())), "/missing")
        with self.assertRaisesRegex(Exception, "Remote permission denied"):
            list_remote_browser_entries(SFTPBrowserClient(_Remote(error=PermissionError())), "/private")
        with self.assertRaisesRegex(Exception, "Directory listing failed"):
            list_remote_browser_entries(SFTPBrowserClient(_Remote(error=RuntimeError())), "/down")

    def test_sorting_keeps_directories_first(self):
        client = SFTPBrowserClient(_Remote([_Attr("z", 0o100644, 9), _Attr("a", 0o040755, 1)]))
        entries = list_remote_browser_entries(client, "/")
        self.assertEqual([entry.name for entry in entries], ["a", "z"])
        for column in ("name", "size", "modified", "type", "permissions", "owner"):
            self.assertTrue(sort_browser_entries(entries, column, True)[0].is_directory)


if __name__ == "__main__":
    unittest.main()
