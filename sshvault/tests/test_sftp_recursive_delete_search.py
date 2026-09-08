from pathlib import Path
from types import SimpleNamespace
import os
import tempfile
import unittest

from sshvault_core import (
    ProfileError,
    SFTPBrowserClient,
    delete_remote_browser_entries,
    delete_remote_browser_path,
    filter_browser_entries,
)


class FilesystemChannel:
    def lstat(self, path):
        return os.lstat(path)

    def listdir_attr(self, path):
        return [SimpleNamespace(filename=name) for name in os.listdir(path)]

    def remove(self, path):
        os.unlink(path)

    def rmdir(self, path):
        os.rmdir(path)


class RemoteDeleteSearchTests(unittest.TestCase):
    def test_recursive_delete_includes_hidden_files_but_does_not_follow_links(self):
        with tempfile.TemporaryDirectory() as root:
            root = Path(root)
            outside = root / "keep"
            outside.mkdir()
            (outside / "file").write_text("keep")
            folder = root / "delete"
            (folder / "nested").mkdir(parents=True)
            (folder / "nested" / "list.sh").write_text("echo hi")
            (folder / ".hidden").write_text("hidden")
            (folder / "link").symlink_to(outside, target_is_directory=True)
            (folder / "broken").symlink_to(root / "missing")
            entries = [SimpleNamespace(full_path=str(folder))]
            self.assertEqual(
                delete_remote_browser_entries(SFTPBrowserClient(FilesystemChannel()), entries, recursive=True),
                [str(folder)],
            )
            self.assertFalse(folder.exists())
            self.assertEqual((outside / "file").read_text(), "keep")

    def test_regular_file_delete(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "list.sh")
            path.touch()
            delete_remote_browser_path(SFTPBrowserClient(FilesystemChannel()), str(path))
            self.assertFalse(path.exists())

    def test_permission_failure_is_reported(self):
        class Denied(FilesystemChannel):
            def remove(self, path):
                raise PermissionError("Permission denied: " + path)

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "file")
            path.touch()
            with self.assertRaisesRegex(PermissionError, "Permission denied"):
                delete_remote_browser_path(SFTPBrowserClient(Denied()), str(path))
            self.assertTrue(path.exists())

    def test_root_and_invalid_child_names_are_rejected(self):
        client = SFTPBrowserClient(FilesystemChannel())
        with self.assertRaises(ProfileError):
            delete_remote_browser_path(client, "/")

        class Invalid(FilesystemChannel):
            def listdir_attr(self, path):
                return [SimpleNamespace(filename="../keep")]

        with tempfile.TemporaryDirectory() as root:
            with self.assertRaises(ProfileError):
                delete_remote_browser_path(SFTPBrowserClient(Invalid()), root)
            self.assertTrue(Path(root).exists())

    def test_filename_search_is_literal_case_insensitive_and_reversible(self):
        entries = [SimpleNamespace(name=name) for name in ("list.sh", "LIST.txt", "folder", "[a].txt")]
        self.assertEqual(filter_browser_entries(entries, "LiSt"), entries[:2])
        self.assertEqual(filter_browser_entries(entries, "["), entries[3:])
        self.assertEqual(filter_browser_entries(entries, "absent"), [])
        self.assertEqual(filter_browser_entries(entries, ""), entries)
        self.assertEqual(len(entries), 4)
