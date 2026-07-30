from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sshvault_core import (
    LocalBrowserEntry,
    ProfileError,
    RemoteBrowserEntry,
    SFTPBrowserClient,
    SessionController,
    SessionLifecycleState,
    browser_entry_properties,
    confirmed_sftp_delete_entries,
    delete_local_browser_entries,
    delete_remote_browser_entries,
    list_local_browser_entries,
    list_remote_browser_entries,
    selected_browser_path,
    sftp_file_action_states,
)


class _Attr:
    def __init__(self, name: str, directory: bool = False) -> None:
        self.filename = name
        self.st_mode = 0o040755 if directory else 0o100644
        self.st_size = 10
        self.st_mtime = 20
        self.st_uid = 1000


class _RemoteChannel:
    def __init__(self, root: list[_Attr], children: dict[str, list[_Attr]] | None = None) -> None:
        self.root = list(root)
        self.children = children or {}
        self.removed: list[str] = []
        self.removed_directories: list[str] = []

    def normalize(self, path: str) -> str:
        return "/home/alice" if path == "." else path

    def listdir_attr(self, path: str) -> list[_Attr]:
        return list(self.root if path == "/remote" else self.children.get(path, []))

    def stat(self, _path: str) -> None:
        return None

    def remove(self, path: str) -> None:
        self.removed.append(path)
        self.root = [entry for entry in self.root if f"/remote/{entry.filename}" != path]

    def rmdir(self, path: str) -> None:
        self.removed_directories.append(path)
        self.root = [entry for entry in self.root if f"/remote/{entry.filename}" != path]

    def close(self) -> None:
        return None


def _local_entry(path: Path, *, directory: bool = False) -> LocalBrowserEntry:
    return LocalBrowserEntry(
        path.name,
        str(path),
        directory,
        False,
        0,
        1,
        "Directory" if directory else "File",
        "0o644",
    )


def _remote_entry(name: str, *, directory: bool = False) -> RemoteBrowserEntry:
    return RemoteBrowserEntry(
        name,
        f"/remote/{name}",
        directory,
        False,
        10,
        20,
        "Directory" if directory else "File",
        "0o644",
        "1000",
    )


class SFTPFileActionTests(unittest.TestCase):
    def test_local_file_deletion_and_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "file.txt")
            path.write_text("data")
            self.assertEqual(delete_local_browser_entries([_local_entry(path)]), [str(path)])
            self.assertEqual(list_local_browser_entries(root), [])

    def test_remote_file_deletion_and_refresh(self) -> None:
        channel = _RemoteChannel([_Attr("file.txt")])
        client = SFTPBrowserClient(channel)
        self.assertEqual(
            delete_remote_browser_entries(client, [_remote_entry("file.txt")]),
            ["/remote/file.txt"],
        )
        self.assertEqual(channel.removed, ["/remote/file.txt"])
        self.assertEqual(list_remote_browser_entries(client, "/remote"), [])

    def test_empty_directory_deletion_local_and_remote(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root, "empty")
            directory.mkdir()
            delete_local_browser_entries([_local_entry(directory, directory=True)])
            self.assertFalse(directory.exists())
        channel = _RemoteChannel([_Attr("empty", directory=True)])
        delete_remote_browser_entries(SFTPBrowserClient(channel), [_remote_entry("empty", directory=True)])
        self.assertEqual(channel.removed_directories, ["/remote/empty"])

    def test_non_empty_directory_rejection_preserves_listing_and_session(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root, "full")
            directory.mkdir()
            Path(directory, "child").write_text("data")
            with self.assertRaisesRegex(ProfileError, "empty"):
                delete_local_browser_entries([_local_entry(directory, directory=True)])
            self.assertTrue(directory.exists())
        channel = _RemoteChannel(
            [_Attr("full", directory=True)],
            {"/remote/full": [_Attr("child")]},
        )
        client = SFTPBrowserClient(channel)
        session = SessionController().create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        before = list_remote_browser_entries(client, "/remote")
        with self.assertRaisesRegex(ProfileError, "empty"):
            delete_remote_browser_entries(client, [_remote_entry("full", directory=True)])
        self.assertEqual(list_remote_browser_entries(client, "/remote"), before)
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_confirmation_cancellation_returns_no_delete_plan(self) -> None:
        entries = [_remote_entry("one"), _remote_entry("two")]
        self.assertEqual(confirmed_sftp_delete_entries(entries, False), [])
        self.assertEqual(confirmed_sftp_delete_entries(entries, True), entries)

    def test_multiple_local_and_remote_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            paths = [Path(root, "one"), Path(root, "two")]
            for path in paths:
                path.write_text("data")
            delete_local_browser_entries([_local_entry(path) for path in paths])
            self.assertEqual(list_local_browser_entries(root), [])
        channel = _RemoteChannel([_Attr("one"), _Attr("two")])
        delete_remote_browser_entries(
            SFTPBrowserClient(channel),
            [_remote_entry("one"), _remote_entry("two")],
        )
        self.assertEqual(channel.removed, ["/remote/one", "/remote/two"])

    def test_properties_include_safe_metadata(self) -> None:
        properties = browser_entry_properties(_remote_entry("file.txt"))
        self.assertEqual(
            properties,
            {
                "Name": "file.txt",
                "Full path": "/remote/file.txt",
                "Type": "File",
                "Size": "10",
                "Modified": "20",
                "Permissions": "0o644",
                "Owner": "1000",
            },
        )

    def test_copy_path_requires_exactly_one_selection(self) -> None:
        entries = [_remote_entry("one"), _remote_entry("two")]
        self.assertEqual(selected_browser_path(entries, ["/remote/one"]), "/remote/one")
        self.assertIsNone(selected_browser_path(entries, []))
        self.assertIsNone(selected_browser_path(entries, ["/remote/one", "/remote/two"]))

    def test_disabled_states_follow_selection_loading_and_connection(self) -> None:
        self.assertEqual(
            sftp_file_action_states(
                local_selection_count=0,
                remote_selection_count=0,
                local_loading=False,
                remote_loading=False,
                remote_available=False,
            ),
            {
                "local_delete": False,
                "local_properties": False,
                "local_copy_path": False,
                "remote_delete": False,
                "remote_properties": False,
                "remote_copy_path": False,
            },
        )
        enabled = sftp_file_action_states(
            local_selection_count=2,
            remote_selection_count=2,
            local_loading=False,
            remote_loading=False,
            remote_available=True,
        )
        self.assertTrue(enabled["local_delete"])
        self.assertTrue(enabled["remote_delete"])
        self.assertFalse(enabled["local_properties"])
        self.assertFalse(enabled["remote_copy_path"])

    def test_remote_view_isolation(self) -> None:
        first_channel = _RemoteChannel([_Attr("first")])
        second_channel = _RemoteChannel([_Attr("second")])
        delete_remote_browser_entries(
            SFTPBrowserClient(first_channel),
            [_remote_entry("first")],
        )
        self.assertEqual(first_channel.root, [])
        self.assertEqual([entry.filename for entry in second_channel.root], ["second"])


if __name__ == "__main__":
    unittest.main()
