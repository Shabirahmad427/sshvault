from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sshvault_core import (
    ProfileError,
    SFTPBrowserClient,
    SessionController,
    SessionLifecycleState,
    create_local_browser_folder,
    create_remote_browser_folder,
    list_local_browser_entries,
    list_remote_browser_entries,
    rename_local_browser_entry,
    rename_remote_browser_entry,
    sftp_mutation_action_states,
    validate_sftp_item_name,
)


class _Attr:
    def __init__(self, name: str, directory: bool = False) -> None:
        self.filename = name
        self.st_mode = 0o040755 if directory else 0o100644
        self.st_size = 0
        self.st_mtime = 1
        self.st_uid = 1000


class _RemoteChannel:
    def __init__(self, names: list[str] | None = None, *, fail_mutation: bool = False) -> None:
        self.names = list(names or [])
        self.fail_mutation = fail_mutation
        self.mkdir_calls: list[str] = []
        self.rename_calls: list[tuple[str, str]] = []

    def normalize(self, path: str) -> str:
        return "/home/alice" if path == "." else path

    def listdir_attr(self, _path: str) -> list[_Attr]:
        return [_Attr(name) for name in self.names]

    def stat(self, _path: str) -> None:
        return None

    def mkdir(self, path: str) -> None:
        if self.fail_mutation:
            raise PermissionError
        self.mkdir_calls.append(path)
        self.names.append(Path(path).name)

    def rename(self, old_path: str, new_path: str) -> None:
        if self.fail_mutation:
            raise PermissionError
        self.rename_calls.append((old_path, new_path))
        self.names[self.names.index(Path(old_path).name)] = Path(new_path).name

    def close(self) -> None:
        return None


class SFTPMutationActionTests(unittest.TestCase):
    def test_local_folder_creation_and_refreshed_listing(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            created = create_local_browser_folder(root, "folder")
            self.assertEqual(created, str(Path(root, "folder")))
            self.assertEqual([entry.name for entry in list_local_browser_entries(root)], ["folder"])

    def test_remote_folder_creation_and_refreshed_listing(self) -> None:
        channel = _RemoteChannel()
        client = SFTPBrowserClient(channel)
        created = create_remote_browser_folder(client, "/remote", "folder")
        self.assertEqual(created, "/remote/folder")
        self.assertEqual(channel.mkdir_calls, ["/remote/folder"])
        self.assertEqual([entry.name for entry in list_remote_browser_entries(client, "/remote")], ["folder"])

    def test_local_rename_preserves_parent_and_refreshes_listing(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "before.txt")
            source.write_text("data")
            renamed = rename_local_browser_entry(str(source), "after.txt")
            self.assertEqual(renamed, str(Path(root, "after.txt")))
            self.assertEqual([entry.name for entry in list_local_browser_entries(root)], ["after.txt"])

    def test_remote_rename_preserves_parent_and_refreshes_listing(self) -> None:
        channel = _RemoteChannel(["before.txt"])
        client = SFTPBrowserClient(channel)
        renamed = rename_remote_browser_entry(client, "/remote/before.txt", "after.txt")
        self.assertEqual(renamed, "/remote/after.txt")
        self.assertEqual(channel.rename_calls, [("/remote/before.txt", "/remote/after.txt")])
        self.assertEqual([entry.name for entry in list_remote_browser_entries(client, "/remote")], ["after.txt"])

    def test_names_reject_empty_and_path_separators(self) -> None:
        for invalid in ("", "   ", ".", "..", "one/two", r"one\two"):
            with self.subTest(invalid=invalid), self.assertRaises(ProfileError):
                validate_sftp_item_name(invalid)
        self.assertEqual(validate_sftp_item_name(" folder "), "folder")

    def test_disabled_states_follow_selection_loading_and_connection(self) -> None:
        self.assertEqual(
            sftp_mutation_action_states(
                local_selection_count=0,
                remote_selection_count=0,
                local_loading=True,
                remote_loading=True,
                remote_available=False,
            ),
            {
                "local_new_folder": False,
                "local_rename": False,
                "remote_new_folder": False,
                "remote_rename": False,
            },
        )
        self.assertEqual(
            sftp_mutation_action_states(
                local_selection_count=1,
                remote_selection_count=1,
                local_loading=False,
                remote_loading=False,
                remote_available=True,
            ),
            {
                "local_new_folder": True,
                "local_rename": True,
                "remote_new_folder": True,
                "remote_rename": True,
            },
        )
        self.assertFalse(
            sftp_mutation_action_states(
                local_selection_count=2,
                remote_selection_count=2,
                local_loading=False,
                remote_loading=False,
                remote_available=True,
            )["remote_rename"]
        )

    def test_failed_remote_operation_preserves_listing(self) -> None:
        session = SessionController().create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        channel = _RemoteChannel(["kept.txt"], fail_mutation=True)
        client = SFTPBrowserClient(channel)
        before = list_remote_browser_entries(client, "/remote")
        with self.assertRaises(PermissionError):
            rename_remote_browser_entry(client, "/remote/kept.txt", "changed.txt")
        self.assertEqual(list_remote_browser_entries(client, "/remote"), before)
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_mutating_one_view_does_not_affect_another(self) -> None:
        first_channel = _RemoteChannel(["first.txt"])
        second_channel = _RemoteChannel(["second.txt"])
        first = SFTPBrowserClient(first_channel)
        second = SFTPBrowserClient(second_channel)
        rename_remote_browser_entry(first, "/remote/first.txt", "changed.txt")
        self.assertEqual([entry.name for entry in list_remote_browser_entries(first, "/remote")], ["changed.txt"])
        self.assertEqual([entry.name for entry in list_remote_browser_entries(second, "/remote")], ["second.txt"])


if __name__ == "__main__":
    unittest.main()
