from __future__ import annotations

import unittest

from sshvault_core import (
    RemoteBrowserEntry,
    SFTPViewNavigationState,
    normalize_remote_path,
    selected_directory_target,
    sort_browser_entries,
    update_browser_sort,
)


def _entry(
    name: str,
    *,
    directory: bool = False,
    size: int = 0,
    modified: float = 0,
    kind: str = "File",
    permissions: str = "0o644",
    owner: str = "1000",
) -> RemoteBrowserEntry:
    return RemoteBrowserEntry(
        name=name,
        full_path=f"/root/{name}",
        is_directory=directory,
        is_symlink=False,
        size=size,
        modified_time=modified,
        type_label="Directory" if directory else kind,
        permissions=permissions,
        owner=owner,
    )


def _successful_result(
    state: SFTPViewNavigationState,
    target: str,
    action: str,
) -> None:
    generation = state.begin_remote_listing()
    accepted = state.complete_remote_listing(
        generation,
        target,
        update_path=False,
    )
    if not accepted:
        return
    if action == "back":
        state.navigate_back(True)
    elif action == "forward":
        state.navigate_forward(True)
    elif action == "new":
        state.navigate_new(target, True)


class RemoteNavigationTests(unittest.TestCase):
    def test_back_forward_up_home_and_refresh(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/home/alice/one")
        _successful_result(state, "/home/alice/two", "new")
        _successful_result(state, state.remote_back_history[-1], "back")
        self.assertEqual(state.remote_current_path, "/home/alice/one")
        _successful_result(state, state.remote_forward_history[-1], "forward")
        self.assertEqual(state.remote_current_path, "/home/alice/two")
        parent = normalize_remote_path("..", state.remote_current_path)
        _successful_result(state, parent, "new")
        self.assertEqual(state.remote_current_path, "/home/alice")
        _successful_result(state, "/tmp", "new")
        _successful_result(state, "/home/alice", "new")
        self.assertEqual(state.remote_current_path, "/home/alice")
        history = (list(state.remote_back_history), list(state.remote_forward_history))
        self.assertEqual(state.refresh(True), "/home/alice")
        self.assertEqual(history, (state.remote_back_history, state.remote_forward_history))

    def test_path_entry_navigation_uses_posix_normalization(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/home/alice")
        target = normalize_remote_path("../shared/./data", state.remote_current_path)
        _successful_result(state, target, "new")
        self.assertEqual(state.remote_current_path, "/home/shared/data")
        self.assertEqual(state.remote_back_history, ["/home/alice"])

    def test_directory_activation_is_shared_by_double_click_and_enter(self) -> None:
        entries = [_entry("folder", directory=True), _entry("file")]
        for _activation in ("double-click", "enter"):
            self.assertEqual(
                selected_directory_target(entries, ["/root/folder"]),
                "/root/folder",
            )
        self.assertIsNone(selected_directory_target(entries, ["/root/file"]))
        self.assertIsNone(selected_directory_target(entries, ["/root/folder", "/root/file"]))

    def test_failed_navigation_preserves_path_listing_and_history(self) -> None:
        state = SFTPViewNavigationState(
            remote_current_path="/good",
            remote_back_history=["/older"],
            remote_forward_history=["/newer"],
        )
        displayed = [_entry("kept")]
        before = (
            state.remote_current_path,
            list(state.remote_back_history),
            list(state.remote_forward_history),
            list(displayed),
        )
        generation = state.begin_remote_listing()
        self.assertFalse(
            state.complete_remote_listing(
                generation,
                "/bad",
                error="Remote directory not found",
                update_path=False,
            )
        )
        self.assertEqual(
            before,
            (
                state.remote_current_path,
                state.remote_back_history,
                state.remote_forward_history,
                displayed,
            ),
        )

    def test_heading_sort_toggle_and_directories_first(self) -> None:
        entries = [
            _entry("z", size=20, modified=2, owner="bob"),
            _entry("a", size=10, modified=1, permissions="0o600", owner="alice"),
            _entry("folder", directory=True),
        ]
        state = SFTPViewNavigationState()
        for column in ("name", "size", "modified", "type", "permissions", "owner"):
            update_browser_sort(state, column, remote=True)
            first_direction = state.remote_sort_descending
            self.assertTrue(sort_browser_entries(entries, column, first_direction)[0].is_directory)
            update_browser_sort(state, column, remote=True)
            self.assertNotEqual(state.remote_sort_descending, first_direction)
            self.assertTrue(sort_browser_entries(entries, column, state.remote_sort_descending)[0].is_directory)

    def test_two_views_have_independent_remote_histories(self) -> None:
        first = SFTPViewNavigationState(remote_current_path="/first")
        second = SFTPViewNavigationState(remote_current_path="/second")
        _successful_result(first, "/first/child", "new")
        self.assertEqual(first.remote_back_history, ["/first"])
        self.assertEqual(second.remote_back_history, [])
        self.assertEqual(second.remote_current_path, "/second")


if __name__ == "__main__":
    unittest.main()
