from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sshvault_core import (
    ProfileError,
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPViewNavigationState,
    SessionController,
    SessionLifecycleState,
    list_local_browser_entries,
    list_remote_browser_entries,
    validate_profile,
)


class _Channel:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error
        self.closed = 0

    def listdir_attr(self, _path: str) -> list[object]:
        if self.error is not None:
            raise self.error
        return []

    def normalize(self, path: str) -> str:
        return "/home/alice" if path == "." else path

    def stat(self, _path: str) -> None:
        return None

    def close(self) -> None:
        self.closed += 1


class SFTPPhaseTwoIntegrationTests(unittest.TestCase):
    def test_two_views_keep_independent_paths_and_histories(self) -> None:
        first = SFTPViewNavigationState(
            local_current_path="/local/one",
            remote_current_path="/remote/one",
        )
        second = SFTPViewNavigationState(
            local_current_path="/local/two",
            remote_current_path="/remote/two",
        )
        first.navigate_new("/local/one/child", False)
        first.navigate_new("/remote/one/child", True)
        self.assertEqual(first.local_back_history, ["/local/one"])
        self.assertEqual(first.remote_back_history, ["/remote/one"])
        self.assertEqual(second.local_current_path, "/local/two")
        self.assertEqual(second.remote_current_path, "/remote/two")
        self.assertEqual(second.local_back_history, [])
        self.assertEqual(second.remote_back_history, [])

    def test_remote_failure_leaves_local_pane_and_session_connected(self) -> None:
        controller = SessionController()
        session = controller.create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        with tempfile.TemporaryDirectory() as root:
            Path(root, "local.txt").write_text("local")
            local_before = list_local_browser_entries(root)
            with self.assertRaisesRegex(ProfileError, "Remote directory not found"):
                list_remote_browser_entries(
                    SFTPBrowserClient(_Channel(FileNotFoundError())),
                    "/missing",
                )
            self.assertEqual(list_local_browser_entries(root), local_before)
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)

    def test_profile_edits_do_not_change_open_view_snapshot(self) -> None:
        profile = validate_profile(
            {
                "id": "phase-two",
                "host": "host.example",
                "user": "alice",
                "sftp_options": {
                    "initial_local_directory": "/local/original",
                    "initial_remote_directory": "/remote/original",
                },
            },
            check_key_exists=False,
        )
        session = SessionController().create_session(profile)
        captured = session.profile_snapshot["sftp_options"]
        view = SFTPViewNavigationState(
            local_current_path=captured["initial_local_directory"],
            remote_current_path=captured["initial_remote_directory"],
        )
        profile["sftp_options"]["initial_local_directory"] = "/local/edited"
        profile["sftp_options"]["initial_remote_directory"] = "/remote/edited"
        self.assertEqual(view.local_current_path, "/local/original")
        self.assertEqual(view.remote_current_path, "/remote/original")
        self.assertEqual(
            session.profile_snapshot["sftp_options"]["initial_remote_directory"],
            "/remote/original",
        )

    def test_closing_one_view_leaves_the_other_working(self) -> None:
        registry = SFTPBrowserRegistry()
        first_channel, second_channel = _Channel(), _Channel()
        registry.register("session", "first", SFTPBrowserClient(first_channel))
        registry.register("session", "second", SFTPBrowserClient(second_channel))
        self.assertTrue(registry.close_view("session", "first"))
        remaining = registry.get("session", "second")
        self.assertIsNotNone(remaining)
        self.assertEqual(remaining.list_directory("/"), [])
        self.assertEqual(first_channel.closed, 1)
        self.assertEqual(second_channel.closed, 0)

    def test_browsing_client_exposes_no_transfer_or_mutation_actions(self) -> None:
        client = SFTPBrowserClient(_Channel())
        for action in (
            "upload",
            "download",
            "put",
            "get",
            "delete",
        ):
            self.assertFalse(hasattr(client, action), action)


if __name__ == "__main__":
    unittest.main()
