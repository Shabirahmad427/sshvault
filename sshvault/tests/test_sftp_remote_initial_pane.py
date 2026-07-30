from __future__ import annotations

import threading
import unittest

from sshvault_core import (
    ProfileError,
    SFTPBrowserClient,
    SFTPViewNavigationState,
    SessionController,
    SessionLifecycleState,
    list_remote_browser_entries,
)


class _Attr:
    def __init__(self, name: str, mode: int = 0o100644) -> None:
        self.filename = name
        self.st_mode = mode
        self.st_size = 12
        self.st_mtime = 20
        self.st_uid = 1000


class _Channel:
    def __init__(self, entries: list[_Attr] | None = None, error: BaseException | None = None) -> None:
        self.entries = entries or []
        self.error = error
        self.paths: list[str] = []

    def normalize(self, path: str) -> str:
        return "/home/alice" if path == "." else path

    def listdir_attr(self, path: str) -> list[_Attr]:
        self.paths.append(path)
        if self.error is not None:
            raise self.error
        return self.entries

    def stat(self, _path: str) -> None:
        return None

    def close(self) -> None:
        return None


class RemoteInitialPaneTests(unittest.TestCase):
    def test_empty_path_resolves_to_remote_home(self) -> None:
        channel = _Channel([_Attr("file")])
        entries = list_remote_browser_entries(SFTPBrowserClient(channel), "")
        self.assertEqual(channel.paths, ["/home/alice"])
        self.assertEqual([entry.name for entry in entries], ["file"])

    def test_configured_remote_path_is_loaded(self) -> None:
        channel = _Channel([_Attr("project", 0o040755)])
        entries = list_remote_browser_entries(SFTPBrowserClient(channel), "/srv/project")
        self.assertEqual(channel.paths, ["/srv/project"])
        self.assertTrue(entries[0].is_directory)

    def test_successful_listing_can_complete_from_worker_result(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/old")
        generation = state.begin_remote_listing()
        result: list[str] = []

        def worker() -> None:
            entries = list_remote_browser_entries(SFTPBrowserClient(_Channel([_Attr("file")])), "/new")
            result.extend(entry.name for entry in entries)

        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        self.assertTrue(state.complete_remote_listing(generation, "/new"))
        self.assertEqual(result, ["file"])
        self.assertEqual(state.remote_current_path, "/new")
        self.assertFalse(state.remote_loading)

    def test_hidden_entries_follow_captured_setting(self) -> None:
        channel = _Channel([_Attr(".hidden"), _Attr("visible")])
        client = SFTPBrowserClient(channel)
        self.assertEqual([entry.name for entry in list_remote_browser_entries(client, "/")], ["visible"])
        self.assertEqual(
            [entry.name for entry in list_remote_browser_entries(client, "/", show_hidden=True)],
            [".hidden", "visible"],
        )

    def test_stale_result_is_ignored(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/old")
        stale = state.begin_remote_listing()
        current = state.begin_remote_listing()
        self.assertFalse(state.complete_remote_listing(stale, "/stale"))
        self.assertEqual(state.remote_current_path, "/old")
        self.assertTrue(state.complete_remote_listing(current, "/current"))

    def test_closed_view_result_is_ignored(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/old")
        generation = state.begin_remote_listing()
        self.assertFalse(state.complete_remote_listing(generation, "/closed", view_open=False))
        self.assertEqual(state.remote_current_path, "/old")

    def test_failure_preserves_previous_listing_context(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/good")
        displayed = ["kept"]
        generation = state.begin_remote_listing()
        with self.assertRaisesRegex(ProfileError, "Remote directory not found"):
            list_remote_browser_entries(
                SFTPBrowserClient(_Channel(error=FileNotFoundError())),
                "/missing",
            )
        self.assertFalse(
            state.complete_remote_listing(
                generation,
                "/missing",
                error="Remote directory not found",
            )
        )
        self.assertEqual(state.remote_current_path, "/good")
        self.assertEqual(displayed, ["kept"])
        self.assertEqual(state.last_remote_error, "Remote directory not found")

    def test_listing_failure_does_not_disconnect_session(self) -> None:
        profile = {
            "name": "Test",
            "host": "host.example",
            "port": 22,
            "user": "alice",
            "auth_method": "agent",
        }
        session = SessionController().create_session(profile)
        session.state = SessionLifecycleState.CONNECTED
        state = SFTPViewNavigationState(remote_current_path="/good")
        generation = state.begin_remote_listing()
        state.complete_remote_listing(
            generation,
            "/bad",
            error="Directory listing failed",
        )
        self.assertIs(session.state, SessionLifecycleState.CONNECTED)


if __name__ == "__main__":
    unittest.main()
