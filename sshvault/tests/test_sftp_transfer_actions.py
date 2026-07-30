from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from sshvault_core import (
    RemoteBrowserEntry,
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPTransferRouter,
    SessionController,
    SessionLifecycleState,
    TransferScheduler,
    TransferState,
    selected_file_entries,
)


class _RecordingScheduler:
    def __init__(self) -> None:
        self.items = []
        self.operations = []

    def enqueue(self, item, operation=None):
        self.items.append(item)
        self.operations.append(operation)
        return item


class _BrowserChannel:
    def close(self) -> None:
        return None


class _FailingTransferClient:
    def put(self, _source, _target, callback=None) -> None:
        raise OSError("transfer failed")

    def get(self, _source, _target, callback=None) -> None:
        raise OSError("transfer failed")

    def close(self) -> None:
        return None


def _remote(name: str, *, directory: bool = False) -> RemoteBrowserEntry:
    return RemoteBrowserEntry(
        name=name,
        full_path=f"/remote/{name}",
        is_directory=directory,
        is_symlink=False,
        size=12,
        modified_time=1,
        type_label="Directory" if directory else "File",
        permissions="0o644",
        owner="1000",
    )


class SFTPTransferActionTests(unittest.TestCase):
    def test_upload_routes_multiple_files_to_current_remote_directory(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPTransferRouter(scheduler)
        with tempfile.TemporaryDirectory() as root:
            first, second = Path(root, "one.txt"), Path(root, "two.txt")
            first.write_text("one")
            second.write_text("two")
            queued = router.queue_uploads([str(first), str(second)], "/incoming")
        self.assertEqual(len(queued), 2)
        self.assertEqual([item.source for item in queued], [str(first), str(second)])
        self.assertEqual([item.target for item in queued], ["/incoming/one.txt", "/incoming/two.txt"])
        self.assertTrue(all(item.direction == "Upload" for item in queued))

    def test_download_routes_multiple_files_to_current_local_directory(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPTransferRouter(scheduler)
        with tempfile.TemporaryDirectory() as root:
            queued = router.queue_downloads([_remote("one.txt"), _remote("two.txt")], root)
            self.assertEqual(
                [item.target for item in queued],
                [str(Path(root, "one.txt")), str(Path(root, "two.txt"))],
            )
        self.assertEqual([item.source for item in queued], ["/remote/one.txt", "/remote/two.txt"])
        self.assertTrue(all(item.direction == "Download" for item in queued))

    def test_multiple_selection_excludes_directories(self) -> None:
        entries = [_remote("one.txt"), _remote("folder", directory=True), _remote("two.txt")]
        selected = selected_file_entries(
            entries,
            ["/remote/one.txt", "/remote/folder", "/remote/two.txt"],
        )
        self.assertEqual([entry.name for entry in selected], ["one.txt", "two.txt"])

    def test_action_states_require_selection_connection_and_client(self) -> None:
        self.assertEqual(
            SFTPTransferRouter.action_states(
                local_selected=False,
                remote_selected=False,
                connected=True,
                client_available=True,
            ),
            {"upload": False, "download": False},
        )
        self.assertEqual(
            SFTPTransferRouter.action_states(
                local_selected=True,
                remote_selected=True,
                connected=False,
                client_available=True,
            ),
            {"upload": False, "download": False},
        )
        self.assertEqual(
            SFTPTransferRouter.action_states(
                local_selected=True,
                remote_selected=True,
                connected=True,
                client_available=False,
            ),
            {"upload": False, "download": False},
        )
        self.assertEqual(
            SFTPTransferRouter.action_states(
                local_selected=True,
                remote_selected=True,
                connected=True,
                client_available=True,
            ),
            {"upload": True, "download": True},
        )

    def test_router_reuses_the_supplied_scheduler(self) -> None:
        scheduler = _RecordingScheduler()
        first = SFTPTransferRouter(scheduler)
        second = SFTPTransferRouter(scheduler)
        self.assertIs(first.scheduler, scheduler)
        self.assertIs(second.scheduler, scheduler)

    def test_transfer_failure_does_not_close_view_or_disconnect_session(self) -> None:
        controller = SessionController()
        session = controller.create_session({"host": "host.example", "user": "alice"})
        session.state = SessionLifecycleState.CONNECTED
        browsing_client = SFTPBrowserClient(_BrowserChannel())
        registry = SFTPBrowserRegistry()
        registry.register(session.session_id, "view", browsing_client)
        scheduler = TransferScheduler(lambda: _FailingTransferClient(), monitor_interval=0.05)
        try:
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "upload.txt")
                source.write_text("data")
                item = SFTPTransferRouter(scheduler).queue_uploads([str(source)], "/remote")[0]
                deadline = time.monotonic() + 2
                while item.status not in TransferState.TERMINAL and time.monotonic() < deadline:
                    time.sleep(0.01)
            self.assertEqual(item.status, TransferState.FAILED)
            self.assertIs(registry.get(session.session_id, "view"), browsing_client)
            self.assertTrue(browsing_client.is_alive())
            self.assertIs(session.state, SessionLifecycleState.CONNECTED)
        finally:
            scheduler.shutdown()


if __name__ == "__main__":
    unittest.main()
