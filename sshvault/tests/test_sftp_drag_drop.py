from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sshvault_core import (
    RemoteBrowserEntry,
    SFTPDragDropRouter,
    SFTPTransferRouter,
)


class _RecordingScheduler:
    def __init__(self) -> None:
        self.items = []

    def enqueue(self, item, operation=None):
        self.items.append(item)
        return item


def _remote(name: str) -> RemoteBrowserEntry:
    return RemoteBrowserEntry(
        name=name,
        full_path=f"/remote/source/{name}",
        is_directory=False,
        is_symlink=False,
        size=12,
        modified_time=1,
        type_label="File",
        permissions="0o644",
        owner="1000",
    )


class SFTPDragDropTests(unittest.TestCase):
    def test_local_to_remote_drop_routes_upload(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPDragDropRouter(SFTPTransferRouter(scheduler))
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "local.txt")
            source.write_text("data")
            queued = router.route_drop(
                source_pane="local",
                target_pane="remote",
                connected=True,
                client_available=True,
                local_paths=[str(source)],
                remote_directory="/remote/target",
            )
        self.assertEqual(len(queued), 1)
        self.assertEqual(queued[0].source, str(source))
        self.assertEqual(queued[0].target, "/remote/target/local.txt")
        self.assertEqual(queued[0].direction, "Upload")

    def test_remote_to_local_drop_routes_download(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPDragDropRouter(SFTPTransferRouter(scheduler))
        with tempfile.TemporaryDirectory() as root:
            queued = router.route_drop(
                source_pane="remote",
                target_pane="local",
                connected=True,
                client_available=True,
                remote_entries=[_remote("remote.txt")],
                local_directory=root,
            )
            self.assertEqual(queued[0].target, str(Path(root, "remote.txt")))
        self.assertEqual(queued[0].source, "/remote/source/remote.txt")
        self.assertEqual(queued[0].direction, "Download")

    def test_multiple_selected_files_are_queued(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPDragDropRouter(SFTPTransferRouter(scheduler))
        with tempfile.TemporaryDirectory() as root:
            local_paths = [Path(root, "one"), Path(root, "two")]
            for path in local_paths:
                path.write_text(path.name)
            uploads = router.route_drop(
                source_pane="local",
                target_pane="remote",
                connected=True,
                client_available=True,
                local_paths=[str(path) for path in local_paths],
                remote_directory="/target",
            )
            downloads = router.route_drop(
                source_pane="remote",
                target_pane="local",
                connected=True,
                client_available=True,
                remote_entries=[_remote("three"), _remote("four")],
                local_directory=root,
            )
        self.assertEqual(len(uploads), 2)
        self.assertEqual(len(downloads), 2)

    def test_disconnected_or_unavailable_drop_is_ignored(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPDragDropRouter(SFTPTransferRouter(scheduler))
        self.assertEqual(
            router.route_drop(
                source_pane="remote",
                target_pane="local",
                connected=False,
                client_available=True,
                remote_entries=[_remote("one")],
                local_directory="/local",
            ),
            [],
        )
        self.assertEqual(
            router.route_drop(
                source_pane="remote",
                target_pane="local",
                connected=True,
                client_available=False,
                remote_entries=[_remote("two")],
                local_directory="/local",
            ),
            [],
        )
        self.assertEqual(scheduler.items, [])

    def test_same_pane_drop_is_ignored(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPDragDropRouter(SFTPTransferRouter(scheduler))
        for pane in ("local", "remote"):
            self.assertEqual(
                router.route_drop(
                    source_pane=pane,
                    target_pane=pane,
                    connected=True,
                    client_available=True,
                    remote_entries=[_remote("one")],
                    local_directory="/local",
                    remote_directory="/remote",
                ),
                [],
            )
        self.assertEqual(scheduler.items, [])

    def test_existing_scheduler_is_reused(self) -> None:
        scheduler = _RecordingScheduler()
        transfer_router = SFTPTransferRouter(scheduler)
        drag_router = SFTPDragDropRouter(transfer_router)
        self.assertIs(drag_router.transfer_router, transfer_router)
        self.assertIs(drag_router.scheduler, scheduler)


if __name__ == "__main__":
    unittest.main()
