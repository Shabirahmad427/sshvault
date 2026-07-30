from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from sshvault_core import (
    LocalBrowserEntry,
    RemoteBrowserEntry,
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPDragDropRouter,
    SFTPTransferRouter,
    TransferItem,
    TransferScheduler,
    TransferState,
    browser_entry_properties,
    create_local_browser_folder,
    delete_local_browser_entries,
    rename_local_browser_entry,
    selected_browser_path,
    sftp_transfer_control_states,
    sftp_transfer_queue_rows,
)


class _RecordingScheduler:
    def __init__(self) -> None:
        self.items = []

    def enqueue(self, item, operation=None):
        self.items.append(item)
        return item


class _BrowserChannel:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1


def _local(path: Path, *, directory: bool = False) -> LocalBrowserEntry:
    return LocalBrowserEntry(
        name=path.name,
        full_path=str(path),
        is_directory=directory,
        is_symlink=False,
        size=0,
        modified_time=1,
        type_label="Directory" if directory else "File",
        permissions="0o644",
    )


def _remote(name: str) -> RemoteBrowserEntry:
    return RemoteBrowserEntry(
        name=name,
        full_path=f"/remote/{name}",
        is_directory=False,
        is_symlink=False,
        size=4,
        modified_time=2,
        type_label="File",
        permissions="0o640",
        owner="alice",
    )


class SFTPPhaseThreeIntegrationTests(unittest.TestCase):
    def test_upload_and_download_share_the_existing_scheduler(self) -> None:
        scheduler = _RecordingScheduler()
        router = SFTPTransferRouter(scheduler)
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "upload.txt")
            source.write_text("data")
            upload = router.queue_uploads([str(source)], "/incoming")
            download = router.queue_downloads([_remote("download.txt")], root)
        self.assertIs(router.scheduler, scheduler)
        self.assertEqual(scheduler.items, upload + download)
        self.assertEqual([item.direction for item in scheduler.items], ["Upload", "Download"])

    def test_mutation_properties_and_copy_path_actions_work_together(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            created = Path(create_local_browser_folder(root, "new-folder"))
            renamed = Path(rename_local_browser_entry(str(created), "renamed-folder"))
            entry = _local(renamed, directory=True)
            properties = browser_entry_properties(entry)
            copied_path = selected_browser_path([entry], [entry.full_path])
            deleted = delete_local_browser_entries([entry])
        self.assertEqual(properties["Name"], "renamed-folder")
        self.assertEqual(properties["Full path"], str(renamed))
        self.assertEqual(copied_path, str(renamed))
        self.assertEqual(deleted, [str(renamed)])
        self.assertFalse(renamed.exists())

    def test_transfer_queue_controls_and_display_work_together(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            active = scheduler.enqueue(TransferItem("one", "target", "Upload", total=10))
            self.assertTrue(sftp_transfer_control_states(active, scheduler.items)["pause"])
            self.assertTrue(scheduler.pause(active.item_id))
            self.assertTrue(sftp_transfer_control_states(active, scheduler.items)["resume"])
            self.assertTrue(scheduler.resume(active.item_id))
            self.assertTrue(scheduler.cancel(active.item_id))
            self.assertTrue(sftp_transfer_control_states(active, scheduler.items)["retry"])
            self.assertTrue(scheduler.retry(active.item_id))
            active.transferred = 5
            active.speed = 5
            row = sftp_transfer_queue_rows([active])[0]
            self.assertEqual((row.progress, row.speed, row.eta), ("50.0%", "5 B/s", "1s"))
            active.status = TransferState.COMPLETED
            self.assertTrue(sftp_transfer_control_states(active, scheduler.items)["remove_completed"])
            scheduler.clear_completed()
            self.assertEqual(scheduler.items, [])
        finally:
            scheduler.shutdown()

    def test_closing_one_view_does_not_cancel_transfer_or_other_view(self) -> None:
        registry = SFTPBrowserRegistry()
        first_channel, second_channel = _BrowserChannel(), _BrowserChannel()
        registry.register("session", "first", SFTPBrowserClient(first_channel))
        registry.register("session", "second", SFTPBrowserClient(second_channel))
        scheduler = TransferScheduler(None)
        try:
            transfer = scheduler.enqueue(TransferItem("source", "target", "Upload", total=10))
            self.assertTrue(registry.close_view("session", "first"))
            self.assertNotIn(transfer.status, TransferState.TERMINAL)
            self.assertFalse(scheduler.closed)
            self.assertIsNotNone(registry.get("session", "second"))
            self.assertEqual(first_channel.closed, 1)
            self.assertEqual(second_channel.closed, 0)
        finally:
            scheduler.shutdown()

    def test_unsupported_drag_drop_leaves_manual_buttons_working(self) -> None:
        scheduler = _RecordingScheduler()
        transfer_router = SFTPTransferRouter(scheduler)
        drag_router = SFTPDragDropRouter(transfer_router)
        # An unsupported native DnD environment never invokes the drag router;
        # the explicit button state and routes remain independent and usable.
        self.assertEqual(
            drag_router.route_drop(
                source_pane="local",
                target_pane="local",
                connected=True,
                client_available=True,
            ),
            [],
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
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "manual-upload")
            source.write_text("data")
            uploads = transfer_router.queue_uploads([str(source)], "/remote")
            downloads = transfer_router.queue_downloads([_remote("manual-download")], root)
        self.assertEqual(len(uploads), 1)
        self.assertEqual(len(downloads), 1)
        self.assertIs(drag_router.scheduler, scheduler)


if __name__ == "__main__":
    unittest.main()
