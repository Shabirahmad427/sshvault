from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from sshvault_core import (
    RemoteBrowserEntry,
    SFTPTransferRefreshTracker,
    SFTPTransferRouter,
    TransferItem,
    TransferScheduler,
    TransferState,
)
from test_large_file_sftp_regressions import _Client, _File, _Storage


class TransferRefreshTests(unittest.TestCase):
    def test_refreshes_only_destination_and_only_on_completion(self):
        tracker = SFTPTransferRefreshTracker()
        upload = TransferItem("a", "b", "Upload")
        download = TransferItem("c", "d", "Download")
        items = [upload, download]
        self.assertEqual(tracker.changed_destinations(items), set())
        upload.status = TransferState.TRANSFERRING
        self.assertEqual(tracker.changed_destinations(items), set())
        upload.status = TransferState.COMPLETED
        self.assertEqual(tracker.changed_destinations(items), {"remote"})
        self.assertEqual(tracker.changed_destinations(items), set())
        download.status = TransferState.COMPLETED
        self.assertEqual(tracker.changed_destinations(items), {"local"})
        self.assertEqual(tracker.changed_destinations(items), set())

    def test_failed_partial_and_retry_refresh_again(self):
        tracker = SFTPTransferRefreshTracker()
        item = TransferItem("a", "b", "Download", status=TransferState.FAILED)
        self.assertEqual(tracker.changed_destinations([item]), {"local"})
        item.status = TransferState.PENDING
        self.assertEqual(tracker.changed_destinations([item]), set())
        item.status = TransferState.COMPLETED
        self.assertEqual(tracker.changed_destinations([item]), {"local"})
        self.assertEqual(tracker.changed_destinations([]), set())


class LongTransferTests(unittest.TestCase):
    def test_upload_and_download_keep_making_progress_past_stall_deadline(self):
        for direction in ("Upload", "Download"):
            with self.subTest(direction=direction), tempfile.TemporaryDirectory() as directory:
                data = b"x" * (4 * 1024 * 1024 + 10)
                path = Path(directory, "equil10.nc")
                storage = _Storage()
                storage.checksum_extension = False
                clock = [100.0]
                scheduler = TransferScheduler(
                    lambda: _Client(storage),
                    concurrency=1,
                    clock=lambda: clock[0],
                    stall_timeout=60,
                    monitor_interval=1000,
                )
                router = SFTPTransferRouter(scheduler)
                stalls = []
                original_read, original_write = _File.read, _File.write

                def advance():
                    clock[0] += 20
                    stalls.extend(scheduler.check_stalls())

                def read(stream, size=-1):
                    advance()
                    return original_read(stream, size)

                def write(stream, chunk):
                    advance()
                    return original_write(stream, chunk)

                try:
                    with patch.object(_File, "read", read), patch.object(_File, "write", write):
                        if direction == "Upload":
                            path.write_bytes(data)
                            item = router.queue_uploads([str(path)], "/remote")[0]
                        else:
                            storage.files["/remote/equil10.nc"] = data
                            entry = RemoteBrowserEntry(
                                "equil10.nc", "/remote/equil10.nc", False, False, len(data), 1, "File", "0o644", "user"
                            )
                            item = router.queue_downloads([entry], directory)[0]
                        deadline = time.monotonic() + 5
                        while item.status not in TransferState.TERMINAL and time.monotonic() < deadline:
                            time.sleep(0.005)
                        self.assertEqual(item.status, TransferState.COMPLETED, item.error)
                        self.assertEqual(stalls, [])
                        self.assertGreater(clock[0], 160)
                        if direction == "Upload":
                            self.assertEqual(storage.files["/remote/equil10.nc"], data)
                        else:
                            self.assertEqual(path.read_bytes(), data)
                finally:
                    scheduler.shutdown()

    def test_nested_folder_job_creates_missing_parents(self):
        class StrictClient:
            def __init__(self):
                self.directories = {"/"}

            def mkdir(self, path):
                if str(Path(path).parent) not in self.directories:
                    raise FileNotFoundError(path)
                self.directories.add(path)

        class Worker:
            def checkpoint(self, transferred=None, total=None):
                pass

        client = StrictClient()
        SFTPTransferRouter._mkdir_remote(TransferItem("local", "/a/b/c", "Upload"), client, Worker())
        self.assertIn("/a/b/c", client.directories)


class QueueRedrawTests(unittest.TestCase):
    def test_only_changed_rows_are_written(self):
        from sshvault import update_transfer_tree_rows
        from unittest.mock import Mock

        tree = Mock()
        previous = {}
        rows = [("one", ("file", "Pending")), ("two", ("other", "Completed"))]
        update_transfer_tree_rows(tree, rows, previous)
        self.assertEqual(tree.insert.call_count, 2)
        tree.reset_mock()
        update_transfer_tree_rows(tree, rows, previous)
        self.assertEqual(tree.mock_calls, [])
        update_transfer_tree_rows(tree, [("one", ("file", "Transferring")), rows[1]], previous)
        tree.item.assert_called_once_with("one", values=("file", "Transferring"))
        tree.delete.assert_not_called()
        tree.insert.assert_not_called()
        tree.reset_mock()
        update_transfer_tree_rows(tree, [rows[1]], previous)
        tree.delete.assert_called_once_with("one")
