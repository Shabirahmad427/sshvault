"""Display-free throughput guards for buffered SFTP transfers."""

from __future__ import annotations

from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from sshvault import SFTPPanel
from sshvault_core import (
    DurableProgressPolicy,
    SFTP_TRANSFER_CHUNK_SIZES,
    TransferItem,
    TransferScheduler,
    validate_settings,
)


class FakeAttributes:
    def __init__(self, size: int):
        self.st_size = size
        self.st_mtime = 1


class FakeRemoteFile:
    def __init__(self, data: bytes):
        self.data = data
        self.position = 0
        self.read_sizes = []
        self.prefetch_calls = []
        self.fail_after_reads = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def seek(self, offset: int):
        self.position = offset

    def read(self, size: int) -> bytes:
        if self.fail_after_reads is not None and len(self.read_sizes) >= self.fail_after_reads:
            raise OSError("fake read failure")
        self.read_sizes.append(size)
        value = self.data[self.position : self.position + size]
        self.position += len(value)
        return value

    def prefetch(self, **kwargs):
        self.prefetch_calls.append(kwargs)


class FakeSFTP:
    def __init__(self, data: bytes):
        self.data = data
        self.source = FakeRemoteFile(data)

    def stat(self, _path):
        return FakeAttributes(len(self.data))

    def open(self, _path, _mode):
        return self.source


class FakeWorker:
    def __init__(self):
        self.progress = []
        self.resumed = False

    def checkpoint(self, transferred, total):
        self.progress.append((transferred, total))

    def durable_update_required(self):
        return False

    def mark_resuming(self):
        self.resumed = True


class DurableWorker(FakeWorker):
    def durable_update_required(self):
        return True


class FakePanel:
    _enable_download_prefetch = staticmethod(SFTPPanel._enable_download_prefetch)
    _persist_download_progress = staticmethod(SFTPPanel._persist_download_progress)
    _persist_closed_download_progress = staticmethod(SFTPPanel._persist_closed_download_progress)
    _partial_local_metadata_path = staticmethod(SFTPPanel._partial_local_metadata_path)

    def _remote_identity(self, _sftp):
        return "profile:fake"

    def _transfer_chunk_size(self):
        return 1048576


class DirectoryPanel:
    def __init__(self):
        self.uploads = []

    def _scheduled_upload(self, item, _sftp, _worker, local, remote, replace):
        self.uploads.append((item, local, remote, replace))


class ThroughputSettingsTests(unittest.TestCase):
    def test_chunk_size_defaults_and_legacy_values_are_validated(self):
        self.assertEqual(validate_settings({})["sftp_chunk_size"], 1048576)
        self.assertEqual(validate_settings({"sftp_chunk_size": 262144})["sftp_chunk_size"], 262144)
        self.assertEqual(
            validate_settings({"sftp_chunk_size": 99999999})["sftp_chunk_size"], SFTP_TRANSFER_CHUNK_SIZES[-1]
        )

    def test_durable_progress_is_due_by_bytes_or_time_only(self):
        policy = DurableProgressPolicy(0, 0)
        self.assertFalse(policy.due(1048576, 1))
        self.assertTrue(policy.due(16 * 1024 * 1024, 1))
        policy.persisted(16 * 1024 * 1024, 1)
        self.assertTrue(policy.due(16 * 1024 * 1024 + 1, 6.1))

    def test_progress_callbacks_are_throttled_but_state_callback_is_immediate(self):
        now = [0.0]
        callbacks = []
        scheduler = TransferScheduler(clock=lambda: now[0], on_change=lambda: callbacks.append(now[0]))
        item = TransferItem("a", "b", "Download", total=10)
        scheduler.record(item)
        callbacks.clear()
        scheduler._changed(item_id=item.item_id, progress=True, force=False)
        now[0] = 0.1
        scheduler._changed(item_id=item.item_id, progress=True, force=False)
        now[0] = 0.2
        scheduler._changed(item_id=item.item_id, progress=True, force=False)
        scheduler._changed()
        self.assertEqual(callbacks, [0.0, 0.2])
        self.assertEqual(item.metrics.ui_progress_callbacks, 1)


class BufferedDownloadTests(unittest.TestCase):
    def test_selected_chunk_size_prefetch_and_bounded_sidecar_updates(self):
        data = b"x" * (5 * 1024 * 1024)
        sftp = FakeSFTP(data)
        item = TransferItem("/remote", "target", "Download", total=len(data))
        worker = FakeWorker()
        panel = FakePanel()
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "target"
            writes = []

            def capture(*_args, **kwargs):
                writes.append(kwargs["completed_bytes"])

            with patch("sshvault.write_partial_download_metadata", side_effect=capture):
                SFTPPanel._scheduled_download(panel, item, sftp, worker, "/remote", local, True)
            self.assertEqual(local.read_bytes(), data)
        self.assertTrue(all(size == 1048576 for size in sftp.source.read_sizes[:-1]))
        self.assertEqual(sftp.source.prefetch_calls, [{"file_size": len(data), "max_concurrent_prefetch_requests": 8}])
        self.assertEqual(writes, [0, len(data)])
        self.assertEqual(item.metrics.average_bytes_per_call("remote_read"), 5 * 1024 * 1024 / 6)
        self.assertEqual(worker.progress[-1], (len(data), len(data)))

    def test_upload_pipelining_is_supported_only_when_available(self):
        calls = []

        class Target:
            def set_pipelined(self, enabled):
                calls.append(enabled)

        SFTPPanel._enable_upload_pipelining(Target())
        SFTPPanel._enable_upload_pipelining(object())
        self.assertEqual(calls, [True])

    def test_pause_or_failure_forces_a_flushed_durable_sidecar(self):
        data = b"x" * 1048576
        panel = FakePanel()
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "target"
            writes = []

            def capture(*_args, **kwargs):
                writes.append(kwargs["completed_bytes"])

            with patch("sshvault.write_partial_download_metadata", side_effect=capture):
                SFTPPanel._scheduled_download(
                    panel,
                    TransferItem("/remote", "target", "Download"),
                    FakeSFTP(data),
                    DurableWorker(),
                    "/remote",
                    local,
                    True,
                )
            self.assertEqual(writes, [0, len(data)])

        failing = FakeSFTP(data)
        failing.source.fail_after_reads = 1
        with tempfile.TemporaryDirectory() as directory:
            local = Path(directory) / "target"
            writes = []
            with patch(
                "sshvault.write_partial_download_metadata",
                side_effect=lambda *_args, **kwargs: writes.append(kwargs["completed_bytes"]),
            ):
                with self.assertRaises(OSError):
                    SFTPPanel._scheduled_download(
                        panel,
                        TransferItem("/remote", "target", "Download"),
                        failing,
                        FakeWorker(),
                        "/remote",
                        local,
                        True,
                    )
            self.assertEqual(writes, [0, len(data)])

    def test_remote_directory_cache_reuses_successes_and_retries_errors(self):
        class Directories:
            def __init__(self):
                self.calls = []
                self.fail = set()

            def mkdir(self, path):
                self.calls.append(path)
                if path in self.fail:
                    raise OSError("fake mkdir failure")

        panel = DirectoryPanel()
        sftp = Directories()
        cache, lock = set(), threading.Lock()
        item = TransferItem("source", "target", "Upload")
        SFTPPanel._scheduled_upload_with_dirs(panel, item, sftp, object(), Path("one"), "/root/a/one", cache, lock)
        SFTPPanel._scheduled_upload_with_dirs(panel, item, sftp, object(), Path("two"), "/root/a/two", cache, lock)
        self.assertEqual(sftp.calls, ["/root", "/root/a"])
        sftp.fail.add("/root/b")
        SFTPPanel._scheduled_upload_with_dirs(panel, item, sftp, object(), Path("three"), "/root/b/three", cache, lock)
        SFTPPanel._scheduled_upload_with_dirs(panel, item, sftp, object(), Path("four"), "/root/b/four", cache, lock)
        self.assertEqual(sftp.calls.count("/root/b"), 2)


if __name__ == "__main__":
    unittest.main()
