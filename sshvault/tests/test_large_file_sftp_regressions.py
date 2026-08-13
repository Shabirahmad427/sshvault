"""Regression coverage for extension-neutral resumable large-file SFTP."""

from __future__ import annotations

import hashlib
import os
import socket
import tempfile
import time
import unittest
from io import BytesIO
from pathlib import Path

from sshvault_core import SFTPTransferRouter, TransferScheduler, TransferState


class _Stat:
    def __init__(self, size: int, mtime: float = 1) -> None:
        self.st_size, self.st_mtime = size, mtime


class _Channel:
    def __init__(self) -> None:
        self.timeout = None

    def settimeout(self, value) -> None:
        self.timeout = value


class _Storage:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.mtimes: dict[str, float] = {}
        self.directories: set[str] = set()
        self.clients = 0
        self.write_opens = 0
        self.failure: BaseException | None = None
        self.failures_left = 0
        self.on_first_write = None
        self.wrote_once = False


class _File:
    def __init__(self, client: "_Client", path: str, mode: str) -> None:
        self.client, self.path, self.mode = client, path, mode
        initial = client.storage.files.get(path, b"") if "r" in mode or "a" in mode else b""
        self.buffer = BytesIO(initial)
        if "a" in mode:
            self.buffer.seek(0, 2)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def read(self, size=-1):
        return self.buffer.read(size)

    def write(self, data):
        written = self.buffer.write(data)
        storage = self.client.storage
        if not storage.wrote_once:
            storage.wrote_once = True
            if storage.on_first_write:
                storage.on_first_write()
        if storage.failures_left:
            storage.failures_left -= 1
            raise storage.failure or ConnectionResetError("connection reset")
        return written

    def seek(self, offset):
        return self.buffer.seek(offset)

    def check(self, _algorithm, length=0):
        data = self.client.storage.files.get(self.path, b"")
        return hashlib.sha1(data[:length] if length else data).digest()

    def set_pipelined(self, _enabled):
        return None

    def prefetch(self, **_kwargs):
        return None

    def close(self):
        if not self.buffer.closed and any(flag in self.mode for flag in ("w", "a", "+")):
            self.client.storage.files[self.path] = self.buffer.getvalue()
        self.buffer.close()


class _Client:
    def __init__(self, storage: _Storage) -> None:
        self.storage = storage
        self.channel = _Channel()
        self.closed = False
        storage.clients += 1

    def get_channel(self):
        return self.channel

    def stat(self, path):
        if path in self.storage.files:
            return _Stat(len(self.storage.files[path]), self.storage.mtimes.get(path, 1))
        if path in self.storage.directories:
            return _Stat(0)
        raise FileNotFoundError(path)

    def open(self, path, mode):
        if any(flag in mode for flag in ("w", "a", "+")):
            self.storage.write_opens += 1
        return _File(self, path, mode)

    def mkdir(self, path):
        self.storage.directories.add(path)

    def remove(self, path):
        self.storage.files.pop(path, None)

    def rename(self, old, new):
        self.storage.files[new] = self.storage.files.pop(old)
        self.storage.mtimes[new] = self.storage.mtimes.pop(old, 1)

    def utime(self, path, times):
        self.storage.mtimes[path] = times[1]

    def close(self):
        self.closed = True


class LargeFileSFTPRegressions(unittest.TestCase):
    @staticmethod
    def _wait(item, timeout=3):
        deadline = time.monotonic() + timeout
        while item.status not in TransferState.TERMINAL and time.monotonic() < deadline:
            time.sleep(0.005)
        return item.status

    def _upload(self, source: Path, storage: _Storage, *, session="sahmaddo", verify=True):
        scheduler = TransferScheduler(
            lambda: _Client(storage),
            concurrency=1,
            reuse_worker_channels=True,
            session_id=session,
            operation_timeout=5,
        )
        router = SFTPTransferRouter(scheduler, verify_completed=verify)
        item = router.queue_uploads([str(source)], "/remote")[0]
        self._wait(item)
        return scheduler, item

    def test_large_nc_file_streams_in_chunks_with_scaled_timeout(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "equil10.nc")
            source.write_bytes(os.urandom(3 * 1024 * 1024 + 17))
            storage = _Storage()
            scheduler, item = self._upload(source, storage)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual(storage.files["/remote/equil10.nc"], source.read_bytes())
                self.assertGreater(scheduler._idle_worker_clients[0].channel.timeout, 5)
            finally:
                scheduler.shutdown()

    def test_source_growing_during_upload_is_reported_then_remaining_bytes_resume(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "equil-growing.nc")
            source.write_bytes(b"a" * (2 * 1024 * 1024))
            storage = _Storage()
            def grow_source():
                with source.open("ab") as handle:
                    handle.write(b"tail")

            storage.on_first_write = grow_source
            scheduler, item = self._upload(source, storage)
            try:
                self.assertEqual((item.status, item.error), (TransferState.FAILED, "Source file is still being modified"))
                self.assertIn("/remote/equil-growing.nc.sshvault-part", storage.files)
                storage.on_first_write = None
                self.assertTrue(scheduler.retry(item.item_id))
                self._wait(item)
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual(storage.files["/remote/equil-growing.nc"], source.read_bytes())
            finally:
                scheduler.shutdown()

    def test_interrupted_large_upload_reconnects_and_resumes_confirmed_offset(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "large.bin")
            source.write_bytes(os.urandom(3 * 1024 * 1024))
            storage = _Storage()
            storage.failure, storage.failures_left = ConnectionResetError("connection reset"), 1
            scheduler, item = self._upload(source, storage)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertGreaterEqual(storage.clients, 2)
                self.assertIn("Connection interrupted", item.diagnostics)
                self.assertEqual(storage.files["/remote/large.bin"], source.read_bytes())
            finally:
                scheduler.shutdown()

    def test_channel_timeout_reconnects_and_continues(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "large.dat")
            source.write_bytes(os.urandom(2 * 1024 * 1024))
            storage = _Storage()
            storage.failure, storage.failures_left = socket.timeout("timed out"), 1
            scheduler, item = self._upload(source, storage)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertIn("SFTP channel timeout", item.diagnostics)
                self.assertEqual(storage.files["/remote/large.dat"], source.read_bytes())
            finally:
                scheduler.shutdown()

    def test_valid_partial_file_resumes(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "large.bin")
            source.write_bytes(b"abcdef")
            storage = _Storage()
            storage.files["/remote/large.bin.sshvault-part"] = b"abc"
            scheduler, item = self._upload(source, storage)
            try:
                self.assertEqual(item.resume_offset, 3)
                self.assertEqual(storage.files["/remote/large.bin"], b"abcdef")
            finally:
                scheduler.shutdown()

    def test_invalid_partial_restarts_only_that_file(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "large.bin")
            source.write_bytes(b"abcdef")
            storage = _Storage()
            storage.files.update({"/remote/large.bin.sshvault-part": b"wrong", "/remote/other": b"keep"})
            scheduler, item = self._upload(source, storage)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual(storage.files["/remote/other"], b"keep")
                self.assertIn("Invalid partial file", item.diagnostics)
            finally:
                scheduler.shutdown()

    def test_completed_file_is_not_retransferred(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "done.bin")
            source.write_bytes(b"complete")
            os.utime(source, (1, 1))
            storage = _Storage()
            storage.files["/remote/done.bin"] = b"complete"
            storage.mtimes["/remote/done.bin"] = 1
            scheduler, item = self._upload(source, storage)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual(storage.write_opens, 0)
            finally:
                scheduler.shutdown()

    def test_same_large_file_behavior_for_sahmaddo_and_clauberh(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "equil-profile.nc")
            source.write_bytes(os.urandom(2 * 1024 * 1024))
            for account in ("sahmaddo", "clauberh"):
                with self.subTest(account=account):
                    storage = _Storage()
                    scheduler, item = self._upload(source, storage, session=account)
                    try:
                        self.assertEqual((item.session_id, item.status), (account, TransferState.COMPLETED))
                        self.assertEqual(storage.files["/remote/equil-profile.nc"], source.read_bytes())
                    finally:
                        scheduler.shutdown()


if __name__ == "__main__":
    unittest.main()
