"""F10 transfer preflight diagnostics regressions."""

from io import BytesIO
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest

from sshvault_core import RemoteBrowserEntry, SFTPTransferRouter, TransferScheduler, TransferState


class _Stat:
    def __init__(self, size=0, mtime=1, mode=0o100644):
        self.st_size = size
        self.st_mtime = mtime
        self.st_mode = mode


class _RemoteFile:
    def __init__(self, client, path, mode):
        self.client, self.path, self.mode = client, path, mode
        initial = client.files.get(path, b"") if "a" in mode or "r" in mode else b""
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
        return self.buffer.write(data)

    def seek(self, offset, whence=0):
        return self.buffer.seek(offset, whence)

    def check(self, _algorithm, length=0):
        data = self.client.files.get(self.path, b"")
        return hashlib.sha1(data[:length] if length else data).digest()

    def close(self):
        if not self.buffer.closed and ("w" in self.mode or "a" in self.mode or "+" in self.mode):
            self.client.files[self.path] = self.buffer.getvalue()
        self.buffer.close()


class _Client:
    def __init__(self, *, free_space=10**9):
        self.files = {}
        self.free_space = free_space
        self.closed = False

    def get_channel(self):
        return type("Channel", (), {"settimeout": lambda _self, _value: None})()

    def stat(self, path):
        if path in self.files:
            return _Stat(len(self.files[path]))
        if path in {"/", "/remote"}:
            return _Stat(mode=0o040755)
        raise FileNotFoundError(path)

    def statvfs(self, _path):
        if self.free_space is None:
            raise OSError("statvfs unsupported")
        return type("VFS", (), {"f_bavail": self.free_space, "f_frsize": 1})()

    def mkdir(self, _path):
        return None

    def open(self, path, mode):
        return _RemoteFile(self, path, mode)

    def remove(self, path):
        if path not in self.files:
            raise FileNotFoundError(path)
        self.files.pop(path)

    def rename(self, source, target):
        self.files[target] = self.files.pop(source)

    def utime(self, _path, _times):
        return None

    def close(self):
        self.closed = True


class SFTPPreflightDiagnosticsTests(unittest.TestCase):
    @staticmethod
    def _wait(item):
        deadline = time.monotonic() + 2
        while item.status not in TransferState.TERMINAL and time.monotonic() < deadline:
            time.sleep(0.005)

    def _upload(self, source, client, *, session="sahmaddo", profile="sahmaddo-profile", configure=None):
        scheduler = TransferScheduler(lambda: client, concurrency=1, session_id=session, profile_id=profile)
        router = SFTPTransferRouter(scheduler)
        router._local_source_open = lambda _path: False
        if configure:
            configure(router)
        item = router.queue_uploads([str(source)], "/remote")[0]
        self._wait(item)
        return scheduler, item

    def test_stable_source_records_complete_preflight(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "stable.bin")
            source.write_bytes(b"stable")
            scheduler, item = self._upload(source, _Client())
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual(item.preflight.source_size, 6)
                self.assertEqual(item.preflight.source_mtime, source.stat().st_mtime_ns)
                self.assertFalse(item.preflight.source_open)
                self.assertEqual(item.preflight.destination_free_space, 10**9)
                self.assertEqual(item.preflight.existing_partial_size, 0)
                self.assertEqual(
                    (item.preflight.session_id, item.preflight.profile_id), ("sahmaddo", "sahmaddo-profile")
                )
            finally:
                scheduler.shutdown()

    def test_download_records_remote_source_and_local_destination_preflight(self):
        with tempfile.TemporaryDirectory() as root:
            client = _Client()
            client.files["/remote/download.bin"] = b"download"
            scheduler = TransferScheduler(
                lambda: client,
                concurrency=1,
                session_id="clauberh",
                profile_id="clauberh-profile",
            )
            router = SFTPTransferRouter(scheduler)
            router._local_free_space = lambda _path: 500
            entry = RemoteBrowserEntry(
                "download.bin",
                "/remote/download.bin",
                False,
                False,
                8,
                1,
                "File",
                "-rw-r--r--",
                "clauberh",
            )
            item = router.queue_downloads([entry], root)[0]
            self._wait(item)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual((item.preflight.source_size, item.preflight.source_mtime), (8, 1))
                self.assertIsNone(item.preflight.source_open)
                self.assertEqual(item.preflight.destination_free_space, 500)
                self.assertEqual(item.preflight.existing_partial_size, 0)
                self.assertEqual(
                    (item.preflight.session_id, item.preflight.profile_id),
                    ("clauberh", "clauberh-profile"),
                )
            finally:
                scheduler.shutdown()

    def test_source_changing_during_preflight_is_stopped(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "changing.bin")
            source.write_bytes(b"source")

            def configure(router):
                original = router._source_snapshot
                calls = 0

                def snapshot(path):
                    nonlocal calls
                    calls += 1
                    size, mtime = original(path)
                    return (size, mtime if calls == 1 else mtime + 1)

                router._source_snapshot = snapshot

            scheduler, item = self._upload(source, _Client(), configure=configure)
            try:
                self.assertEqual(item.status, TransferState.FAILED)
                self.assertEqual(item.error, "Source file is still being modified")
                self.assertIn("Source still changing", item.diagnostics)
            finally:
                scheduler.shutdown()

    def test_existing_partial_size_is_recorded(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "partial.bin")
            source.write_bytes(b"abcdef")
            client = _Client()
            client.files["/remote/partial.bin.sshvault-part"] = b"abc"
            scheduler, item = self._upload(source, client)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual(item.preflight.existing_partial_size, 3)
                self.assertEqual(item.resume_offset, 3)
            finally:
                scheduler.shutdown()

    def test_oversized_partial_is_diagnosed_and_only_that_file_restarts(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "oversized.bin")
            source.write_bytes(b"data")
            client = _Client()
            client.files.update({"/remote/oversized.bin.sshvault-part": b"too large", "/remote/keep": b"keep"})
            scheduler, item = self._upload(source, client)
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertEqual(item.preflight.existing_partial_size, 9)
                self.assertIn("Invalid/oversized partial", item.diagnostics)
                self.assertEqual(client.files["/remote/keep"], b"keep")
            finally:
                scheduler.shutdown()

    def test_insufficient_remote_free_space_fails_before_writing(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "large.bin")
            source.write_bytes(b"123456")
            client = _Client(free_space=5)
            scheduler, item = self._upload(source, client)
            try:
                self.assertEqual((item.status, item.error), (TransferState.FAILED, "Remote filesystem full"))
                self.assertIn("Insufficient remote free space", item.diagnostics)
                self.assertNotIn("/remote/large.bin.sshvault-part", client.files)
            finally:
                scheduler.shutdown()

    def test_unknown_free_space_capability_continues_safely(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "unknown.bin")
            source.write_bytes(b"data")
            scheduler, item = self._upload(source, _Client(free_space=None))
            try:
                self.assertEqual(item.status, TransferState.COMPLETED)
                self.assertIsNone(item.preflight.destination_free_space)
            finally:
                scheduler.shutdown()

    def test_diagnostics_remain_session_and_profile_isolated(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "owned.bin")
            source.write_bytes(os.urandom(16))
            first_scheduler, first = self._upload(source, _Client(), session="sahmaddo", profile="profile-a")
            second_scheduler, second = self._upload(source, _Client(), session="clauberh", profile="profile-b")
            try:
                self.assertEqual((first.preflight.session_id, first.preflight.profile_id), ("sahmaddo", "profile-a"))
                self.assertEqual((second.preflight.session_id, second.preflight.profile_id), ("clauberh", "profile-b"))
                self.assertIsNot(first.preflight, second.preflight)
            finally:
                first_scheduler.shutdown()
                second_scheduler.shutdown()


if __name__ == "__main__":
    unittest.main()
