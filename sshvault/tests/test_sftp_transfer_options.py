"""Focused regression coverage for session-snapshotted SFTP transfer options."""

from __future__ import annotations

from io import BytesIO
import os
from pathlib import Path
from types import SimpleNamespace
import tempfile
import threading
import unittest

from sshvault import SSHVaultApp
from sshvault_core import SessionLifecycleState, SFTPTransferRouter, TransferItem, TransferScheduler


class _Stat:
    def __init__(self, size: int, mtime: float = 1) -> None:
        self.st_size = size
        self.st_mtime = mtime


class _RemoteFile:
    def __init__(self, client: "_Client", path: str, mode: str) -> None:
        self.client = client
        self.path = path
        self.mode = mode
        initial = client.files.get(path, b"") if "r" in mode or "a" in mode else b""
        self.buffer = BytesIO(initial)
        if "a" in mode:
            self.buffer.seek(0, os.SEEK_END)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def read(self, size=-1):
        return self.buffer.read(size)

    def write(self, data):
        return self.buffer.write(data)

    def seek(self, offset):
        return self.buffer.seek(offset)

    def close(self):
        if not self.buffer.closed and any(flag in self.mode for flag in ("w", "a", "+")):
            self.client.files[self.path] = self.buffer.getvalue()
        self.buffer.close()


class _Client:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.mtimes: dict[str, float] = {}
        self.directories: set[str] = set()
        self.open_modes: list[tuple[str, str]] = []
        self.utime_calls: list[tuple[str, tuple[float, float]]] = []

    def stat(self, path):
        if path in self.files:
            return _Stat(len(self.files[path]), self.mtimes.get(path, 1))
        if path in self.directories:
            return _Stat(0)
        raise FileNotFoundError(path)

    def open(self, path, mode):
        self.open_modes.append((path, mode))
        return _RemoteFile(self, path, mode)

    def mkdir(self, path):
        self.directories.add(path)

    def remove(self, path):
        self.files.pop(path, None)
        self.mtimes.pop(path, None)

    def rename(self, old, new):
        self.files[new] = self.files.pop(old)
        self.mtimes[new] = self.mtimes.pop(old, 1)

    def utime(self, path, times):
        self.utime_calls.append((path, times))
        self.mtimes[path] = times[1]


class _Worker:
    def __init__(self) -> None:
        self.timeout = None

    def checkpoint(self, _transferred, _total):
        return None

    def set_operation_timeout(self, timeout):
        self.timeout = timeout


class SFTPTransferOptionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.scheduler = TransferScheduler(lambda: _Client(), concurrency=1, operation_timeout=5)
        self.worker = _Worker()

    def tearDown(self) -> None:
        self.scheduler.shutdown()

    def _router(self, **options) -> SFTPTransferRouter:
        return SFTPTransferRouter(self.scheduler, verify_completed=False, **options)

    def _upload(self, router: SFTPTransferRouter, source: Path, client: _Client, target="/remote/file.bin"):
        item = TransferItem(str(source), target, "Upload")
        router._upload(item, client, self.worker)
        return item

    def test_ask_confirm_yes_replaces_destination(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"new")
            client = _Client()
            client.files["/remote/file.bin"] = b"old"
            prompted = []
            router = self._router(
                collision_behavior="ask",
                confirm_overwrite=lambda item: prompted.append(item.target) or True,
            )
            self._upload(router, source, client)
            self.assertEqual((prompted, client.files["/remote/file.bin"]), (["/remote/file.bin"], b"new"))

    def test_ask_confirm_no_leaves_destination_untouched(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"new")
            client = _Client()
            client.files["/remote/file.bin"] = b"old"
            item = self._upload(
                self._router(collision_behavior="ask", confirm_overwrite=lambda _item: False),
                source,
                client,
            )
            self.assertEqual(client.files["/remote/file.bin"], b"old")
            self.assertIn("Skipped existing destination", item.diagnostics)

    def test_overwrite_replaces_destination(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"replacement")
            client = _Client()
            client.files["/remote/file.bin"] = b"old"
            self._upload(self._router(collision_behavior="overwrite"), source, client)
            self.assertEqual(client.files["/remote/file.bin"], b"replacement")

    def test_skip_leaves_destination_untouched(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"new")
            client = _Client()
            client.files["/remote/file.bin"] = b"old"
            self._upload(self._router(collision_behavior="skip"), source, client)
            self.assertEqual(client.files["/remote/file.bin"], b"old")

    def test_rename_uses_first_name_without_final_or_partial_collision(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"new")
            client = _Client()
            client.files.update(
                {
                    "/remote/file.bin": b"old",
                    "/remote/file (1).bin.sshvault-part": b"partial",
                }
            )
            item = self._upload(self._router(collision_behavior="rename"), source, client)
            self.assertEqual(item.target, "/remote/file (2).bin")
            self.assertEqual(client.files[item.target], b"new")

    def test_resume_enabled_uses_valid_partial_offset(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"abcdef")
            client = _Client()
            client.files["/remote/file.bin.sshvault-part"] = b"abc"
            item = self._upload(self._router(resume_partial=True), source, client)
            self.assertEqual(item.resume_offset, 3)
            self.assertIn(("/remote/file.bin.sshvault-part", "ab"), client.open_modes)

    def test_resume_disabled_restarts_only_that_partial(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"abcdef")
            client = _Client()
            client.files.update({"/remote/file.bin.sshvault-part": b"abc", "/remote/other": b"keep"})
            item = self._upload(self._router(resume_partial=False), source, client)
            self.assertEqual(item.resume_offset, 0)
            self.assertIn(("/remote/file.bin.sshvault-part", "wb"), client.open_modes)
            self.assertEqual(client.files["/remote/other"], b"keep")

    def test_preserve_timestamp_enabled_sets_source_mtime(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"data")
            os.utime(source, (1234, 1234))
            client = _Client()
            self._upload(self._router(preserve_timestamps=True), source, client)
            self.assertEqual(client.utime_calls, [("/remote/file.bin", (1234.0, 1234.0))])

    def test_preserve_timestamp_disabled_leaves_server_default(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root, "file.bin")
            source.write_bytes(b"data")
            client = _Client()
            self._upload(self._router(preserve_timestamps=False), source, client)
            self.assertEqual(client.utime_calls, [])

    def test_download_rename_and_timestamp_options_apply_to_resolved_target(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root, "file.bin")
            target.write_bytes(b"existing")
            client = _Client()
            client.files["/remote/file.bin"] = b"downloaded"
            client.mtimes["/remote/file.bin"] = 2345
            item = TransferItem("/remote/file.bin", str(target), "Download")
            self._router(collision_behavior="rename", preserve_timestamps=True)._download(item, client, self.worker)
            renamed = Path(root, "file (1).bin")
            self.assertEqual(item.target, str(renamed))
            self.assertEqual(renamed.read_bytes(), b"downloaded")
            self.assertEqual(int(renamed.stat().st_mtime), 2345)
            self.assertEqual(target.read_bytes(), b"existing")

    def test_download_timestamp_disabled_keeps_local_default(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root, "file.bin")
            client = _Client()
            client.files["/remote/file.bin"] = b"downloaded"
            client.mtimes["/remote/file.bin"] = 1
            item = TransferItem("/remote/file.bin", str(target), "Download")
            self._router(preserve_timestamps=False)._download(item, client, self.worker)
            self.assertNotEqual(int(target.stat().st_mtime), 1)

    def test_folder_upload_applies_collision_rule_per_file(self):
        with tempfile.TemporaryDirectory() as root:
            folder = Path(root, "folder")
            folder.mkdir()
            (folder / "keep.bin").write_bytes(b"new keep")
            (folder / "copy.bin").write_bytes(b"new copy")
            client = _Client()
            client.files["/remote/folder/keep.bin"] = b"existing"
            router = self._router(collision_behavior="skip")
            for item, operation in router._folder_upload_children(folder, "/remote/folder"):
                if operation is not None:
                    operation(item, client, self.worker)
            self.assertEqual(client.files["/remote/folder/keep.bin"], b"existing")
            self.assertEqual(client.files["/remote/folder/copy.bin"], b"new copy")

    def test_session_snapshot_options_are_isolated_from_live_edits(self):
        first_scheduler = TransferScheduler(lambda: _Client(), concurrency=1)
        second_scheduler = TransferScheduler(lambda: _Client(), concurrency=1)
        try:
            first = SimpleNamespace(
                session_id="sahmaddo-session",
                profile_snapshot={
                    "id": "sahmaddo",
                    "sftp_options": {
                        "collision_behavior": "skip",
                        "resume_partial": False,
                        "preserve_timestamps": False,
                    },
                },
            )
            second = SimpleNamespace(
                session_id="clauberh-session",
                profile_snapshot={
                    "id": "clauberh",
                    "sftp_options": {
                        "collision_behavior": "rename",
                        "resume_partial": True,
                        "preserve_timestamps": True,
                    },
                },
            )
            app = SimpleNamespace(
                _sftp_transfer_schedulers={
                    first.session_id: first_scheduler,
                    second.session_id: second_scheduler,
                },
            )
            app._confirm_sftp_overwrite = lambda *_args: False
            live_profile = {"sftp_options": {"collision_behavior": "overwrite"}}
            first_router = SSHVaultApp._sftp_transfer_router(app, first)
            live_profile["sftp_options"]["collision_behavior"] = "ask"
            second_router = SSHVaultApp._sftp_transfer_router(app, second)
            self.assertEqual(
                (first_router.collision_behavior, first_router.resume_partial, first_router.preserve_timestamps),
                ("skip", False, False),
            )
            self.assertEqual(
                (second_router.collision_behavior, second_router.resume_partial, second_router.preserve_timestamps),
                ("rename", True, True),
            )
            self.assertIs(first_router.scheduler, first_scheduler)
            self.assertIs(second_router.scheduler, second_scheduler)
        finally:
            first_scheduler.shutdown()
            second_scheduler.shutdown()

    def test_queued_overwrite_prompt_releases_worker_when_scheduler_stops(self):
        record = SimpleNamespace(session_id="session-a", state=SessionLifecycleState.CONNECTED)
        scheduler = SimpleNamespace(closed=False)
        callbacks = []
        queued = threading.Event()

        def after(_delay, callback):
            callbacks.append(callback)
            queued.set()

        app = SimpleNamespace(
            _session_controller=SimpleNamespace(get=lambda _session_id: record),
            _sftp_transfer_schedulers={record.session_id: scheduler},
            after=after,
        )
        result = []
        worker = threading.Thread(
            target=lambda: result.append(
                SSHVaultApp._confirm_sftp_overwrite(
                    app, record, TransferItem(source="a", target="b", direction="upload", total=1)
                )
            )
        )
        worker.start()
        self.assertTrue(queued.wait(1))
        scheduler.closed = True
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [False])
        callbacks[0]()


if __name__ == "__main__":
    unittest.main()
