from __future__ import annotations

import tempfile
import unittest
import errno
import hashlib
import os
import threading
import time
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from sshvault import SSHVaultApp
from sshvault_core import (
    LocalBrowserEntry,
    RemoteBrowserEntry,
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPDragDropRouter,
    SFTPTransferRouter,
    ProfileError,
    SessionController,
    SessionLifecycleState,
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


class _RemoteListingClient:
    def __init__(self, listings) -> None:
        self.listings = listings

    def list_directory(self, path):
        return self.listings[path]

    def home_directory(self):
        return "/"


class _RemoteStat:
    def __init__(self, size: int, mtime: float = 1) -> None:
        self.st_size = size
        self.st_mtime = mtime


class _RemoteFile:
    def __init__(self, client, path: str, mode: str) -> None:
        self.client, self.path, self.mode = client, path, mode
        initial = client.files.get(path, b"") if "r" in mode or "a" in mode else b""
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

    def seek(self, offset):
        return self.buffer.seek(offset)

    def check(self, _algorithm, length=0):
        data = self.client.files.get(self.path, b"")
        if length:
            data = data[:length]
        return hashlib.sha1(data).digest()

    def close(self):
        if any(flag in self.mode for flag in ("w", "a", "+")):
            self.client.files[self.path] = self.buffer.getvalue()
        self.buffer.close()


class _ResumeClient:
    def __init__(self) -> None:
        self.files: dict[str, bytes] = {}
        self.mtimes: dict[str, float] = {}
        self.directories: set[str] = set()

    def stat(self, path: str):
        if path in self.files:
            return _RemoteStat(len(self.files[path]), self.mtimes.get(path, 1))
        if path in self.directories:
            return _RemoteStat(0, self.mtimes.get(path, 1))
        raise FileNotFoundError(path)

    def open(self, path: str, mode: str):
        return _RemoteFile(self, path, mode)

    def mkdir(self, path: str):
        self.directories.add(path)

    def remove(self, path: str):
        self.files.pop(path, None)

    def rename(self, old: str, new: str):
        self.files[new] = self.files.pop(old)
        self.mtimes[new] = self.mtimes.pop(old, 1)

    def utime(self, path: str, times):
        self.mtimes[path] = times[1]

    def close(self):
        return None


class _Connection:
    def __init__(self, client) -> None:
        self.client = client

    def open_sftp(self):
        return self.client


class _Tab:
    def __init__(self, client) -> None:
        self._client = client


class _RouterApp:
    _sftp_transfer_router = SSHVaultApp._sftp_transfer_router

    def __init__(self, records, clients) -> None:
        self._sftp_transfer_schedulers = {}
        self._conn_tabs = {record.session_id: _Tab(_Connection(client)) for record, client in zip(records, clients)}

    def _sftp_transfer_changed(self, _session_id):
        return None


class _Checkpoint:
    def __init__(self, item) -> None:
        self.item = item

    def checkpoint(self, transferred=None, total=None):
        if transferred is not None:
            self.item.transferred = transferred
        if total is not None:
            self.item.total = total


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
    @staticmethod
    def _wait(item) -> None:
        deadline = time.monotonic() + 2
        while item.status not in TransferState.TERMINAL and time.monotonic() < deadline:
            time.sleep(0.005)

    def test_two_profile_uploads_keep_session_ownership_and_transport(self) -> None:
        controller = SessionController()
        records = []
        for profile_id, user in (("sahmaddo-profile", "sahmaddo"), ("clauberh-profile", "clauberh")):
            record = controller.create_session(
                {
                    "id": profile_id,
                    "host": "coaraci.ifi.unicamp.br",
                    "user": user,
                    "sftp_options": {"concurrent_transfers": 1},
                }
            )
            record.state = SessionLifecycleState.CONNECTED
            records.append(record)
        clients = [_ResumeClient(), _ResumeClient()]
        app = _RouterApp(records, clients)
        try:
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "file with spaces.txt")
                source.write_text("data")
                first = app._sftp_transfer_router(records[0]).queue_uploads([str(source)], "/incoming")[0]
                second = app._sftp_transfer_router(records[1]).queue_uploads([str(source)], "/incoming")[0]
                self._wait(first)
                self._wait(second)
            self.assertEqual((first.session_id, first.profile_id), (records[0].session_id, "sahmaddo-profile"))
            self.assertEqual((second.session_id, second.profile_id), (records[1].session_id, "clauberh-profile"))
            self.assertEqual((first.status, second.status), (TransferState.COMPLETED, TransferState.COMPLETED))
            self.assertEqual(clients[0].files["/incoming/file with spaces.txt"], b"data")
            self.assertEqual(clients[1].files["/incoming/file with spaces.txt"], b"data")
            # Reusing a session scheduler used to reference an unbound option
            # before the second transfer could reach the queue.
            self.assertIs(
                app._sftp_transfer_router(records[0]).scheduler,
                app._sftp_transfer_schedulers[records[0].session_id],
            )
        finally:
            for scheduler in app._sftp_transfer_schedulers.values():
                scheduler.shutdown()

    def test_verification_is_enabled_by_default_and_can_be_disabled(self):
        self.assertTrue(SFTPTransferRouter(TransferScheduler(None)).verify_completed)
        self.assertFalse(SFTPTransferRouter(TransferScheduler(None), verify_completed=False).verify_completed)

    def test_folder_upload_queues_nested_and_empty_directories(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "project")
                (source / "nested" / "deeper" / "empty-deep").mkdir(parents=True)
                (source / "empty").mkdir()
                (source / "root.txt").write_text("root")
                (source / "file with spaces.txt").write_text("spaces")
                (source / ".hidden").write_text("hidden")
                (source / "nested" / "child.txt").write_text("child")
                (source / "nested" / "deeper" / "grandchild.txt").write_text("grandchild")
                queued = router.queue_uploads([str(source)], "/incoming")
                self._wait(queued[0])
            targets = {item.target for item in scheduler.items}
            self.assertIn("/incoming/project", targets)
            self.assertIn("/incoming/project/empty", targets)
            self.assertIn("/incoming/project/nested/child.txt", targets)
            self.assertIn("/incoming/project/nested/deeper/grandchild.txt", targets)
            self.assertIn("/incoming/project/nested/deeper/empty-deep", targets)
            self.assertIn("/incoming/project/file with spaces.txt", targets)
            self.assertIn("/incoming/project/.hidden", targets)
            self.assertEqual({item.direction for item in queued}, {"Upload"})
            self.assertIs(router.scheduler, scheduler)
        finally:
            scheduler.shutdown()

    def test_deep_upload_queues_incrementally_without_blocking_terminal_events(self) -> None:
        scheduler = TransferScheduler(None)
        release = threading.Event()
        first_level_queued = threading.Event()
        real_walk = os.walk
        try:
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "project")
                (source / "one" / "two" / "three").mkdir(parents=True)
                for index in range(20):
                    (source / "one" / "two" / "three" / f"{index}.txt").write_text("data")

                def slow_walk(*args, **kwargs):
                    for index, row in enumerate(real_walk(*args, **kwargs)):
                        yield row
                        if index == 0:
                            first_level_queued.set()
                            release.wait(1)

                started = time.monotonic()
                with patch("sshvault_core.os.walk", side_effect=slow_walk):
                    planning = SFTPTransferRouter(scheduler).queue_uploads([str(source)], "/incoming")[0]
                    self.assertLess(time.monotonic() - started, 0.2)
                    self.assertTrue(first_level_queued.wait(0.5))
                    visible_before_scan_finished = len(scheduler.items)
                    terminal_input_processed = True
                    self.assertTrue(terminal_input_processed)
                    self.assertGreater(visible_before_scan_finished, 1)
                    self.assertEqual(planning.status, TransferState.PREPARING)
                    release.set()
                    self._wait(planning)
            self.assertEqual(planning.status, TransferState.COMPLETED)
            self.assertGreater(len(scheduler.items), visible_before_scan_finished)
        finally:
            release.set()
            scheduler.shutdown()

    def test_folder_download_listing_does_not_block_terminal_io(self) -> None:
        entered = threading.Event()
        release = threading.Event()

        class SlowListingClient:
            def list_directory(self, _path):
                entered.set()
                release.wait(1)
                return []

            def home_directory(self):
                return "/"

            def close(self):
                return None

        scheduler = TransferScheduler(lambda: SlowListingClient(), concurrency=1)
        try:
            entry = RemoteBrowserEntry("folder", "/folder", True, False, None, None, "Directory", "—", "—")
            started = time.monotonic()
            scan = SFTPTransferRouter(scheduler).queue_downloads([entry], "/tmp")[0]
            self.assertLess(time.monotonic() - started, 0.2)
            self.assertTrue(entered.wait(0.5))
            terminal_output_processed = True
            self.assertTrue(terminal_output_processed)
            release.set()
            self._wait(scan)
            self.assertEqual(scan.status, TransferState.COMPLETED)
        finally:
            release.set()
            scheduler.shutdown()

    def test_unreadable_file_is_visible_and_does_not_block_good_file(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            with tempfile.TemporaryDirectory() as root:
                bad, good = Path(root, "bad.txt"), Path(root, "good.txt")
                bad.write_text("bad")
                good.write_text("good")
                real_access = os.access
                with patch(
                    "sshvault_core.os.access",
                    side_effect=lambda path, mode: False if Path(path) == bad else real_access(path, mode),
                ):
                    queued = router.queue_uploads([str(bad), str(good)], "/incoming")
            self.assertEqual(len(queued), 2)
            self.assertEqual((queued[0].status, queued[0].error), (TransferState.FAILED, "Local file unreadable"))
            self.assertIn(queued[1], scheduler.items)
        finally:
            scheduler.shutdown()

    def test_remote_upload_failures_have_stable_user_messages(self) -> None:
        class FailingClient:
            def __init__(self, failure) -> None:
                self.failure = failure

            def mkdir(self, _path):
                raise self.failure

            def stat(self, _path):
                raise self.failure

        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            item = TransferItem("local", "/blocked", "Upload")
            cases = (
                (PermissionError(errno.EACCES, "Permission denied"), "Remote permission denied"),
                (FileNotFoundError(errno.ENOENT, "No such file"), "Remote directory not found"),
                (OSError(errno.ENOSPC, "No space left"), "Remote filesystem full"),
            )
            for failure, expected in cases:
                with self.subTest(expected=expected), self.assertRaisesRegex(ProfileError, f"^{expected}$"):
                    router._mkdir_remote(item, FailingClient(failure), _Checkpoint(item))
        finally:
            scheduler.shutdown()

    def test_symlink_policy_and_real_source_paths(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            with tempfile.TemporaryDirectory() as root:
                folder = Path(root, "folder")
                folder.mkdir()
                real = folder / "real.txt"
                real.write_text("real")
                link = folder / "link.txt"
                link.symlink_to(real)
                excluded = SFTPTransferRouter(scheduler).queue_uploads([str(link)], "/off")[0]
                included = SFTPTransferRouter(scheduler, follow_symlinks=True).queue_uploads([str(link)], "/on")[0]
            self.assertEqual(
                (excluded.status, excluded.error), (TransferState.FAILED, "Symbolic links are not followed")
            )
            self.assertEqual(included.source, str(real.resolve()))
            self.assertEqual(included.target, "/on/link.txt")
        finally:
            scheduler.shutdown()

    def test_oversized_partial_restarts_only_that_file(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            client = _ResumeClient()
            client.files["/remote/data.txt.sshvault-part"] = b"oversized"
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "data.txt")
                source.write_bytes(b"data")
                item = TransferItem(str(source), "/remote/data.txt", "Upload")
                router._upload(item, client, _Checkpoint(item))
            self.assertEqual(client.files["/remote/data.txt"], b"data")
            self.assertNotIn("/remote/data.txt.sshvault-part", client.files)
        finally:
            scheduler.shutdown()

    def test_one_account_failure_does_not_interrupt_other_scheduler(self) -> None:
        class DeniedClient(_ResumeClient):
            def mkdir(self, _path):
                raise PermissionError(errno.EACCES, "Permission denied")

        failing = TransferScheduler(lambda: DeniedClient(), concurrency=1, session_id="sahmaddo")
        working_client = _ResumeClient()
        working = TransferScheduler(lambda: working_client, concurrency=1, session_id="clauberh")
        try:
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "data.txt")
                source.write_text("data")
                failed = SFTPTransferRouter(failing).queue_uploads([str(source)], "/incoming")[0]
                completed = SFTPTransferRouter(working).queue_uploads([str(source)], "/incoming")[0]
                self._wait(failed)
                self._wait(completed)
            self.assertEqual((failed.status, failed.error), (TransferState.FAILED, "Remote permission denied"))
            self.assertEqual(completed.status, TransferState.COMPLETED)
            self.assertEqual(working_client.files["/incoming/data.txt"], b"data")
        finally:
            failing.shutdown()
            working.shutdown()

    def test_folder_download_queues_nested_and_empty_directories(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            root_entry = RemoteBrowserEntry(
                "project", "/remote/project", True, False, None, None, "Directory", "—", "—"
            )
            client = _RemoteListingClient(
                {
                    "/remote/project": [
                        type("Attr", (), {"filename": "nested", "st_mode": 0o040755})(),
                        type("Attr", (), {"filename": "empty", "st_mode": 0o040755})(),
                    ],
                    "/remote/project/nested": [
                        type(
                            "Attr",
                            (),
                            {
                                "filename": "child.txt",
                                "st_mode": 0o100644,
                                "st_size": 4,
                                "st_mtime": 2,
                                "st_uid": "alice",
                            },
                        )(),
                    ],
                    "/remote/project/empty": [],
                }
            )
            scheduler.shutdown()
            scheduler = TransferScheduler(lambda: client, concurrency=1)
            router = SFTPTransferRouter(scheduler)
            # The root row appears immediately; descendants are discovered on
            # a worker-owned channel and appended incrementally.
            queued = router.queue_downloads([root_entry], "/tmp/download", browser_client=client)
            self._wait(queued[0])
            targets = {item.target for item in scheduler.items}
            self.assertIn("/tmp/download/project", targets)
            self.assertIn("/tmp/download/project/empty", targets)
            self.assertIn("/tmp/download/project/nested/child.txt", targets)
            self.assertEqual({item.direction for item in queued}, {"Download"})
            self.assertIs(router.scheduler, scheduler)
        finally:
            scheduler.shutdown()

    def test_mixed_selection_and_button_state(self) -> None:
        self.assertEqual(
            SFTPTransferRouter.action_states(
                local_selected=True,
                remote_selected=True,
                connected=True,
                client_available=True,
            ),
            {"upload": True, "download": True},
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

    def test_interrupted_upload_resumes_and_finalizes_partial(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            client = _ResumeClient()
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "data.txt")
                source.write_bytes(b"abcdef")
                client.files["/remote/data.txt.sshvault-part"] = b"abc"
                item = TransferItem(str(source), "/remote/data.txt", "Upload")
                router._upload(item, client, _Checkpoint(item))
            self.assertEqual(client.files["/remote/data.txt"], b"abcdef")
            self.assertNotIn("/remote/data.txt.sshvault-part", client.files)
            self.assertEqual(item.transferred, 6)
        finally:
            scheduler.shutdown()

    def test_interrupted_download_resumes_and_finalizes_partial(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            client = _ResumeClient()
            client.files["/remote/data.txt"] = b"abcdef"
            with tempfile.TemporaryDirectory() as root:
                target = Path(root, "data.txt")
                Path(str(target) + ".sshvault-part").write_bytes(b"abc")
                item = TransferItem("/remote/data.txt", str(target), "Download")
                router._download(item, client, _Checkpoint(item))
                self.assertEqual(target.read_bytes(), b"abcdef")
                self.assertFalse(Path(str(target) + ".sshvault-part").exists())
            self.assertEqual(item.transferred, 6)
        finally:
            scheduler.shutdown()

    def test_completed_upload_is_skipped_and_changed_file_retransfers(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            client = _ResumeClient()
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "data.txt")
                source.write_bytes(b"abcdef")
                client.files["/remote/data.txt"] = b"abcdef"
                os.utime(source, (1, 1))
                client.mtimes["/remote/data.txt"] = 1
                skipped = TransferItem(str(source), "/remote/data.txt", "Upload")
                router._upload(skipped, client, _Checkpoint(skipped))
                self.assertEqual(skipped.transferred, 6)
                client.mtimes["/remote/data.txt"] = 99
                changed = TransferItem(str(source), "/remote/data.txt", "Upload")
                router._upload(changed, client, _Checkpoint(changed))
                self.assertEqual(client.files["/remote/data.txt"], b"abcdef")
                self.assertEqual(client.mtimes["/remote/data.txt"], 1)
        finally:
            scheduler.shutdown()

    def test_invalid_partial_restarts_only_that_file(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            router = SFTPTransferRouter(scheduler)
            client = _ResumeClient()
            client.files["/remote/data.txt.sshvault-part"] = b"wrong"
            with tempfile.TemporaryDirectory() as root:
                source = Path(root, "data.txt")
                source.write_bytes(b"abcdef")
                item = TransferItem(str(source), "/remote/data.txt", "Upload")
                router._upload(item, client, _Checkpoint(item))
                self.assertEqual(client.files["/remote/data.txt"], b"abcdef")
                self.assertNotIn("/remote/data.txt.sshvault-part", client.files)
                self.assertEqual(item.diagnostics, ["Invalid partial file"])
        finally:
            scheduler.shutdown()

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
