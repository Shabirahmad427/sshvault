"""Display-free bounded-concurrency SFTP transfer scheduler tests."""

import threading
import time
import unittest
from pathlib import Path
import tempfile

from sshvault_core import (
    TransferBatch,
    TransferItem,
    TransferScheduler,
    TransferState,
    partial_download_metadata_path,
    partial_download_path,
    write_partial_download_metadata,
)


class FakeSFTP:
    def __init__(self, owner):
        self.owner = owner
        self.closed = False
        owner.clients.append(self)

    def close(self):
        self.closed = True


class _TimeoutChannel:
    def __init__(self) -> None:
        self.timeout = None

    def settimeout(self, value) -> None:
        self.timeout = value


class TimeoutSFTP(FakeSFTP):
    def __init__(self, owner):
        super().__init__(owner)
        self.channel = _TimeoutChannel()

    def get_channel(self):
        return self.channel


class FakeTransport:
    def __init__(self):
        self.active = True


class ResumeSFTP(FakeSFTP):
    def __init__(self, owner, transport):
        super().__init__(owner)
        self.transport = transport
        self.channel_id = len(owner.clients)
        self.reads = 0
        self.writes = 0

    def read(self) -> bytes:
        self.reads += 1
        return b"xyz"

    def write(self, data: bytes) -> None:
        self.writes += len(data)


class TransferSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.clients = []
        self.release = threading.Event()
        self.started = threading.Event()

    def scheduler(self, concurrency=3):
        return TransferScheduler(lambda: FakeSFTP(self), concurrency=concurrency)

    def blocking_operation(self, item, _client, worker):
        self.started.set()
        while not self.release.wait(0.005):
            worker.checkpoint(item.transferred + 1, item.total)
        worker.checkpoint(item.total or 0, item.total)

    def test_default_concurrency_and_bounds(self):
        self.assertEqual(TransferScheduler().concurrency, 3)
        self.assertEqual(TransferScheduler(concurrency=0).concurrency, 1)
        self.assertEqual(TransferScheduler(concurrency=99).concurrency, 8)

    def test_three_active_and_fourth_pending_then_slot_released(self):
        scheduler = self.scheduler()
        rows = [
            scheduler.enqueue(TransferItem(str(i), str(i), "Upload", total=4), self.blocking_operation)
            for i in range(4)
        ]
        for _ in range(100):
            if scheduler.active_count == 3:
                break
            time.sleep(0.005)
        self.assertEqual(scheduler.active_count, 3)
        self.assertEqual(rows[3].status, TransferState.PENDING)
        self.release.set()
        scheduler.shutdown()
        self.assertEqual(len({id(x) for x in self.clients}), len(self.clients))

    def test_pending_pause_retry_remove_clear_and_batch_aggregation(self):
        scheduler = self.scheduler(1)
        first = scheduler.enqueue(TransferItem("a", "a", "Upload", total=10), self.blocking_operation)
        second = scheduler.enqueue(TransferItem("b", "b", "Upload", total=10), self.blocking_operation)
        self.assertTrue(scheduler.pause(second.item_id))
        self.assertEqual(second.status, TransferState.PAUSED)
        self.assertTrue(scheduler.cancel(second.item_id))
        self.assertTrue(scheduler.retry(second.item_id))
        self.assertTrue(scheduler.remove(second.item_id))
        batch = TransferBatch("folder", "Upload", "src", "dst")
        child = TransferItem("c", "c", "Upload", total=10, transferred=4)
        scheduler.add_batch(batch, [(child, self.blocking_operation)])
        progress = scheduler.batch_progress(batch.batch_id)
        self.assertEqual(progress.transferred, 4)
        self.assertEqual(progress.total, 10)
        self.assertFalse(scheduler.move(first.item_id, 1))
        self.release.set()
        scheduler.shutdown()

    def test_generation_suppression_and_shutdown_cleanup(self):
        scheduler = self.scheduler(1)
        item = scheduler.enqueue(TransferItem("a", "a", "Download", total=2), self.blocking_operation)
        self.started.wait(0.5)
        scheduler.invalidate_session(fail_active=True)
        self.assertEqual(item.status, TransferState.FAILED)
        scheduler.shutdown()
        self.assertTrue(all(client.closed for client in self.clients))

    def test_worker_channel_receives_remote_operation_timeout(self):
        scheduler = TransferScheduler(lambda: TimeoutSFTP(self), concurrency=1, operation_timeout=7)
        item = scheduler.enqueue(
            TransferItem("a", "a", "Upload", total=1),
            lambda row, _client, worker: worker.checkpoint(1, row.total),
        )
        for _ in range(100):
            if item.status == TransferState.COMPLETED:
                break
            time.sleep(0.005)
        self.assertEqual(item.status, TransferState.COMPLETED)
        self.assertEqual(self.clients[0].channel.timeout, 7)
        scheduler.shutdown()

    def test_retry_failed_resubmits_only_failed_items(self):
        scheduler = self.scheduler(1)
        attempts: dict[str, int] = {}

        def operation(item, _client, worker):
            attempts[item.source] = attempts.get(item.source, 0) + 1
            if item.source == "failed" and attempts[item.source] == 1:
                raise OSError("one file failed")
            worker.checkpoint(item.total or 0, item.total)

        failed = scheduler.enqueue(TransferItem("failed", "failed", "Upload", total=1), operation)
        completed = scheduler.enqueue(TransferItem("completed", "completed", "Upload", total=1), operation)
        cancelled = scheduler.record(
            TransferItem("cancelled", "cancelled", "Upload", total=1, status=TransferState.CANCELLED)
        )
        for _ in range(200):
            if failed.status == TransferState.FAILED and completed.status == TransferState.COMPLETED:
                break
            time.sleep(0.005)
        scheduler.retry_failed()
        for _ in range(200):
            if failed.status == TransferState.COMPLETED:
                break
            time.sleep(0.005)
        self.assertEqual(attempts, {"failed": 2, "completed": 1})
        self.assertEqual(cancelled.status, TransferState.CANCELLED)
        scheduler.shutdown()


class ParallelResumeSchedulerTests(unittest.TestCase):
    def setUp(self):
        self.clients = []
        self.transport = FakeTransport()
        self.browsing_client = object()
        self.clock_value = 0.0

    def clock(self):
        return self.clock_value

    def scheduler(self, **kwargs):
        return TransferScheduler(
            lambda: ResumeSFTP(self, self.transport),
            concurrency=3,
            clock=self.clock,
            monitor_interval=1000,
            **kwargs,
        )

    def wait_for(self, predicate, message="condition was not reached"):
        for _ in range(200):
            if predicate():
                return
            time.sleep(0.005)
        self.fail(message)

    @staticmethod
    def resumed_operation(item, client, worker):
        item.resume_offset = 2
        item.transferred = 2
        worker.mark_resuming()
        data = client.read()
        client.write(data)
        worker.checkpoint(item.resume_offset + len(data), item.resume_offset + len(data))

    def test_three_resumed_downloads_own_independent_clients_and_channels(self):
        scheduler = self.scheduler(debug_transfers=True)
        rows = [
            scheduler.enqueue(TransferItem(str(index), str(index), "Download", total=5), self.resumed_operation)
            for index in range(3)
        ]
        self.wait_for(lambda: all(row.status == TransferState.COMPLETED for row in rows))
        self.assertEqual([row.transferred for row in rows], [5, 5, 5])
        self.assertEqual(len({id(client) for client in self.clients}), 3)
        self.assertEqual({client.channel_id for client in self.clients}, {1, 2, 3})
        self.assertNotIn(self.browsing_client, self.clients)
        self.assertTrue(all(client.reads == 1 and client.writes == 3 for client in self.clients))
        states = [event["state"] for event in scheduler.diagnostic_events if event["transfer_id"] == rows[0].item_id]
        self.assertLess(states.index(TransferState.RESUMING), states.index(TransferState.DOWNLOADING))
        self.assertTrue(all(client.closed for client in self.clients))
        self.assertTrue(self.transport.active)
        scheduler.shutdown()

    def test_client_factory_runs_without_the_scheduler_lock(self):
        lock_was_free = threading.Event()
        scheduler: TransferScheduler | None = None

        def factory():
            assert scheduler is not None
            acquired = scheduler._condition.acquire(blocking=False)
            if acquired:
                scheduler._condition.release()
                lock_was_free.set()
            return ResumeSFTP(self, self.transport)

        scheduler = TransferScheduler(factory, concurrency=1, monitor_interval=1000)
        row = scheduler.enqueue(TransferItem("a", "a", "Download", total=5), self.resumed_operation)
        self.wait_for(lambda: row.status == TransferState.COMPLETED)
        self.assertTrue(lock_was_free.is_set())
        scheduler.shutdown()

    def test_reuse_worker_channels_across_sequential_items(self):
        created = []

        def factory():
            client = FakeSFTP(self)
            created.append(client)
            return client

        scheduler = TransferScheduler(factory, concurrency=1, reuse_worker_channels=True)
        seen = []

        def operation(item, client, worker):
            seen.append(id(client))
            worker.checkpoint(item.total or 0, item.total)

        rows = [scheduler.enqueue(TransferItem(str(i), str(i), "Upload", total=1), operation) for i in range(3)]
        for _ in range(200):
            if all(row.status == TransferState.COMPLETED for row in rows):
                break
            time.sleep(0.005)
        self.assertEqual(len(created), 1)
        self.assertEqual(len(set(seen)), 1)
        scheduler.shutdown()
        self.assertTrue(created[0].closed)

    def test_stall_fails_one_worker_without_blocking_other_resumes(self):
        entered = threading.Event()
        changes = []

        def stalled(item, client, worker):
            item.resume_offset = 2
            item.transferred = 2
            worker.mark_resuming()
            entered.set()
            while not client.closed:
                time.sleep(0.002)
            worker.checkpoint(3, 5)

        scheduler = TransferScheduler(
            lambda: ResumeSFTP(self, self.transport),
            concurrency=3,
            clock=self.clock,
            on_change=lambda: changes.append(True),
            stall_timeout=2,
            monitor_interval=1000,
        )
        stuck = scheduler.enqueue(TransferItem("stuck", "stuck", "Download", total=5), stalled)
        good = [
            scheduler.enqueue(TransferItem(str(index), str(index), "Download", total=5), self.resumed_operation)
            for index in range(2)
        ]
        self.wait_for(entered.is_set)
        self.wait_for(lambda: all(row.status == TransferState.COMPLETED for row in good))
        self.clock_value = 3.0
        self.assertEqual(scheduler.check_stalls(), [stuck.item_id])
        self.wait_for(lambda: stuck.item_id not in scheduler._threads)
        self.assertEqual(stuck.status, TransferState.FAILED)
        self.assertIn("stalled", stuck.error)
        self.assertEqual(scheduler.active_count, 0)
        self.assertTrue(self.transport.active)
        self.assertGreater(len(changes), 0)
        self.assertEqual(scheduler.summary()["completed"], 2)
        scheduler.shutdown()

    def test_stalled_partial_is_preserved_and_retry_uses_durable_offset(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "data.bin"
            partial = partial_download_path(destination)
            partial.write_bytes(b"ab")
            write_partial_download_metadata(
                destination,
                remote_identity="profile:test",
                remote_path="/data.bin",
                remote_size=5,
                remote_mtime=1,
                completed_bytes=2,
                now=0,
            )
            first = threading.Event()

            def operation(item, client, worker):
                item.resume_offset = 2
                item.transferred = 2
                worker.mark_resuming()
                if not first.is_set():
                    first.set()
                    while not client.closed:
                        time.sleep(0.002)
                    worker.checkpoint(3, 5)
                with partial.open("ab") as handle:
                    handle.write(b"xyz")
                write_partial_download_metadata(
                    destination,
                    remote_identity="profile:test",
                    remote_path="/data.bin",
                    remote_size=5,
                    remote_mtime=1,
                    completed_bytes=5,
                    now=4,
                )
                worker.checkpoint(5, 5)

            scheduler = self.scheduler(stall_timeout=2)
            row = scheduler.enqueue(TransferItem("remote", str(destination), "Download", total=5), operation)
            self.wait_for(first.is_set)
            self.clock_value = 3.0
            scheduler.check_stalls()
            self.wait_for(lambda: row.item_id not in scheduler._threads)
            self.assertEqual(partial.read_bytes(), b"ab")
            self.assertEqual(partial_download_metadata_path(destination).is_file(), True)
            self.assertTrue(scheduler.retry(row.item_id))
            self.wait_for(lambda: row.status == TransferState.COMPLETED)
            self.assertEqual(partial.read_bytes(), b"abxyz")
            self.assertEqual(row.transferred, 5)
            scheduler.shutdown()


if __name__ == "__main__":
    unittest.main()
