"""Display-free bounded-concurrency SFTP transfer scheduler tests."""

import threading
import time
import unittest

from sshvault_core import TransferBatch, TransferItem, TransferScheduler, TransferState


class FakeSFTP:
    def __init__(self, owner):
        self.owner = owner
        self.closed = False
        owner.clients.append(self)

    def close(self):
        self.closed = True


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


if __name__ == "__main__":
    unittest.main()
