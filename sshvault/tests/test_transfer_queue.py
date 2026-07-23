import tempfile
import unittest
from pathlib import Path
from sshvault_core import ProfileError, TransferItem, TransferQueueManager, safe_transfer_plan


class TransferQueueTests(unittest.TestCase):
    def item(self, name, direction="upload"):
        return TransferItem(name, "/remote/" + name, direction, total=100)

    def test_fifo_pause_cancel_retry_and_clear(self):
        q = TransferQueueManager(2)
        a = q.enqueue(self.item("a"))
        b = q.enqueue(self.item("b"))
        self.assertIs(q.active, a)
        q.mark_transferring()
        self.assertTrue(q.pause(a.item_id))
        self.assertTrue(q.resume(a.item_id))
        q.complete(a.item_id)
        self.assertIs(q.active, b)
        q.mark_transferring()
        q.complete(b.item_id)
        self.assertEqual(b.status, "Completed")
        q.clear_completed()
        self.assertFalse(q.items)

    def test_move_and_stale_generation(self):
        q = TransferQueueManager(1)
        a = q.enqueue(self.item("a"))
        q.complete(a.item_id, error="failed")
        q.retry_failed()
        self.assertEqual(a.status, "Preparing")
        q.generation = 2
        self.assertFalse(q.complete(a.item_id))

    def test_recursive_plan_and_traversal(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "folder").mkdir()
            (root / "folder" / "a.txt").write_text("a")
            self.assertEqual(safe_transfer_plan(root, ["folder"])[0][1], "folder/a.txt")
            with self.assertRaises(ProfileError):
                safe_transfer_plan(root, ["../outside"])

    def test_unknown_size_and_shutdown(self):
        q = TransferQueueManager()
        item = q.enqueue(TransferItem("a", "b", "download"))
        self.assertIsNone(item.progress())
        q.shutdown()
        self.assertEqual(item.status, "Cancelled")


if __name__ == "__main__":
    unittest.main()
