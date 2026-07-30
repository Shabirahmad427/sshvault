from __future__ import annotations

import unittest

from sshvault_core import (
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPTransferRouter,
    TransferItem,
    TransferScheduler,
    TransferState,
    sftp_transfer_control_states,
    sftp_transfer_queue_rows,
)


class _BrowserChannel:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class SFTPTransferQueueTests(unittest.TestCase):
    def test_queue_change_notifications_and_shared_rows(self) -> None:
        notifications: list[int] = []
        scheduler = TransferScheduler(None, on_change=lambda: notifications.append(len(scheduler.items)))
        try:
            first = SFTPTransferRouter(scheduler)
            second = SFTPTransferRouter(scheduler)
            scheduler.enqueue(TransferItem("/local/one", "/remote/one", "Upload", total=10))
            self.assertEqual(notifications, [1])
            self.assertEqual(
                sftp_transfer_queue_rows(first.scheduler.items), sftp_transfer_queue_rows(second.scheduler.items)
            )
        finally:
            scheduler.shutdown()

    def test_progress_speed_eta_and_status_display(self) -> None:
        item = TransferItem(
            "/remote/file.txt",
            "/local/file.txt",
            "Download",
            total=100,
            transferred=25,
            speed=10,
            status=TransferState.DOWNLOADING,
        )
        row = sftp_transfer_queue_rows([item])[0]
        self.assertEqual(row.file, "file.txt")
        self.assertEqual(row.direction, "Download")
        self.assertEqual(row.progress, "25.0%")
        self.assertEqual(row.speed, "10 B/s")
        self.assertEqual(row.eta, "8s")
        self.assertEqual(row.status, TransferState.DOWNLOADING)

    def test_pause_resume_and_cancel(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            item = scheduler.enqueue(TransferItem("source", "target", "Upload", total=10))
            self.assertTrue(scheduler.pause(item.item_id))
            self.assertEqual(item.status, TransferState.PAUSED)
            self.assertTrue(scheduler.resume(item.item_id))
            self.assertTrue(scheduler.cancel(item.item_id))
            self.assertEqual(item.status, TransferState.CANCELLED)
        finally:
            scheduler.shutdown()

    def test_retry_and_remove_completed(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            failed = scheduler.record(TransferItem("failed", "target", "Upload", status=TransferState.FAILED))
            completed = scheduler.record(TransferItem("done", "target", "Download", status=TransferState.COMPLETED))
            self.assertTrue(scheduler.retry(failed.item_id))
            scheduler.clear_completed()
            self.assertIsNone(scheduler.get(completed.item_id))
            self.assertIsNotNone(scheduler.get(failed.item_id))
        finally:
            scheduler.shutdown()

    def test_transfer_control_states(self) -> None:
        paused = TransferItem("source", "target", "Upload", status=TransferState.PAUSED)
        completed = TransferItem("done", "target", "Upload", status=TransferState.COMPLETED)
        states = sftp_transfer_control_states(paused, [paused, completed])
        self.assertFalse(states["pause"])
        self.assertTrue(states["resume"])
        self.assertTrue(states["cancel"])
        self.assertFalse(states["retry"])
        self.assertTrue(states["remove_completed"])

    def test_closing_window_client_does_not_cancel_shared_scheduler(self) -> None:
        scheduler = TransferScheduler(None)
        registry = SFTPBrowserRegistry()
        first_channel, second_channel = _BrowserChannel(), _BrowserChannel()
        registry.register("session", "first", SFTPBrowserClient(first_channel))
        registry.register("session", "second", SFTPBrowserClient(second_channel))
        try:
            item = scheduler.enqueue(TransferItem("source", "target", "Upload", total=10))
            registry.close_view("session", "first")
            self.assertTrue(first_channel.closed)
            self.assertFalse(second_channel.closed)
            self.assertFalse(scheduler.closed)
            self.assertIs(scheduler.get(item.item_id), item)
        finally:
            scheduler.shutdown()

    def test_two_routers_do_not_create_a_second_scheduler(self) -> None:
        scheduler = TransferScheduler(None)
        try:
            first = SFTPTransferRouter(scheduler)
            second = SFTPTransferRouter(scheduler)
            self.assertIs(first.scheduler, scheduler)
            self.assertIs(second.scheduler, scheduler)
        finally:
            scheduler.shutdown()


if __name__ == "__main__":
    unittest.main()
