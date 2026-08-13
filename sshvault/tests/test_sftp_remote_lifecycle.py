from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from sshvault import SSHVaultApp
from sshvault_core import (
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPViewNavigationState,
    SessionController,
    TransferItem,
    TransferScheduler,
    list_local_browser_entries,
)


class _Channel:
    def __init__(self) -> None:
        self.active = True
        self.closed = False
        self.close_count = 0

    def get_channel(self) -> "_Channel":
        return self

    def close(self) -> None:
        self.close_count += 1
        self.closed = True
        self.active = False


class RemoteLifecycleTests(unittest.TestCase):
    def test_closing_sftp_view_returns_immediately_and_keeps_transfer(self) -> None:
        release = threading.Event()
        close_entered = threading.Event()

        class SlowChannel(_Channel):
            def close(self) -> None:
                close_entered.set()
                release.wait(1)
                super().close()

        class Window:
            destroyed = False

            def destroy(self):
                self.destroyed = True

        controller = SessionController()
        session = controller.create_session({"id": "profile", "host": "host", "user": "user"})
        controller.register_sftp_view(session.session_id, "view")
        registry = SFTPBrowserRegistry()
        registry.register(session.session_id, "view", SFTPBrowserClient(SlowChannel()))
        scheduler = TransferScheduler()
        transfer = scheduler.record(TransferItem("source", "target", "Upload"))
        window = Window()
        app = type(
            "App",
            (),
            {
                "_close_sftp_views_for_session": SSHVaultApp._close_sftp_views_for_session,
                "_session_controller": controller,
                "_sftp_browser_clients": registry,
                "_sftp_views": {"view": window},
                "_sftp_view_state_callbacks": {"view": object()},
                "_sftp_transfer_status_callbacks": {"view": object()},
                "_sftp_transfer_queue_callbacks": {"view": object()},
                "_refresh_sessions": lambda self: None,
            },
        )()
        try:
            started = time.monotonic()
            app._close_sftp_views_for_session(session.session_id)
            self.assertLess(time.monotonic() - started, 0.2)
            self.assertTrue(window.destroyed)
            self.assertTrue(close_entered.wait(0.5))
            self.assertIs(scheduler.get(transfer.item_id), transfer)
            self.assertFalse(scheduler.closed)
        finally:
            release.set()
            scheduler.shutdown()

    def test_disconnect_disables_remote_controls_state(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/remote")
        state.mark_remote_disconnected()
        self.assertFalse(state.remote_available)
        self.assertFalse(state.remote_loading)
        self.assertEqual(state.last_remote_error, "Disconnected")

    def test_local_pane_remains_usable_after_remote_disconnect(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            Path(root, "local.txt").write_text("local")
            state = SFTPViewNavigationState(local_current_path=root)
            local_generation = state.local_generation
            state.mark_remote_disconnected()
            self.assertEqual([entry.name for entry in list_local_browser_entries(root)], ["local.txt"])
            self.assertEqual(state.local_current_path, root)
            self.assertEqual(state.local_generation, local_generation)

    def test_disconnect_preserves_remote_listing_path_and_history(self) -> None:
        displayed = ["one", "two"]
        state = SFTPViewNavigationState(
            remote_current_path="/remote",
            remote_back_history=["/old"],
            remote_forward_history=["/new"],
        )
        before = (
            state.remote_current_path,
            list(state.remote_back_history),
            list(state.remote_forward_history),
            list(displayed),
        )
        state.mark_remote_disconnected()
        self.assertEqual(
            before,
            (
                state.remote_current_path,
                state.remote_back_history,
                state.remote_forward_history,
                displayed,
            ),
        )

    def test_pending_callback_is_stale_after_disconnect(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/remote")
        generation = state.begin_remote_listing()
        state.mark_remote_disconnected()
        self.assertFalse(state.complete_remote_listing(generation, "/stale"))
        self.assertEqual(state.remote_current_path, "/remote")

    def test_reconnect_enables_controls_without_loading(self) -> None:
        state = SFTPViewNavigationState(remote_current_path="/remote")
        state.mark_remote_disconnected()
        generation = state.remote_generation
        self.assertTrue(state.mark_remote_reconnected(True))
        self.assertTrue(state.remote_available)
        self.assertFalse(state.remote_loading)
        self.assertEqual(state.remote_generation, generation)
        self.assertEqual(state.remote_current_path, "/remote")

    def test_closing_view_unregisters_and_closes_only_its_client(self) -> None:
        controller = SessionController()
        session = controller.create_session(
            {
                "name": "Test",
                "host": "host.example",
                "port": 22,
                "user": "alice",
                "auth_method": "agent",
            }
        )
        channel = _Channel()
        client = SFTPBrowserClient(channel)
        registry = SFTPBrowserRegistry()
        registry.register(session.session_id, "view", client)
        controller.register_sftp_view(session.session_id, "view")
        controller.unregister_sftp_view(session.session_id, "view")
        self.assertTrue(registry.close_view(session.session_id, "view"))
        self.assertNotIn("view", session.sftp_view_ids)
        self.assertFalse(client.is_alive())
        self.assertEqual(channel.close_count, 1)
        self.assertFalse(registry.close_view(session.session_id, "view"))
        self.assertEqual(channel.close_count, 1)


if __name__ == "__main__":
    unittest.main()
