from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path

from sshvault import ConnectionTab, SSHVaultApp
from sshvault_core import (
    SFTPBrowserClient,
    SFTPBrowserRegistry,
    SFTPViewNavigationState,
    SessionController,
    SessionLifecycleState,
    TransferItem,
    TransferScheduler,
    TransferState,
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
    @staticmethod
    def _connected_session(controller: SessionController, profile_id: str):
        record = controller.create_session({"id": profile_id, "host": "host", "user": profile_id})
        record.state = SessionLifecycleState.CONNECTED
        return record

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

    def test_browser_registry_replaces_old_client_without_closing_new_client(self) -> None:
        registry = SFTPBrowserRegistry()
        old_channel, new_channel = _Channel(), _Channel()
        old_client, new_client = SFTPBrowserClient(old_channel), SFTPBrowserClient(new_channel)
        registry.register("session", "view", old_client)
        self.assertIs(registry.replace("session", "view", new_client), old_client)
        self.assertEqual((old_channel.close_count, new_channel.close_count), (1, 0))
        self.assertIs(registry.get("session", "view"), new_client)

    def test_manual_and_automatic_reconnect_rebind_open_view_and_navigation(self) -> None:
        for mode in ("manual", "automatic"):
            with self.subTest(mode=mode):
                controller = SessionController()
                record = self._connected_session(controller, mode)
                old_channel, new_channel = _Channel(), _Channel()
                registry = SFTPBrowserRegistry()
                registry.register(record.session_id, "view", SFTPBrowserClient(old_channel))
                state = SFTPViewNavigationState(
                    local_current_path="/local",
                    remote_current_path="/remote/work",
                    remote_back_history=["/remote"],
                    remote_forward_history=["/remote/next"],
                )
                snapshots = []

                def rebind(_client) -> None:
                    registry.replace(record.session_id, "view", SFTPBrowserClient(new_channel))
                    state.mark_remote_reconnected(True)
                    snapshots.append(
                        (
                            state.local_current_path,
                            state.remote_current_path,
                            list(state.remote_back_history),
                            list(state.remote_forward_history),
                        )
                    )

                app = type(
                    "App",
                    (),
                    {
                        "_rebind_sftp_resources_for_session": SSHVaultApp._rebind_sftp_resources_for_session,
                        "_sftp_view_rebind_callbacks": {"view": (record.session_id, rebind)},
                        "_sftp_transfer_schedulers": {},
                    },
                )()
                app._rebind_sftp_resources_for_session(record.session_id, object())
                self.assertEqual((old_channel.close_count, new_channel.close_count), (1, 0))
                self.assertTrue(registry.get(record.session_id, "view").is_alive())
                self.assertEqual(snapshots, [("/local", "/remote/work", ["/remote"], ["/remote/next"])])

    def test_manual_reconnect_suspends_session_sftp_before_connecting(self) -> None:
        events = []
        controller = type(
            "Reconnect",
            (),
            {
                "new_session": lambda self: events.append("new-session"),
                "reconnect_now": lambda self: events.append("reconnect"),
            },
        )()
        app = type(
            "App",
            (),
            {"_suspend_sftp_resources_for_reconnect": lambda self, session_id: events.append(session_id)},
        )()
        tab = type(
            "Tab",
            (),
            {
                "session_id": "session",
                "_reconnect_controller": controller,
                "winfo_toplevel": lambda self: app,
                "_reconnect_now": ConnectionTab._reconnect_now,
            },
        )()
        tab._reconnect_now()
        self.assertEqual(events, ["session", "new-session", "reconnect"])

    def test_automatic_connection_loss_suspends_session_sftp(self) -> None:
        events = []
        reconnect = type(
            "Reconnect",
            (),
            {"unexpected_loss": lambda self, generation: events.append(("automatic", generation))},
        )()
        app = type(
            "App",
            (),
            {"_suspend_sftp_resources_for_reconnect": lambda self, session_id: events.append(session_id)},
        )()
        tab = type(
            "Tab",
            (),
            {
                "session_id": "session",
                "_session_generation": 7,
                "_workspace_state": type("State", (), {"status": "connected"})(),
                "_reconnect_controller": reconnect,
                "winfo_toplevel": lambda self: app,
                "_set_workspace_status": lambda self, *_args: None,
                "_on_connection_lost": ConnectionTab._on_connection_lost,
            },
        )()
        tab._on_connection_lost(7)
        self.assertEqual(events, ["session", ("automatic", 7)])

    def test_scheduler_rebind_resumes_paused_transfer_on_new_factory(self) -> None:
        old_channels: list[_Channel] = []
        new_channels: list[_Channel] = []

        def old_factory():
            channel = _Channel()
            old_channels.append(channel)
            return channel

        def new_factory():
            channel = _Channel()
            new_channels.append(channel)
            return channel

        scheduler = TransferScheduler(old_factory, concurrency=1, session_id="session")
        item = TransferItem("source", "target", "Upload")

        def operation(_item, _client, worker) -> None:
            worker.checkpoint(1, 1)

        scheduler._suspended_for_reconnect = True
        scheduler.enqueue(item, operation)
        scheduler.pause(item.item_id)
        try:
            scheduler.suspend_for_reconnect()
            scheduler.rebind_client_factory(new_factory)
            self.assertEqual(item.status, TransferState.PAUSED)
            self.assertTrue(scheduler.resume(item.item_id))
            deadline = time.monotonic() + 1
            while item.status not in TransferState.TERMINAL and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertEqual(item.status, TransferState.COMPLETED)
            self.assertEqual(old_channels, [])
            self.assertEqual(len(new_channels), 1)
        finally:
            scheduler.shutdown()

    def test_rebinding_one_session_does_not_affect_other_session(self) -> None:
        controller = SessionController()
        first = self._connected_session(controller, "sahmaddo")
        second = self._connected_session(controller, "clauberh")
        first_old, first_new, second_channel = _Channel(), _Channel(), _Channel()
        registry = SFTPBrowserRegistry()
        registry.register(first.session_id, "first-view", SFTPBrowserClient(first_old))
        registry.register(second.session_id, "second-view", SFTPBrowserClient(second_channel))

        def rebind_first(_client) -> None:
            registry.replace(first.session_id, "first-view", SFTPBrowserClient(first_new))

        second_called = []
        app = type(
            "App",
            (),
            {
                "_rebind_sftp_resources_for_session": SSHVaultApp._rebind_sftp_resources_for_session,
                "_sftp_view_rebind_callbacks": {
                    "first-view": (first.session_id, rebind_first),
                    "second-view": (second.session_id, lambda _client: second_called.append(True)),
                },
                "_sftp_transfer_schedulers": {},
            },
        )()
        app._rebind_sftp_resources_for_session(first.session_id, object())
        self.assertEqual((first_old.close_count, first_new.close_count, second_channel.close_count), (1, 0, 0))
        self.assertEqual(second_called, [])
        self.assertTrue(registry.get(second.session_id, "second-view").is_alive())


if __name__ == "__main__":
    unittest.main()
