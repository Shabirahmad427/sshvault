"""Display-free transfer-manager window state and table-order tests."""

from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from sshvault import SSHVaultApp, SessionTransferManagerWindow
from sshvault_core import (
    SessionLifecycleState,
    TransferItem,
    TransferManagerWindowState,
    TransferScheduler,
    TransferState,
)


class TransferManagerWindowStateTests(unittest.TestCase):
    def test_default_window_state_is_safe(self):
        state = TransferManagerWindowState.from_settings(None)
        self.assertEqual(state.geometry_for_screen(1920, 1080), (1180, 430, 370, 325))

    def test_offscreen_geometry_is_centered(self):
        state = TransferManagerWindowState.from_settings({"width": 900, "height": 500, "x": 5000, "y": -100})
        self.assertEqual(state.geometry_for_screen(1600, 900), (900, 500, 350, 200))

    def test_geometry_and_maximize_persist(self):
        state = TransferManagerWindowState(
            width=800,
            height=400,
            x=20,
            y=30,
            maximized=True,
            column_widths={"name": 240},
            column_order=["name", "speed"],
            sort_column="speed",
            sort_descending=True,
        )
        restored = TransferManagerWindowState.from_settings(state.to_settings())
        self.assertEqual(restored.to_settings(), state.to_settings())

    def test_column_widths_are_bounded(self):
        state = TransferManagerWindowState.from_settings({"column_widths": {"name": 1, "error": 9000}})
        self.assertEqual(state.column_widths, {"name": 40, "error": 2000})

    def test_sorting_is_display_only(self):
        scheduler = TransferScheduler()
        first = scheduler.record(TransferItem("z", "a", "Download", total=10))
        second = scheduler.record(TransferItem("a", "b", "Upload", total=20))
        state = TransferManagerWindowState(sort_column="name")
        self.assertEqual(state.sorted_ids(scheduler.items, lambda item: item.source), [second.item_id, first.item_id])
        self.assertEqual([item.item_id for item in scheduler.items], [first.item_id, second.item_id])

    def test_queue_order_view_preserves_scheduler_order(self):
        scheduler = TransferScheduler()
        first = scheduler.record(TransferItem("b", "a", "Download"))
        second = scheduler.record(TransferItem("a", "b", "Download"))
        self.assertEqual(TransferManagerWindowState().sorted_ids(scheduler.items), [first.item_id, second.item_id])

    def test_selection_ids_survive_a_table_rebuild(self):
        scheduler = TransferScheduler()
        first = scheduler.record(TransferItem("a", "a", "Download"))
        selected = {first.item_id}
        rebuilt = {item.item_id for item in scheduler.items}
        self.assertEqual(selected & rebuilt, selected)

    def test_hiding_a_view_does_not_touch_scheduler(self):
        scheduler = TransferScheduler()
        item = scheduler.record(TransferItem("a", "a", "Download", status=TransferState.DOWNLOADING))
        self.assertEqual(scheduler.get(item.item_id).status, TransferState.DOWNLOADING)

    def test_window_settings_have_a_stable_sort_default(self):
        self.assertEqual(TransferManagerWindowState.from_settings({"sort_column": "bogus"}).sort_column, "bogus")


class SessionTransferManagerRoutingTests(unittest.TestCase):
    def setUp(self):
        self.sahmaddo = TransferScheduler(None, session_id="sahmaddo-session")
        self.clauberh = TransferScheduler(None, session_id="clauberh-session")

    def tearDown(self):
        self.sahmaddo.shutdown()
        self.clauberh.shutdown()

    @staticmethod
    def _record(session_id, profile_id):
        return SimpleNamespace(
            session_id=session_id,
            state=SessionLifecycleState.CONNECTED,
            profile_snapshot={"id": profile_id, "name": profile_id, "host": "coaraci", "user": profile_id},
        )

    def _app(self, selected):
        schedulers = {
            "sahmaddo-session": self.sahmaddo,
            "clauberh-session": self.clauberh,
        }
        windows = {session_id: SimpleNamespace(winfo_exists=lambda: True, show=Mock()) for session_id in schedulers}
        app = SimpleNamespace(
            selected=selected,
            _selected_session_record=lambda: selected,
            _sftp_transfer_router=lambda record: SimpleNamespace(scheduler=schedulers[record.session_id]),
            _session_transfer_manager_windows=windows,
            _conn_tabs={},
        )
        return app, windows

    def test_selected_session_routes_to_its_manager(self):
        record = self._record("sahmaddo-session", "sahmaddo")
        app, windows = self._app(record)
        self.assertEqual(SSHVaultApp._open_transfer_manager(app), "break")
        windows[record.session_id].show.assert_called_once_with()
        windows["clauberh-session"].show.assert_not_called()

    def test_switching_profile_changes_target_manager(self):
        first = self._record("sahmaddo-session", "sahmaddo")
        second = self._record("clauberh-session", "clauberh")
        app, windows = self._app(first)
        SSHVaultApp._open_transfer_manager(app)
        app._selected_session_record = lambda: second
        SSHVaultApp._open_transfer_manager(app)
        windows[first.session_id].show.assert_called_once_with()
        windows[second.session_id].show.assert_called_once_with()

    def test_open_does_not_use_legacy_sftp_manager(self):
        record = self._record("sahmaddo-session", "sahmaddo")
        app, _windows = self._app(record)
        legacy = Mock()
        app._conn_tabs[record.session_id] = SimpleNamespace(_sftp_panel=SimpleNamespace(_show_transfer_manager=legacy))
        SSHVaultApp._open_transfer_manager(app)
        legacy.assert_not_called()

    def test_all_transfer_states_are_visible_for_owner(self):
        expected = {
            TransferState.PENDING,
            TransferState.TRANSFERRING,
            TransferState.PAUSED,
            TransferState.FAILED,
            TransferState.COMPLETED,
        }
        for status in expected:
            self.sahmaddo.record(TransferItem(status, "/target", "Upload", status=status))
        visible = SessionTransferManagerWindow.items_for_session(self.sahmaddo, "sahmaddo-session")
        self.assertEqual({item.status for item in visible}, expected)

    def test_sahmaddo_and_clauberh_queues_are_isolated(self):
        first = self.sahmaddo.record(TransferItem("sahmaddo", "/one", "Upload"))
        second = self.clauberh.record(TransferItem("clauberh", "/two", "Download"))
        self.assertEqual(SessionTransferManagerWindow.items_for_session(self.sahmaddo, "sahmaddo-session"), [first])
        self.assertEqual(SessionTransferManagerWindow.items_for_session(self.clauberh, "clauberh-session"), [second])

    def test_controls_operate_only_on_owned_scheduler(self):
        pending = self.sahmaddo.record(TransferItem("pending", "/target", "Upload"))
        paused = self.sahmaddo.record(TransferItem("paused", "/target", "Upload", status=TransferState.PAUSED))
        failed = self.sahmaddo.record(TransferItem("failed", "/target", "Upload", status=TransferState.FAILED))
        completed = self.sahmaddo.record(TransferItem("completed", "/target", "Upload", status=TransferState.COMPLETED))
        foreign = self.clauberh.record(TransferItem("foreign", "/target", "Upload"))
        action = SessionTransferManagerWindow.apply_action
        self.assertTrue(action(self.sahmaddo, "sahmaddo-session", "pause", pending.item_id))
        self.assertTrue(action(self.sahmaddo, "sahmaddo-session", "resume", paused.item_id))
        self.assertTrue(action(self.sahmaddo, "sahmaddo-session", "cancel", paused.item_id))
        self.assertTrue(action(self.sahmaddo, "sahmaddo-session", "retry", failed.item_id))
        self.assertFalse(action(self.sahmaddo, "sahmaddo-session", "pause", foreign.item_id))
        self.assertTrue(action(self.sahmaddo, "sahmaddo-session", "remove_completed"))
        self.assertIsNone(self.sahmaddo.get(completed.item_id))
        self.assertIsNotNone(self.clauberh.get(foreign.item_id))

    def test_disconnected_action_reports_concise_message(self):
        record = self._record("sahmaddo-session", "sahmaddo")
        record.state = SessionLifecycleState.DISCONNECTED
        app, windows = self._app(record)
        with patch("sshvault.messagebox.showinfo") as showinfo:
            self.assertEqual(SSHVaultApp._open_transfer_manager(app), "break")
        showinfo.assert_called_once_with("Transfer Manager", "Select a connected session.", parent=app)
        windows[record.session_id].show.assert_not_called()


if __name__ == "__main__":
    unittest.main()
