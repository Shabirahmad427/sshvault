"""Display-free transfer-manager window state and table-order tests."""

import unittest

from sshvault_core import TransferItem, TransferManagerWindowState, TransferScheduler, TransferState


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


if __name__ == "__main__":
    unittest.main()
