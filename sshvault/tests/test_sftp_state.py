"""Display-free SFTP presentation and transfer-state tests."""

from __future__ import annotations

import unittest

from sshvault_core import DirectoryLoadState, SFTPPanelState


class SFTPPanelStateTests(unittest.TestCase):
    def test_loading_and_folder_first_sorting(self) -> None:
        state = SFTPPanelState()
        self.assertEqual((state.local_state, state.remote_state), ("loading", "loading"))
        items = [{"name": "z.txt", "is_dir": False}, {"name": "b", "is_dir": True}, {"name": "a", "is_dir": True}]
        self.assertEqual([item["name"] for item in state.folder_first(items)], ["a", "b", "z.txt"])

    def test_size_format_and_selection_actions(self) -> None:
        self.assertEqual(SFTPPanelState.format_size(1024), "1 KB")
        state = SFTPPanelState()
        self.assertTrue(state.action_enabled(local_selected=True, remote_selected=True)["upload"])
        self.assertTrue(state.action_enabled(local_selected=True, remote_selected=True)["download"])

    def test_progress_cancellation_completion_and_disconnect_style_failure(self) -> None:
        state = SFTPPanelState()
        state.start_transfer("report.txt", now=10.0)
        self.assertEqual(state.progress(50, 200, now=11.0), 25.0)
        self.assertEqual(state.progress_text(now=12.0), "50 B / 200 B (25%) · 25 B/s")
        self.assertTrue(state.action_enabled(local_selected=True, remote_selected=True)["cancel"])
        state.cancel()
        self.assertEqual(state.transfer_state, "cancelled")
        state.start_transfer("report.txt")
        state.complete()
        self.assertEqual(state.transfer_state, "complete")
        state.fail("password=secret")
        self.assertEqual(state.transfer_state, "failed")
        self.assertNotIn("secret", state.message)

    def test_zero_size_progress_has_no_division_error(self) -> None:
        state = SFTPPanelState()
        state.start_transfer("empty", now=1.0)
        self.assertEqual(state.progress(0, 0, now=2.0), 0.0)
        self.assertIn("unknown size", state.progress_text(now=2.0))

    def test_partial_cleanup_policy_reports_cancelled_or_failed_without_secrets(self) -> None:
        state = SFTPPanelState()
        state.start_transfer("partial", now=1.0)
        state.cancel()
        self.assertIn("Partial data", state.message)
        state.start_transfer("partial", now=2.0)
        state.fail("token=secret")
        self.assertNotIn("secret", state.message)

    def test_no_overwrite_policy_is_represented_by_explicit_action_state(self) -> None:
        # Collision decisions are deliberately explicit UI actions; state has
        # no automatic replace mode.
        state = SFTPPanelState()
        self.assertEqual(state.transfer_state, "idle")
        self.assertFalse(state.action_enabled(local_selected=False, remote_selected=False)["upload"])


class DirectoryLoadStateTests(unittest.TestCase):
    def test_load_starts_loading_and_accepts_current_dispatch_result(self) -> None:
        state = DirectoryLoadState()
        token = state.request()
        self.assertEqual(state.state, "loading")
        self.assertTrue(state.pending)
        self.assertTrue(state.accepts(token))
        self.assertTrue(state.finish(token, success=True))
        self.assertEqual(state.state, "ready")

    def test_stale_slow_result_cannot_overwrite_newer_navigation(self) -> None:
        state = DirectoryLoadState()
        old = state.request()
        new = state.request()
        self.assertFalse(state.finish(old, success=True))
        self.assertTrue(state.finish(new, success=True))
        self.assertEqual(state.state, "ready")

    def test_repeated_refresh_invalidates_without_accepting_older_result(self) -> None:
        state = DirectoryLoadState()
        first = state.request()
        second = state.request()
        third = state.request()
        self.assertFalse(state.accepts(first))
        self.assertFalse(state.accepts(second))
        self.assertTrue(state.accepts(third))

    def test_close_suppresses_late_success_and_error_results(self) -> None:
        state = DirectoryLoadState()
        token = state.request()
        state.close()
        self.assertFalse(state.finish(token, success=True))
        self.assertFalse(state.finish(token, success=False))
        self.assertTrue(state.closed)

    def test_error_state_is_current_result_only(self) -> None:
        state = DirectoryLoadState()
        token = state.request()
        self.assertTrue(state.finish(token, success=False))
        self.assertEqual(state.state, "error")
