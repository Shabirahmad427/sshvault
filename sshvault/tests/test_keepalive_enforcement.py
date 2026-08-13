"""Per-session missed SSH keepalive enforcement regressions."""

from types import SimpleNamespace
import threading
import unittest

from sshvault import ConnectionTab
from sshvault_core import SessionKeepaliveState


class _Reconnect:
    def __init__(self) -> None:
        self.losses: list[int] = []

    def unexpected_loss(self, generation: int) -> bool:
        self.losses.append(generation)
        return True


class _KeepaliveHarness:
    _stop_keepalive_monitor = ConnectionTab._stop_keepalive_monitor
    _schedule_keepalive_tick = ConnectionTab._schedule_keepalive_tick
    _record_keepalive_result = ConnectionTab._record_keepalive_result
    _keepalive_tick = ConnectionTab._keepalive_tick
    _start_keepalive_monitor = ConnectionTab._start_keepalive_monitor
    _on_connection_lost = ConnectionTab._on_connection_lost

    def __init__(self, session_id: str, *, interval: int = 10, maximum: int = 3) -> None:
        self.session_id = session_id
        self._session_generation = 7
        self._workspace_state = SimpleNamespace(status="connected")
        self._keepalive_interval = interval
        self._keepalive_state = SessionKeepaliveState(session_id, maximum)
        self._keepalive_generation = 0
        self._keepalive_after_id = None
        self._keepalive_probe = None
        self._reconnect_controller = _Reconnect()
        self.scheduled = []
        self.cancelled = []
        self.status_messages = []
        self._profile = {
            "connection_options": {
                "ssh_preferences": {
                    "keepalive_interval": interval,
                    "maximum_missed_keepalives": maximum,
                }
            }
        }
        self._client = None

    def after(self, delay, callback):
        self.scheduled.append((delay, callback))
        return f"after-{len(self.scheduled)}"

    def after_cancel(self, identifier) -> None:
        self.cancelled.append(identifier)

    def _session_profile_snapshot(self):
        return self._profile

    def _set_workspace_status(self, status, message="") -> None:
        self._workspace_state.status = status
        self.status_messages.append((status, message))

    def winfo_toplevel(self):
        return object()


class KeepaliveEnforcementTests(unittest.TestCase):
    def test_successful_keepalive_resets_consecutive_missed_count(self) -> None:
        state = SessionKeepaliveState("sahmaddo", 3)
        self.assertFalse(state.record(False))
        self.assertFalse(state.record(False))
        self.assertFalse(state.record(True))
        self.assertEqual((state.missed, state.unhealthy), (0, False))

    def test_async_transport_probe_success_resets_session_counter(self) -> None:
        completed = threading.Event()

        class Transport:
            def global_request(self, kind, wait=True):
                self.request = (kind, wait)
                completed.set()
                return True

            @staticmethod
            def is_active():
                return True

        transport = Transport()
        tab = _KeepaliveHarness("sahmaddo", maximum=3)
        tab._keepalive_state.record(False)
        tab._client = type("Client", (), {"get_transport": lambda _self: transport})()
        generation = tab._keepalive_generation
        tab._keepalive_tick(generation, 7)
        self.assertTrue(completed.wait(0.5))
        tab._keepalive_tick(generation, 7)
        self.assertEqual(tab._keepalive_state.missed, 0)
        self.assertEqual(transport.request, ("keepalive@openssh.com", True))

    def test_consecutive_failures_increment_counter(self) -> None:
        state = SessionKeepaliveState("sahmaddo", 3)
        self.assertFalse(state.record(False))
        self.assertEqual(state.missed, 1)
        self.assertFalse(state.record(False))
        self.assertEqual(state.missed, 2)

    def test_threshold_reached_triggers_existing_recovery_policy(self) -> None:
        tab = _KeepaliveHarness("sahmaddo", maximum=2)
        self.assertFalse(tab._record_keepalive_result(False, 7))
        self.assertTrue(tab._record_keepalive_result(False, 7))
        self.assertEqual(tab._keepalive_state.missed, 2)
        self.assertTrue(tab._keepalive_state.unhealthy)
        self.assertEqual(tab._reconnect_controller.losses, [7])
        self.assertEqual(tab._workspace_state.status, "failed")
        self.assertIn("Keepalive responses missed", tab.status_messages[-1][1])

    def test_below_threshold_does_not_disconnect(self) -> None:
        tab = _KeepaliveHarness("sahmaddo", maximum=3)
        self.assertFalse(tab._record_keepalive_result(False, 7))
        self.assertFalse(tab._record_keepalive_result(False, 7))
        self.assertEqual(tab._workspace_state.status, "connected")
        self.assertEqual(tab._reconnect_controller.losses, [])

    def test_zero_keepalive_interval_schedules_nothing(self) -> None:
        tab = _KeepaliveHarness("sahmaddo", interval=0)
        tab._start_keepalive_monitor(7)
        self.assertEqual(tab.scheduled, [])
        self.assertEqual(tab._keepalive_state.missed, 0)

    def test_reconnect_resets_missed_count_and_schedules_new_generation(self) -> None:
        tab = _KeepaliveHarness("sahmaddo", interval=12, maximum=3)
        tab._keepalive_state.record(False)
        tab._keepalive_state.record(False)
        previous_generation = tab._keepalive_generation
        tab._start_keepalive_monitor(7)
        self.assertEqual((tab._keepalive_state.missed, tab._keepalive_state.unhealthy), (0, False))
        self.assertGreater(tab._keepalive_generation, previous_generation)
        self.assertEqual(tab.scheduled[0][0], 12_000)

    def test_session_keepalive_failures_are_isolated(self) -> None:
        sahmaddo = _KeepaliveHarness("sahmaddo", maximum=1)
        clauberh = _KeepaliveHarness("clauberh", maximum=2)
        self.assertTrue(sahmaddo._record_keepalive_result(False, 7))
        self.assertEqual(sahmaddo._reconnect_controller.losses, [7])
        self.assertEqual(clauberh._reconnect_controller.losses, [])
        self.assertEqual(clauberh._workspace_state.status, "connected")
        self.assertEqual(clauberh._keepalive_state.missed, 0)


if __name__ == "__main__":
    unittest.main()
