import unittest

from sshvault_core import ConnectionLogEvent, SessionDashboardState


class SessionDashboardTests(unittest.TestCase):
    def test_identity_and_safe_events(self):
        state = SessionDashboardState(profile_name="Work", host="host.test", port=2200, username="dev")
        self.assertEqual(state.identity, "dev@host.test:2200")
        state.add_event("authentication succeeded password=hidden")
        self.assertNotIn("hidden", state.events[-1].message)

    def test_event_history_is_bounded(self):
        state = SessionDashboardState(max_events=2)
        for index in range(4):
            state.add_event(f"event {index}")
        self.assertEqual([event.message for event in state.events], ["event 2", "event 3"])

    def test_status_transition_records_safe_event(self):
        state = SessionDashboardState()
        state.transition("connected", "host-key verified")
        self.assertEqual(state.status, "connected")
        self.assertIsInstance(state.events[0], ConnectionLogEvent)


if __name__ == "__main__":
    unittest.main()
