import unittest
from sshvault_core import ReconnectController, reconnect_delay


class ReconnectTests(unittest.TestCase):
    def test_backoff_and_clamp(self):
        self.assertEqual([reconnect_delay(2, 5, n) for n in range(1, 5)], [2, 4, 5, 5])

    def test_disabled_and_exhausted(self):
        scheduled = []
        ctl = ReconnectController({"automatic_reconnect": False}, lambda d, cb: scheduled.append((d, cb)))
        self.assertFalse(ctl.unexpected_loss(0))
        self.assertFalse(scheduled)
        ctl = ReconnectController(
            {"automatic_reconnect": True, "maximum_attempts": 2}, lambda d, cb: scheduled.append((d, cb)), lambda: False
        )
        ctl.new_session()
        self.assertTrue(ctl.unexpected_loss(ctl.generation))
        scheduled[-1][1]()
        scheduled[-1][1]()
        self.assertIn(ctl.state, {"waiting", "attempts exhausted"})

    def test_successful_reconnect(self):
        scheduled = []
        ctl = ReconnectController({"automatic_reconnect": True}, lambda d, cb: scheduled.append(cb), lambda: True)
        ctl.new_session()
        ctl.unexpected_loss(ctl.generation)
        scheduled.pop()()
        self.assertEqual(ctl.state, "reconnected")

    def test_cancel_and_now(self):
        ctl = ReconnectController({"automatic_reconnect": True}, lambda d, cb: None, lambda: True)
        ctl.new_session()
        ctl.unexpected_loss(ctl.generation)
        ctl.cancel()
        self.assertEqual(ctl.state, "manually disconnected")
        ctl.reconnect_now()
        self.assertEqual(ctl.state, "manually disconnected")

    def test_generation_and_duplicate_suppression(self):
        scheduled = []
        ctl = ReconnectController({"automatic_reconnect": True}, lambda d, cb: scheduled.append(cb))
        ctl.new_session()
        self.assertTrue(ctl.unexpected_loss(ctl.generation))
        self.assertFalse(ctl.unexpected_loss(ctl.generation))
        ctl.new_session()
        scheduled[0]()
        self.assertEqual(ctl.state, "connected")


if __name__ == "__main__":
    unittest.main()
