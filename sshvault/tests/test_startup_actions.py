import unittest
from sshvault_core import StartupActionCoordinator


class StartupActionTests(unittest.TestCase):
    def test_order_and_skips(self):
        seen = []
        c = StartupActionCoordinator(
            {name: (lambda n=name: seen.append(n)) for name in ("tunnels", "terminal", "sftp")}
        )
        results = c.run({"restart_tunnels": True, "open_terminal": True, "open_sftp": True}, 1)
        self.assertEqual(seen, ["tunnels", "terminal", "sftp"])
        self.assertEqual([r.status for r in results], ["completed"] * 3 + ["skipped"])

    def test_command_and_partial_failure(self):
        seen = []

        def fail():
            raise RuntimeError("password=secret")

        c = StartupActionCoordinator(
            {
                "tunnels": fail,
                "terminal": lambda: seen.append("terminal"),
                "sftp": lambda: seen.append("sftp"),
                "command": lambda _: seen.append("command"),
            }
        )
        results = c.run(
            {"restart_tunnels": True, "open_terminal": True, "open_sftp": True, "startup_command": "echo visible"}, 1
        )
        self.assertEqual(seen, ["terminal", "sftp", "command"])
        self.assertEqual(results[0].status, "failed")
        self.assertNotIn("secret", results[0].error)

    def test_duplicate_and_manual_rerun(self):
        calls = []
        c = StartupActionCoordinator({"terminal": lambda: calls.append(1)})
        c.run({"open_terminal": True}, 1)
        c.run({"open_terminal": True}, 1)
        c.run({"open_terminal": True}, 1, manual=True)
        self.assertEqual(len(calls), 2)

    def test_cancel_and_generation(self):
        c = StartupActionCoordinator({"terminal": lambda: None})
        c.cancel()
        results = c.run({"open_terminal": True}, 2)
        self.assertTrue(results)


if __name__ == "__main__":
    unittest.main()
