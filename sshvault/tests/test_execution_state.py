from __future__ import annotations
import unittest
from sshvault_core import CommandExecutionState, redact_secrets


class CommandExecutionStateTests(unittest.TestCase):
    def test_lifecycle_cancel_and_stale_output(self):
        s = CommandExecutionState()
        a = s.start()
        self.assertEqual(s.status, "running")
        self.assertIsNone(s.start())
        self.assertTrue(s.cancel(a))
        self.assertTrue(s.finish(a))
        b = s.start()
        self.assertIsNotNone(b)
        self.assertFalse(s.accepts(a))
        self.assertTrue(s.finish(b))
        self.assertEqual(s.status, "completed")

    def test_failure_redaction(self):
        self.assertNotIn("pw", str(redact_secrets("password=pw")))
