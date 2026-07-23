"""Display-free tunnel form and lifecycle tests."""

from __future__ import annotations
import threading
import unittest
from sshvault_core import TunnelFormState, TunnelRuntime, redact_secrets


class TunnelFormStateTests(unittest.TestCase):
    def test_local_remote_and_socks_validation(self):
        self.assertTrue(TunnelFormState("Local", "127.0.0.1", 8080, "db.test", 5432).start_enabled)
        self.assertTrue(TunnelFormState("Remote", "127.0.0.1", 8022, "host.test", 22).start_enabled)
        self.assertTrue(TunnelFormState("Dynamic/SOCKS", "127.0.0.1", 1080).start_enabled)

    def test_invalid_and_missing_destination_rejected(self):
        self.assertFalse(TunnelFormState("Local", "127.0.0.1", 0, "x", 22).start_enabled)
        self.assertFalse(TunnelFormState("Remote", "127.0.0.1", 22, "", "").start_enabled)

    def test_public_bind_endpoint_and_lifecycle(self):
        state = TunnelFormState("Dynamic/SOCKS", "::", 1080)
        self.assertTrue(state.public_bind_warning)
        self.assertEqual(state.endpoint(), "[::]:1080")
        self.assertTrue(state.transition("starting"))
        self.assertTrue(state.transition("active"))
        self.assertTrue(state.transition("stopping"))
        self.assertTrue(state.transition("stopped"))
        self.assertFalse(state.transition("stopped"))

    def test_stale_and_secret_safe_diagnostics(self):
        state = TunnelFormState("Local", "127.0.0.1", 9000, "x", 22)
        state.generation = 2
        self.assertFalse(state.transition("starting", generation=1))
        self.assertNotIn("pw", str(redact_secrets("password=pw")))

    def test_field_visibility_and_runtime_stop_is_bounded(self):
        self.assertTrue(TunnelFormState("Local").visible_fields()["destination"])
        self.assertFalse(TunnelFormState("Dynamic/SOCKS").visible_fields()["destination"])
        closed = []

        class Listener:
            def close(self):
                closed.append(True)

        stopped = threading.Event()
        thread = threading.Thread(target=lambda: stopped.wait(1))
        thread.start()
        runtime = TunnelRuntime(listener=Listener(), thread=thread, stop_event=stopped)
        runtime.stop()
        runtime.stop()
        thread.join(0.5)
        self.assertTrue(closed)
        self.assertFalse(thread.is_alive())

    def test_runtime_stale_generation_and_byte_counters(self):
        runtime = TunnelRuntime(generation=3)
        self.assertFalse(runtime.accepts(2))
        self.assertTrue(runtime.accepts(3))
        runtime.add_bytes(12)
        self.assertEqual(runtime.bytes_transferred, 12)
        runtime.add_bytes(None)
        self.assertIsNone(runtime.bytes_transferred)
