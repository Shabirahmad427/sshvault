import unittest

from sshvault_core import ProfileError, TunnelManager, TunnelRuntime, parse_socks5_connect


class Resource:
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


class SavedTunnelTests(unittest.TestCase):
    def rule(self, kind="Local", rid="one", port=8000):
        return {
            "rule_id": rid,
            "type": kind,
            "enabled": True,
            "bind_address": "127.0.0.1",
            "bind_port": port,
            "destination_host": "example.test" if kind != "SOCKS" else "",
            "destination_port": 22 if kind != "SOCKS" else 0,
        }

    def test_disconnected_start_rejected(self):
        with self.assertRaises(ProfileError):
            TunnelManager().start(self.rule())

    def test_local_start_and_states(self):
        manager = TunnelManager(object(), 4)
        item = manager.start(self.rule(), lambda running: setattr(running.runtime, "thread", None))
        self.assertEqual(item.status, "running")
        self.assertTrue(manager.stop("one"))
        self.assertFalse(manager.stop("one"))

    def test_duplicate_runtime_bind_rejected(self):
        manager = TunnelManager(object())
        manager.start(self.rule(), lambda _: None)
        with self.assertRaises(ProfileError):
            manager.start(self.rule(rid="two"), lambda _: None)

    def test_start_failure_is_recorded_and_cleaned(self):
        manager = TunnelManager(object())
        with self.assertRaises(RuntimeError):
            manager.start(self.rule(), lambda _: (_ for _ in ()).throw(RuntimeError("password=hidden")))
        self.assertEqual(manager.running["one"].status, "failed")
        self.assertNotIn("hidden", manager.running["one"].error)

    def test_stop_all_and_invalidate(self):
        manager = TunnelManager(object(), 7)
        manager.start(self.rule(rid="a", port=8001), lambda _: None)
        manager.start(self.rule(rid="b", port=8002), lambda _: None)
        manager.stop_all()
        self.assertTrue(all(item.status == "stopped" for item in manager.running.values()))
        manager.invalidate(7)
        self.assertFalse(manager.connected)

    def test_socks5_ipv4_domain_ipv6_and_unsupported(self):
        self.assertEqual(parse_socks5_connect(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x16"), ("127.0.0.1", 22))
        self.assertEqual(parse_socks5_connect(b"\x05\x01\x00\x03\x0cexample.test\x00\x16"), ("example.test", 22))
        self.assertEqual(
            parse_socks5_connect(b"\x05\x01\x00\x04" + bytes.fromhex("20010db8000000000000000000000001") + b"\x00\x16"),
            ("2001:db8::1", 22),
        )
        self.assertIsNone(parse_socks5_connect(b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x16"))

    def test_runtime_stop_is_idempotent(self):
        resource = Resource()
        runtime = TunnelRuntime(listener=resource)
        runtime.stop()
        runtime.stop()
        self.assertEqual(resource.closed, 1)


if __name__ == "__main__":
    unittest.main()
