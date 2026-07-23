import unittest
from sshvault_core import DiagnosticsCollector


class DiagnosticsTests(unittest.TestCase):
    def test_deterministic_fields_and_redaction(self):
        d = DiagnosticsCollector.collect(
            {"name": "p", "host": "example.test", "port": 22, "user": "u"},
            {"generation": 4, "error": "password=secret token=abc"},
        )
        self.assertEqual([r.field for r in d.records], list(DiagnosticsCollector.FIELDS))
        text = d.as_text()
        self.assertNotIn("secret", text)
        self.assertNotIn("abc", text)

    def test_unavailable_and_network_success(self):
        d = DiagnosticsCollector.collect()
        self.assertIn("Unavailable", d.as_text())

        def resolver(*args, **kwargs):
            return [(None, None, None, None, ("127.0.0.1", 22))]

        class Socket:
            def close(self):
                pass

        result = DiagnosticsCollector.network_check(
            "example.test", 22, resolver=resolver, connector=lambda *a, **k: Socket()
        )
        self.assertEqual(result["dns"], "127.0.0.1")

    def test_network_failure(self):
        result = DiagnosticsCollector.network_check(
            "example.test",
            22,
            resolver=lambda *a, **k: (_ for _ in ()).throw(OSError("token=hidden")),
            connector=lambda *a, **k: None,
        )
        self.assertEqual(result["dns"], "Unavailable")
        self.assertNotIn("hidden", result["tcp"])


if __name__ == "__main__":
    unittest.main()
