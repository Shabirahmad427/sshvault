from __future__ import annotations

import unittest

from sshvault_core import SFTPBrowserClient, SFTPBrowserRegistry


class _Channel:
    def __init__(self) -> None:
        self.closed = 0

    def close(self) -> None:
        self.closed += 1

    def listdir_attr(self, path: str):
        return []

    def stat(self, path: str):
        return path

    def normalize(self, path: str):
        return "/home" if path == "." else path


class SFTPBrowserClientTests(unittest.TestCase):
    def test_each_view_owns_and_closes_only_its_client(self) -> None:
        registry, first, second = SFTPBrowserRegistry(), _Channel(), _Channel()
        registry.register("session", "one", SFTPBrowserClient(first))
        registry.register("session", "two", SFTPBrowserClient(second))
        registry.close_view("session", "one")
        self.assertEqual(first.closed, 1)
        self.assertEqual(second.closed, 0)
        self.assertIsNotNone(registry.get("session", "two"))

    def test_session_cleanup_is_isolated_and_idempotent(self) -> None:
        registry, first, second = SFTPBrowserRegistry(), _Channel(), _Channel()
        registry.register("a", "one", SFTPBrowserClient(first))
        registry.register("b", "two", SFTPBrowserClient(second))
        registry.close_session("a")
        registry.close_session("a")
        self.assertEqual(first.closed, 1)
        self.assertEqual(second.closed, 0)


if __name__ == "__main__":
    unittest.main()
