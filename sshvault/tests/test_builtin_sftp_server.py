from __future__ import annotations

from pathlib import Path
import os
import socket
import tempfile
import threading
import unittest
from unittest.mock import patch

import paramiko

from sshvault_sftp_server import (
    BuiltinSFTPServerConfig,
    BuiltinSFTPServerRuntime,
    RootEscapeError,
    RootedSFTPServer,
    SERVER_FAILED,
    SERVER_RUNNING,
    SERVER_STOPPED,
)


class BuiltinSFTPServerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._temporary = tempfile.TemporaryDirectory()
        self.root = Path(self._temporary.name)
        self.runtime = BuiltinSFTPServerRuntime()

    def tearDown(self) -> None:
        self.runtime.stop()
        self._temporary.cleanup()

    def _config(self, port: int = 0) -> BuiltinSFTPServerConfig:
        return BuiltinSFTPServerConfig("127.0.0.1", port, "local-user", self.root)

    def _connect(self) -> tuple[paramiko.SSHClient, paramiko.SFTPClient]:
        address = self.runtime.bound_address
        self.assertIsNotNone(address)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            *address,
            username="local-user",
            password="runtime-secret",
            allow_agent=False,
            look_for_keys=False,
            timeout=3,
        )
        return client, client.open_sftp()

    def test_start_stop_binds_only_configured_listener(self) -> None:
        self.runtime.start(self._config(), "runtime-secret")
        self.assertEqual(self.runtime.status, SERVER_RUNNING)
        address = self.runtime.bound_address
        self.assertIsNotNone(address)
        self.assertEqual(address[0], "127.0.0.1")
        self.assertGreater(address[1], 0)
        self.runtime.stop()
        self.assertEqual(self.runtime.status, SERVER_STOPPED)
        self.assertIsNone(self.runtime.bound_address)

    def test_bind_failure_reports_failed(self) -> None:
        occupied = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        occupied.bind(("127.0.0.1", 0))
        occupied.listen(1)
        self.addCleanup(occupied.close)
        port = int(occupied.getsockname()[1])
        with self.assertRaisesRegex(RuntimeError, "Could not bind"):
            self.runtime.start(self._config(port), "runtime-secret")
        self.assertEqual(self.runtime.status, SERVER_FAILED)
        self.assertTrue(self.runtime.error)
        self.assertFalse(self.runtime.has_live_resources)

    def test_root_isolation_allows_only_configured_tree(self) -> None:
        (self.root / "inside.txt").write_text("inside", encoding="utf-8")
        outside = self.root.parent / f"{self.root.name}-outside.txt"
        outside.write_text("outside", encoding="utf-8")
        self.addCleanup(outside.unlink, missing_ok=True)
        self.runtime.start(self._config(), "runtime-secret")
        client, sftp = self._connect()
        try:
            self.assertEqual(sftp.open("/inside.txt").read(), b"inside")
            with self.assertRaises(PermissionError):
                sftp.stat(f"/../{outside.name}")
            with self.assertRaises(PermissionError):
                sftp.stat("/../../etc/passwd")
        finally:
            sftp.close()
            client.close()

    def test_traversal_and_symlink_escape_are_rejected(self) -> None:
        interface = object.__new__(RootedSFTPServer)
        interface.root = self.root.resolve()
        with self.assertRaises(RootEscapeError):
            interface._local_path("../../outside")
        outside = self.root.parent / f"{self.root.name}-outside"
        outside.mkdir()
        self.addCleanup(outside.rmdir)
        (self.root / "escape").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(RootEscapeError):
            interface._local_path("/escape/secret")

    def test_open_closes_descriptor_when_attribute_setup_fails(self) -> None:
        interface = object.__new__(RootedSFTPServer)
        interface.root = self.root.resolve()
        attr = paramiko.SFTPAttributes()
        with (
            patch("sshvault_sftp_server.os.open", return_value=73),
            patch.object(paramiko.SFTPServer, "set_file_attr", side_effect=OSError(5, "failed")),
            patch("sshvault_sftp_server.os.close") as close,
        ):
            result = interface.open("/new.txt", os.O_WRONLY | os.O_CREAT, attr)
        self.assertNotEqual(result, paramiko.SFTP_OK)
        close.assert_called_once_with(73)

    def test_repeated_start_stop_is_idempotent(self) -> None:
        for _ in range(4):
            self.runtime.start(self._config(), "runtime-secret")
            self.runtime.start(self._config(), "runtime-secret")
            self.assertEqual(self.runtime.status, SERVER_RUNNING)
            self.runtime.stop()
            self.runtime.stop()
            self.assertEqual(self.runtime.status, SERVER_STOPPED)
            self.assertFalse(self.runtime.has_live_resources)

    def test_stop_closes_connected_transport_and_all_threads(self) -> None:
        baseline = {thread.ident for thread in threading.enumerate() if thread.name.startswith("sshvault-sftp-")}
        self.runtime.start(self._config(), "runtime-secret")
        client, sftp = self._connect()
        self.assertTrue(self.runtime.has_live_resources)
        self.runtime.stop()
        try:
            sftp.close()
        except EOFError:
            # The server intentionally closed this transport during shutdown.
            pass
        client.close()
        remaining = {
            thread.ident
            for thread in threading.enumerate()
            if thread.name.startswith("sshvault-sftp-") and thread.is_alive()
        }
        self.assertEqual(remaining, baseline)
        self.assertFalse(self.runtime.has_live_resources)

    def test_outbound_sftp_factory_is_never_used_by_server_runtime(self) -> None:
        with patch.object(paramiko.SFTPClient, "from_transport", wraps=paramiko.SFTPClient.from_transport) as outbound:
            self.runtime.start(self._config(), "runtime-secret")
            self.runtime.stop()
        outbound.assert_not_called()


if __name__ == "__main__":
    unittest.main()
