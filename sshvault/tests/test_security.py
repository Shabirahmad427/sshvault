from __future__ import annotations

from pathlib import Path
import ast
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import paramiko

from sshvault_security import (
    InteractiveHostKeyPolicy,
    KnownHostsError,
    KnownHostsStore,
    ProxyConnectionContext,
    SecurityRequestQueue,
    SSHConnectionManager,
    TrustDecision,
    UnknownHostCancelled,
    host_lookup_name,
    sha256_fingerprint,
)


class SecurityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.path = Path(self.temp.name) / "known_hosts"
        self.key = paramiko.RSAKey.generate(1024)
        self.profile = {"name": "Test", "host": "server.test", "port": 22, "user": "dev", "auth_method": "agent"}

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_fingerprint_and_lookup_names(self) -> None:
        self.assertTrue(sha256_fingerprint(self.key).startswith("SHA256:"))
        self.assertEqual(sha256_fingerprint(self.key), sha256_fingerprint(self.key))
        self.assertNotEqual(sha256_fingerprint(self.key), sha256_fingerprint(paramiko.RSAKey.generate(1024)))
        self.assertEqual(host_lookup_name("server.test", 22), "server.test")
        self.assertEqual(host_lookup_name("server.test", 2200), "[server.test]:2200")

    def test_unknown_key_decisions_and_persistence(self) -> None:
        store = KnownHostsStore(self.path)
        manager = SSHConnectionManager(store, "server.test", 22)
        client = MagicMock()
        once = InteractiveHostKeyPolicy(manager, self.profile, lambda _: TrustDecision.TRUST_ONCE)
        once.missing_host_key(client, "server.test", self.key)
        self.assertFalse(self.path.exists())
        save = InteractiveHostKeyPolicy(manager, self.profile, lambda _: TrustDecision.TRUST_AND_SAVE)
        save.missing_host_key(client, "server.test", self.key)
        self.assertIn("server.test", self.path.read_text())
        cancel = InteractiveHostKeyPolicy(manager, self.profile, lambda _: TrustDecision.CANCEL)
        with self.assertRaises(UnknownHostCancelled):
            cancel.missing_host_key(client, "server.test", self.key)

    def test_known_hosts_write_failure_and_malformed_input(self) -> None:
        store = KnownHostsStore(self.path)
        with patch("sshvault_security.os.replace", side_effect=OSError("no")):
            with self.assertRaises(KnownHostsError):
                store.save_key("server.test", 22, self.key)
        self.path.write_text("not a known hosts line\n")
        with self.assertRaises(KnownHostsError):
            store.load()

    def test_changed_key_roles_and_fingerprints_are_not_reversed(self) -> None:
        manager = SSHConnectionManager(KnownHostsStore(self.path), "jump.test", 2200)
        expected, received = paramiko.RSAKey.generate(1024), paramiko.RSAKey.generate(1024)
        error = paramiko.BadHostKeyException("jump.test", received, expected)
        event = manager.changed_request({"name": "Jump", "host_role": "Jump host"}, error)
        self.assertEqual(event.host_role, "Jump host")
        self.assertEqual(event.saved_fingerprint, sha256_fingerprint(expected))
        self.assertEqual(event.received_fingerprint, sha256_fingerprint(received))

    def test_proxy_context_closes_in_destination_channel_jump_order_and_is_idempotent(self) -> None:
        order = []

        class Resource:
            def __init__(self, name):
                self.name = name

            def close(self):
                order.append(self.name)

        context = ProxyConnectionContext(
            jump_client=Resource("jump"), proxy_channel=Resource("channel"), destination_client=Resource("destination")
        )
        self.assertEqual(context.close(), [])
        self.assertEqual(order, ["destination", "channel", "jump"])
        self.assertEqual(context.close(), [])

    def test_proxy_cleanup_continues_when_close_fails(self) -> None:
        order = []

        class Resource:
            def __init__(self, name, fail=False):
                self.name, self.fail = name, fail

            def close(self):
                order.append(self.name)
                if self.fail:
                    raise RuntimeError("secret=password")

        context = ProxyConnectionContext(Resource("jump"), Resource("channel", True), Resource("destination", True))
        self.assertEqual(order, [])
        self.assertEqual(len(context.close()), 2)
        self.assertEqual(order, ["destination", "channel", "jump"])

    def test_security_layer_has_no_tkinter_or_auto_accept_policy(self) -> None:
        source = Path(__file__).parents[1].joinpath("sshvault_security.py").read_text()
        self.assertNotIn("tkinter", source)
        self.assertNotIn("AutoAddPolicy", source)
        self.assertNotIn("WarningPolicy", source)
        tree = ast.parse(source)
        creators = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "SSHClient"
        ]
        self.assertEqual(len(creators), 1)

    def test_ipv6_and_nondefault_lookup_names(self) -> None:
        self.assertEqual(host_lookup_name("2001:db8::1", 22), "2001:db8::1")
        self.assertEqual(host_lookup_name("2001:db8::1", 2200), "[2001:db8::1]:2200")

    def test_proxy_context_clears_owned_references(self) -> None:
        resource = MagicMock()
        context = ProxyConnectionContext(
            jump_client=resource, proxy_channel=MagicMock(), destination_client=MagicMock()
        )
        context.close()
        self.assertIsNone(context.jump_client)
        self.assertIsNone(context.proxy_channel)
        self.assertIsNone(context.destination_client)

    def test_architecture_routes_clients_only_through_manager(self) -> None:
        source = Path(__file__).parents[1].joinpath("sshvault.py").read_text()
        self.assertNotIn("AutoAddPolicy", source)
        self.assertNotIn("WarningPolicy", source)
        self.assertIn("manager.connect(", source)
        self.assertIn("secure_profile", source)
        self.assertIn("proxy_profile", source)

    def test_connection_tab_sftp_open_and_cleanup_are_worker_owned(self) -> None:
        source = Path(__file__).parents[1].joinpath("sshvault.py").read_text()
        tree = ast.parse(source)
        connection = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ConnectionTab")
        methods = {node.name: node for node in connection.body if isinstance(node, ast.FunctionDef)}
        open_sftp = ast.get_source_segment(source, methods["_open_sftp"]) or ""
        disconnect = ast.get_source_segment(source, methods["_disconnect"]) or ""
        cleanup = ast.get_source_segment(source, methods["_cleanup_connection_panels"]) or ""
        self.assertIn("open_sftp()", open_sftp)
        self.assertIn("threading.Thread", open_sftp)
        self.assertIn("_cleanup_connection_panels", disconnect)
        self.assertIn("shutdown", cleanup)
        self.assertIn("_session_generation", disconnect)

    def test_connection_tab_rejects_stale_callbacks_and_jump_mismatch(self) -> None:
        source = Path(__file__).parents[1].joinpath("sshvault.py").read_text()
        self.assertIn("generation != self._session_generation", source)
        self.assertIn("ChangedHostKeyRejected", source)
        self.assertIn("manager.changed_request(proxy_profile, exc)", source)
        self.assertIn("self._proxy_context.close()", source)

    def test_sftp_open_is_worker_owned_and_late_clients_are_closed(self) -> None:
        source = Path(__file__).parents[1].joinpath("sshvault.py").read_text()
        tree = ast.parse(source)
        connection = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ConnectionTab")
        methods = {node.name: node for node in connection.body if isinstance(node, ast.FunctionDef)}
        opening = ast.get_source_segment(source, methods["_open_sftp"]) or ""
        disconnect = ast.get_source_segment(source, methods["_disconnect"]) or ""
        self.assertIn("client.open_sftp()", opening)
        self.assertIn("threading.Thread", opening)
        self.assertIn("sftp.close()", opening)
        self.assertIn("_sftp_open_thread", disconnect)
        self.assertIn("join(timeout=0.25)", disconnect)

    def test_disconnect_cleanup_is_ordered_and_isolated(self) -> None:
        source = Path(__file__).parents[1].joinpath("sshvault.py").read_text()
        tree = ast.parse(source)
        connection = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ConnectionTab")
        methods = {node.name: node for node in connection.body if isinstance(node, ast.FunctionDef)}
        cleanup = ast.get_source_segment(source, methods["_cleanup_connection_panels"]) or ""
        disconnect = ast.get_source_segment(source, methods["_disconnect"]) or ""
        self.assertLess(cleanup.find('("_sftp_panel", "shutdown")'), cleanup.find('("_exec_panel", "shutdown")'))
        self.assertIn('("_tunnels_panel", "_stop_all_tunnels")', cleanup)
        self.assertIn("except Exception as exc", cleanup)
        self.assertIn("terminal.detach()", disconnect)
        self.assertIn("_cleanup_connection_panels()", disconnect)

    def test_direct_unknown_host_smoke_uses_no_network(self) -> None:
        manager = SSHConnectionManager(KnownHostsStore(self.path), "server.test", 22)
        seen = []
        policy = InteractiveHostKeyPolicy(
            manager, self.profile, lambda request: seen.append(request) or TrustDecision.CANCEL
        )
        with self.assertRaises(UnknownHostCancelled):
            policy.missing_host_key(MagicMock(), "server.test", self.key)
        self.assertEqual(seen[0].host_role, "Destination host")

    def test_jump_and_destination_events_remain_distinct(self) -> None:
        key2 = paramiko.RSAKey.generate(1024)
        jump = SSHConnectionManager(KnownHostsStore(self.path), "jump.test", 2200)
        dest = SSHConnectionManager(KnownHostsStore(self.path), "dest.test", 2222)
        jump_event = jump.changed_request(
            {"name": "Jump", "host_role": "Jump host"}, paramiko.BadHostKeyException("jump.test", key2, self.key)
        )
        dest_event = dest.changed_request(
            {"name": "Destination", "host_role": "Destination host"},
            paramiko.BadHostKeyException("dest.test", self.key, key2),
        )
        self.assertEqual((jump_event.host_role, dest_event.host_role), ("Jump host", "Destination host"))
        self.assertNotEqual(jump_event.received_fingerprint, dest_event.received_fingerprint)

    def test_request_queue_serializes_and_resolves_unknown_requests(self) -> None:
        state = SecurityRequestQueue()
        first = state.submit("unknown", "one")
        second = state.submit("unknown", "two")
        self.assertEqual(state.next().identifier, first.identifier)
        self.assertIsNone(state.next())
        self.assertTrue(state.resolve(first.identifier, TrustDecision.TRUST_ONCE))
        self.assertEqual(state.next().identifier, second.identifier)
        self.assertTrue(first.event.is_set())

    def test_request_queue_close_releases_active_and_queued_workers(self) -> None:
        state = SecurityRequestQueue()
        unknown = state.submit("unknown", "u")
        changed = state.submit("changed", "c")
        state.next()
        state.close()
        state.close()
        self.assertTrue(unknown.event.is_set() and changed.event.is_set())
        self.assertEqual(unknown.result, TrustDecision.CANCEL)
        self.assertFalse(state.resolve(unknown.identifier, TrustDecision.TRUST_ONCE))
