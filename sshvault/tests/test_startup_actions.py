import unittest
from unittest.mock import Mock

from sshvault import ConnectionTab
from sshvault_core import StartupActionCoordinator


class _ServiceStartupHarness:
    _service_start_allowed = ConnectionTab._service_start_allowed
    _coordinate_enabled_services = ConnectionTab._coordinate_enabled_services

    def __init__(self, session_id="session", snapshot=None):
        self.session_id = session_id
        self.snapshot = snapshot or {}
        self._session_generation = 1
        self._services_started_generation = None
        self._intentionally_stopped_services = set()
        self.starts = []
        self._start_enabled_local_forwarding = lambda: self.starts.append((session_id, "local"))
        self._start_enabled_remote_forwarding = lambda: self.starts.append((session_id, "remote"))
        self._start_enabled_dynamic_forwarding = lambda: self.starts.append((session_id, "dynamic"))
        self._start_enabled_http_forwarding = lambda: self.starts.append((session_id, "http"))
        self._start_x11_forwarding = lambda: self.starts.append((session_id, "x11"))

    def _session_profile_snapshot(self):
        return self.snapshot


class StartupActionTests(unittest.TestCase):
    def test_order_and_skips(self):
        seen = []
        c = StartupActionCoordinator(
            {name: (lambda n=name: seen.append(n)) for name in ("tunnels", "terminal", "sftp")}
        )
        results = c.run({"restart_tunnels": True, "open_terminal": True, "open_sftp": True}, 1)
        self.assertEqual(seen, ["tunnels", "terminal", "sftp"])
        self.assertEqual([r.status for r in results], ["completed", "skipped", "completed", "completed"])

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
            {
                "restart_tunnels": True,
                "open_terminal": True,
                "open_sftp": True,
                "run_startup_commands": True,
                "startup_command": "echo visible",
            },
            1,
        )
        self.assertEqual(seen, ["command", "terminal", "sftp"])
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

    def test_first_connection_service_startup_policy_enabled_and_disabled(self):
        enabled = _ServiceStartupHarness(snapshot={"launch_preferences": {"start_enabled_services": True}})
        disabled = _ServiceStartupHarness(snapshot={"launch_preferences": {"start_enabled_services": False}})
        self.assertTrue(enabled._service_start_allowed(reconnecting=False))
        self.assertFalse(disabled._service_start_allowed(reconnecting=False))
        if enabled._service_start_allowed(reconnecting=False):
            enabled._coordinate_enabled_services()
        if disabled._service_start_allowed(reconnecting=False):
            disabled._coordinate_enabled_services()
        self.assertEqual(len(enabled.starts), 5)
        self.assertEqual(disabled.starts, [])

    def test_reconnect_restart_policy_enabled_and_disabled(self):
        enabled = _ServiceStartupHarness(snapshot={"connection_options": {"restart_tunnels": True}})
        disabled = _ServiceStartupHarness(snapshot={"connection_options": {"restart_tunnels": False}})
        enabled._session_generation = disabled._session_generation = 2
        self.assertTrue(enabled._service_start_allowed(reconnecting=True))
        self.assertFalse(disabled._service_start_allowed(reconnecting=True))
        if enabled._service_start_allowed(reconnecting=True):
            enabled._coordinate_enabled_services(reconnecting=True)
        if disabled._service_start_allowed(reconnecting=True):
            disabled._coordinate_enabled_services(reconnecting=True)
        self.assertEqual(len(enabled.starts), 5)
        self.assertEqual(disabled.starts, [])

    def test_intentionally_stopped_service_remains_stopped_on_reconnect(self):
        harness = _ServiceStartupHarness(snapshot={"connection_options": {"restart_tunnels": True}})
        harness._intentionally_stopped_services = {"remote", "x11"}
        harness._coordinate_enabled_services(reconnecting=True)
        self.assertEqual([name for _session, name in harness.starts], ["local", "dynamic", "http"])

    def test_duplicate_service_start_for_generation_is_prevented(self):
        harness = _ServiceStartupHarness()
        harness._coordinate_enabled_services()
        harness._coordinate_enabled_services()
        self.assertEqual(len(harness.starts), 5)
        harness._session_generation += 1
        harness._coordinate_enabled_services(reconnecting=True)
        self.assertEqual(len(harness.starts), 10)

    def test_failed_service_does_not_abort_other_services_or_disconnect_ssh(self):
        harness = _ServiceStartupHarness()
        harness.connected = True
        harness._start_enabled_remote_forwarding = Mock(side_effect=RuntimeError("listener failed"))
        harness._coordinate_enabled_services()
        harness._start_enabled_remote_forwarding.assert_called_once_with()
        self.assertTrue(harness.connected)
        self.assertEqual([name for _session, name in harness.starts], ["local", "dynamic", "http", "x11"])

    def test_service_startup_is_session_isolated(self):
        sahmaddo = _ServiceStartupHarness("sahmaddo")
        clauberh = _ServiceStartupHarness("clauberh")
        sahmaddo._coordinate_enabled_services()
        self.assertTrue(all(session == "sahmaddo" for session, _name in sahmaddo.starts))
        self.assertEqual(clauberh.starts, [])


if __name__ == "__main__":
    unittest.main()
