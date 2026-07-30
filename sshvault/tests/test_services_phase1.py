from __future__ import annotations

import copy
import unittest

from sshvault_core import (
    PORT_FORWARDING_COLUMNS,
    PORT_FORWARDING_TYPES,
    SERVICES_SECTIONS,
    PortForwardingEditor,
    ProfileError,
    SessionController,
    port_forwarding_display_row,
)


def _rule(
    *,
    kind: str = "Local",
    listen_host: str = "127.0.0.1",
    listen_port: int = 8080,
    destination_host: str = "server.example",
    destination_port: int = 80,
    enabled: bool = True,
) -> dict:
    return {
        "enabled": enabled,
        "type": kind,
        "bind_address": listen_host,
        "bind_port": listen_port,
        "destination_host": destination_host,
        "destination_port": destination_port,
    }


class ServicesPhaseOneTests(unittest.TestCase):
    def test_layout_sections_columns_and_types_are_exact(self) -> None:
        self.assertEqual(
            SERVICES_SECTIONS,
            ("Port Forwarding", "SOCKS/HTTP Proxy", "X11 Forwarding"),
        )
        self.assertEqual(
            PORT_FORWARDING_COLUMNS,
            (
                "Enabled",
                "Type",
                "Listen Host",
                "Listen Port",
                "Destination Host",
                "Destination Port",
            ),
        )
        self.assertEqual(PORT_FORWARDING_TYPES, ("Local", "Remote", "Dynamic", "HTTP"))

    def test_add_edit_remove_and_duplicate(self) -> None:
        editor = PortForwardingEditor()
        added = editor.add(_rule())
        self.assertEqual(len(editor.rules), 1)
        edited = editor.edit(
            added["rule_id"],
            {
                "type": "Remote",
                "bind_port": 9090,
                "destination_host": "remote.example",
                "destination_port": 22,
            },
        )
        self.assertEqual(edited["type"], "Remote")
        self.assertEqual(edited["bind_port"], 9090)
        duplicate = editor.duplicate(added["rule_id"])
        self.assertNotEqual(duplicate["rule_id"], added["rule_id"])
        self.assertFalse(duplicate["enabled"])
        self.assertEqual(len(editor.rules), 2)
        self.assertTrue(editor.remove(duplicate["rule_id"]))
        self.assertFalse(editor.remove("missing"))
        self.assertEqual(len(editor.rules), 1)

    def test_validation_rejects_ports_hosts_and_conflicting_listeners(self) -> None:
        for port in (0, 65536):
            with self.subTest(port=port), self.assertRaises(ProfileError):
                PortForwardingEditor().add(_rule(listen_port=port))
        with self.assertRaisesRegex(ProfileError, "Listen host"):
            PortForwardingEditor().add(_rule(listen_host=""))
        with self.assertRaisesRegex(ProfileError, "destination"):
            PortForwardingEditor().add(_rule(destination_host=""))
        editor = PortForwardingEditor()
        editor.add(_rule())
        with self.assertRaisesRegex(ProfileError, "unique"):
            editor.add(_rule(kind="Remote", destination_port=22))

    def test_dynamic_forwarding_needs_no_destination(self) -> None:
        editor = PortForwardingEditor()
        dynamic = editor.add(
            _rule(
                kind="Dynamic",
                listen_port=1080,
                destination_host="",
                destination_port=0,
            )
        )
        self.assertEqual(dynamic["type"], "SOCKS")
        self.assertEqual(dynamic["destination_host"], "")
        self.assertEqual(dynamic["destination_port"], 0)
        self.assertEqual(
            port_forwarding_display_row(dynamic),
            ("Yes", "Dynamic", "127.0.0.1", "1080", "", ""),
        )

    def test_http_forwarding_needs_no_fixed_destination(self) -> None:
        editor = PortForwardingEditor()
        http = editor.add(
            _rule(
                kind="HTTP",
                listen_port=8088,
                destination_host="",
                destination_port=0,
            )
        )
        self.assertEqual(http["type"], "HTTP")
        self.assertEqual(http["destination_host"], "")
        self.assertEqual(http["destination_port"], 0)
        self.assertEqual(
            port_forwarding_display_row(http),
            ("Yes", "HTTP", "127.0.0.1", "8088", "", ""),
        )

    def test_dirty_state_tracks_semantic_rule_changes(self) -> None:
        profile = {"tunnel_options": {"rules": [_rule()]}}
        editor = PortForwardingEditor.from_profile(profile)
        self.assertFalse(editor.dirty)
        added = editor.add(_rule(listen_port=8081))
        self.assertTrue(editor.dirty)
        editor.remove(added["rule_id"])
        self.assertFalse(editor.dirty)

    def test_working_copy_changes_do_not_mutate_stored_profile(self) -> None:
        stored = {"tunnel_options": {"rules": [_rule()]}}
        working = copy.deepcopy(stored)
        editor = PortForwardingEditor.from_profile(working)
        editor.add(_rule(listen_port=8081))
        editor.apply_to_working_profile(working)
        self.assertEqual(len(stored["tunnel_options"]["rules"]), 1)
        self.assertEqual(len(working["tunnel_options"]["rules"]), 2)
        self.assertTrue(editor.dirty)

    def test_active_session_snapshot_isolated_from_services_edits(self) -> None:
        profile = {
            "id": "services-profile",
            "name": "Services",
            "host": "host.example",
            "port": 22,
            "user": "alice",
            "auth_method": "agent",
            "tunnel_options": {"rules": [_rule()]},
        }
        controller = SessionController()
        session = controller.create_session(profile)
        working = copy.deepcopy(profile)
        editor = PortForwardingEditor.from_profile(working)
        editor.edit(editor.rules[0]["rule_id"], {"destination_host": "edited.example"})
        editor.apply_to_working_profile(working)
        self.assertEqual(
            session.profile_snapshot["tunnel_options"]["rules"][0]["destination_host"],
            "server.example",
        )
        self.assertEqual(
            working["tunnel_options"]["rules"][0]["destination_host"],
            "edited.example",
        )
        self.assertEqual(len(controller.sessions), 1)


if __name__ == "__main__":
    unittest.main()
