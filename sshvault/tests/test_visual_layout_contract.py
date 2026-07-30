from __future__ import annotations

import unittest

from sshvault_core import (
    CONTROLLER_DEFAULT_GEOMETRY,
    CONTROLLER_MINIMUM_GEOMETRY,
    CONTROLLER_REGION_ORDER,
    OPTIONS_GROUPS,
    SECTION_PADDING,
    TERMINAL_GROUPS,
)


class VisualLayoutContractTests(unittest.TestCase):
    def test_compact_controller_region_order_and_geometry(self) -> None:
        self.assertEqual(
            CONTROLLER_REGION_ORDER,
            ("Profile heading", "Profile rail / Configuration notebook", "Connection log", "Login/status strip"),
        )
        self.assertEqual(CONTROLLER_DEFAULT_GEOMETRY, (1050, 720))
        self.assertEqual(CONTROLLER_MINIMUM_GEOMETRY, (900, 620))

    def test_group_layout_contracts_are_compact(self) -> None:
        self.assertEqual(SECTION_PADDING, 6)
        self.assertEqual(OPTIONS_GROUPS, ("On successful login", "Application startup", "On logout"))
        self.assertEqual(TERMINAL_GROUPS[:2], ("Terminal Emulation", "Appearance"))


if __name__ == "__main__":
    unittest.main()
