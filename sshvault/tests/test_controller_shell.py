"""Display-free contract for the visible connection-controller shell."""

import unittest

from sshvault import CONTROLLER_BOTTOM_ACTIONS, CONTROLLER_CONFIG_TABS, CONTROLLER_PROFILE_ACTIONS


class ControllerShellTests(unittest.TestCase):
    def test_exact_visible_action_and_tab_order(self):
        self.assertEqual(
            CONTROLLER_PROFILE_ACTIONS,
            ("Load profile", "Save profile as", "New profile", "Reset profile"),
        )
        self.assertEqual(CONTROLLER_CONFIG_TABS, ("Login", "Options", "Terminal", "SFTP", "Services", "SSH"))
        self.assertEqual(CONTROLLER_BOTTOM_ACTIONS, ("Log in / Log out", "Exit"))
