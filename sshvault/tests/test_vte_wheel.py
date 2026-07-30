"""Installed-wheel coverage for the standalone Native VTE helper."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


class VTEWheelTests(unittest.TestCase):
    def test_canonical_wheel_contains_standalone_helper(self) -> None:
        root = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as output:
            subprocess.run(
                [sys.executable, "-m", "build", "--wheel", "--no-isolation", "--outdir", output],
                cwd=root,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            wheel = next(Path(output).glob("sshvault-0.3.4-py3-none-any.whl"))
            with zipfile.ZipFile(wheel) as archive:
                self.assertIn("sshvault_vte_helper.py", archive.namelist())
