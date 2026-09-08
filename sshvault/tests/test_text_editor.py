import os
from pathlib import Path
import tempfile
import unittest

from sshvault import LocalEditorChannel
from sshvault_core import ProfileError, read_remote_text, save_remote_text


class TextEditorTests(unittest.TestCase):
    def test_save_preserves_script_permissions_and_line_endings(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "list.sh")
            original = b"#!/bin/sh\r\necho old\r\n"
            path.write_bytes(original)
            path.chmod(0o755)
            channel = LocalEditorChannel()
            self.assertEqual(read_remote_text(channel, str(path)), original)
            replacement = original.replace(b"old", b"new")
            save_remote_text(channel, str(path), original, replacement)
            self.assertEqual(path.read_bytes(), replacement)
            self.assertEqual(path.stat().st_mode & 0o777, 0o755)
            self.assertEqual(os.listdir(root), ["list.sh"])

    def test_conflict_keeps_external_changes(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "list.sh")
            path.write_bytes(b"external")
            with self.assertRaisesRegex(ProfileError, "changed"):
                save_remote_text(LocalEditorChannel(), str(path), b"original", b"edited")
            self.assertEqual(path.read_bytes(), b"external")

    def test_failed_replace_keeps_original_and_cleans_staging_file(self):
        class FailingChannel(LocalEditorChannel):
            def posix_rename(self, source, destination):
                raise OSError("unsupported")

        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "list.sh")
            path.write_bytes(b"original")
            with self.assertRaises(OSError):
                save_remote_text(FailingChannel(), str(path), b"original", b"edited")
            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(os.listdir(root), ["list.sh"])

    def test_rejects_binary_encoding_and_large_files(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root, "file")
            for data in (b"a\x00b", b"\xff", b"a" * (2 * 1024 * 1024 + 1)):
                path.write_bytes(data)
                with self.assertRaises(ProfileError):
                    read_remote_text(LocalEditorChannel(), str(path))
                self.assertEqual(path.read_bytes(), data)
