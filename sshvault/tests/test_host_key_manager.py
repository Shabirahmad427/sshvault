import tempfile
import unittest
from pathlib import Path
import paramiko
from sshvault_security import HostKeyRepository, KnownHostsStore, sha256_fingerprint


class HostKeyManagerTests(unittest.TestCase):
    def test_empty_and_listing_export_remove_exact(self):
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "known_hosts"
            repo = HostKeyRepository(path, [{"name": "p", "host": "example.test", "port": 22}])
            self.assertEqual(repo.list_records(), [])
            key1 = paramiko.RSAKey.generate(1024)
            key2 = paramiko.ECDSAKey.generate()
            store = KnownHostsStore(path)
            store.save_key("example.test", 22, key1)
            store.save_key("example.test", 22, key2)
            records = repo.list_records()
            self.assertEqual(len(records), 2)
            self.assertTrue(all(r.associated_profiles == ("p",) for r in records))
            repo.export(Path(td) / "export.json")
            self.assertIn("sshvault-application-known-hosts", (Path(td) / "export.json").read_text())
            repo.remove(next(r for r in records if r.algorithm == key1.get_name()))
            self.assertEqual(len(repo.list_records()), 1)

    def test_fingerprint_stable(self):
        key = paramiko.RSAKey.generate(1024)
        self.assertEqual(sha256_fingerprint(key), sha256_fingerprint(key))


if __name__ == "__main__":
    unittest.main()
