"""Display-free metadata and safe-decision tests for resumable downloads."""

import json
from pathlib import Path
import tempfile
import unittest

from sshvault_core import (
    DownloadResumeDecision,
    TransferState,
    adopt_legacy_download,
    inspect_download_resume,
    partial_download_metadata_path,
    partial_download_path,
    write_partial_download_metadata,
)


class ResumableDownloadTests(unittest.TestCase):
    remote = "/runs/rep1/trajectory.nc"
    host = "profile:production"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.destination = Path(self.temp.name) / "trajectory.nc"

    def tearDown(self):
        self.temp.cleanup()

    def inspect(self, *, size=10, mtime=100):
        return inspect_download_resume(
            self.destination, remote_identity=self.host, remote_path=self.remote, remote_size=size, remote_mtime=mtime
        )

    def sidecar(self, count=6, *, size=10, mtime=100, host=None, remote=None):
        partial_download_path(self.destination).write_bytes(b"x" * count)
        write_partial_download_metadata(
            self.destination,
            remote_identity=host or self.host,
            remote_path=remote or self.remote,
            remote_size=size,
            remote_mtime=mtime,
            completed_bytes=count,
            now=1,
        )

    def test_no_local_file_downloads_normally(self):
        plan = self.inspect()
        self.assertEqual(plan.decision, DownloadResumeDecision.DOWNLOAD)
        self.assertEqual(plan.status, TransferState.DOWNLOADING)
        self.assertEqual(plan.remaining_bytes, 10)

    def test_matching_partial_is_resume_available(self):
        self.sidecar()
        plan = self.inspect()
        self.assertEqual((plan.decision, plan.offset, plan.remaining_bytes), (DownloadResumeDecision.RESUME, 6, 4))
        self.assertEqual(plan.partial_path.name, "trajectory.nc.sshvault-part")
        self.assertEqual(plan.metadata_path.name, "trajectory.nc.sshvault-part.json")

    def test_legacy_final_requires_adoption_then_resumes(self):
        self.destination.write_bytes(b"x" * 6)
        plan = self.inspect()
        self.assertEqual(plan.decision, DownloadResumeDecision.ADOPT_LEGACY)
        adopted = adopt_legacy_download(plan, now=2)
        self.assertEqual(adopted.decision, DownloadResumeDecision.RESUME)
        self.assertFalse(self.destination.exists())
        self.assertEqual(partial_download_path(self.destination).stat().st_size, 6)

    def test_zero_length_legacy_file_can_be_adopted(self):
        self.destination.touch()
        self.assertEqual(self.inspect().decision, DownloadResumeDecision.ADOPT_LEGACY)

    def test_equal_final_file_is_already_complete(self):
        self.destination.write_bytes(b"x" * 10)
        plan = self.inspect()
        self.assertEqual(
            (plan.decision, plan.status), (DownloadResumeDecision.ALREADY_COMPLETE, TransferState.ALREADY_COMPLETE)
        )

    def test_larger_final_file_is_conflict(self):
        self.destination.write_bytes(b"x" * 11)
        plan = self.inspect()
        self.assertEqual(plan.decision, DownloadResumeDecision.CONFLICT)
        self.assertIn("larger", plan.message)

    def test_mismatched_remote_path_is_not_resumed(self):
        self.sidecar(remote="/other/trajectory.nc")
        self.assertEqual(self.inspect().decision, DownloadResumeDecision.CONFLICT)

    def test_mismatched_remote_host_is_not_resumed(self):
        self.sidecar(host="profile:other")
        self.assertEqual(self.inspect().decision, DownloadResumeDecision.CONFLICT)

    def test_changed_remote_modification_time_is_not_resumed(self):
        self.sidecar(mtime=99)
        self.assertEqual(self.inspect().decision, DownloadResumeDecision.CONFLICT)

    def test_changed_remote_size_is_not_resumed(self):
        self.sidecar(size=9)
        self.assertEqual(self.inspect().decision, DownloadResumeDecision.CONFLICT)

    def test_missing_sidecar_is_not_resumed(self):
        partial_download_path(self.destination).write_bytes(b"x" * 6)
        self.assertEqual(self.inspect().decision, DownloadResumeDecision.CONFLICT)

    def test_corrupted_sidecar_is_not_resumed(self):
        partial_download_path(self.destination).write_bytes(b"x" * 6)
        partial_download_metadata_path(self.destination).write_text("not json", encoding="utf-8")
        self.assertEqual(self.inspect().decision, DownloadResumeDecision.CONFLICT)

    def test_sidecar_contains_no_secret_and_tracks_offset(self):
        self.sidecar()
        payload = json.loads(partial_download_metadata_path(self.destination).read_text(encoding="utf-8"))
        self.assertEqual(payload["completed_byte_count"], 6)
        self.assertEqual(payload["expected_remote_size"], 10)
        self.assertNotIn("password", payload)
        self.assertEqual(payload["local_destination_path"], str(self.destination.resolve()))

    def test_type_conflict_is_explicit(self):
        self.destination.mkdir()
        plan = self.inspect()
        self.assertEqual(plan.decision, DownloadResumeDecision.CONFLICT)
        self.assertIn("Type conflict", plan.message)

    def test_adoption_never_overwrites_an_existing_partial(self):
        self.destination.write_bytes(b"x" * 6)
        partial_download_path(self.destination).write_bytes(b"x")
        with self.assertRaises(ValueError):
            adopt_legacy_download(self.inspect())

    def test_metadata_is_written_atomically_to_final_sidecar_name(self):
        self.sidecar()
        self.assertTrue(partial_download_metadata_path(self.destination).is_file())
        self.assertFalse(
            any(
                path.name.startswith(".trajectory.nc.sshvault-part.json.") for path in self.destination.parent.iterdir()
            )
        )


if __name__ == "__main__":
    unittest.main()
