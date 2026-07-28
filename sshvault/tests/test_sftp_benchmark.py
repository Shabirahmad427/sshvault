"""Display-free measurements for the development SFTP benchmark harness."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from sftp_benchmark import SFTPBenchmarkRunner
from sshvault_core import AdaptiveTransferTuner, bounded_prefetch_depth, ssh_compression_recommended


class Channel:
    in_window_size = 4194304
    in_max_packet_size = 32768

    class transport:
        local_cipher = "aes128-ctr"
        local_mac = "hmac-sha2-256"
        local_compression = "none"


class Source:
    def __init__(self, data):
        self.data, self.offset, self.prefetch_calls = data, 0, []

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, size):
        value = self.data[self.offset : self.offset + size]
        self.offset += len(value)
        return value

    def prefetch(self, **kwargs):
        self.prefetch_calls.append(kwargs)


class SFTP:
    def __init__(self, data):
        self.data, self.source, self.closed = data, Source(data), False

    def get_channel(self):
        return Channel()

    def stat(self, _path):
        return type("Stat", (), {"st_size": len(self.data)})()

    def open(self, _path, _mode):
        return self.source

    def close(self):
        self.closed = True


class BenchmarkTests(unittest.TestCase):
    def test_metrics_account_for_actual_reads_and_bounded_prefetch(self):
        client = SFTP(b"x" * (3 * 1024 * 1024))
        runner = SFTPBenchmarkRunner(lambda: client)
        with tempfile.TemporaryDirectory() as directory:
            metrics = runner.download("/benchmark", Path(directory) / "out", chunk_size=1024 * 1024, prefetch_depth=64)
        self.assertEqual(metrics.bytes_transferred, 3 * 1024 * 1024)
        self.assertEqual(metrics.effective_request_size, 1024 * 1024)
        self.assertEqual(metrics.outstanding_requests, 32)
        self.assertEqual(client.source.prefetch_calls[0]["max_concurrent_prefetch_requests"], 32)
        self.assertEqual(metrics.safe_dict()["cipher"], "aes128-ctr")
        self.assertTrue(client.closed)

    def test_prefetch_memory_bound_and_compression_recommendation(self):
        self.assertEqual(bounded_prefetch_depth(1024 * 1024, 64, workers=3), 32)
        self.assertEqual(bounded_prefetch_depth(2 * 1024 * 1024, 64, workers=8), 4)
        self.assertFalse(ssh_compression_recommended("trajectory.nc", latency_seconds=0.1))
        self.assertTrue(ssh_compression_recommended("notes.txt", latency_seconds=0.1))

    def test_tuning_is_large_file_only_and_changes_one_setting_at_a_time(self):
        small = AdaptiveTransferTuner(31 * 1024 * 1024)
        self.assertEqual(small.observe(16 * 1024 * 1024, 10), (1048576, 8))
        self.assertFalse(small.active)
        tuner = AdaptiveTransferTuner(64 * 1024 * 1024)
        tuner.observe(8 * 1024 * 1024, 1)
        tuner.observe(12 * 1024 * 1024, 5)
        self.assertEqual(tuner.observe(16 * 1024 * 1024, 7), (2 * 1024 * 1024, 8))
        self.assertEqual(tuner.prefetch_depth, 8)
        tuner.observe(20 * 1024 * 1024, 15)
        tuner.observe(24 * 1024 * 1024, 23)
        self.assertTrue(tuner.stopped)
