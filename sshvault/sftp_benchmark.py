"""Development-only, credential-free measurements for an existing SFTP session.

Callers supply an already authenticated worker-owned SFTP client factory. This
module never reads SSHVault profiles, keys, passwords, or file payloads.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import time
from typing import Any, Callable

from sshvault_core import bounded_prefetch_depth


@dataclass
class SFTPBenchmarkMetrics:
    bytes_transferred: int = 0
    elapsed_seconds: float = 0.0
    cpu_seconds: float = 0.0
    round_trip_seconds: float = 0.0
    local_read_seconds: float = 0.0
    local_write_seconds: float = 0.0
    remote_read_seconds: float = 0.0
    remote_write_seconds: float = 0.0
    request_count: int = 0
    effective_request_size: float = 0.0
    outstanding_requests: int = 0
    cipher: str = "unknown"
    mac: str = "unknown"
    compression: str = "unknown"
    channel_window_size: int | None = None
    channel_max_packet_size: int | None = None

    @property
    def throughput_bytes_per_second(self) -> float:
        return self.bytes_transferred / self.elapsed_seconds if self.elapsed_seconds else 0.0

    def safe_dict(self) -> dict[str, Any]:
        """Metrics intentionally omit hosts, paths, credentials, and payloads."""
        return asdict(self) | {"throughput_bytes_per_second": self.throughput_bytes_per_second}


def transport_metrics(sftp: Any) -> SFTPBenchmarkMetrics:
    result = SFTPBenchmarkMetrics()
    channel = sftp.get_channel()
    transport = getattr(channel, "transport", None)
    if transport is not None:
        result.cipher = str(getattr(transport, "local_cipher", "unknown"))
        result.mac = str(getattr(transport, "local_mac", "unknown"))
        result.compression = str(getattr(transport, "local_compression", "unknown"))
    # These are observational compatibility attributes, never mutated.
    result.channel_window_size = getattr(channel, "in_window_size", None)
    result.channel_max_packet_size = getattr(channel, "in_max_packet_size", None)
    return result


class SFTPBenchmarkRunner:
    """Benchmark an existing authenticated session using temporary remote data."""

    def __init__(self, sftp_factory: Callable[[], Any], *, clock: Callable[[], float] = time.perf_counter) -> None:
        self.sftp_factory, self.clock = sftp_factory, clock

    def download(
        self, remote_path: str, local_path: Path, *, chunk_size: int, prefetch_depth: int = 8
    ) -> SFTPBenchmarkMetrics:
        sftp = self.sftp_factory()
        metrics = transport_metrics(sftp)
        started = self.clock()
        cpu_started = time.process_time()
        try:
            total = sftp.stat(remote_path).st_size
            with sftp.open(remote_path, "rb") as source, local_path.open("wb") as target:
                prefetch = getattr(source, "prefetch", None)
                depth = bounded_prefetch_depth(chunk_size, prefetch_depth)
                if callable(prefetch) and depth:
                    prefetch(file_size=total, max_concurrent_prefetch_requests=depth)
                    metrics.outstanding_requests = depth
                while True:
                    began = self.clock()
                    chunk = source.read(chunk_size)
                    metrics.remote_read_seconds += self.clock() - began
                    metrics.request_count += 1
                    if not chunk:
                        break
                    began = self.clock()
                    target.write(chunk)
                    metrics.local_write_seconds += self.clock() - began
                    metrics.bytes_transferred += len(chunk)
        finally:
            metrics.elapsed_seconds = self.clock() - started
            metrics.cpu_seconds = time.process_time() - cpu_started
            sftp.close()
        metrics.effective_request_size = metrics.bytes_transferred / max(1, metrics.request_count - 1)
        return metrics

    def upload(self, local_path: Path, remote_path: str, *, chunk_size: int) -> SFTPBenchmarkMetrics:
        sftp = self.sftp_factory()
        metrics = transport_metrics(sftp)
        started = self.clock()
        cpu_started = time.process_time()
        try:
            with local_path.open("rb") as source, sftp.open(remote_path, "wb") as target:
                set_pipelined = getattr(target, "set_pipelined", None)
                if callable(set_pipelined):
                    set_pipelined(True)
                while True:
                    began = self.clock()
                    chunk = source.read(chunk_size)
                    metrics.local_read_seconds += self.clock() - began
                    if not chunk:
                        break
                    began = self.clock()
                    target.write(chunk)
                    metrics.remote_write_seconds += self.clock() - began
                    metrics.request_count += 1
                    metrics.bytes_transferred += len(chunk)
        finally:
            metrics.elapsed_seconds = self.clock() - started
            metrics.cpu_seconds = time.process_time() - cpu_started
            sftp.close()
        metrics.effective_request_size = metrics.bytes_transferred / max(1, metrics.request_count)
        return metrics

    def round_trip(self, remote_path: str) -> float:
        """Measure one public SFTP stat round trip without recording its path."""
        sftp = self.sftp_factory()
        started = self.clock()
        try:
            sftp.stat(remote_path)
            return self.clock() - started
        finally:
            sftp.close()

    def local_disk_read(self, path: Path, *, chunk_size: int) -> SFTPBenchmarkMetrics:
        metrics = SFTPBenchmarkMetrics()
        started = self.clock()
        with path.open("rb") as source:
            while chunk := source.read(chunk_size):
                metrics.bytes_transferred += len(chunk)
                metrics.request_count += 1
        metrics.elapsed_seconds = self.clock() - started
        metrics.local_read_seconds = metrics.elapsed_seconds
        metrics.effective_request_size = metrics.bytes_transferred / max(1, metrics.request_count)
        return metrics

    @staticmethod
    def temporary_name(prefix: str = ".sshvault-benchmark-") -> str:
        return prefix + os.urandom(8).hex()
