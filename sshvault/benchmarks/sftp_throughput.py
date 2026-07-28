"""Deterministic, offline SFTP request-overhead benchmark model.

This intentionally models a fake SFTP server with fixed per-request latency;
it does not touch a network, credentials, paths, or payload contents.
"""

from __future__ import annotations

from math import ceil


TOTAL_BYTES = 64 * 1024 * 1024
REQUEST_LATENCY_SECONDS = 0.002


def modeled_seconds(chunk_size: int, *, prefetch_depth: int = 1, workers: int = 1) -> float:
    requests = ceil(TOTAL_BYTES / chunk_size)
    request_rounds = ceil(requests / max(1, prefetch_depth))
    return request_rounds * REQUEST_LATENCY_SECONDS / max(1, workers)


def main() -> None:
    cases = (
        ("256 KiB synchronous, concurrency 1", 256 * 1024, 1, 1),
        ("1 MiB buffered, concurrency 1", 1024 * 1024, 1, 1),
        ("1 MiB prefetch depth 8, concurrency 1", 1024 * 1024, 8, 1),
        ("1 MiB prefetch depth 8, concurrency 3", 1024 * 1024, 8, 3),
    )
    for label, chunk_size, depth, workers in cases:
        seconds = modeled_seconds(chunk_size, prefetch_depth=depth, workers=workers)
        mib_per_second = TOTAL_BYTES / seconds / (1024 * 1024)
        print(f"{label}: {mib_per_second:.1f} MiB/s ({seconds:.3f}s model)")


if __name__ == "__main__":
    main()
