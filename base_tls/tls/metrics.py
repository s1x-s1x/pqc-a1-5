"""Timing and byte accounting shared by the handshake and the benchmarks."""

from __future__ import annotations

import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

__all__ = ["MessageRecord", "Metrics", "TLS_RECORD_HEADER_BYTES"]

#: Every TLS record carries a five-byte header, which is plaintext on the wire.
TLS_RECORD_HEADER_BYTES = 5


@dataclass(frozen=True)
class MessageRecord:
    """One observed handshake record fragment; plaintext and overhead stay separate."""

    name: str
    sender: str
    #: Handshake message bytes or a fragment thereof.
    message_bytes: int
    #: Actual inner type and AEAD tag bytes; no imputed TLS record header.
    protection_bytes: int = 0
    #: Actual private transport prefix per record, if this observation used TCP.
    transport_prefix_bytes: int = 0
    record_count: int = 1

    @property
    def record_bytes(self) -> int:
        """Actual serialized bare harness bytes (no imputed TLS header)."""
        return self.message_bytes + self.protection_bytes

    @property
    def tcp_framed_bytes(self) -> int:
        return self.record_bytes + 4 * self.record_count

    @property
    def standard_tls_model_bytes(self) -> int:
        """Size model adding TLS's 5-byte header; no interoperability claim."""
        return self.record_bytes + TLS_RECORD_HEADER_BYTES * self.record_count

    @property
    def total_bytes(self) -> int:
        """Bytes this message contributes to the handshake flight."""
        return self.record_bytes + self.transport_prefix_bytes * self.record_count


@dataclass
class Metrics:
    """Accumulates labelled durations and counters for one measured run."""

    durations: dict[str, list[float]] = field(default_factory=dict)
    counts: dict[str, int] = field(default_factory=dict)

    @contextmanager
    def time(self, label: str) -> Iterator[None]:
        """Record the wall-clock duration of the enclosed block under ``label``."""
        start = time.perf_counter()
        try:
            yield
        finally:
            self.durations.setdefault(label, []).append(time.perf_counter() - start)

    def count(self, label: str, amount: int = 1) -> None:
        """Add ``amount`` to the counter ``label``."""
        self.counts[label] = self.counts.get(label, 0) + amount

    def total(self, label: str) -> float:
        """Sum every recorded duration for ``label``."""
        return sum(self.durations.get(label, ()))

    def median(self, label: str) -> float:
        """Median recorded duration for ``label``; zero when nothing was recorded."""
        samples = sorted(self.durations.get(label, ()))
        if not samples:
            return 0.0
        middle = len(samples) // 2
        if len(samples) % 2:
            return samples[middle]
        return (samples[middle - 1] + samples[middle]) / 2

    def summary(self) -> dict[str, float]:
        """Flatten every duration total and counter into one mapping."""
        flat = {f"time.{key}": self.total(key) for key in self.durations}
        flat.update({f"count.{key}": float(value) for key, value in self.counts.items()})
        return flat
