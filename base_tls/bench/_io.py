"""Shared output helpers for the benchmark scripts.

Every benchmark writes machine-readable JSON plus a Markdown table, so a number in
a report can always be traced back to the run that produced it.
"""

from __future__ import annotations

import json
import platform
import statistics
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

__all__ = ["Sample", "benchmark", "environment", "write_outputs"]

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / ".bench-out"


@dataclass(frozen=True)
class Sample:
    """Timing summary for one primitive."""

    label: str
    iterations: int
    total_seconds: float
    median_seconds: float
    minimum_seconds: float
    maximum_seconds: float
    operations_per_second: float
    metadata: dict[str, Any]

    def as_row(self) -> dict[str, Any]:
        """Flatten to a JSON-friendly mapping."""
        return {
            "label": self.label,
            "iterations": self.iterations,
            "median_ms": round(self.median_seconds * 1000, 4),
            "min_ms": round(self.minimum_seconds * 1000, 4),
            "max_ms": round(self.maximum_seconds * 1000, 4),
            "mean_ms": round(self.total_seconds / max(self.iterations, 1) * 1000, 4),
            "ops_per_second": round(self.operations_per_second, 1),
            **self.metadata,
        }


def benchmark(label: str, iterations: int, operation, metadata: dict[str, Any] | None = None) -> Sample:
    """Time ``operation`` ``iterations`` times and summarise the samples.

    ``operation`` receives the iteration index so a caller can alternate between
    inputs; the first call is excluded from the summary as a warm-up only when more
    than three iterations run, so short runs still report every sample.
    """
    samples: list[float] = []
    started = time.perf_counter()
    for index in range(iterations):
        begin = time.perf_counter()
        operation(index)
        samples.append(time.perf_counter() - begin)
    total = time.perf_counter() - started
    if iterations > 3:
        samples = samples[1:]
    median = statistics.median(samples)
    return Sample(
        label=label,
        iterations=len(samples),
        total_seconds=total,
        median_seconds=median,
        minimum_seconds=min(samples),
        maximum_seconds=max(samples),
        operations_per_second=(1.0 / median) if median > 0 else float("inf"),
        metadata=metadata or {},
    )


def environment() -> dict[str, Any]:
    """Describe the machine and interpreter the numbers came from."""
    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "processor": platform.processor() or "unknown",
        "machine": platform.machine(),
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    }


def _markdown_table(rows: list[dict[str, Any]], columns: Iterable[str]) -> str:
    columns = list(columns)
    lines = ["| " + " | ".join(columns) + " |", "|" + "|".join("---" for _ in columns) + "|"]
    for row in rows:
        lines.append("| " + " | ".join(str(row.get(column, "")) for column in columns) + " |")
    return "\n".join(lines)


def write_outputs(
    stem: str,
    payload: dict[str, Any],
    rows: list[dict[str, Any]],
    columns: Iterable[str],
    output_dir: Path | None = None,
    title: str | None = None,
) -> tuple[Path, Path]:
    """Write ``<stem>.json`` and ``<stem>.md`` and return both paths."""
    directory = output_dir or DEFAULT_OUTPUT_DIR
    directory.mkdir(parents=True, exist_ok=True)
    json_path = directory / f"{stem}.json"
    markdown_path = directory / f"{stem}.md"

    document = {"environment": environment(), **payload}
    json_path.write_text(json.dumps(document, indent=2, ensure_ascii=False), encoding="utf-8")

    header = f"# {title or stem}\n\n"
    meta = document["environment"]
    body = (
        f"- python: {meta['python']}\n"
        f"- platform: {meta['platform']}\n"
        f"- processor: {meta['processor']}\n"
        f"- generated: {meta['timestamp']}\n\n"
    )
    markdown_path.write_text(header + body + _markdown_table(rows, columns) + "\n", encoding="utf-8")
    return json_path, markdown_path
