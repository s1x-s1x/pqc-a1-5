"""Measure the handshake over loopback TCP and count the round trips on the wire.

Two questions the in-process benchmark cannot answer:

* Does the post-quantum material cost an extra round trip? The client-side wait count
  is observed from the socket: one wait before the server is authenticated and the
  handshake keys are usable means the handshake is still 1-RTT.
* What does the transport add? The same profile is measured both ways, so
  ``transport_overhead_ms`` is the difference rather than a guess.

The absolute TCP numbers here are dominated by thread creation, the accept handshake,
and scheduler wake-ups on a loopback that never leaves the machine -- they measure the
harness, not a network. The wait count and the in-process comparison are the parts
that carry meaning.

Usage:
    python bench/measure_tcp.py
    python bench/measure_tcp.py --repeats 20 --pq xmss --xmss-height 8
"""

from __future__ import annotations

import argparse
import statistics
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench._io import write_outputs  # noqa: E402
from tls.config import HybridTLSConfig  # noqa: E402
from tls.handshake.connection import HybridConnection  # noqa: E402
from tls.transport.tcp import run_over_tcp  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=10, help="loopback handshakes per profile")
    parser.add_argument("--kem", default="ml-kem-768", help="KEM for every profile")
    parser.add_argument("--pq", nargs="*", default=None, help="post-quantum signers (default: a small set)")
    parser.add_argument("--xmss-height", type=int, default=8, help="tree height for the XMSS profile")
    parser.add_argument("--out", default=None, help="output directory (default: .bench-out)")
    return parser.parse_args(argv)


def measure(config: HybridTLSConfig, repeats: int) -> dict:
    """Run one profile ``repeats`` times over loopback and once in process."""
    tcp_times: list[float] = []
    in_process_times: list[float] = []
    waits: set[int] = set()
    waits_to_authenticated: set[int] = set()
    byte_counts: list[int] = []
    ok = True
    errors: list[str] = []

    for _ in range(repeats):
        result = run_over_tcp(config)
        ok = ok and result.application_ok and result.error is None
        if result.error:
            errors.append(result.error)
        tcp_times.append(result.client_wall_ms)
        byte_counts.append(result.handshake_bytes)
        waits.add(result.client_waits)
        waits_to_authenticated.add(result.waits_to_authenticated)

    for _ in range(repeats):
        measurement = HybridConnection.run(config)
        in_process_times.append(measurement.metrics.total("handshake_total") * 1000)
        ok = ok and measurement.application_payload_ok and measurement.exporters_match

    tcp_median = statistics.median(tcp_times)
    in_process_median = statistics.median(in_process_times)
    return {
        "kem": config.kem,
        "pq_signer": config.pq_signer,
        "repeats": repeats,
        "handshake_bytes": int(statistics.median([float(value) for value in byte_counts])),
        "client_waits": sorted(waits),
        "waits_to_authenticated": sorted(waits_to_authenticated),
        "one_rtt": waits_to_authenticated == {1},
        "tcp_median_ms": round(tcp_median, 3),
        "in_process_median_ms": round(in_process_median, 3),
        "transport_overhead_ms": round(tcp_median - in_process_median, 3),
        "ok": ok,
        "error": errors[0] if errors else "",
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    signers = args.pq or ["falcon-512", "ml-dsa-44", "xmss"]
    profiles = [
        HybridTLSConfig(kem=args.kem, pq_signer=signer, xmss_height=args.xmss_height)
        for signer in signers
    ]
    rows: list[dict] = []
    for index, config in enumerate(profiles, start=1):
        print(f"[{index}/{len(profiles)}] {config.kem} + {config.pq_signer}", flush=True)
        row = measure(config, args.repeats)
        rows.append(row)
        print(
            f"    waits={row['waits_to_authenticated']} (1-RTT: {row['one_rtt']}), "
            f"tcp {row['tcp_median_ms']} ms vs in-process {row['in_process_median_ms']} ms, ok={row['ok']}",
            flush=True,
        )

    columns = [
        "kem",
        "pq_signer",
        "handshake_bytes",
        "waits_to_authenticated",
        "one_rtt",
        "tcp_median_ms",
        "in_process_median_ms",
        "transport_overhead_ms",
        "ok",
    ]
    json_path, markdown_path = write_outputs(
        "tcp",
        {"repeats": args.repeats, "results": rows},
        rows,
        columns,
        Path(args.out) if args.out else None,
        title="Loopback TCP handshake: round trips and transport overhead",
    )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    return 0 if all(row["ok"] and row["one_rtt"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
