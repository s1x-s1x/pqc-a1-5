"""Measure the handshake under emulated links, and check the link's own prediction.

The point of shaping is to make the latency numbers mean something. Each run reports
three things:

* **measured** — the client's wall time until the server is authenticated;
* **predicted** — what the link's arithmetic says that interval should cost, which is
  one round trip plus the serialization time of both flights;
* **harness overhead** — measured minus predicted, reported separately rather than
  hidden. It is a constant of this test rig (thread creation, accept, scheduling), and
  the ``lan`` profile measures it directly because its predicted value is ~0.

The comparison that matters is hybrid against the classical baseline **on the same
link**: whatever the harness overhead is, it cancels, and what is left is the
post-quantum bytes' contribution to a handshake's wall time.

Conditions default to the ones the KEMTLS measurements use: 31.1 ms and 195.6 ms RTT at
1000 Mbps and 10 Mbps.

Usage:
    python bench/measure_shaped.py
    python bench/measure_shaped.py --repeats 5 --links wan-slow wan-lossy
"""

from __future__ import annotations

import argparse
import statistics
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench._io import write_outputs  # noqa: E402
from tls.config import HybridTLSConfig  # noqa: E402
from tls.transport.shaper import DEFAULT_PROFILES, LINK_PROFILES, LinkProfile  # noqa: E402
from tls.transport.tcp import run_over_tcp  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=3, help="handshakes per profile per link")
    parser.add_argument("--links", nargs="*", default=list(DEFAULT_PROFILES), help="link profile names")
    parser.add_argument("--pq", default="falcon-512", help="post-quantum signature backend")
    parser.add_argument("--kem", default="ml-kem-768", help="post-quantum KEM")
    parser.add_argument(
        "--modeled-certificate",
        action="store_true",
        help="use the modelled certificate instead of the real X.509 chain",
    )
    parser.add_argument("--out", default=None, help="output directory (default: .bench-out)")
    return parser.parse_args(argv)


def measure_one(config: HybridTLSConfig, link: LinkProfile) -> dict:
    """Run one handshake over one link and return its measured and predicted latency."""
    sample = run_over_tcp(config, link=link)
    return {
        "authenticated_ms": sample.authenticated_ms,
        "total_ms": sample.client_wall_ms,
        "predicted_ms": sample.predicted_authenticated_ms,
        "handshake_bytes": sample.handshake_bytes,
        "one_rtt": sample.waits_to_authenticated == 1,
        "records_lost": sample.records_lost,
        "ok": sample.application_ok and sample.error is None and sample.waits_to_authenticated == 1,
        "error": sample.error or "",
    }


def summarise(samples: list[dict], variant: str, config: HybridTLSConfig) -> dict:
    """Reduce one variant's samples to a reportable row."""
    authenticated = [sample["authenticated_ms"] for sample in samples]
    totals = [sample["total_ms"] for sample in samples]
    first = samples[0]
    return {
        "variant": variant,
        "pq_signer": config.pq_signer if config.pq_enabled else "(none)",
        "kem": config.kem if config.pq_enabled else "(none)",
        "certificate": "x509" if config.x509 else "modelled",
        "handshake_bytes": first["handshake_bytes"],
        "authenticated_ms": round(statistics.median(authenticated), 3),
        # Latency noise is additive here: scheduling can only inflate a run, never shrink
        # it. The minimum is therefore the cleanest estimate of the link's own cost.
        "authenticated_min_ms": round(min(authenticated), 3),
        "authenticated_max_ms": round(max(authenticated), 3),
        "predicted_ms": round(first["predicted_ms"], 3),
        "total_ms": round(statistics.median(totals), 3),
        "one_rtt": all(sample["one_rtt"] for sample in samples),
        "records_lost": sum(sample["records_lost"] for sample in samples),
        "ok": all(sample["ok"] for sample in samples),
        "error": next((sample["error"] for sample in samples if sample["error"]), ""),
    }


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    base = HybridTLSConfig(
        kem=args.kem, pq_signer=args.pq, x509=not args.modeled_certificate
    )
    variants = [("hybrid", base), ("classical", replace(base, pq_enabled=False))]

    rows: list[dict] = []
    for link_name in args.links:
        link = LINK_PROFILES[link_name]
        print(f"[{link_name}] rtt {link.rtt_ms} ms, {link.bandwidth_mbps} Mbps, loss {link.loss_percent}%", flush=True)
        # Interleaved, not sequential: alternating the two variants inside each round means
        # any drift in machine state lands on both, and the per-round difference is what
        # gets reported. Measuring one variant to completion and then the other would let
        # drift masquerade as the post-quantum cost -- which is exactly what it did before
        # this loop was written this way.
        samples: dict[str, list[dict]] = {label: [] for label, _ in variants}
        paired: list[float] = []
        for index in range(args.repeats):
            # AB/BA alternation, not a fixed hybrid-then-classical order inside every
            # round. A constant order leaves any order-dependent bias -- cache state,
            # allocator state, the OS timer -- entirely on one variant, which an external
            # review caught: the previous loop called itself interleaved and was not.
            order = variants if index % 2 == 0 else list(reversed(variants))
            round_samples = {}
            for label, config in order:
                result = measure_one(config, link)
                samples[label].append(result)
                round_samples[label] = result
            paired.append(
                round_samples["hybrid"]["authenticated_ms"]
                - round_samples["classical"]["authenticated_ms"]
            )

        hybrid = summarise(samples["hybrid"], "hybrid", base)
        classical = summarise(samples["classical"], "classical", replace(base, pq_enabled=False))
        expected = link.serialization_ms(hybrid["handshake_bytes"] - classical["handshake_bytes"])
        for row in (hybrid, classical):
            row["link"] = link_name
            row["rtt_ms"] = link.rtt_ms
            row["bandwidth_mbps"] = link.bandwidth_mbps
            row["loss_percent"] = link.loss_percent
            row["pq_cost_ms"] = round(statistics.median(paired), 3)
            row["pq_cost_min_ms"] = round(min(paired), 3)
            row["pq_cost_max_ms"] = round(max(paired), 3)
            row["pq_cost_predicted_ms"] = round(expected, 3)
            rows.append(row)

        for label, row in (("hybrid", hybrid), ("classical", classical)):
            print(
                f"    {label:<10}{row['authenticated_ms']:>9.2f} ms "
                f"(predicted {row['predicted_ms']:.2f}, harness overhead {row['authenticated_ms'] - row['predicted_ms']:+.2f})"
                f"  ok={row['ok']}",
                flush=True,
            )
        print(
            f"    post-quantum cost, paired per round: {statistics.median(paired):+.2f} ms median "
            f"[{min(paired):+.2f}, {max(paired):+.2f}] over {len(paired)} rounds "
            f"({hybrid['handshake_bytes'] - classical['handshake_bytes']:+d} bytes, "
            f"pure serialization {expected:.2f} ms)",
            flush=True,
        )

    columns = [
        "link",
        "rtt_ms",
        "bandwidth_mbps",
        "variant",
        "handshake_bytes",
        "authenticated_ms",
        "authenticated_min_ms",
        "predicted_ms",
        "pq_cost_ms",
        "pq_cost_min_ms",
        "pq_cost_max_ms",
        "pq_cost_predicted_ms",
        "one_rtt",
        "ok",
    ]
    json_path, markdown_path = write_outputs(
        "shaped",
        {"repeats": args.repeats, "links": args.links, "results": rows},
        rows,
        columns,
        Path(args.out) if args.out else None,
        title="Handshake latency under emulated links",
    )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    return 0 if all(row["ok"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
