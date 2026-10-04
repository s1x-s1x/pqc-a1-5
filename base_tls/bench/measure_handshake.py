"""Measure handshake byte counts and end-to-end latency per profile.

This covers the last two measurement categories the design calls for: total
handshake bytes (split per message and per post-quantum addition) and the latency of
the handshake itself.

Reading the byte numbers: the certificate here is a minimal two-key structure with
no X.509 chain, so the *absolute* total is much smaller than a deployed TLS 1.3
handshake. The per-field deltas and the per-message breakdown are the parts that
transfer, because those are exactly the bytes the post-quantum additions cost.

Usage:
    python bench/measure_handshake.py
    python bench/measure_handshake.py --repeats 20 --kems ml-kem-768
    python bench/measure_handshake.py --profile quick
"""

from __future__ import annotations

import argparse
import statistics
import sys
import time
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench._io import write_outputs  # noqa: E402
from tls.config import HybridTLSConfig  # noqa: E402
from tls.handshake.connection import HybridConnection  # noqa: E402
from tls.metrics import Metrics  # noqa: E402
from tls.pq.kem import available_kems  # noqa: E402
from tls.pq.signature import available_pq_signers  # noqa: E402

#: Timings reported per profile, taken from the Metrics labels the handshake emits.
STAGE_LABELS = (
    "kdf_handshake_secret",
    "kdf_handshake_traffic",
    "kdf_master_secret",
    "kdf_application_traffic",
    "kdf_resumption_secret",
    "server_kem_encaps",
    "client_kem_decaps",
    "server_sign_pq",
    "client_verify_pq",
    "server_sign_classical",
    "client_verify_classical",
    "handshake_total",
)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repeats", type=int, default=10, help="handshakes per profile")
    parser.add_argument("--kems", nargs="*", default=None, help="KEMs to sweep (default: all available)")
    parser.add_argument("--signers", nargs="*", default=None, help="post-quantum signers to sweep")
    parser.add_argument("--xmss-height", type=int, default=10, help="tree height for the XMSS profile")
    parser.add_argument("--skip-xmss", action="store_true", help="omit the hash-based profile")
    parser.add_argument(
        "--profile",
        choices=("full", "quick", "baseline"),
        default="full",
        help="full sweeps every axis; quick keeps one value per axis; baseline is the default profile only",
    )
    parser.add_argument("--out", default=None, help="output directory (default: .bench-out)")
    parser.add_argument(
        "--x509",
        action="store_true",
        help="use the real X.509 chain instead of the modelled certificate; the baseline "
        "then matches a deployment's size and the ratios become comparable",
    )
    return parser.parse_args(argv)


def build_profiles(args: argparse.Namespace) -> list[HybridTLSConfig]:
    """Turn the sweep options into the list of profiles to measure."""
    kems = args.kems or sorted(available_kems())
    signers = [name for name, status in sorted(available_pq_signers().items()) if status == "ok"]
    if args.signers:
        signers = [name for name in args.signers if name in signers]
    if args.skip_xmss:
        signers = [name for name in signers if not name.startswith("xmss")]

    if args.profile == "baseline":
        return [HybridTLSConfig()]
    if args.profile == "quick":
        kems = kems[:1] or ["ml-kem-768"]
        signers = [name for name in signers if name in {"falcon-512", "ml-dsa-44", "xmss"}] or ["falcon-512"]

    profiles: list[HybridTLSConfig] = []
    # One axis at a time: vary the KEM with the default signature, then the
    # signature with the default KEM, so each row isolates one choice.
    for kem in kems:
        profiles.append(
            HybridTLSConfig(kem=kem, pq_signer="falcon-512", xmss_height=args.xmss_height, x509=args.x509)
        )
    for signer in signers:
        profiles.append(
            HybridTLSConfig(kem="ml-kem-768", pq_signer=signer, xmss_height=args.xmss_height, x509=args.x509)
        )
    if args.x509:
        # The baseline itself is worth a row: it is what every delta is measured against.
        profiles.insert(0, HybridTLSConfig(pq_enabled=False, x509=True))
    return profiles


def _median(values: list[float]) -> float:
    return statistics.median(values) if values else 0.0


def measure_profile(config: HybridTLSConfig, repeats: int, with_baseline: bool = True) -> dict:
    """Run one profile ``repeats`` times and summarise bytes, stages, and latency.

    When ``with_baseline`` is set and the profile is hybrid, the same profile is also run
    with ``pq_enabled=False``, so ``baseline_bytes`` and ``measured_pq_delta`` come from a
    handshake that actually ran rather than from a per-field formula.
    """
    byte_totals: list[int] = []
    client_bytes: list[int] = []
    server_bytes: list[int] = []
    wall_times: list[float] = []
    handshake_times: list[float] = []
    stage_samples: dict[str, list[float]] = {label: [] for label in STAGE_LABELS}
    per_message: dict[str, int] = {}
    pq_deltas: dict[str, int] = {}
    baseline_totals: list[int] = []
    baseline_times: list[float] = []
    ok = True

    for _ in range(repeats):
        metrics = Metrics()
        started = time.perf_counter()
        result = HybridConnection.run(config, metrics=metrics)
        wall_times.append(time.perf_counter() - started)
        byte_totals.append(result.handshake_bytes)
        client_bytes.append(result.client_bytes)
        server_bytes.append(result.server_bytes)
        handshake_times.append(metrics.total("handshake_total"))
        for label in STAGE_LABELS:
            stage_samples[label].append(metrics.total(label))
        for name, _sender, plain, protection in result.flight_table():
            per_message[name] = per_message.get(name, 0) + plain + protection
        pq_deltas = result.pq_deltas()
        ok = ok and result.application_payload_ok and result.exporters_match

    if with_baseline and config.pq_enabled:
        baseline_config = replace(config, pq_enabled=False)
        for _ in range(repeats):
            baseline_metrics = Metrics()
            baseline = HybridConnection.run(baseline_config, metrics=baseline_metrics)
            baseline_totals.append(baseline.handshake_bytes)
            baseline_times.append(baseline_metrics.total("handshake_total"))
            ok = ok and baseline.application_payload_ok and baseline.exporters_match

    runs = max(len(wall_times), 1)
    row: dict[str, object] = {
        "kem": config.kem,
        "pq_signer": config.pq_signer,
        "classical_signer": config.classical_signer,
        "group": config.group,
        "repeats": runs,
        "handshake_bytes": int(_median([float(value) for value in byte_totals])),
        "handshake_bytes_min": min(byte_totals),
        "handshake_bytes_max": max(byte_totals),
        "client_bytes": int(_median([float(value) for value in client_bytes])),
        "server_bytes": int(_median([float(value) for value in server_bytes])),
        "pq_delta_bytes": sum(pq_deltas.values()),
        "handshake_ms": round(_median(handshake_times) * 1000, 3),
        "wall_ms": round(_median(wall_times) * 1000, 3),
        "ok": ok,
    }
    if baseline_totals:
        baseline_bytes = int(_median([float(value) for value in baseline_totals]))
        row["baseline_bytes"] = baseline_bytes
        row["measured_pq_delta"] = row["handshake_bytes"] - baseline_bytes  # type: ignore[operator]
        row["baseline_ms"] = round(_median(baseline_times) * 1000, 3)
        row["size_ratio"] = round(row["handshake_bytes"] / baseline_bytes, 3)  # type: ignore[operator]
    for name, total in sorted(per_message.items()):
        row[f"bytes.{name}"] = total // runs
    for label, samples in stage_samples.items():
        row[f"stage_ms.{label}"] = round(_median(samples) * 1000, 3)
    for key, value in pq_deltas.items():
        row[f"pq.{key}"] = value
    return row


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    profiles = build_profiles(args)
    rows: list[dict] = []
    for index, config in enumerate(profiles, start=1):
        label = f"{config.kem} + {config.pq_signer}"
        print(f"[{index}/{len(profiles)}] {label}", flush=True)
        row = measure_profile(config, args.repeats)
        rows.append(row)
        print(
            f"    {row['handshake_bytes']} bytes, handshake {row['handshake_ms']} ms, "
            f"pq additions {row['pq_delta_bytes']} bytes, ok={row['ok']}",
            flush=True,
        )

    columns = [
        "kem",
        "pq_signer",
        "handshake_bytes",
        "client_bytes",
        "server_bytes",
        "pq_delta_bytes",
        "handshake_ms",
        "bytes.ClientHello",
        "bytes.ServerHello",
        "bytes.Certificate",
        "bytes.CertificateVerify",
        "stage_ms.server_kem_encaps",
        "stage_ms.client_kem_decaps",
        "stage_ms.server_sign_pq",
        "stage_ms.client_verify_pq",
        "ok",
    ]
    output_dir = Path(args.out) if args.out else None
    json_path, markdown_path = write_outputs(
        "handshake",
        {"repeats": args.repeats, "profile_set": args.profile, "results": rows},
        rows,
        columns,
        output_dir,
        title="Hybrid handshake size and latency",
    )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    return 0 if all(row["ok"] for row in rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
