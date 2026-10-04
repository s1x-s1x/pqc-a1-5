"""Cost decomposition for the stateful (XMSS) authentication path, cold and hot.

Why this exists. A red-team pass measured a two-second stall per connection and asked the
obvious follow-up: what exactly is being spent, and on what trigger (their W1). The answer
cannot come from a handshake timer, because the driver's timers start *after* the credentials
have been built. This benchmark therefore measures the phases separately, on this machine, with
the raw samples kept:

1. **whole-tree key generation** -- the XMSS backend hashes ``2 ** height`` WOTS+ public keys, so
   this is the expensive one. ``max_signatures`` leaves are produced, and the U-03 change (a
   fresh public seed per tree, addressed chain keys and bitmasks) made it slower than the
   pre-U-03 code by a factor this run is meant to quantify rather than inherit;
2. **certificate build** -- signing the hybrid certificate body with the CA key;
3. **one signature and its verification**;
4. **the online handshake**, in two modes:
   * *cold*: credentials built inside the timed section, which is what a driver that generates a
     key per connection pays;
   * *hot*: credentials generated before the timer and reused. **Only the authentication
     credential is reused** -- every handshake still builds its own transcript, ECDHE and KEM
     ephemeral keys, traffic secrets and record sequences, so this is a real handshake. It is
     not a cache of connections, and the plan forbids reading it as one;
5. **entry to completion**, wall clock and process CPU time, so the numbers can be checked
   against the machine rather than trusted.

Trigger timeline: the JSON records when the credentials were built relative to the driver's
phases, so "one connection costs a keygen" can be checked against what actually runs.

Usage:
    python bench/measure_xmss_lifecycle.py                     # h=8 and h=10, 5 cold, 30 hot
    python bench/measure_xmss_lifecycle.py --heights 8 --cold 3 --hot 10
    python bench/measure_xmss_lifecycle.py --out .bench-lifecycle
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench._io import environment, write_outputs  # noqa: E402
from tls.config import HybridTLSConfig  # noqa: E402
from tls.credentials import CertificateAuthority, ServerCredentials  # noqa: E402
from tls.handshake.connection import DEFAULT_APPLICATION_PAYLOAD, HybridConnection  # noqa: E402

DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parents[1] / ".bench-lifecycle"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--heights", nargs="*", type=int, default=[8, 10], help="Merkle heights to measure")
    parser.add_argument("--cold", type=int, default=5, help="cold initialisations per height")
    parser.add_argument("--hot", type=int, default=30, help="hot handshakes per height")
    parser.add_argument("--kem", default="ml-kem-768", help="KEM for the handshake measurements")
    parser.add_argument("--out", default=None, help="output directory (default: .bench-lifecycle)")
    return parser.parse_args(argv)


def _cpu_seconds() -> float:
    return time.process_time()


def _summary(samples: list[float]) -> dict[str, float]:
    return {
        "count": len(samples),
        "median_ms": round(statistics.median(samples) * 1000, 3),
        "min_ms": round(min(samples) * 1000, 3),
        "max_ms": round(max(samples) * 1000, 3),
        "mean_ms": round(statistics.fmean(samples) * 1000, 3),
    }


def measure_height(height: int, args: argparse.Namespace) -> dict:
    """Every phase for one tree height, with raw samples."""
    config = HybridTLSConfig(kem=args.kem, pq_signer="xmss", xmss_height=height)
    authority = CertificateAuthority(config.classical())
    backend = config.pq()

    row: dict = {
        "height": height,
        "max_signatures": backend.max_signatures,
        "public_key_bytes": backend.public_key_bytes,
        "signature_bytes": backend.signature_bytes,
        "phases": {},
    }

    # 1. Whole-tree key generation.
    keygen_samples: list[float] = []
    cpu_before = _cpu_seconds()
    credentials: list[ServerCredentials] = []
    for _index in range(args.cold):
        started = time.perf_counter()
        credentials.append(ServerCredentials(config, identity=b"server.example"))
        keygen_samples.append(time.perf_counter() - started)
    row["phases"]["tree_keygen"] = {
        **_summary(keygen_samples),
        "cpu_seconds_total": round(_cpu_seconds() - cpu_before, 4),
        "samples_ms": [round(value * 1000, 3) for value in keygen_samples],
    }

    # 2. Certificate build (CA signature over the hybrid body), same credential reused.
    certificate_samples: list[float] = []
    for index in range(args.cold):
        started = time.perf_counter()
        credentials[index].bind_to(authority)
        certificate_samples.append(time.perf_counter() - started)
    row["phases"]["certificate_build"] = {
        **_summary(certificate_samples),
        "samples_ms": [round(value * 1000, 3) for value in certificate_samples],
    }

    # 3. One signature and its verification, on the credential that still has leaves.
    signer = config.pq()
    secret, public = signer.keygen()
    message = b"benchmark message"
    sign_samples: list[float] = []
    verify_samples: list[float] = []
    for index in range(min(args.cold, 5)):
        started = time.perf_counter()
        signature = signer.sign(secret, message)
        sign_samples.append(time.perf_counter() - started)
        started = time.perf_counter()
        assert signer.verify(public, message, signature)
        verify_samples.append(time.perf_counter() - started)
    row["phases"]["sign"] = {**_summary(sign_samples), "samples_ms": [round(v * 1000, 3) for v in sign_samples]}
    row["phases"]["verify"] = {**_summary(verify_samples), "samples_ms": [round(v * 1000, 3) for v in verify_samples]}

    # 4a. Cold handshakes: credentials generated inside the timed section, as a per-connection
    # keygen would be. Measured once, because each iteration spends a whole tree.
    cold_timings: list[dict] = []
    cold_samples: list[float] = []
    for _index in range(1):
        timings: dict[str, float] = {}
        cpu_before = _cpu_seconds()
        started = time.perf_counter()
        fresh_authority = CertificateAuthority(config.classical())
        fresh = ServerCredentials(config, identity=b"server.example")
        certificate = fresh.bind_to(fresh_authority)
        timings["credentials_built"] = time.perf_counter() - started
        HybridConnection.run(
            config,
            authority=fresh_authority,
            credentials=fresh,
            certificate=certificate,
            application_payload=DEFAULT_APPLICATION_PAYLOAD,
            timings=timings,
        )
        cold_samples.append(time.perf_counter() - started)
        timings["cpu_seconds"] = round(_cpu_seconds() - cpu_before, 4)
        cold_timings.append(timings)
    row["phases"]["cold_handshake"] = {
        **_summary(cold_samples),
        "samples_ms": [round(value * 1000, 3) for value in cold_samples],
        "timeline_seconds": cold_timings,
    }

    # 4b. Hot handshakes: the credential is reused, everything else is per handshake. The tree
    # has a finite number of leaves, so the count is capped by what remains.
    hot_credentials = ServerCredentials(config, identity=b"server.example")
    hot_certificate = hot_credentials.bind_to(authority)
    remaining_before = hot_credentials.pq_signatures_remaining()
    hot_count = max(1, min(args.hot, remaining_before - 1))
    hot_samples: list[float] = []
    hot_online: list[float] = []
    cpu_before = _cpu_seconds()
    for index in range(hot_count):
        timings: dict[str, float] = {}
        started = time.perf_counter()
        HybridConnection.run(
            config,
            authority=authority,
            credentials=hot_credentials,
            certificate=hot_certificate,
            application_payload=DEFAULT_APPLICATION_PAYLOAD,
            timings=timings,
        )
        hot_samples.append(time.perf_counter() - started)
        if "client_hello_ready" in timings and "complete" in timings:
            hot_online.append(timings["complete"] - timings["client_hello_ready"])
    leaves_after = hot_credentials.pq_signatures_remaining()
    row["phases"]["hot_handshake"] = {
        **_summary(hot_samples),
        "online_median_ms": round(statistics.median(hot_online) * 1000, 3) if hot_online else None,
        "cpu_seconds_total": round(_cpu_seconds() - cpu_before, 4),
        "leaves_before": remaining_before,
        "leaves_spent": remaining_before - leaves_after,
        "leaves_remaining_after": leaves_after,
        "samples_ms": [round(value * 1000, 3) for value in hot_samples],
        "leaf_index_uniqueness": "asserted by tests/test_handshake.py "
                                 "(test_xmss_credentials_spend_one_leaf_per_handshake) and "
                                 "tests/test_wots_xmss.py (test_xmss_sign_exhaustion_and_no_index_reuse)",
    }
    row["hot_reuses_credential_only"] = True
    return row


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    started = time.perf_counter()
    rows = [measure_height(height, args) for height in args.heights]
    total_seconds = time.perf_counter() - started

    payload = {
        "kem": args.kem,
        "cold_iterations": args.cold,
        "hot_iterations": args.hot,
        "wall_seconds": round(total_seconds, 3),
        "cpu_seconds": round(_cpu_seconds(), 3),
        "results": rows,
        "reading": {
            "cold_handshake": "credentials (whole-tree keygen + certificate) built inside the timed section",
            "hot_handshake": "authentication credential reused; transcript, ECDHE/KEM ephemeral keys, "
                             "traffic secrets and record sequences are per handshake",
            "not_measured": "connection flooding, mid-handshake aborts, queue backpressure, and any "
                            "cross-process key state; those need the state design the plan gates",
        },
    }
    table_rows = []
    for row in rows:
        phases = row["phases"]
        table_rows.append(
            {
                "height": row["height"],
                "leaves": row["max_signatures"],
                "tree_keygen_median_ms": phases["tree_keygen"]["median_ms"],
                "tree_keygen_range_ms": f"{phases['tree_keygen']['min_ms']} - {phases['tree_keygen']['max_ms']}",
                "sign_median_ms": phases["sign"]["median_ms"],
                "verify_median_ms": phases["verify"]["median_ms"],
                "cold_handshake_median_ms": phases["cold_handshake"]["median_ms"],
                "hot_handshake_median_ms": phases["hot_handshake"]["median_ms"],
                "hot_online_median_ms": phases["hot_handshake"]["online_median_ms"],
                "hot_repeats": phases["hot_handshake"]["count"],
            }
        )
    out_dir = Path(args.out) if args.out else DEFAULT_OUTPUT_DIR
    json_path, markdown_path = write_outputs(
        "xmss_lifecycle",
        payload,
        table_rows,
        list(table_rows[0].keys()) if table_rows else [],
        out_dir,
        title="XMSS lifecycle cost decomposition (cold and hot)",
    )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    print(json.dumps(environment(), indent=2))
    for row in table_rows:
        print(
            f"  h={row['height']:<3} keygen={row['tree_keygen_median_ms']:>9} ms"
            f"  cold={row['cold_handshake_median_ms']:>9} ms"
            f"  hot={row['hot_handshake_median_ms']:>7} ms"
            f"  (online {row['hot_online_median_ms']} ms over {row['hot_repeats']} runs)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
