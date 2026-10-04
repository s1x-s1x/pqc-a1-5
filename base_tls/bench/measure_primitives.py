"""Time every cryptographic primitive the hybrid handshake uses, and report sizes.

This covers the first two of the four measurement categories the design calls for:
KEM key generation / encapsulation / decapsulation, and post-quantum signature
generation / verification. Handshake byte counts and end-to-end latency are the
other two and live in ``measure_handshake.py``.

Usage:
    python bench/measure_primitives.py
    python bench/measure_primitives.py --iterations 200 --kems ml-kem-768
    python bench/measure_primitives.py --xmss-height 8 --skip-xmss
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bench._io import benchmark, write_outputs  # noqa: E402
from tls.classical.signature import CLASSICAL_SIGNERS, get_classical_signer  # noqa: E402
from tls.pq.kem import KEM_BACKENDS, get_kem  # noqa: E402
from tls.pq.signature import available_pq_signers, get_pq_signer  # noqa: E402

MESSAGE = b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + bytes(range(32))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--iterations", type=int, default=50, help="timed repetitions per primitive")
    parser.add_argument("--keygen-iterations", type=int, default=10, help="timed repetitions for key generation")
    parser.add_argument("--kems", nargs="*", default=None, help="KEM names to measure (default: all available)")
    parser.add_argument("--signers", nargs="*", default=None, help="signature backends to measure")
    parser.add_argument("--xmss-height", type=int, default=10, help="tree height used for the XMSS backend")
    parser.add_argument("--skip-xmss", action="store_true", help="omit the hash-based backend")
    parser.add_argument("--xmss-keygen-iterations", type=int, default=3, help="XMSS key generation builds a whole tree")
    parser.add_argument("--out", default=None, help="output directory (default: .bench-out)")
    return parser.parse_args(argv)


def measure_kems(requested: list[str] | None, iterations: int, keygen_iterations: int) -> list[dict]:
    """Measure every KEM's three operations and record its sizes."""
    names = requested or sorted(KEM_BACKENDS)
    rows: list[dict] = []
    for name in names:
        try:
            kem = get_kem(name)
        except Exception as error:  # noqa: BLE001 - an unavailable backend must not stop the sweep
            print(f"skip KEM {name}: {type(error).__name__}: {error}", file=sys.stderr)
            continue

        keypairs: list[tuple[bytes, bytes]] = []

        def keygen(_index: int) -> None:
            keypairs.append(kem.keygen())

        keygen_sample = benchmark(f"{name}.keygen", keygen_iterations, keygen, {"backend": name, "family": "kem", "operation": "keygen"})
        rows.append({**keygen_sample.as_row(), "public_key_bytes": kem.public_key_bytes, "ciphertext_bytes": kem.ciphertext_bytes, "shared_secret_bytes": kem.shared_secret_bytes, "post_quantum": kem.post_quantum})

        encapsulations: list[tuple[bytes, bytes]] = []

        def encaps(index: int) -> None:
            encapsulations.append(kem.encapsulate(keypairs[index % len(keypairs)][0]))

        encaps_sample = benchmark(f"{name}.encaps", iterations, encaps, {"backend": name, "family": "kem", "operation": "encapsulate"})
        rows.append({**encaps_sample.as_row(), "public_key_bytes": kem.public_key_bytes, "ciphertext_bytes": kem.ciphertext_bytes, "shared_secret_bytes": kem.shared_secret_bytes, "post_quantum": kem.post_quantum})

        def decaps(index: int) -> None:
            ciphertext, _secret = encapsulations[index % len(encapsulations)]
            kem.decapsulate(keypairs[index % len(keypairs)][1], ciphertext)

        decaps_sample = benchmark(f"{name}.decaps", iterations, decaps, {"backend": name, "family": "kem", "operation": "decapsulate"})
        rows.append({**decaps_sample.as_row(), "public_key_bytes": kem.public_key_bytes, "ciphertext_bytes": kem.ciphertext_bytes, "shared_secret_bytes": kem.shared_secret_bytes, "post_quantum": kem.post_quantum})
        del keypairs, encapsulations
    return rows


def _measure_signer(
    signer,
    label: str,
    family: str,
    iterations: int,
    keygen_iterations: int,
) -> list[dict]:
    """Measure one signature backend's key generation, signing, and verification."""
    metadata = {"backend": label, "family": family, "post_quantum": bool(signer.post_quantum)}
    rows: list[dict] = []

    secrets: list[tuple[object, bytes]] = []

    def keygen(index: int) -> None:
        secrets.append(signer.keygen())

    keygen_sample = benchmark(
        f"{label}.keygen", keygen_iterations, keygen, {**metadata, "operation": "keygen"}
    )
    rows.append(
        {
            **keygen_sample.as_row(),
            "post_quantum": bool(signer.post_quantum),
            "public_key_bytes": signer.public_key_bytes,
            "signature_bytes": signer.signature_bytes,
        }
    )

    signatures: list[bytes] = []

    def sign(index: int) -> None:
        signatures.append(signer.sign(secrets[index % len(secrets)][0], MESSAGE))

    sign_sample = benchmark(f"{label}.sign", iterations, sign, {**metadata, "operation": "sign"})
    measured_signature = len(signatures[0]) if signatures else 0
    rows.append(
        {
            **sign_sample.as_row(),
            "post_quantum": bool(signer.post_quantum),
            "public_key_bytes": signer.public_key_bytes,
            "signature_bytes": measured_signature,
        }
    )

    def verify(index: int) -> None:
        signer.verify(secrets[index % len(secrets)][1], MESSAGE, signatures[index % len(signatures)])

    verify_sample = benchmark(f"{label}.verify", iterations, verify, {**metadata, "operation": "verify"})
    rows.append(
        {
            **verify_sample.as_row(),
            "post_quantum": bool(signer.post_quantum),
            "public_key_bytes": signer.public_key_bytes,
            "signature_bytes": measured_signature,
        }
    )
    return rows


def measure_signers(
    requested: list[str] | None,
    iterations: int,
    keygen_iterations: int,
    xmss_height: int,
    xmss_keygen_iterations: int,
    skip_xmss: bool,
) -> list[dict]:
    """Measure signing and verification for the classical and post-quantum schemes."""
    rows: list[dict] = []

    classical_names = sorted(CLASSICAL_SIGNERS) if requested is None else [n for n in requested if n in CLASSICAL_SIGNERS]
    for name in classical_names:
        rows.extend(_measure_signer(get_classical_signer(name), name, "classical", iterations, keygen_iterations))

    report = available_pq_signers()
    pq_names = sorted(report) if requested is None else [n for n in requested if n in report]
    for name in pq_names:
        if report[name] != "ok":
            print(f"skip signer {name}: {report[name]}", file=sys.stderr)
            continue
        if skip_xmss and name.startswith("xmss"):
            continue
        options = {"height": xmss_height} if name.startswith("xmss") else {}
        signer = get_pq_signer(name, **options)
        # An XMSS key generation hashes the whole tree, so it gets its own budget.
        per_signer_keygen = xmss_keygen_iterations if name.startswith("xmss") else keygen_iterations
        rows.extend(_measure_signer(signer, name, "post-quantum", iterations, per_signer_keygen))
    return rows


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    kem_rows = measure_kems(args.kems, args.iterations, args.keygen_iterations)
    signer_rows = measure_signers(
        args.signers,
        args.iterations,
        args.keygen_iterations,
        args.xmss_height,
        args.xmss_keygen_iterations,
        args.skip_xmss,
    )
    rows = kem_rows + signer_rows
    output_dir = Path(args.out) if args.out else None
    columns = [
        "label",
        "family",
        "operation",
        "median_ms",
        "mean_ms",
        "ops_per_second",
        "public_key_bytes",
        "ciphertext_bytes",
        "signature_bytes",
        "post_quantum",
    ]
    json_path, markdown_path = write_outputs(
        "primitives",
        {
            "iterations": args.iterations,
            "keygen_iterations": args.keygen_iterations,
            "xmss_height": args.xmss_height,
            "results": rows,
        },
        rows,
        columns,
        output_dir,
        title="Cryptographic primitive timings",
    )
    print(f"wrote {json_path}")
    print(f"wrote {markdown_path}")
    for row in rows:
        print(
            f"  {row['label']:<26}{row.get('median_ms', ''):>10} ms   "
            f"pk={row.get('public_key_bytes', '')} sig={row.get('signature_bytes', '')}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
