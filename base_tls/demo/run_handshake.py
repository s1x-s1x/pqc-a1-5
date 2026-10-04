"""Run one hybrid handshake and print what it did, or show which check rejects tampering.

Usage:
    python demo/run_handshake.py
    python demo/run_handshake.py --pq xmss --kem ml-kem-768
    python demo/run_handshake.py --pq falcon-1024 --xmss-height 12
    python demo/run_handshake.py --list-backends
    python demo/run_handshake.py --tamper pq-signature
    python demo/run_handshake.py --fingerprint

Output hygiene: by default this driver prints stage names, algorithms, lengths and
verification status only. Derived secrets are never printed, not even a prefix. `--fingerprint`
additionally prints a **labelled hash** of each derived value (a domain-separated SHA-256
digest truncated for display) for comparison work; that mode is explicit because a fingerprint
is still key material-derived. A red-team pass (their W3) found the earlier default printing
the first 12 bytes of the key schedule.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tls.classical.signature import ClassicalSigner  # noqa: E402
from tls.config import HybridTLSConfig  # noqa: E402
from tls.credentials import CertificateAuthority, ServerCredentials  # noqa: E402
from tls.errors import HybridTLSError  # noqa: E402
from tls.handshake.certificate_verify import HybridCertificateVerify  # noqa: E402
from tls.handshake.client import HybridClient  # noqa: E402
from tls.handshake.connection import HybridConnection  # noqa: E402
from tls.handshake.messages import Certificate, CertificateVerify  # noqa: E402
from tls.handshake.server import HybridServer  # noqa: E402
from tls.pq.kem import available_kems  # noqa: E402
from tls.pq.signature import available_pq_signers  # noqa: E402
from tls.wire import split_handshake_message  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--group", default="x25519", help="classical ECDHE group")
    parser.add_argument("--classical", default="ecdsa-p256-sha256", help="classical signature scheme")
    parser.add_argument("--kem", default="ml-kem-768", help="post-quantum KEM")
    parser.add_argument("--pq", default="falcon-512", help="post-quantum signature scheme")
    parser.add_argument("--xmss-height", type=int, default=10, help="Merkle tree height for the XMSS backend")
    parser.add_argument("--list-backends", action="store_true", help="show which backends this environment provides")
    parser.add_argument(
        "--fingerprint",
        action="store_true",
        help="also print a labelled hash of each derived value (never the value or a prefix)",
    )
    parser.add_argument(
        "--tamper",
        choices=("none", "pq-signature", "classic-signature", "certificate", "kem-ciphertext"),
        default="none",
        help="corrupt one field and show which check rejects it",
    )
    return parser.parse_args(argv)


def show_backends() -> None:
    """Print the KEM and signature backends usable in this environment."""
    print("KEM backends available here:")
    for name in available_kems():
        print(f"  {name}")
    print("\npost-quantum signature backends:")
    for name, status in sorted(available_pq_signers().items()):
        marker = "ok" if status == "ok" else f"unavailable: {status.splitlines()[0][:90]}"
        print(f"  {name:<24}{marker}")


def _corrupt_signature(frame: bytes, which: str) -> bytes:
    """Flip one byte of the named signature inside a CertificateVerify frame."""
    message_type, body = split_handshake_message(frame)
    payload = HybridCertificateVerify.decode(CertificateVerify.decode(body).payload)
    field = "classic_signature" if which == "classic" else "pq_signature"
    raw = bytearray(getattr(payload, field))
    if not raw:
        raise SystemExit(f"the {field} is empty; nothing to corrupt")
    raw[0] ^= 0x01
    broken = HybridCertificateVerify(
        classic_scheme=payload.classic_scheme,
        classic_signature=bytes(raw) if which == "classic" else payload.classic_signature,
        pq_scheme=payload.pq_scheme,
        pq_signature=bytes(raw) if which != "classic" else payload.pq_signature,
    )
    return CertificateVerify(payload=broken.encode()).to_message()


def _corrupt_ca_signature(frame: bytes) -> bytes:
    """Flip one byte of the CA signature inside a Certificate frame."""
    _message_type, body = split_handshake_message(frame)
    certificate = Certificate.decode(body)
    raw = bytearray(certificate.ca_signature)
    if not raw:
        raise SystemExit("the CA signature is empty; nothing to corrupt")
    raw[0] ^= 0x01
    broken = Certificate(
        body=certificate.body,
        ca_signature=bytes(raw),
        extensions=certificate.extensions,
        certificate_request_context=certificate.certificate_request_context,
    )
    return broken.to_message()


def _describe(error: HybridTLSError) -> str:
    """Render any handshake failure, with its step when it has one."""
    step = getattr(error, "step", None)
    reason = getattr(error, "reason", str(error))
    return f"{step}: {reason}" if step else str(error)


def run_tampered(config: HybridTLSConfig, tamper: str, ca_signer: ClassicalSigner) -> int:
    """Run a handshake with one field corrupted and report which check failed."""
    authority = CertificateAuthority(ca_signer)
    credentials = ServerCredentials(config)
    certificate = credentials.bind_to(authority)
    client = HybridClient(config, authority)
    server = HybridServer(config, credentials, certificate)

    client_hello = client.create_client_hello()
    server_hello = server.receive_client_hello(client_hello)

    if tamper == "kem-ciphertext":
        # Flip the last byte of ServerHello, which is inside the KEM ciphertext.
        broken = server_hello[:-1] + bytes([server_hello[-1] ^ 0x01])
        try:
            client.receive_server_hello(broken)
        except HybridTLSError as error:
            print(f"rejected at {_describe(error)}")
            return 0
        try:
            client.receive_server_flight([record for _, record, _ in server.send_authenticated_flight()])
        except HybridTLSError as error:
            print(f"corrupted KEM ciphertext detected at {_describe(error)}")
            return 0
        print("NOT rejected: a corrupted KEM ciphertext was accepted")
        return 1

    client.receive_server_hello(server_hello)

    def frame_filter(name: str, frame: bytes) -> bytes:
        if tamper == "certificate" and name == "Certificate":
            return _corrupt_ca_signature(frame)
        if tamper == "pq-signature" and name == "CertificateVerify":
            return _corrupt_signature(frame, "pq")
        if tamper == "classic-signature" and name == "CertificateVerify":
            return _corrupt_signature(frame, "classic")
        return frame

    records = [record for _, record, _ in server.send_authenticated_flight(frame_filter)]
    try:
        client.receive_server_flight(records)
    except HybridTLSError as error:
        print(f"rejected at {_describe(error)}")
        return 0
    print("NOT accepted: the tampered handshake was rejected")  # pragma: no cover - defensive
    return 1


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    if args.list_backends:
        show_backends()
        return 0

    config = HybridTLSConfig(
        group=args.group,
        classical_signer=args.classical,
        kem=args.kem,
        pq_signer=args.pq,
        xmss_height=args.xmss_height,
    )
    ca_signer = config.classical()

    if args.tamper != "none":
        return run_tampered(config, args.tamper, ca_signer)

    result = HybridConnection.run(config, ca_signer=ca_signer)
    print(result.report())

    print("\nrecord layer: derived traffic keys (values withheld)")
    for label, layer in (
        ("client handshake", result.client.client_records),
        ("server handshake", result.client.server_records),
        ("client application", result.client.application_client_records),
        ("server application", result.client.application_server_records),
    ):
        if layer is None:
            print(f"  {label:<20}absent")
            continue
        detail = (
            f"keys=derived  aead={layer.suite.name}"
            f"  records={layer.sequence}"
        )
        if args.fingerprint:
            detail += f"  fingerprint={_fingerprint(layer.key_fingerprint().encode())}"
        print(f"  {label:<20}{detail}")

    schedule = result.client.schedule
    rows = (
        ("early_secret", schedule.early_secret),
        ("handshake_secret", schedule.handshake_secret),
        ("master_secret", schedule.master_secret),
        ("c hs traffic", schedule.client_handshake_traffic),
        ("s hs traffic", schedule.server_handshake_traffic),
        ("c ap traffic", schedule.client_application_traffic),
        ("s ap traffic", schedule.server_application_traffic),
        ("exporter master", schedule.exporter_master_secret),
    )
    if args.fingerprint:
        print("\nkey schedule fingerprints (labelled hash, not the value):")
        for label, value in rows:
            print(f"  {label:<20}{_fingerprint(value)}")
    else:
        print("\nkey schedule: derived values withheld (lengths only; --fingerprint for hashes):")
        for label, value in rows:
            print(f"  {label:<20}{len(value or b'')} bytes")
    return 0


def _fingerprint(value: bytes | None) -> str:
    """A labelled hash of a derived value: never the value, never a prefix of it.

    Domain separated, so a fingerprint cannot be matched against a digest of the raw secret
    computed elsewhere. ``-`` for an absent value, so an empty string is never dressed up as a
    real fingerprint.
    """
    if not value:
        return "-"
    digest = hashlib.sha256(b"hybrid-tls13/demo-fingerprint\x00" + value).hexdigest()
    return f"sha256:{digest[:16]}"


if __name__ == "__main__":
    raise SystemExit(main())
