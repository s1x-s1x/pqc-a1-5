"""Dump the exact wire encoding of one handshake, field by field.

Used to keep docs/PROTOCOL.md honest: the document states layouts and offsets, and
this prints the bytes those statements describe.

Usage:
    python tools/dump_wire.py
    python tools/dump_wire.py --pq xmss --kem ml-kem-512
    python tools/dump_wire.py --hex          # include full hex of each message
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tls.config import HybridTLSConfig  # noqa: E402
from tls.credentials import CertificateAuthority, ServerCredentials  # noqa: E402
from tls.handshake.client import HybridClient  # noqa: E402
from tls.handshake.messages import (  # noqa: E402
    CERTIFICATE,
    CERTIFICATE_VERIFY,
    CLIENT_HELLO,
    ENCRYPTED_EXTENSIONS,
    FINISHED,
    SERVER_HELLO,
)
from tls.handshake.server import HybridServer  # noqa: E402
from tls.wire import split_handshake_message  # noqa: E402

NAMES = {
    CLIENT_HELLO: "ClientHello",
    SERVER_HELLO: "ServerHello",
    ENCRYPTED_EXTENSIONS: "EncryptedExtensions",
    CERTIFICATE: "Certificate",
    CERTIFICATE_VERIFY: "CertificateVerify",
    FINISHED: "Finished",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line options."""
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--kem", default="ml-kem-768")
    parser.add_argument("--pq", default="falcon-512")
    parser.add_argument("--group", default="x25519")
    parser.add_argument("--xmss-height", type=int, default=8)
    parser.add_argument("--hex", action="store_true", help="print the full hex of each message")
    parser.add_argument("--head", type=int, default=24, help="hex bytes to show per field when --hex is off")
    return parser.parse_args(argv)


def show(name: str, frame: bytes, head: int, full_hex: bool) -> None:
    """Print one handshake message's framing and first bytes."""
    message_type, body = split_handshake_message(frame)
    print(f"\n== {name} (type {message_type}) ==")
    print(f"   frame          {len(frame)} bytes  = 1 type + 3 length + {len(body)} body")
    length_field = int.from_bytes(frame[1:4], "big")
    print(f"   length field   {length_field}  (matches body: {length_field == len(body)})")
    if full_hex:
        for offset in range(0, len(frame), 32):
            chunk = frame[offset : offset + 32]
            print(f"   {offset:06x}  {chunk.hex(' ')}")
    else:
        print(f"   first bytes    {frame[:head].hex(' ')}")
        print(f"   last bytes     {frame[-head:].hex(' ')}")


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    args = parse_args(argv)
    config = HybridTLSConfig(group=args.group, kem=args.kem, pq_signer=args.pq, xmss_height=args.xmss_height)
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config)
    certificate = credentials.bind_to(authority)
    client = HybridClient(config, authority)
    server = HybridServer(config, credentials, certificate)

    print(f"profile: {config.describe()}")
    print(f"classical signer scheme_id {config.classical().scheme_id:#06x}")
    print(f"KEM scheme_id              {config.kem_backend().scheme_id:#06x}  ({config.kem})")
    print(f"PQ signer scheme_id        {config.pq().scheme_id:#06x}  ({config.pq_signer})")
    print(f"cipher suite               {config.cipher_suite_id:#06x}")

    client_hello = client.create_client_hello()
    show(NAMES[CLIENT_HELLO], client_hello, args.head, args.hex)

    server_hello = server.receive_client_hello(client_hello)
    show(NAMES[SERVER_HELLO], server_hello, args.head, args.hex)
    client.receive_server_hello(server_hello)

    stored: list[tuple[str, bytes]] = []
    for name, record, frame in server.send_authenticated_flight():
        stored.append((name, frame))
        print(
            f"\n== {name} (protected) ==\n"
            f"   plaintext {len(frame)} bytes, record {len(record)} bytes "
            f"(+{len(record) - len(frame)} tag), on the wire {len(record) + 5} with the record header"
        )
    for name, frame in stored:
        show(f"{name} (plaintext)", frame, args.head, args.hex)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
