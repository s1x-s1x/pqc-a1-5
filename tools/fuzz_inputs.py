"""Deterministic parser mutation smoke and optional Atheris/native cache entry.

This checks rejection and state invariants, not cryptographic performance. The
receiver uses inert decrypt/semantic callbacks; full authenticated tests are a
separate regression gate. Input and iteration limits keep the smoke bounded.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import random
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "base_tls"))
from tls.config import HybridTLSConfig
from tls.der import DerError, elements, oid_text
from tls.errors import HybridTLSError
from tls.handshake.client import HybridClient
from tls.handshake.messages import (Certificate, CertificateVerify, ClientHello,
                                    EncryptedExtensions, Finished, ServerHello, X509Chain)
from tls.wire import split_handshake_message

MAX_INPUT = 65536


def check_input(data):
    if len(data) > MAX_INPUT:
        return
    for parse in (elements, oid_text, split_handshake_message, ClientHello.decode, ServerHello.decode,
                  Certificate.decode, X509Chain.decode, CertificateVerify.decode,
                  EncryptedExtensions.decode, Finished.decode):
        try:
            parse(data)
        except (DerError, HybridTLSError, ValueError, OverflowError, IndexError, KeyError):
            pass
    client = HybridClient(HybridTLSConfig(pq_enabled=False, server_flight_max_records=64,
                           server_flight_max_audit_entries=64, server_flight_max_plaintext_bytes=32768,
                           server_flight_max_ciphertext_bytes=65536), authority=None)
    client.open_handshake = lambda record: record
    client._consume_server_handshake = lambda frame: None
    client.setup_application_keys = lambda: None
    width = 1 + (data[0] if data else 0)
    try:
        for start in range(0, len(data), width):
            client.receive_server_record(data[start:start + width])
        client.finish_server_flight()
    except HybridTLSError:
        assert not client.server_flight_complete
        assert not client._handshake_buffer
        assert client.application_client_records is None
        assert client.application_server_records is None
        try:
            client.receive_server_record(b"x")
        except HybridTLSError:
            pass
        else:
            raise AssertionError("failed receiver resumed")
    assert len(client.server_flight_fragments) <= 64
    assert len(client._handshake_buffer) <= 1 << 20


def mutate(rng, seeds):
    seed = rng.choice(seeds)
    mode = rng.randrange(5)
    if mode == 0:
        return rng.randbytes(rng.randrange(2049))
    if mode == 1:
        return seed[:rng.randrange(len(seed) + 1)]
    if mode == 2:
        value = bytearray(seed)
        if value:
            value[rng.randrange(len(value))] ^= 1 << rng.randrange(8)
        return bytes(value)
    if mode == 3:
        return seed + rng.randbytes(rng.randrange(65))
    return seed * rng.randrange(1, 17)


def check_cache(native, public, valid, malformed, path):
    path.write_bytes(malformed)
    from native import NativeError
    try:
        native.cache_load(path, public)
    except NativeError as error:
        assert error.code == -4, error
    else:
        raise AssertionError("mutated cache accepted")
    native.cache_save(path)
    assert path.read_bytes() == valid, "rejected cache replaced live cache"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1000)
    parser.add_argument("--seed", type=int, default=20261004)
    parser.add_argument("--library", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--atheris", action="store_true")
    args, rest = parser.parse_known_args()
    if not 1 <= args.iterations <= 100000:
        parser.error("iterations must be 1..100000")
    if args.atheris:
        import atheris
        atheris.Setup([sys.argv[0], *rest], check_input)
        atheris.Fuzz()
        return
    if rest:
        parser.error("unrecognized arguments: " + " ".join(rest))
    seeds = [b"", b"\x30\x00", b"\x30\x80", b"\x06\x01\x80", b"\x08\x00\x00\x02\x00\x00",
             b"\x08\x10\x00\x00", b"\x0b\x00\x00\x00", b"\x08\x00\x00\x00\x0b\x00\x00\x00\x0f\x00\x00\x00\x14\x00\x00\x00"]
    rng = random.Random(args.seed)
    for seed in seeds:
        check_input(seed)
    for _ in range(args.iterations):
        check_input(mutate(rng, seeds))
    cache_checks = 0
    if args.library:
        from native import NativeSlhDsa
        with tempfile.TemporaryDirectory(prefix="a15-cache-fuzz-") as directory, NativeSlhDsa(pid=201, threads=1, flags=1, library=args.library) as native:
            public, secret = native.keygen_internal(bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 48)))
            native.cache_build(secret, 5)
            path = Path(directory) / "cache.bin"
            native.cache_save(path)
            valid = path.read_bytes()
            variants = [valid[:i] for i in (0, 1, 8, 95, 96, len(valid) - 1)] + [valid + b"x"]
            for offset in range(96):
                changed = bytearray(valid)
                changed[offset] ^= 1
                variants.append(bytes(changed))
            for _ in range(args.iterations):
                changed = bytearray(valid)
                changed[rng.randrange(len(changed))] ^= 1 << rng.randrange(8)
                variants.append(bytes(changed))
            for value in variants:
                check_cache(native, public, valid, value, path)
                cache_checks += 1
    record = dict(schema="a15-parser-fuzz-smoke-v1", passed=True, seed=args.seed,
                  parser_inputs=args.iterations + len(seeds), native_cache_mutations=cache_checks,
                  script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  library_sha256=hashlib.sha256(args.library.read_bytes()).hexdigest() if args.library else None,
                  created_utc=datetime.now(timezone.utc).isoformat(), formal_performance_started=False, real_timing_samples=0,
                  scope="Bounded deterministic mutations; receiver callbacks inert; optional real toy cache rejection/state preservation. No exhaustive fuzz claim.")
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({k:record[k] for k in ("passed", "parser_inputs", "native_cache_mutations", "real_timing_samples")}))


if __name__ == "__main__":
    main()
