"""Generate once, verify and measure P0-P4 offline alternative CA fixtures.

Generation is deliberately separate from normal regression/handshake execution.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "base_tls"))
import tls  # initializes the project-local optional dependency paths
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from tls.alt_chain import build_alt_test_chain, verify_alt_chain, get_alt_signer
from tls.der import pre_tbs
from tls.pq.signature import get_pq_signer

ALGORITHMS = ("slh-dsa-sm3-128-24", "slh-dsa-sm3-128s", "ml-dsa-44")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source_hashes():
    paths = [ROOT / "tools/alt_chain_fixtures.py", ROOT / "tools/native.py"]
    paths.extend((ROOT / "base_tls/tls").rglob("*.py"))
    paths.extend((ROOT / "reference").glob("*.py"))
    return {p.relative_to(ROOT).as_posix(): sha(p.read_bytes()) for p in sorted(paths)}


def write(path, data, *, private=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600 if private else 0o644)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()


def generate(args):
    if args.budget_db is None and not args.test_only_no_budget:
        raise ValueError("fixture generation requires --budget-db; explicit test-only bypass is separate")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    before = source_hashes()
    library_before = sha(Path(args.library).read_bytes())
    signer = get_pq_signer(args.handshake_signer)
    secret, public = signer.keygen()
    if not isinstance(secret, bytes):
        raise ValueError("fixture handshake signer must have a serializable stateless secret")
    leaf_key, root_key, intermediate_key = [ec.generate_private_key(ec.SECP256R1()) for _ in range(3)]
    now = datetime.now(timezone.utc).replace(microsecond=0)
    reserve, finish, ledger = None, None, None
    if args.budget_db is not None:
        from tools.signing_budget import SigningBudget
        ledger = SigningBudget(args.budget_db)
        reserve = ledger.reserve
        finish = ledger.finish
    completed = []
    for name in ALGORITHMS:
        print(json.dumps({"phase": "fixture-generation", "algorithm": name}), flush=True)
        material = build_alt_test_chain(name, leaf_key=leaf_key, root_key=root_key,
            intermediate_key=intermediate_key, pq_scheme_id=signer.scheme_id,
            pq_public_key=public, threads=args.threads, library=args.library,
            before_sign=reserve, after_sign=finish, now=now)
        if ledger is not None:
            for row in material.signing_records:
                reconciliation = ledger.validate_receipt(row["budget_receipt"], algorithm=row["algorithm"],
                    message_sha256=row["pre_tbs_sha256"], signature_sha256=row["signature_sha256"])
                if reconciliation["public_key_sha256"] != row["issuer_public_key_sha256"]:
                    raise ValueError("CA receipt public key differs from issued edge")
                row["ledger_uuid"] = ledger.ledger_uuid
        directory = output / name
        files, chains = {}, {}
        for kind, chain, prefix in (("alt", material.chain, ""), ("hybrid", material.baseline_chain, "hybrid-"),
                                    ("classical", material.classical_chain, "classical-")):
            chains[kind] = {}
            for label, data in (("root", chain.root_der), ("leaf", chain.leaf_der), ("intermediate", chain.chain_der[1])):
                filename = prefix + label + ".der"
                files[filename] = data
                chains[kind][label] = filename
        for label, key in (("leaf", leaf_key), ("root", root_key), ("intermediate", intermediate_key)):
            files[label + "-test-key.pem"] = key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        files["handshake-test-key.json"] = json_bytes({"test_only": True, "algorithm": signer.name,
                                                      "public_key": public.hex(), "secret_key": secret.hex()})
        for label, blob in (("leaf", material.chain.leaf_der), ("intermediate", material.chain.chain_der[1])):
            files[label + "-pre-tbs.der"] = pre_tbs(x509.load_der_x509_certificate(blob).tbs_certificate_bytes)
        for filename, data in files.items():
            write(directory / filename, data, private="key" in filename)
        metadata = {"schema": "a15-alt-fixture-v1", "test_only": True, "alt_algorithm": name,
                    "identity": "server.example", "handshake_signer": signer.name,
                    "generated_at_utc": now.isoformat(), "validity": {"not_before": (now.timestamp()-86400), "not_after": now.timestamp()+365*86400},
                    "chains": chains, "files_sha256": {k: sha(v) for k, v in files.items()},
                    "signing_records": material.signing_records, "sources_sha256": before,
                    "budget_ledger_uuid": ledger.ledger_uuid if ledger is not None else None,
                    "library_sha256": library_before,
                    "threads": args.threads,
                    "scope": "offline test-only CA chains; private test keys are fixture credentials, not production keys"}
        write(directory / "fixture.json", json_bytes(metadata))
        completed.append({"algorithm": name, "fixture_path": str(directory), "fixture_sha256": sha(json_bytes(metadata))})
    if before != source_hashes():
        raise ValueError("fixture source changed during generation")
    if library_before != sha(Path(args.library).read_bytes()):
        raise ValueError("fixture native library changed during generation")
    write(output / "MANIFEST.json", json_bytes({"schema": "a15-alt-fixtures-v1", "test_only": True,
        "generated_at_utc": now.isoformat(), "fixtures": completed, "sources_sha256": before,
        "command": sys.argv, "source_unchanged": True,
        "library_sha256": library_before, "library_unchanged": True,
        "budget_ledger_uuid": ledger.ledger_uuid if ledger is not None else None}))
    print(json.dumps({"completed": completed}), flush=True)


def verify(args):
    from tls.alt_fixtures import load_fixture
    rows = []
    for name in ALGORITHMS:
        directory = args.fixtures / name
        metadata = json.loads((directory / "fixture.json").read_text())
        signer = get_pq_signer(metadata["handshake_signer"])
        chain, _, _, _ = load_fixture(directory, pq_signer=signer, expected_algorithm=name,
                                       library=args.library, require_native=name.startswith("slh-"))
        root = x509.load_der_x509_certificate(chain.root_der)
        for python in ([False, True] if name.startswith("slh-") else [False]):
            result = verify_alt_chain(chain.chain_der, root, "server.example", require_alt_chain=True,
                                      expected_algorithm=name, force_python=python,
                                      require_native=name.startswith("slh-") and not python,
                                      library=args.library)
            expected_mode = "python" if python else ("native" if name.startswith("slh-") else "provider")
            if any(x["mode"] != expected_mode for x in result.verifiers):
                raise ValueError("fixture verifier did not execute its required backend")
            rows.append({"algorithm": name, "verifier": expected_mode, "verifiers": result.verifiers,
                         "checked_edges": result.checked_edges, "passed": result.complete,
                         "fixture_sha256": sha((directory / "fixture.json").read_bytes())})
    write(args.output, json_bytes({"schema": "a15-alt-fixture-verification-v1", "passed": all(x["passed"] for x in rows),
                                 "rows": rows, "sources_sha256": source_hashes(), "command": sys.argv}))
    print(json.dumps(rows), flush=True)


def e1(args):
    from tls.alt_profiles import profiles, e1_record
    configs = profiles(args.fixtures, handshake_signer=args.handshake_signer)
    with args.output.open("x", encoding="utf-8") as stream:
        for code, config in configs.items():
            record = e1_record(code, config)
            record.update({"generated_at_utc": datetime.now(timezone.utc).isoformat(),
                           "sources_sha256": source_hashes(), "command": sys.argv})
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            print(json.dumps({"profile": code, "passed": record["passed"],
                              "server_flight_bytes": record["server_flight_bytes"]}), flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    gen = commands.add_parser("generate")
    gen.add_argument("--output", type=Path, required=True)
    gen.add_argument("--library", type=Path, required=True)
    gen.add_argument("--threads", type=int, default=32)
    gen.add_argument("--handshake-signer", default="falcon-512")
    gen.add_argument("--budget-db", type=Path)
    gen.add_argument("--test-only-no-budget", action="store_true")
    for action in ("verify", "e1"):
        sub = commands.add_parser(action)
        sub.add_argument("--fixtures", type=Path, required=True)
        sub.add_argument("--output", type=Path, required=True)
        if action == "e1":
            sub.add_argument("--handshake-signer", default="falcon-512")
        else:
            sub.add_argument("--library", type=Path, required=True,
                             help="explicit native library; both native and independent Python paths are mandatory")
    args = parser.parse_args()
    if args.action == "generate":
        generate(args)
    elif args.action == "verify":
        verify(args)
    else:
        e1(args)


if __name__ == "__main__":
    main()
