"""A1-5 binary-file keygen/sign/verify/cache command-line interface."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from native import NAMES, PREHASH, NativeSlhDsa
from signing_budget import SigningBudget

BACKENDS = {"auto": 0, "ref": 1, "avx2": 2, "cuda": 5}


def write_new(path, data, *, secret=False):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if secret else 0o644)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def digest(data):
    return hashlib.sha256(data).hexdigest()


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--pid", type=int, choices=sorted(NAMES.values()), default=3)
    result.add_argument("--backend", choices=BACKENDS, default="auto")
    result.add_argument("--threads", type=int, default=1)
    result.add_argument("--library", type=Path)
    sub = result.add_subparsers(dest="command", required=True)
    kg = sub.add_parser("keygen", help="create PREFIX.pk, PREFIX.sk and PREFIX.json")
    kg.add_argument("prefix", type=Path)
    kg.add_argument("--cache-level", type=int)
    kg.add_argument("--save-cache", type=Path)
    kg.add_argument("--seed-hex", help="48 seed bytes for reproducible fixtures")
    for command in ("sign", "verify"):
        p = sub.add_parser(command)
        p.add_argument("message", type=Path)
        p.add_argument("key", type=Path, help="64-byte secret for sign; 32-byte public for verify")
        p.add_argument("signature", type=Path)
        p.add_argument("--context-hex", default="")
        p.add_argument("--prehash", choices=PREHASH)
        if command == "sign":
            p.add_argument("--load-cache", type=Path)
            p.add_argument("--randomized", action="store_true")
            p.add_argument("--budget-db", type=Path, required=True,
                           help="shared durable reservations; failed computations consume budget")
            p.add_argument("--budget-limit", type=int)
    cb = sub.add_parser("cache-build")
    cb.add_argument("secret_key", type=Path)
    cb.add_argument("output", type=Path)
    cb.add_argument("--level", type=int, default=12)
    cl = sub.add_parser("cache-load", help="validate a saved cache against a public key")
    cl.add_argument("cache", type=Path)
    cl.add_argument("public_key", type=Path)
    sub.add_parser("capabilities")
    return result


def main(argv=None):
    args = parser().parse_args(argv)
    flags = BACKENDS[args.backend] | (0x100 if args.command == "sign" else 0)
    try:
        with NativeSlhDsa(args.pid, threads=args.threads, flags=flags, library=args.library) as native:
            result = {"command": args.command, "pid": args.pid, "backend_requested": args.backend,
                      "backend_selected": native.backend, "threads_requested": args.threads,
                      "library_sha256": digest(Path(native.library_path).read_bytes())}
            if args.command == "keygen":
                pk_path, sk_path, metadata = (Path(str(args.prefix) + suffix) for suffix in (".pk", ".sk", ".json"))
                for path in (pk_path, sk_path, metadata, args.save_cache):
                    if path is not None and path.exists():
                        raise FileExistsError(path)
                if args.cache_level is not None:
                    native.set_cache_level(args.cache_level)
                if args.seed_hex:
                    seeds = bytes.fromhex(args.seed_hex)
                    if len(seeds) != 48:
                        raise ValueError("seed-hex must encode exactly 48 bytes")
                    pk, sk = native.keygen_internal(seeds[:16], seeds[16:32], seeds[32:])
                else:
                    pk, sk = native.keygen()
                write_new(sk_path, sk, secret=True)
                write_new(pk_path, pk)
                if args.save_cache:
                    native.cache_save(args.save_cache)
                result.update({"pk_sha256": digest(pk), "sk_sha256": digest(sk),
                               "pk_bytes": len(pk), "sk_bytes": len(sk),
                               "signature_bytes": native.sig_bytes, "fixture_seeded": bool(args.seed_hex)})
                write_new(metadata, (json.dumps(result, indent=2) + "\n").encode())
            elif args.command == "sign":
                if args.signature.exists():
                    raise FileExistsError(args.signature)
                message, sk = args.message.read_bytes(), args.key.read_bytes()
                if len(sk) != native.sk_bytes:
                    raise ValueError("secret-key length differs from the selected parameter")
                context = bytes.fromhex(args.context_hex)
                if len(context) > 255:
                    raise ValueError("context exceeds 255 bytes")
                if args.load_cache:
                    native.cache_load(args.load_cache, sk[32:])
                name = next(name for name, pid in NAMES.items() if pid == args.pid)
                ledger = SigningBudget(args.budget_db)
                record_input = (args.prehash or "pure").encode() + b"\0" + bytes([len(context)]) + context + message
                receipt = ledger.reserve(name, sk[32:], record_input, limit=args.budget_limit)
                try:
                    rnd = os.urandom(16) if args.randomized else None
                    signature = (native.sign_prehash(message, sk, args.prehash, context, rnd) if args.prehash
                                 else native.sign(message, sk, context, rnd))
                    write_new(args.signature, signature)
                except BaseException:
                    # A ledger outage must preserve the original signing/write
                    # error. The reservation is already durably charged.
                    try:
                        ledger.finish(receipt)
                    except Exception as ledger_error:
                        print(json.dumps({"budget_receipt": receipt,
                              "ledger_finalize_error": str(ledger_error)}), file=sys.stderr)
                    raise
                ledger.finish(receipt, signature)
                result.update({"signature_bytes": len(signature), "signature_sha256": digest(signature),
                               "budget_receipt": receipt, "ledger_uuid": ledger.ledger_uuid,
                               "budget_evidence": ledger.validate_receipt(receipt, algorithm=name,
                                   public_key=sk[32:], message=record_input, signature=signature),
                               "mode": args.prehash or "pure"})
            elif args.command == "verify":
                message, pk, signature = args.message.read_bytes(), args.key.read_bytes(), args.signature.read_bytes()
                context = bytes.fromhex(args.context_hex)
                valid = (native.verify_prehash(message, signature, pk, args.prehash, context) if args.prehash
                         else native.verify(message, signature, pk, context))
                result["valid"] = valid
                print(json.dumps(result))
                return 0 if valid else 2
            elif args.command == "cache-build":
                if args.output.exists():
                    raise FileExistsError(args.output)
                native.cache_build(args.secret_key.read_bytes(), args.level)
                native.cache_save(args.output)
                result.update({"cache_bytes": args.output.stat().st_size, "cache_sha256": digest(args.output.read_bytes())})
            elif args.command == "cache-load":
                native.cache_load(args.cache, args.public_key.read_bytes())
                result["cache_valid"] = True
            elif args.command == "capabilities":
                result.update({"public_key_bytes": native.pk_bytes, "secret_key_bytes": native.sk_bytes,
                               "signature_bytes": native.sig_bytes, "prehash": list(PREHASH) if hasattr(native.lib, "slh_sign_prehash") else []})
            print(json.dumps(result))
        return 0
    except Exception as error:
        print(json.dumps({"error": f"{type(error).__name__}: {error}"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
