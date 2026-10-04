"""CA model v2: retain origin of signatures and authenticate complete flights.

v1 models and outputs are never overwritten. Symbolic runs are bounded and
untimed for implementation-performance purposes. Attacks remain real results.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import run_ca_models as v1

MODELS = ROOT / "base_tls/verification/ca_models_v2"
SCENARIOS = dict(v1.SCENARIOS)
PRIORITY = ["M1_honest", "M2_honest", "M1_ca_leaked", "M2_ca_leaked",
            "M2_all_classical", "M2_dual_all_classical",
            "control_all_ca_leaked", "control_both_online_leaked"]
QUERY_MAP = [
    {"name": "Binding", "query": "authentication? Intermediate -> Client: leafTBS",
     "meaning": "Issuing-CA source of accepted certificate identity/keys/policy, conditioned on application sending; stronger than reusable-certificate authorization."},
    {"name": "SignatureOrigin", "query": "authentication? Server -> Client: onlineSignature",
     "meaning": "Source of the received classical signature atom, separately bound by ASSERT to the signature extracted from the complete flight; not by itself session agreement."},
    {"name": "SessionAuth", "query": "authentication? Server -> Client: serverAuthentication",
     "meaning": "Source of the complete accepted flight: server hello, exact accepted certificate transcript, both online proofs and Finished, conditioned on application sending."},
    {"name": "Fresh", "query": "freshness? transcriptClient",
     "meaning": "Accepted transcript includes fresh values; this alone does not imply authenticated peer or unknown session key."},
    {"name": "Secret", "query": "confidentiality? applicationMessage",
     "meaning": "Application plaintext after all received-flight checks stays unknown to the attacker."},
]


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def replace_once(text, before, after):
    if text.count(before) != 1:
        raise ValueError("v1 generator shape changed: expected one exact replacement")
    return text.replace(before, after, 1)


def model(name, options):
    alt, _, _, dual, _, _ = options
    text = v1.model(name, options).replace("tools/run_ca_models.py", "tools/run_ca_models_v2.py")
    text = replace_once(text,
        "    serverFinished = MAC(finishedKey, HASH(transcriptServer, onlineSignature, onlineAltSignature))\n]",
        "    serverFinished = MAC(finishedKey, HASH(transcriptServer, onlineSignature, onlineAltSignature))\n"
        "    serverAuthentication = CONCAT(serverHello, certificateTranscript, onlineSignature, onlineAltSignature, serverFinished)\n]")
    old = """Server -> Client: serverRandom, serverShare, kemCiphertext, onlineSignature, onlineAltSignature, serverFinished
principal Client[
    clientHelloReceived = CONCAT(clientRandom, clientShare, clientKemPk)
    serverHelloReceived = CONCAT(serverRandom, serverShare, kemCiphertext)
    certificateReceived = CONCAT(leafTBS, leafSig, leafAltSig)
    transcriptClient = HASH(clientHelloReceived, serverHelloReceived, certificateReceived, onlineAlgorithms)
    cvClient = CONCAT(cvContext, transcriptClient)
    _ = SIGNVERIF(receivedOnlineClassicalPk, cvClient, onlineSignature)?
"""
    old += "    _ = SIGNVERIF(receivedOnlineAltPk, cvClient, onlineAltSignature)?\n" if dual else ""
    old += """    dhClient = DH_KEX(serverShare, clientEphemeral)
    kemClient = KEM_DECAP(clientKemSecret, kemCiphertext)
    handshakeKeyClient = HKDF(nil, CONCAT(dhClient, kemClient), hsLabel)
    finishedKeyClient = HKDF(nil, handshakeKeyClient, finishedLabel)
    _ = ASSERT(serverFinished, MAC(finishedKeyClient, HASH(transcriptClient, onlineSignature, onlineAltSignature)))?
"""
    # Verifpal requires the bare atom to be explicitly delivered for its origin
    # query. It is a parallel observation of the CV field, not a new TLS byte
    # encoding; ASSERT makes it equal to the field actually used in the flight.
    new = """// onlineSignature is the projected observation of the CV field for the
// retained atom-origin query. ASSERT below binds it to the actual flight field.
Server -> Client: serverAuthentication, onlineSignature
principal Client[
    receivedServerHello, receivedCertificateTranscript, receivedOnlineSignature, receivedOnlineAltSignature, receivedServerFinished = SPLIT(serverAuthentication)?
    receivedServerRandom, receivedServerShare, receivedKemCiphertext = SPLIT(receivedServerHello)?
    flightTBS, flightClassicalSig, flightAlternativeSig = SPLIT(receivedCertificateTranscript)?
    flightIdentity, flightOnlineKeys, flightPolicy = SPLIT(flightTBS)?
    flightOnlineClassicalPk, flightOnlineAltPk = SPLIT(flightOnlineKeys)?
    _ = ASSERT(receivedCertificateTranscript, CONCAT(leafTBS, leafSig, leafAltSig))?
    _ = ASSERT(flightIdentity, identity)?
    _ = ASSERT(flightPolicy, CONCAT(serverUse, serverValidity, onlineAlgorithms))?
    _ = SIGNVERIF(receivedIntermediateClassicalPk, flightTBS, flightClassicalSig)?
"""
    if alt:
        new += "    _ = SIGNVERIF(receivedIntermediateAltPk, flightTBS, flightAlternativeSig)?\n"
    new += """    _ = ASSERT(receivedOnlineSignature, onlineSignature)?
    clientHelloReceived = CONCAT(clientRandom, clientShare, clientKemPk)
    transcriptClient = HASH(clientHelloReceived, receivedServerHello, receivedCertificateTranscript, onlineAlgorithms)
    cvClient = CONCAT(cvContext, transcriptClient)
    _ = SIGNVERIF(flightOnlineClassicalPk, cvClient, receivedOnlineSignature)?
"""
    if dual:
        new += "    _ = SIGNVERIF(flightOnlineAltPk, cvClient, receivedOnlineAltSignature)?\n"
    new += """    dhClient = DH_KEX(receivedServerShare, clientEphemeral)
    kemClient = KEM_DECAP(clientKemSecret, receivedKemCiphertext)
    handshakeKeyClient = HKDF(nil, CONCAT(dhClient, kemClient), hsLabel)
    finishedKeyClient = HKDF(nil, handshakeKeyClient, finishedLabel)
    _ = ASSERT(receivedServerFinished, MAC(finishedKeyClient, HASH(transcriptClient, receivedOnlineSignature, receivedOnlineAltSignature)))?
"""
    text = replace_once(text, old, new)
    old_queries = """queries[
    authentication? Intermediate -> Client: leafTBS[precondition[Client -> Server: appRecord]]
    authentication? Server -> Client: onlineSignature[precondition[Client -> Server: appRecord]]
    freshness? transcriptClient
    confidentiality? applicationMessage[precondition[Client -> Server: appRecord]]
]
"""
    new_queries = """queries[
    authentication? Intermediate -> Client: leafTBS[precondition[Client -> Server: appRecord]]
    authentication? Server -> Client: onlineSignature[precondition[Client -> Server: appRecord]]
    authentication? Server -> Client: serverAuthentication[precondition[Client -> Server: appRecord]]
    freshness? transcriptClient[precondition[Client -> Server: appRecord]]
    confidentiality? applicationMessage[precondition[Client -> Server: appRecord]]
]
"""
    return replace_once(text, old_queries, new_queries)


def replay_control():
    return """// Small reusable-certificate control. The same certificate can authorize
// fresh online sessions; issuer transmission origin is a stronger question.
attacker[active]
principal Issuer[
    knows private caKey
    caPk = PUBKEY(caKey)
    knows public identity, policy
]
principal Server[
    knows private onlineKey
    onlinePk = PUBKEY(onlineKey)
]
Server -> Issuer: [onlinePk]
principal Issuer[
    leaf = CONCAT(identity, onlinePk, policy)
    certificateSignature = SIGN(caKey, leaf)
    certificate = CONCAT(leaf, certificateSignature)
]
Issuer -> Client: [caPk], certificate
principal Client[
    knows public identity, policy
    receivedLeaf, receivedCertSig = SPLIT(certificate)?
    receivedIdentity, receivedPk, receivedPolicy = SPLIT(receivedLeaf)?
    _ = ASSERT(receivedIdentity, identity)?
    _ = ASSERT(receivedPolicy, policy)?
    _ = SIGNVERIF(caPk, receivedLeaf, receivedCertSig)?
    generates challenge
]
Client -> Server: challenge
principal Server[
    proof = SIGN(onlineKey, challenge)
]
Server -> Client: proof
principal Client[
    _ = SIGNVERIF(receivedPk, challenge, proof)?
    accepted = HASH(challenge, certificate, proof)
]
Client -> Server: accepted
queries[
    authentication? Issuer -> Client: certificate[precondition[Client -> Server: accepted]]
    authentication? Server -> Client: proof[precondition[Client -> Server: accepted]]
    freshness? accepted[precondition[Client -> Server: accepted]]
]
"""


def generate():
    MODELS.mkdir(parents=True, exist_ok=True)
    for name, options in SCENARIOS.items():
        (MODELS / (name + ".vp")).write_text(model(name, options), encoding="utf-8", newline="\n")
    (MODELS / "replay_reusable_certificate.vp").write_text(replay_control(), encoding="utf-8", newline="\n")
    metadata = dict(schema="a15-ca-query-map-v2", queries=QUERY_MAP,
        acceptance="Every main query is conditioned on Client -> Server: appRecord.",
        projected_atom="onlineSignature is delivered alongside the composite only to retain Verifpal's required explicit-reception atom-origin query. ASSERT binds it to receivedOnlineSignature, and every online/Finished/key check uses SPLIT-derived fields. This is not a TLS byte-overhead model.",
        flight="CONCAT(serverHello, certificateTranscript, onlineSignature, onlineAltSignature, serverFinished), with 5 fields; exact certificate binding plus CA verification and local policy assertions are repeated on extracted certificate fields.",
        relationship_to_v1="Adds accepted complete-flight origin and freshness acceptance condition. v1 source/results remain separate and unchanged; no expected result-code table is used.",
        bounds="Ideal primitives, bounded sessions, incomplete attack search. No DER/numeric expiry/implementation or unbounded proof.",
        replay_control="Separate small 2-session certificate-reuse control; exact verdict is retained without assuming failure or success.",
        scenarios={name: dict(zip(("require_alt", "classical_ca_leaked", "classical_online_leaked", "require_dual_online", "alternative_ca_leaked", "alternative_online_leaked"), options)) for name, options in SCENARIOS.items()})
    (MODELS / "queries.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")


def invoke(command, output, timeout):
    started = now()
    try:
        with output.open("xb") as stream:
            done = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=timeout)
        return dict(command=command, started_utc=started, completed_utc=now(),
                    returncode=done.returncode, status="completed", raw_sha256=sha(output))
    except subprocess.TimeoutExpired:
        return dict(command=command, started_utc=started, completed_utc=now(),
                    returncode=None, status="timeout", timeout_seconds=timeout, raw_sha256=sha(output))
    except OSError as error:
        if not output.exists():
            output.write_bytes(b"")
        return dict(command=command, started_utc=started, completed_utc=now(),
                    returncode=None, status="execution_error", error=str(error), raw_sha256=sha(output))


def run_model(verifier, out, name, sessions, timeout):
    path = MODELS / (name + ".vp")
    print(json.dumps(dict(phase="ca-symbolic-v2", model=name, sessions=sessions)), flush=True)
    command = [str(verifier), "verify", str(path), "--sessions", str(sessions), "--color", "never", "--result-code"]
    first = out / (name + ".first.txt")
    row = dict(model=name, sessions=sessions, model_sha256=sha(path),
               first=invoke(command, first, timeout), query_verdicts=[])
    raw = first.read_text(encoding="utf-8", errors="replace")
    code = raw.splitlines()[-1] if raw.splitlines() else ""
    row["result_code"] = code if re.fullmatch(r"(?:[acfeu][01])+", code) else None
    if row["first"]["returncode"] == 0:
        json_command = [str(verifier), "verify", str(path), "--sessions", str(sessions), "--format", "json"]
        json_path = out / (name + ".first.json")
        row["structured"] = invoke(json_command, json_path, timeout)
        if row["structured"]["returncode"] == 0:
            try:
                analysis = json.loads(json_path.read_text(encoding="utf-8"))["models"][0]["analysis"]
                row.update(json_result_code=analysis["code"], attacks=analysis["attacks"],
                           query_verdicts=[dict(query=q["query"], attack_found=q["resolved"],
                                conclusion=q.get("conclusion", ""), envelope=q.get("envelope", {})) for q in analysis["queries"]],
                           codes_agree=analysis["code"] == row["result_code"])
            except (ValueError, KeyError, IndexError) as error:
                row["structured_parse_error"] = str(error)
    row["tool_completed"] = (row["first"]["returncode"] == 0 and row.get("structured", {}).get("returncode") == 0
                              and not row.get("structured_parse_error"))
    (out / (name + ".run.json")).write_text(json.dumps(row, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(dict(model=name, sessions=sessions, code=row["result_code"],
                          status=row["first"]["status"], tool_completed=row["tool_completed"])), flush=True)
    return row


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--generate-only", action="store_true")
    parser.add_argument("--verifier", type=Path, default=ROOT / "build/ca-verifier-1.4.12/verifpal.exe")
    parser.add_argument("--run-dir", type=Path)
    parser.add_argument("--sessions", type=int, choices=(1, 2, 3), default=1)
    parser.add_argument("--models", nargs="+", choices=tuple(SCENARIOS), default=PRIORITY)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--workers", type=int, choices=(1, 2, 3), default=2)
    parser.add_argument("--replay-control", action="store_true")
    args = parser.parse_args()
    generate()
    if args.generate_only:
        return 0
    if args.run_dir is None or args.timeout <= 0:
        parser.error("--run-dir and a positive --timeout are required")
    out = args.run_dir.resolve()
    out.mkdir(parents=True, exist_ok=False)
    verifier = args.verifier.resolve()
    about = subprocess.check_output([str(verifier), "about"], text=True)
    (out / "verifier-about.txt").write_text(about, encoding="utf-8")
    inputs = [Path(__file__).resolve(), ROOT / "tools/run_ca_models.py", *sorted(MODELS.glob("*"))]
    before = {p.relative_to(ROOT).as_posix(): sha(p) for p in inputs}
    with zipfile.ZipFile(out / "source.zip", "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for p in inputs:
            archive.write(p, p.relative_to(ROOT).as_posix())
    manifest = dict(schema="a15-ca-symbolic-run-v2", started_utc=now(), verifier_version=about,
        verifier_sha256=sha(verifier), source_sha256=before, source_archive_sha256=sha(out / "source.zip"),
        sessions=args.sessions, timeout_seconds_per_invocation=args.timeout, workers=args.workers, runs=[],
        real_timing_samples=0, formal_performance_started=False,
        scope="Bounded ideal primitives; attack is a result. Tool timeout/error and attack verdict are separate.")
    def save():
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    save()
    jobs = [(name, args.sessions) for name in args.models]
    if args.replay_control:
        jobs.append(("replay_reusable_certificate", 2))
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(run_model, verifier, out, name, sessions, args.timeout): (name, sessions) for name, sessions in jobs}
        for future in as_completed(futures):
            name, sessions = futures[future]
            try:
                manifest["runs"].append(future.result())
            except Exception as error:
                manifest["runs"].append(dict(model=name, sessions=sessions, tool_completed=False, worker_error=str(error)))
            save()
    manifest.update(completed_utc=now(), source_unchanged=all(sha(ROOT / name) == digest for name, digest in before.items()))
    manifest["tool_runs_completed"] = manifest["source_unchanged"] and all(row["tool_completed"] for row in manifest["runs"])
    save()
    return int(not manifest["tool_runs_completed"])


if __name__ == "__main__":
    raise SystemExit(main())
