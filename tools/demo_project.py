"""Visualize executed A1-5 functional evidence; never generate SLH CA keys or benchmark samples."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import html
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ("P0", "P1", "P2", "P3", "P4")
WIDTH, HEIGHT = 1600, 900


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def checked_hash(value):
    if not isinstance(value, str) or len(value) != 64 or any(x not in "0123456789abcdef" for x in value):
        raise ValueError("evidence contains an invalid SHA-256")
    return value


def selected_profile(row):
    name = row.get("profile")
    if name not in PROFILES:
        raise ValueError("unexpected profile in executed evidence")
    fragments = []
    for record in row.get("per_message", row.get("fragments", [])):
        label = record["name"]
        if label not in ("ClientHello", "ServerHello", "EncryptedExtensions", "Certificate", "CertificateVerify", "Finished"):
            raise ValueError("unexpected record label")
        if record["sender"] not in ("client", "server"):
            raise ValueError("unexpected record sender")
        fragments.append({"name": label, "sender": record["sender"],
            "plaintext_bytes": int(record["plaintext_bytes"]),
            "record_bytes": int(record.get("harness_record_bytes", record.get("record_bytes", record.get("wire_bytes"))))})
    return {"profile": name, "passed": row.get("passed") is True,
            "handshake_bytes": int(row["handshake_bytes"]),
            "server_flight_bytes": int(row["server_flight_bytes"]),
            "chain_der_bytes": [int(x) for x in row["chain_der_bytes"]],
            "chain_der_sha256": [checked_hash(x) for x in row["chain_der_sha256"]],
            "fragments": fragments}


def import_evidence(path):
    """Read whitelisted public fields, and verify related files before displaying them."""
    path = path.resolve()
    source = json.loads(path.read_text(encoding="utf-8"))
    result = {"schema": "a15-demo-evidence-v1", "input_sha256": digest(path),
        "performance_samples": 0, "slh_ca_signing_calls": 0, "profiles": [],
        "dual_verification": [], "negatives": [], "functional_gates": [],
        "library_sha256": source.get("library_sha256"), "source_json_sha256": digest(path)}
    schema = source.get("schema")
    if schema == "a15-demo-evidence-v1":
        if source.get("performance_samples") != 0:
            raise ValueError("this demonstration only accepts evidence without performance samples")
        result["profiles"] = [selected_profile(row) for row in source["profiles"]]
        result["dual_verification"] = [{"algorithm": row["algorithm"], "mode": row["mode"],
            "passed": row["passed"] is True, "checked_edges": int(row["checked_edges"]),
            "library_sha256": [checked_hash(x) for x in row.get("library_sha256", [])]}
            for row in source.get("dual_verification", [])]
        result["negatives"] = [{"name": row["name"], "rejected": row["rejected"] is True,
            "step": row["step"], "public_der_sha256": checked_hash(row["public_der_sha256"]),
            "outer_ecdsa_resigned": row["outer_ecdsa_resigned"] is True, "new_slh_signatures": 0}
            for row in source.get("negatives", [])]
        result["functional_gates"] = [{"name": row["name"], "passed": row["passed"] is True,
            **({"passed_count": int(row["passed_count"]), "skipped_count": int(row["skipped_count"])} if "passed_count" in row else {})}
            for row in source.get("functional_gates", [])]
        result["fixture_manifest_sha256"] = source.get("fixture_manifest_sha256", {})
    elif schema == "a15-project-functional-v1":
        if source.get("formal_performance_started") is not False or source.get("real_timing_samples") != 0:
            raise ValueError("functional manifest must explicitly report zero formal performance samples")
        result["functional_gates"] = [{"name": row["name"], "passed": row["returncode"] == 0,
                                       "log_sha256": checked_hash(row["log_sha256"])} for row in source["steps"]]
        for row in source["steps"]:
            if digest(path.parent / (row["name"] + ".log")) != row["log_sha256"]:
                raise ValueError("functional log hash differs from manifest")
        hashes = source.get("evidence_sha256", {})
        def related(name):
            candidate = path.parent / name
            if name not in hashes or digest(candidate) != checked_hash(hashes[name]):
                raise ValueError("related evidence hash mismatch: " + name)
            return candidate
        if "p0-p4-size-functional.jsonl" in hashes:
            result["profiles"] = [selected_profile(json.loads(line)) for line in
                related("p0-p4-size-functional.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]
        if "ca-verification.json" in hashes:
            rows = json.loads(related("ca-verification.json").read_text(encoding="utf-8"))["rows"]
            result["dual_verification"] = [{"algorithm": row["algorithm"], "mode": row["verifier"],
                "passed": row["passed"] is True, "checked_edges": int(row["checked_edges"]),
                "library_sha256": [checked_hash(x["library_sha256"]) for x in row.get("verifiers", []) if x.get("mode") == "native"]} for row in rows]
    elif schema == "a15-tls-functional-acceptance-v1":
        if source.get("performance_samples") != 0:
            raise ValueError("TLS evidence contains performance samples")
        result["functional_gates"] = [{"name": "TLS full functional regression", "passed": True,
            "passed_count": int(source["functional_full"]["passed"]),
            "skipped_count": int(source["functional_full"]["skipped"])},
            {"name": "TLS final targeted regression", "passed": True,
             "passed_count": int(source["functional_targeted_final"]["passed"]),
             "skipped_count": int(source["functional_targeted_final"]["skipped"])},
            {"name": "TLS live audit", "passed": source["live_audit_exit"] == 0}]
    else:
        raise ValueError("unsupported executed-evidence schema")
    if result["library_sha256"] is not None:
        checked_hash(result["library_sha256"])
    return result


def run_fixtures(fixtures, library, handshake_signer):
    """Use immutable preissued CA material; only classical outer re-signing is used for negative probes."""
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "base_tls"))
    os.environ["SLHDSA_SM3_LIB"] = str(library.resolve())
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from tls.alt_chain import verify_alt_chain
    from tls.alt_profiles import profiles
    from tls.der import bit_string, bit_string_bytes, elements, extension_fields, oid, single, tlv
    from tls.errors import HandshakeError
    from tls.handshake.connection import HybridConnection
    from tls.metrics import Metrics

    class UntimedMetrics(Metrics):
        @contextmanager
        def time(self, label):
            yield

    result = {"schema": "a15-demo-evidence-v1", "performance_samples": 0, "slh_ca_signing_calls": 0,
        "library_sha256": digest(library), "fixture_manifest_sha256": {}, "profiles": [],
        "dual_verification": [], "negatives": [], "functional_gates": [],
        "scope": "executed untimed fixture handshakes and public certificate negative checks; no terminal screenshot or standard TLS interoperability claim"}
    before = digest(library)
    for code, config in profiles(fixtures, handshake_signer=handshake_signer).items():
        session = HybridConnection.run(config, metrics=UntimedMetrics())
        chain = session.server.credentials.chain
        result["profiles"].append({"profile": code,
            "passed": session.application_payload_ok and session.exporters_match,
            "handshake_bytes": session.handshake_bytes, "server_flight_bytes": session.server_bytes,
            "chain_der_bytes": [len(x) for x in chain.chain_der],
            "chain_der_sha256": [hashlib.sha256(x).hexdigest() for x in chain.chain_der],
            "fragments": [{"name": row.name, "sender": row.sender, "plaintext_bytes": row.message_bytes,
                "record_bytes": row.record_bytes, "wire_bytes": row.total_bytes} for row in session.messages]})
        if not result["profiles"][-1]["passed"]:
            raise ValueError("fixture profile functional check failed: " + code)
    for name in ("slh-dsa-sm3-128-24", "slh-dsa-sm3-128s", "ml-dsa-44"):
        directory = fixtures / name
        metadata_path = directory / "fixture.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        result["fixture_manifest_sha256"][name] = digest(metadata_path)
        def read_member(member):
            candidate = (directory / member).resolve()
            if not candidate.is_relative_to(directory.resolve()):
                raise ValueError("fixture member leaves its bundle")
            data = candidate.read_bytes()
            if hashlib.sha256(data).hexdigest() != checked_hash(metadata["files_sha256"][member]):
                raise ValueError("fixture member hash mismatch")
            return data
        profile = metadata["chains"]["alt"]
        root = x509.load_der_x509_certificate(read_member(profile["root"]))
        chain = (read_member(profile["leaf"]), read_member(profile["intermediate"]))
        for python in ([False, True] if name.startswith("slh-") else [False]):
            verification = verify_alt_chain(chain, root, "server.example", require_alt_chain=True,
                expected_algorithm=name, force_python=python, require_native=name.startswith("slh-") and not python,
                library=library)
            mode = "python" if python else ("native" if name.startswith("slh-") else "provider")
            if any(row["mode"] != mode for row in verification.verifiers):
                raise ValueError("verifier backend differs from required mode")
            result["dual_verification"].append({"algorithm": name, "mode": mode,
                "passed": verification.complete, "checked_edges": verification.checked_edges,
                "library_sha256": [row["library_sha256"] for row in verification.verifiers if mode == "native"]})
        if name != "slh-dsa-sm3-128-24":
            continue
        issuer_key = serialization.load_pem_private_key(read_member("intermediate-test-key.pem"), password=None)
        # Re-sign only the ECDSA outer certificate so mutations reach the strict
        # alternative-signature verifier. No new SLH signature is computed.
        for action in ("strip-alt-pair", "tamper-alt-signature"):
            outer = elements(single(chain[0], 0x30).value)
            fields = []
            for field in elements(single(outer[0].encoded, 0x30).value):
                if field.tag != 0xA3:
                    fields.append(field.encoded)
                    continue
                extensions = []
                for ext in elements(single(field.value, 0x30).value):
                    identifier, critical, value = extension_fields(ext.encoded)
                    if action == "strip-alt-pair" and identifier in ("2.5.29.73", "2.5.29.74"):
                        continue
                    if action == "tamper-alt-signature" and identifier == "2.5.29.74":
                        signature = bit_string_bytes(value)
                        value = bit_string(bytes([signature[0] ^ 1]) + signature[1:])
                        extensions.append(tlv(0x30, oid(identifier) + (tlv(1, b"\xff") if critical else b"") + tlv(4, value)))
                    else:
                        extensions.append(ext.encoded)
                fields.append(tlv(0xA3, tlv(0x30, b"".join(extensions))))
            tbs = tlv(0x30, b"".join(fields))
            mutation = tlv(0x30, tbs + outer[1].encoded + bit_string(issuer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))))
            try:
                verify_alt_chain((mutation, chain[1]), root, "server.example", require_alt_chain=True,
                    expected_algorithm=name, require_native=True, library=library)
            except HandshakeError as error:
                if error.step != "certificate_alt":
                    raise ValueError("negative certificate did not reach alternative policy verifier") from error
                result["negatives"].append({"name": action, "rejected": True, "step": error.step,
                    "public_der_sha256": hashlib.sha256(mutation).hexdigest(),
                    "outer_ecdsa_resigned": True, "new_slh_signatures": 0})
            else:
                raise ValueError("mutated alternative certificate was unexpectedly accepted")
    if digest(library) != before:
        raise ValueError("native library changed during demonstration")
    result["passed"] = all(x["passed"] for x in result["profiles"] + result["dual_verification"]) and len(result["negatives"]) == 2
    return result


def panels(evidence, evidence_hash):
    gate_lines = [f"{row['name']}: {'PASS' if row['passed'] else 'FAIL'}" +
        (f" ({row['passed_count']} passed / {row['skipped_count']} skipped)" if "passed_count" in row else "")
        for row in evidence.get("functional_gates", [])][:8]
    modes = [f"{row['algorithm']} | {row['mode']} | {row['checked_edges']} edges | {'PASS' if row['passed'] else 'FAIL'}"
             for row in evidence.get("dual_verification", [])]
    p = {row["profile"]: row for row in evidence["profiles"]}
    profile_lines = [f"{code}  {'PASS' if p[code]['passed'] else 'FAIL'}   handshake={p[code]['handshake_bytes']:,} B   server={p[code]['server_flight_bytes']:,} B"
                     if code in p else f"{code}  NO EXECUTED PROFILE EVIDENCE" for code in PROFILES]
    certificate = [x for x in p.get("P3", {}).get("fragments", []) if x["name"] == "Certificate"]
    fragment_lines = [f"P3 Certificate: {len(certificate)} authenticated records"] if certificate else ["P3 fragmentation: no executed profile evidence in supplied JSON"]
    fragment_lines += [f"  record {i+1}: content={x['plaintext_bytes']:,} B / ciphertext={x['record_bytes']:,} B"
                      for i, x in enumerate(certificate)]
    fragment_lines += ["Content bound: 16,384 B; ciphertext bound: 16,640 B",
        "Transcript hashes complete handshake messages once.", "Private harness / TCP prefix / standard TLS header model stay separate."]
    negatives = [f"{x['name']}: {'REJECTED' if x['rejected'] else 'ACCEPTED'} at {x['step']}" for x in evidence.get("negatives", [])]
    if not negatives:
        negatives = ["Negative fixture probes: not present in supplied JSON", "Use --fixtures + --library to execute stripping/tamper checks."]
    negatives += ["Formal performance samples: 0", "New SLH CA signatures in this demo: 0", "No private keys, tokens, paths or elapsed times are exported."]
    return [
        ("01  EXECUTED FUNCTIONAL EVIDENCE", "Executed JSON evidence visualization; no fabricated terminal screenshot.", gate_lines[:3] + modes or ["No gate summaries in input; inspect source JSON hash below."]),
        ("02  P0-P4 FIXTURE HANDSHAKES", "Preissued credentials; result status and serialized record bytes.", profile_lines + ["DER certificate bytes are retained separately from handshake framing."]),
        ("03  CERTIFICATE RECORD FRAGMENTATION", "Record boundaries preserve authentication order and complete-message transcripts.", fragment_lines),
        ("04  STRICT POLICY NEGATIVE CHECKS", "Public certificate mutations; ECDSA outer signature renewed, SLH signature unchanged.", negatives),
    ]


def render_slides(output, evidence, font_path):
    source = digest(output / "evidence.json")
    slides = panels(evidence, source)
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        Image = ImageDraw = ImageFont = None
    selected_font = font_path
    if selected_font is None:
        for candidate in (Path("C:/Windows/Fonts/arial.ttf"), Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
                          Path("/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf")):
            if candidate.is_file():
                selected_font = candidate
                break
    if ImageFont is not None and selected_font is None:
        raise ValueError("PNG rendering needs a TrueType font; pass --font")
    for index, (title, subtitle, lines) in enumerate(slides, 1):
        title = str(title)
        safe_lines = [str(x)[:120] for x in lines]
        text_rows = [(title, 96, 113, 40, "#eff6ff"), (subtitle, 96, 180, 23, "#a6b5c9")]
        text_rows += [(line, 96, 285+i*52, 25, "#dbe7f3") for i, line in enumerate(safe_lines[:9])]
        text_rows += [("SOURCE JSON SHA-256", 96, 764, 19, "#93c5fd"), (source, 96, 809, 21, "#a6b5c9"),
                      (f"{index}/4  |  FUNCTIONAL ONLY  |  GENERATED EVIDENCE PRESENTATION", 96, 858, 19, "#a6b5c9")]
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}">',
               '<rect width="1600" height="900" fill="#0b1220"/>',
               '<rect x="62" y="56" width="1476" height="644" rx="24" fill="#111e31"/>',
               '<rect x="62" y="56" width="9" height="644" rx="4" fill="#2dd4bf"/>']
        svg += [f'<text x="{x}" y="{y}" font-size="{size}" fill="{color}" font-family="Arial, DejaVu Sans, sans-serif">{html.escape(value)}</text>'
                for value, x, y, size, color in text_rows]
        svg.append("</svg>")
        (output / f"slide-{index:02}.svg").write_text("\n".join(svg)+"\n", encoding="utf-8")
        if Image is not None:
            picture = Image.new("RGB", (WIDTH, HEIGHT), "#0b1220")
            canvas = ImageDraw.Draw(picture)
            canvas.rounded_rectangle((62, 56, 1538, 700), radius=24, fill="#111e31")
            canvas.rounded_rectangle((62, 56, 71, 700), radius=4, fill="#2dd4bf")
            for value, x, y, size, color in text_rows:
                canvas.text((x, y-size), value, font=ImageFont.truetype(str(selected_font), size), fill=color)
            picture.save(output / f"slide-{index:02}.png")
    return [x[0] for x in slides]


def video_files(output, evidence, make_video):
    captions = ["已执行功能证据：按 JSON 与哈希展示，图像不是终端截图。",
                ("P0 至 P4 使用预签发凭据；展示成功状态与真实序列化字节。" if evidence["profiles"] else "所选 JSON 尚未包含 P0 至 P4 直接运行结果，画面据实标记缺项。"),
                ("长 Certificate 按记录分片；完整握手消息的 transcript 语义保持。" if evidence["profiles"] else "所选 JSON 尚未包含 P3 分片记录，画面据实标记缺项。"),
                ("严格策略拒绝 alt 剥离与篡改；性能采样与新 SLH CA 签发均为零。" if evidence["negatives"] else "输入未记录 alt 负例的直接结果；性能采样与新 SLH CA 签发均为零。")]
    (output / "captions.srt").write_text("\n\n".join(
        f"{i+1}\n00:00:{8*i:02},000 --> 00:00:{8*(i+1):02},000\n{text}"
        for i, text in enumerate(captions))+"\n", encoding="utf-8")
    (output / "slides.ffconcat").write_text("ffconcat version 1.0\n"+"".join(
        f"file 'slide-{i:02}.png'\nduration 8\n" for i in range(1,5))+"file 'slide-04.png'\n", encoding="utf-8")
    command = ["ffmpeg", "-nostdin", "-n", "-f", "concat", "-safe", "1", "-i", "slides.ffconcat",
               "-i", "captions.srt", "-map", "0:v:0", "-map", "1:0", "-c:v", "libx264",
               "-r", "24", "-pix_fmt", "yuv420p", "-c:s", "mov_text", "-metadata:s:s:0", "language=zho",
               "-disposition:s:0", "default", "-t", "32", "-movflags", "+faststart", "evidence-demo.mp4"]
    (output / "MAKE_VIDEO.txt").write_text(
        "Generated evidence presentation video; not a captured live terminal session.\n"
        "Run from this output directory after PNG slides are available.\n"+
        " ".join(command)+"\n", encoding="utf-8")
    if not make_video:
        return "command-written"
    if shutil.which("ffmpeg") is None:
        return "ffmpeg-missing-command-written"
    if not all((output / f"slide-{i:02}.png").is_file() for i in range(1,5)):
        # ffmpeg builds with librsvg can rasterize our static SVGs without Pillow.
        for i in range(1, 5):
            raster = subprocess.run(["ffmpeg", "-nostdin", "-n", "-i", f"slide-{i:02}.svg",
                "-frames:v", "1", f"slide-{i:02}.png"], cwd=output, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            if raster.returncode:
                return "png-renderer-missing-command-written"
    subprocess.run(command, cwd=output, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    return "generated"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="new output directory; existing evidence is never overwritten")
    parser.add_argument("--evidence-json", type=Path, help="executed demo/project-functional/TLS acceptance JSON")
    parser.add_argument("--fixtures", type=Path, help="existing preissued alt fixtures; executes functional demonstrations only")
    parser.add_argument("--library", type=Path, help="explicit native library, mandatory with --fixtures")
    parser.add_argument("--handshake-signer", default="falcon-512")
    parser.add_argument("--font", type=Path)
    parser.add_argument("--video", action="store_true", help="encode a 32-second subtitled evidence presentation when ffmpeg is present")
    args = parser.parse_args()
    if args.fixtures is None and args.evidence_json is None:
        parser.error("provide --evidence-json or --fixtures")
    if args.fixtures is not None and args.library is None:
        parser.error("--fixtures requires an explicit --library")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    evidence = import_evidence(args.evidence_json) if args.evidence_json else None
    if args.fixtures:
        executed = run_fixtures(args.fixtures.resolve(), args.library.resolve(), args.handshake_signer)
        if evidence:
            executed["functional_gates"] = evidence["functional_gates"]
            executed["input_sha256"] = evidence["input_sha256"]
        evidence = executed
    (output / "evidence.json").write_text(json.dumps(evidence, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    titles = render_slides(output, evidence, args.font)
    video = video_files(output, evidence, args.video)
    manifest = {"schema": "a15-demo-artifacts-v1", "mode": "executed-fixtures" if args.fixtures else "executed-json-visualization",
        "titles": titles, "video_status": video, "performance_samples": 0, "slh_ca_signing_calls": 0,
        "contains_private_keys": False, "contains_elapsed_times": False,
        "artifacts_sha256": {p.name: digest(p) for p in sorted(output.iterdir()) if p.is_file()},
        "scope": "visualization of executed evidence; generated presentation video, not a live screen recording"}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
    print(json.dumps({"schema": manifest["schema"], "mode": manifest["mode"], "video_status": video,
        "four_svg_slides": True, "performance_samples": 0, "slh_ca_signing_calls": 0}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
