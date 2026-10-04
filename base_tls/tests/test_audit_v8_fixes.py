"""Regression tests for the eighth review (their ``audit_v8``, the red-team pass).

One test per finding, each with its positive control, in the terms the review used:

* **W2** -- the Finished comparisons were content-dependent early exits (``verify_data !=
  expected``). Both roles now compare with ``hmac.compare_digest`` and check the length first,
  so a wrong value of the wrong length gets its own message. The tests drive the real
  comparison on both halves plus one end-to-end tamper, and refuse a regression at the syntax
  level as well (an AST check that no ``verify_data`` equality comparison comes back).
* **W3** -- the demo printed the first 12 bytes of every derived secret. By default it now
  prints names, algorithms, lengths and status only; ``--fingerprint`` adds a labelled hash.
  The tests capture the real output and assert that no derived value -- and no prefix of one --
  appears, that the fingerprint mode is a hash, and that an absent value is not dressed up as
  one.
* **T5** -- a *legal* multi-share ClientHello (RFC 8446 section 4.2.8) was refused with a
  "trailing bytes" decode error, which described a framing problem where the real cause is that
  this profile accepts exactly one classical share and implements no HelloRetryRequest. The
  corrected fixture builds the message properly (inner and outer lengths, second group added to
  ``supported_groups``) and the refusal now names the profile limit.
* **TB-1/TB-2** -- the sandbox helper consulted its explicit switch *before* the platform check,
  so ``DSH_SANDBOX_PYFIX=1`` widened directory permissions on non-Windows platforms too. The
  platform is now decisive and all three combinations are tested.
* **W4** -- a hash *count* is not an association: the lock is now verified per package
  (version pin, at least one well-formed hash, no conflicting duplicate), and a downloaded
  artefact is refused unless its digest is in the trusted lock.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
import subprocess
import sys
import types
from pathlib import Path

import pytest

from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import DecodeError, HandshakeError, HybridTLSError
from tls.handshake.client import HybridClient
from tls.handshake.messages import (
    CLIENT_HELLO,
    EXTENSION_KEY_SHARE,
    EXTENSION_PQ_KEY_SHARE,
    EXTENSION_SIGNATURE_ALGORITHMS,
    EXTENSION_SUPPORTED_GROUPS,
    EXTENSION_SUPPORTED_VERSIONS,
    LEGACY_VERSION,
    TLS13_VERSION,
    ClientHello,
    Finished,
    KeyShareEntry,
    ServerHello,
    _encode_extensions,
)
from tls.handshake.server import HybridServer
from tls.classical.ecdh import EcdheKeyPair
from tls.record.aead import CONTENT_TYPE_HANDSHAKE
from tls.wire import handshake_message, split_handshake_message, u16, u8, vec8, vec16

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROFILE = "ml-kem-768+ml-dsa-44"
SERVER_NAME = "server.example"
X25519 = 0x001D
SECP256R1 = 0x0017


def _roles(config: HybridTLSConfig | None = None):
    """A client and a server positioned after the server flight, plus the credentials."""
    config = config or HybridTLSConfig(kem="ml-kem-768", pq_signer="ml-dsa-44")
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=SERVER_NAME.encode())
    certificate = credentials.bind_to(authority)
    client = HybridClient(config, authority, trusted_name=SERVER_NAME)
    server = HybridServer(config, credentials, certificate)
    server_hello = server.receive_client_hello(client.create_client_hello())
    client.receive_server_hello(server_hello)
    flight = server.send_authenticated_flight()
    client.receive_server_flight([record for _name, record, _frame in flight])
    return client, server


# ------------------------------------------------------------------ W2: Finished comparison


def _flip(value: bytes, position: int) -> bytes:
    mutated = bytearray(value)
    mutated[position] ^= 0x01
    return bytes(mutated)


def test_the_client_accepts_the_servers_own_finished_value():
    """Positive control: the honest value passes the comparison."""
    client, _server = _roles()
    client._check_server_finished(client.finished_verify_data("server"))


@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_the_client_rejects_a_tampered_server_finished(position):
    """First, middle and last byte: every case is a named rejection, not an early exit."""
    client, _server = _roles()
    expected = client.finished_verify_data("server")
    index = {"first": 0, "middle": len(expected) // 2, "last": len(expected) - 1}[position]
    with pytest.raises(HandshakeError) as excinfo:
        client._check_server_finished(_flip(expected, index))
    assert excinfo.value.step == "server_finished"
    assert "does not match" in excinfo.value.reason


def test_the_client_rejects_a_server_finished_of_the_wrong_length():
    """A short or empty value gets the length message, not the content message."""
    client, _server = _roles()
    expected = client.finished_verify_data("server")
    for value in (b"", expected[:-1], expected + b"\x00"):
        with pytest.raises(HandshakeError) as excinfo:
            client._check_server_finished(value)
        assert "bytes, expected" in excinfo.value.reason


def test_the_client_rejects_a_tampered_server_finished_end_to_end():
    """The same rule through the real flight: the filter rewrites the plaintext Finished."""
    config = HybridTLSConfig(kem="ml-kem-768", pq_signer="ml-dsa-44")
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=SERVER_NAME.encode())
    certificate = credentials.bind_to(authority)
    client = HybridClient(config, authority, trusted_name=SERVER_NAME)
    server = HybridServer(config, credentials, certificate)

    def rewrite(name: str, frame: bytes) -> bytes:
        if name != "Finished":
            return frame
        _type, body = split_handshake_message(frame)
        verify_data = Finished.decode(body).verify_data
        return Finished(verify_data=_flip(verify_data, 0)).to_message()

    server_hello = server.receive_client_hello(client.create_client_hello())
    client.receive_server_hello(server_hello)
    flight = server.send_authenticated_flight(frame_filter=rewrite)
    with pytest.raises(HandshakeError) as excinfo:
        client.receive_server_flight([record for _name, record, _frame in flight])
    assert excinfo.value.step == "server_finished"
    assert "does not match" in excinfo.value.reason


def _sealed_client_finished(client, verify_data: bytes) -> bytes:
    """Seal a Finished with the client's handshake keys, at the sequence the server expects."""
    frame = Finished(verify_data=verify_data).to_message()
    return client.client_records.seal(CONTENT_TYPE_HANDSHAKE, frame)


def test_the_server_accepts_the_clients_own_finished_value():
    """Positive control for the server half."""
    client, server = _roles()
    server.receive_client_finished(client.send_client_finished())
    assert server.received_client_finished is not None


@pytest.mark.parametrize("position", ["first", "middle", "last"])
def test_the_server_rejects_a_tampered_client_finished(position):
    """The server compares the same way, on a value it has to decrypt first."""
    client, server = _roles()
    expected = client.finished_verify_data("client")
    index = {"first": 0, "middle": len(expected) // 2, "last": len(expected) - 1}[position]
    with pytest.raises(HybridTLSError) as excinfo:
        server.receive_client_finished(_sealed_client_finished(client, _flip(expected, index)))
    assert "does not match" in str(excinfo.value)


def test_the_server_rejects_a_client_finished_of_the_wrong_length():
    """Length first: an empty or truncated verify_data is refused with its own message."""
    client, server = _roles()
    expected = client.finished_verify_data("client")
    with pytest.raises(HybridTLSError) as excinfo:
        server.receive_client_finished(_sealed_client_finished(client, expected[:-1]))
    assert "bytes, expected" in str(excinfo.value)


def test_no_verify_data_equality_comparison_survives_in_the_handshake_layer():
    """A structural guard, not a keyword scan: the old ``!=`` must not come back.

    Comparisons of the *lengths* are expected -- the length is checked first and gets its own
    message -- so the guard looks for a comparison of the values themselves.
    """
    def compares_values(node: ast.Compare) -> bool:
        sides = [node.left, *node.comparators]
        if any(isinstance(side, ast.Call) for side in sides):
            return False
        return "verify_data" in ast.unparse(node)

    offenders = []
    for name in ("tls/handshake/client.py", "tls/handshake/server.py"):
        tree = ast.parse((PROJECT_ROOT / name).read_text(encoding="utf-8"), filename=name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Compare) or not isinstance(node.ops[0], (ast.Eq, ast.NotEq)):
                continue
            if compares_values(node):
                offenders.append(f"{name}:{node.lineno} {ast.unparse(node)[:60]}")
    assert not offenders, offenders


# ---------------------------------------------------------------------- W3: log hygiene


def _run_demo(*args: str) -> str:
    completed = subprocess.run(
        [sys.executable, "demo/run_handshake.py", *args],
        cwd=PROJECT_ROOT, capture_output=True, text=True, check=False,
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout + completed.stderr


def _real_secrets() -> dict[str, bytes]:
    """Run a handshake in-process and return the derived values the demo would print."""
    from tls.handshake.connection import HybridConnection

    config = HybridTLSConfig(kem="ml-kem-768", pq_signer="ml-dsa-44")
    result = HybridConnection.run(config)
    schedule = result.client.schedule
    return {
        "early_secret": schedule.early_secret,
        "handshake_secret": schedule.handshake_secret,
        "master_secret": schedule.master_secret,
        "c hs traffic": schedule.client_handshake_traffic,
        "s hs traffic": schedule.server_handshake_traffic,
        "c ap traffic": schedule.client_application_traffic,
        "s ap traffic": schedule.server_application_traffic,
        "exporter master": schedule.exporter_master_secret,
    }


def test_the_demo_default_output_carries_no_derived_secret():
    """Capture the real output and look for the real values, whole and truncated."""
    output = _run_demo("--pq", "ml-dsa-44")
    for label, value in _real_secrets().items():
        assert value.hex() not in output, label
        assert value[:12].hex() not in output, f"{label} (12-byte prefix)"
        assert value[:8].hex() not in output, f"{label} (8-byte prefix)"
    assert "withheld" in output


def test_the_demo_fingerprint_mode_prints_hashes_not_values():
    """`--fingerprint` is explicit, labelled, and still not the value."""
    output = _run_demo("--pq", "ml-dsa-44", "--fingerprint")
    assert "sha256:" in output
    assert "fingerprint" in output
    for label, value in _real_secrets().items():
        assert value.hex() not in output, label
        assert value[:12].hex() not in output, f"{label} (12-byte prefix)"


def test_the_demo_fingerprint_is_the_documented_transform():
    """The displayed fingerprint is a domain-separated hash, reproducible by the test."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "demo_under_test", PROJECT_ROOT / "demo" / "run_handshake.py"
    )
    assert spec and spec.loader
    demo = importlib.util.module_from_spec(spec)
    sys.modules["demo_under_test"] = demo
    spec.loader.exec_module(demo)

    value = bytes(range(32))
    expected = hashlib.sha256(b"hybrid-tls13/demo-fingerprint\x00" + value).hexdigest()[:16]
    assert demo._fingerprint(value) == f"sha256:{expected}"
    # An absent value is not dressed up as a real fingerprint.
    assert demo._fingerprint(b"") == "-"
    assert demo._fingerprint(None) == "-"


def test_the_demo_source_prints_no_raw_hex_of_schedule_values():
    """Their W3 scan, kept as a secondary check: the driver has no `.hex()` at all."""
    text = (PROJECT_ROOT / "demo" / "run_handshake.py").read_text(encoding="utf-8")
    assert ".hex()" not in text


# ------------------------------------------------------------------- T5: the share limit


def _client_hello_body(config: HybridTLSConfig, *, second_entry: bool) -> bytes:
    """Rebuild a ClientHello body, optionally with a second group's share added *correctly*.

    The audit's original fixture appended an entry after the vector that was already length
    prefixed, which left the extension unparsable and produced a "trailing bytes" error. Here
    the inner length is recomputed and the second group is added to ``supported_groups``, so
    the message is legal RFC 8446 section 4.2.8 and only the profile limit can refuse it.
    """
    client = HybridClient(config, CertificateAuthority(config.classical()), trusted_name=SERVER_NAME)
    decoded = ClientHello.decode(client.create_client_hello()[4:])
    key_share = decoded.key_share
    if second_entry:
        second = KeyShareEntry(SECP256R1, EcdheKeyPair.generate("secp256r1").public_bytes())
        shares = key_share.encode() + second.encode()
        groups = (X25519, SECP256R1)
    else:
        shares = key_share.encode()
        groups = (X25519,)
    extensions = [
        (EXTENSION_SUPPORTED_VERSIONS, vec8(u16(TLS13_VERSION))),
        (EXTENSION_SUPPORTED_GROUPS, vec16(b"".join(u16(group) for group in groups))),
        (
            EXTENSION_SIGNATURE_ALGORITHMS,
            vec16(b"".join(u16(scheme) for scheme in decoded.signature_algorithms)),
        ),
        (EXTENSION_KEY_SHARE, vec16(shares)),
    ]
    if decoded.kem_scheme is not None and decoded.pq_key_share is not None:
        extensions.append(
            (EXTENSION_PQ_KEY_SHARE, u16(decoded.kem_scheme) + vec16(decoded.pq_key_share))
        )
    return (
        u16(LEGACY_VERSION)
        + decoded.random
        + vec8(decoded.legacy_session_id)
        + vec16(u16(config.cipher_suite_id))
        + vec8(bytes(decoded.legacy_compression_methods))
        + _encode_extensions(extensions)
    )


def test_a_single_share_client_hello_is_still_accepted():
    """Positive control: the profile's own ClientHello decodes."""
    config = HybridTLSConfig(kem="ml-kem-768", pq_signer="ml-dsa-44")
    decoded = ClientHello.decode(_client_hello_body(config, second_entry=False))
    assert decoded.key_share.group == X25519


def test_a_legal_multi_share_client_hello_is_refused_by_profile_not_by_framing():
    """T5, corrected: two well-formed entries, and the refusal names the profile limit."""
    config = HybridTLSConfig(kem="ml-kem-768", pq_signer="ml-dsa-44")
    body = _client_hello_body(config, second_entry=True)
    with pytest.raises(DecodeError) as excinfo:
        ClientHello.decode(body)
    message = str(excinfo.value)
    assert "more than one KeyShareEntry" in message
    assert "HelloRetryRequest" in message
    assert "trailing bytes" not in message

    server = HybridServer(
        config,
        ServerCredentials(config, identity=SERVER_NAME.encode()),
        ServerCredentials(config, identity=SERVER_NAME.encode()).bind_to(
            CertificateAuthority(config.classical())
        ),
    )
    with pytest.raises(HybridTLSError) as excinfo:
        server.receive_client_hello(handshake_message(CLIENT_HELLO, body))
    assert "KeyShareEntry" in str(excinfo.value)


# ------------------------------------------------------ TB-1: the sandbox helper's order


def _load_sitecustomize(*, platform: str, environ: dict[str, str]) -> bool:
    """Execute the helper under a stand-in platform and report whether ``os.mkdir`` changed.

    The helper does ``import os`` itself, so injecting a fake module would be ignored; the real
    ``os`` object's ``name``/``environ`` are patched for the exec and everything is restored
    afterwards, including ``os.mkdir`` (which the helper rebinds process-wide by design).
    """
    source = (PROJECT_ROOT / "tools" / "sandbox_pyfix" / "sitecustomize.py").read_text(
        encoding="utf-8"
    )
    real_mkdir = os.mkdir
    patcher = pytest.MonkeyPatch()
    try:
        patcher.setattr(os, "name", platform)
        patcher.setattr(os, "environ", environ)
        module = types.ModuleType("sitecustomize_under_test")
        exec(compile(source, "sitecustomize.py", "exec"), module.__dict__)
        return os.mkdir is not real_mkdir
    finally:
        patcher.undo()
        os.mkdir = real_mkdir


@pytest.mark.parametrize(
    ("platform", "environ", "expected"),
    [
        # The platform is decisive: the switch cannot enable it elsewhere.
        ("posix", {"DSH_SANDBOX_PYFIX": "1"}, False),
        ("posix", {"DSH_SESSION_ID": "session"}, False),
        # Explicit off wins even on Windows with a sandbox present.
        ("nt", {"DSH_SANDBOX_PYFIX": "0", "DSH_SESSION_ID": "session"}, False),
        # Explicit on works on Windows, which is what the switch is for.
        ("nt", {"DSH_SANDBOX_PYFIX": "1"}, True),
        # Auto-detection on Windows.
        ("nt", {"DSH_SESSION_ID": "session"}, True),
        # Nothing set: inert.
        ("nt", {}, False),
    ],
)
def test_the_sandbox_helper_requires_windows_before_its_switch(platform, environ, expected):
    """TB-1: the three combinations the review asked for, plus the auto-detection cases."""
    assert _load_sitecustomize(platform=platform, environ=environ) is expected


# --------------------------------------------------------------- W4: the dependency locks


def test_the_shipped_locks_are_fully_associated():
    """Every package is pinned and carries at least one well-formed sha256."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "lock_tool", PROJECT_ROOT / "tools" / "verify_dependency_lock.py"
    )
    assert spec and spec.loader
    tool = importlib.util.module_from_spec(spec)
    sys.modules["lock_tool"] = tool
    spec.loader.exec_module(tool)

    locks = [tool.parse_lock(PROJECT_ROOT / name) for name in tool.DEFAULT_LOCKS]
    for lock in locks:
        assert not lock.errors, (lock.path.name, lock.errors)
        assert lock.requirements
        for requirement in lock.requirements:
            assert requirement.hashes, requirement.name
            assert all(re.fullmatch(r"[0-9a-f]{64}", digest) for digest in requirement.hashes)
    assert sum(len(lock.requirements) for lock in locks) == 11


def test_a_package_without_hashes_fails_the_lock_check(tmp_path):
    """W4: a hash *count* is not coverage -- one package without hashes must fail."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "lock_tool_missing", PROJECT_ROOT / "tools" / "verify_dependency_lock.py"
    )
    tool = importlib.util.module_from_spec(spec)
    sys.modules["lock_tool_missing"] = tool
    spec.loader.exec_module(tool)

    lock = tmp_path / "requirements.lock.txt"
    lock.write_text(
        "alpha==1.0 \\\n    --hash=sha256:" + "a" * 64 + "\n"
        "beta==2.0\n",
        encoding="utf-8",
    )
    parsed = tool.parse_lock(lock)
    assert parsed.errors and "no --hash" in parsed.errors[0]
    assert tool.main(["--root", str(tmp_path), "--lock", "requirements.lock.txt"]) == 1


def test_an_unpinned_version_fails_the_lock_check(tmp_path):
    """A range or a bare name is not a pin."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "lock_tool_range", PROJECT_ROOT / "tools" / "verify_dependency_lock.py"
    )
    tool = importlib.util.module_from_spec(spec)
    sys.modules["lock_tool_range"] = tool
    spec.loader.exec_module(tool)

    lock = tmp_path / "requirements.lock.txt"
    lock.write_text("alpha>=1.0\n", encoding="utf-8")
    assert tool.parse_lock(lock).errors
    assert tool.main(["--root", str(tmp_path), "--lock", "requirements.lock.txt"]) == 1


def test_a_downloaded_artefact_must_match_a_pinned_hash(tmp_path):
    """The rule the audit's fetch helpers now follow: verify before unpacking."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "lock_tool_wheel", PROJECT_ROOT / "tools" / "verify_dependency_lock.py"
    )
    tool = importlib.util.module_from_spec(spec)
    sys.modules["lock_tool_wheel"] = tool
    spec.loader.exec_module(tool)

    payload = b"not a real wheel"
    digest = hashlib.sha256(payload).hexdigest()
    lock = tool.LockFile(path=Path("requirements.lock.txt"))
    lock.requirements.append(
        tool.Requirement(name="alpha", version="1.0", hashes=[digest], lineno=1)
    )

    good = tmp_path / "alpha-1.0-py3-none-any.whl"
    good.write_bytes(payload)
    ok, reason = tool.verify_wheel(good, [lock])
    assert ok, reason

    bad = tmp_path / "alpha-1.0-py3-none-any.whl"
    bad.write_bytes(payload + b"x")
    ok, reason = tool.verify_wheel(bad, [lock])
    assert not ok and "does not match any pinned hash" in reason

    stranger = tmp_path / "gamma-9.9-py3-none-any.whl"
    stranger.write_bytes(payload)
    ok, reason = tool.verify_wheel(stranger, [lock])
    assert not ok and "not pinned" in reason


def test_the_source_patch_reports_added_changed_and_removed_files(tmp_path):
    """The delivered patch has to be generated, not hand-written, and has to say what it covers.

    Also a guard on the delivered tree: the scratch root lives *beside* the checkout, so copying
    the tree (which the review harnesses do) cannot trip over run state.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "patch_tool", PROJECT_ROOT / "tools" / "make_source_patch.py"
    )
    tool = importlib.util.module_from_spec(spec)
    sys.modules["patch_tool"] = tool
    spec.loader.exec_module(tool)

    old = tmp_path / "old"
    new = tmp_path / "new"
    for root in (old, new):
        (root / "tls").mkdir(parents=True)
    (old / "tls" / "a.py").write_text("value = 1\n", encoding="utf-8")
    (new / "tls" / "a.py").write_text("value = 2\n", encoding="utf-8")
    (new / "tls" / "b.py").write_text("added = True\n", encoding="utf-8")
    (old / "tls" / "c.py").write_text("removed = True\n", encoding="utf-8")

    out = tmp_path / "patch.diff"
    assert tool.main([str(old), str(new), "--out", str(out)]) == 0
    text = out.read_text(encoding="utf-8")
    assert "files added: 1, removed: 1, changed: 1" in text
    assert "-value = 1" in text and "+value = 2" in text
    assert "+added = True" in text and "-removed = True" in text

    from conftest import SCRATCH_ROOT

    assert PROJECT_ROOT not in SCRATCH_ROOT.parents, (
        "the scratch root must stay outside the checkout: the review harnesses copy the tree"
    )
