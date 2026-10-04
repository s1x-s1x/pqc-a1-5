"""Key-schedule vectors from RFC 8448, the IETF's own TLS 1.3 handshake trace.

A static security review asked for the exporter to be checked against standard test
vectors rather than against this implementation's own idea of the expression. This
module answers that with published vectors: every value below is transcribed from
RFC 8448 (*Example Handshake Traces for TLS 1.3*), and every one of them is checked
against this project's primitives.

What is covered: ``HKDF-Extract``, ``HKDF-Expand-Label``, ``Derive-Secret``, the
handshake and application traffic secrets, traffic keys and IVs, the Finished key, the
**exporter master secret**, and the resumption master secret.

What is not: RFC 8448 publishes no *exported keying material* (the output of the final
``HKDF-Expand-Label(..., "exporter", Hash(context), L)`` step) anywhere in its 68 pages,
so the last Expand step has no vector to check it against. It is covered instead by
``tests/test_security_fixes.py::test_exporter_matches_the_rfc_expression``, which
compares against an independent reimplementation of the RFC expression, and by the
vectors here, which pin every primitive that expression is built from. That gap is
stated rather than hidden.

Provenance of each vector is given in the section label. The transcribing is
self-checking: HKDF is deterministic, so a mistyped input byte would fail the comparison
against the published output rather than pass quietly.
"""

from __future__ import annotations

import pytest

from tls.key_schedule.hkdf import (
    KeySchedule,
    derive_secret,
    hkdf_expand_label,
    hkdf_extract,
)

# --------------------------------------------------------------------------- section 3
# RFC 8448 section 3, "Simple 1-RTT Handshake", TLS_AES_128_GCM_SHA256.

#: ``{server} extract secret "early"``: HKDF-Extract(salt=0, IKM=32 zero octets).
SECTION3_EARLY_SECRET = bytes.fromhex(
    "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"
)
SECTION3_EARLY_SECRET_IKM = bytes(32)

#: ``derive secret for handshake "tls13 derived"``.
SECTION3_DERIVED_FOR_HANDSHAKE = bytes.fromhex(
    "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"
)

#: ``extract secret "handshake"``: the IKM is the ECDHE shared secret of the trace.
SECTION3_ECDHE_SHARED_SECRET = bytes.fromhex(
    "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
)
SECTION3_HANDSHAKE_SECRET = bytes.fromhex(
    "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"
)

#: ``derive secret "tls13 c hs traffic"`` / ``"tls13 s hs traffic"``, both over the
#: ClientHello..ServerHello transcript of the trace.
SECTION3_CH_SH_HASH = bytes.fromhex(
    "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
)
SECTION3_CLIENT_HS_TRAFFIC = bytes.fromhex(
    "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"
)
SECTION3_SERVER_HS_TRAFFIC = bytes.fromhex(
    "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"
)
SECTION3_SERVER_HS_KEY = bytes.fromhex("3fce516009c21727d0f2e4e86ee403bc")
SECTION3_SERVER_HS_IV = bytes.fromhex("5d313eb2671276ee13000b30")
SECTION3_SERVER_HS_FINISHED_KEY = bytes.fromhex(
    "008d3b66f816ea559f96b537e885c31fc068bf492c652f01f288a1d8cdc19fc8"
)

#: ``derive secret for master "tls13 derived"`` and ``extract secret "master"``.
SECTION3_DERIVED_FOR_MASTER = bytes.fromhex(
    "43de77e0c77713859a944db9db2590b53190a65b3ee2e4f12dd7a0bb7ce254b4"
)
SECTION3_MASTER_SECRET = bytes.fromhex(
    "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"
)

#: ``derive secret "tls13 c ap traffic"`` over the full handshake transcript.
SECTION3_APPLICATION_HASH = bytes.fromhex(
    "9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"
)
SECTION3_CLIENT_AP_TRAFFIC = bytes.fromhex(
    "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"
)

# --------------------------------------------------------------------------- section 5
# RFC 8448 section 5, "HelloRetryRequest". These values are taken from that section,
# where the transcript differs from section 3; each vector carries its own inputs, so
# which handshake it came from does not affect what it checks.

#: ``derive secret "tls13 exp master"`` -- the exporter master secret.
SECTION5_MASTER_SECRET = bytes.fromhex(
    "1131545d0baf79ddce9b87f06945781a57dd18ef378dcd2060f8f9a569027ed8"
)
SECTION5_APPLICATION_HASH = bytes.fromhex(
    "50f63cbf36b0dd049e7a0ba27d6455745ea2aaac54bb167f9950b2b7ce9509da"
)
SECTION5_EXPORTER_MASTER_SECRET = bytes.fromhex(
    "7c06d3ae106a3a374ace4837b3985cac67780a6e2c5c04b58319d584df09d223"
)

#: ``derive secret "tls13 c ap traffic"`` and the client's application write keys.
SECTION5_CLIENT_AP_TRAFFIC = bytes.fromhex(
    "75ecf4b972525aa0dcd057c9944d4cd5d82671d8843141d7dc2a4ff15a21dc51"
)
SECTION5_CLIENT_AP_KEY = bytes.fromhex("a7eb2a0525eb4331d58fcbf9f7ca2e9c")
SECTION5_CLIENT_AP_IV = bytes.fromhex("86e8be227c1bd2b3e39cb444")

#: ``derive secret "tls13 res master"`` over the transcript through the client Finished.
SECTION5_RESUMPTION_HASH = bytes.fromhex(
    "0e8b349158b855fdcd0c11dbbc4e83e43caa6e483c6c65df53151888e50165f4"
)
SECTION5_RESUMPTION_MASTER_SECRET = bytes.fromhex(
    "09170c6d472721566f9cf99b08699daff561ec8fb22d5a32c3f94ce009b69975"
)

EMPTY_HASH = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


@pytest.fixture(scope="module")
def schedule() -> KeySchedule:
    """A default schedule: SHA-256 and AES-128-GCM, as RFC 8448's trace uses."""
    return KeySchedule(hash_name="sha256", aead_key_length=16, aead_iv_length=12)


def test_hkdf_extract_matches_the_trace(schedule: KeySchedule) -> None:
    """The early secret, and the extraction that produces the handshake secret."""
    assert schedule.hash_bytes(b"") == EMPTY_HASH
    assert hkdf_extract(bytes(32), SECTION3_EARLY_SECRET_IKM) == SECTION3_EARLY_SECRET
    assert (
        hkdf_extract(SECTION3_DERIVED_FOR_HANDSHAKE, SECTION3_ECDHE_SHARED_SECRET)
        == SECTION3_HANDSHAKE_SECRET
    )
    assert hkdf_extract(SECTION3_DERIVED_FOR_MASTER, bytes(32)) == SECTION3_MASTER_SECRET


def test_hkdf_expand_label_matches_the_trace() -> None:
    """The two ``derived`` expansions, which pin the HkdfLabel byte layout."""
    assert (
        hkdf_expand_label(SECTION3_EARLY_SECRET, "derived", EMPTY_HASH, 32)
        == SECTION3_DERIVED_FOR_HANDSHAKE
    )
    assert (
        hkdf_expand_label(SECTION3_HANDSHAKE_SECRET, "derived", EMPTY_HASH, 32)
        == SECTION3_DERIVED_FOR_MASTER
    )


def test_derive_secret_matches_the_trace() -> None:
    """Every ``Derive-Secret`` the trace publishes an input and output for."""
    assert (
        derive_secret(SECTION3_HANDSHAKE_SECRET, "c hs traffic", SECTION3_CH_SH_HASH)
        == SECTION3_CLIENT_HS_TRAFFIC
    )
    assert (
        derive_secret(SECTION3_HANDSHAKE_SECRET, "s hs traffic", SECTION3_CH_SH_HASH)
        == SECTION3_SERVER_HS_TRAFFIC
    )
    assert (
        derive_secret(SECTION3_MASTER_SECRET, "c ap traffic", SECTION3_APPLICATION_HASH)
        == SECTION3_CLIENT_AP_TRAFFIC
    )
    assert (
        derive_secret(SECTION5_MASTER_SECRET, "c ap traffic", SECTION5_APPLICATION_HASH)
        == SECTION5_CLIENT_AP_TRAFFIC
    )


def test_exporter_master_secret_matches_the_trace() -> None:
    """The vector the static review asked for, at the level the RFC publishes it.

    ``exporter_master_secret = Derive-Secret(Master Secret, "exp master",
    ClientHello...client Finished)`` -- this is the secret the exporter is built from,
    and the trace's published value is reproduced here byte for byte.
    """
    assert (
        derive_secret(
            SECTION5_MASTER_SECRET, "exp master", SECTION5_APPLICATION_HASH
        )
        == SECTION5_EXPORTER_MASTER_SECRET
    )


def test_resumption_master_secret_matches_the_trace() -> None:
    """The neighbouring derivation, checked so the exporter's label is not a special case."""
    assert (
        derive_secret(SECTION5_MASTER_SECRET, "res master", SECTION5_RESUMPTION_HASH)
        == SECTION5_RESUMPTION_MASTER_SECRET
    )


def test_traffic_keys_match_the_trace(schedule: KeySchedule) -> None:
    """``key`` and ``iv`` expansions for both directions the trace publishes."""
    key, iv = schedule.traffic_keys(SECTION3_SERVER_HS_TRAFFIC)
    assert key == SECTION3_SERVER_HS_KEY
    assert iv == SECTION3_SERVER_HS_IV

    key, iv = schedule.traffic_keys(SECTION5_CLIENT_AP_TRAFFIC)
    assert key == SECTION5_CLIENT_AP_KEY
    assert iv == SECTION5_CLIENT_AP_IV


def test_finished_key_matches_the_trace(schedule: KeySchedule) -> None:
    """The ``finished`` expansion, which shares the HKDF-Expand-Label path."""
    assert (
        schedule.finished_key(SECTION3_SERVER_HS_TRAFFIC)
        == SECTION3_SERVER_HS_FINISHED_KEY
    )
