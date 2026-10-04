"""Contract tests for :mod:`tls.key_schedule.hkdf` and :mod:`tls.handshake.transcript`.

Every HKDF primitive is checked against an implementation written out in this file
from RFC 5869, so a change inside ``hkdf.py`` cannot make the test agree with it by
construction. On top of that the tests pin the structural properties the hybrid
design rests on:

* ``encode_hybrid_secret`` is injective, so two different (ECDHE, KEM) pairs can
  never produce the same key-schedule input;
* one ``Z_hybrid`` seeds the whole schedule, so changing it changes every later
  secret;
* client and server traffic secrets -- and therefore their keys, IVs and Finished
  keys -- never coincide;
* ``traffic_keys`` returns the configured AEAD key/IV lengths.
"""

from __future__ import annotations

import hashlib
import hmac

import pytest

from tls.handshake.transcript import Transcript
from tls.key_schedule.hkdf import (
    KeySchedule,
    TrafficSecretPair,
    derive_secret,
    encode_hybrid_secret,
    hash_length,
    hkdf_expand,
    hkdf_expand_label,
    hkdf_extract,
)
from tls.wire import Reader

EMPTY_HASH = hashlib.sha256(b"").digest()


# --------------------------------------------------- independent HKDF reference


def reference_expand(prk: bytes, info: bytes, length: int, hash_name: str = "sha256") -> bytes:
    """HKDF-Expand written out block by block (RFC 5869 section 2.3).

    ``T(0) = ""``, ``T(i) = HMAC(PRK, T(i-1) || info || i)`` with a one-byte
    counter starting at 1, and the output is the concatenation of the blocks
    truncated to ``length``.
    """
    if length < 0:
        raise ValueError("length must not be negative")
    digest_size = hashlib.new(hash_name).digest_size
    blocks = (length + digest_size - 1) // digest_size
    output = b""
    previous = b""
    for counter in range(1, blocks + 1):
        previous = hmac.new(prk, previous + info + bytes([counter]), hash_name).digest()
        output += previous
    return output[:length]


def reference_expand_label(
    secret: bytes, label: str, context: bytes, length: int, hash_name: str = "sha256"
) -> bytes:
    """TLS 1.3 ``HKDF-Expand-Label`` built here from the RFC 8446 ``HkdfLabel`` layout."""
    full_label = b"tls13 " + label.encode("ascii")
    info = (
        length.to_bytes(2, "big")
        + bytes([len(full_label)])
        + full_label
        + bytes([len(context)])
        + context
    )
    return reference_expand(secret, info, length, hash_name)


# ------------------------------------------------------------------- HKDF-Extract


@pytest.mark.parametrize(("salt", "ikm"), [
    pytest.param(b"", b"", id="empty-both"),
    pytest.param(b"salt", b"ikm", id="short"),
    pytest.param(bytes(32), bytes(32), id="tls13-zero-salt"),
    pytest.param(b"\x00" * 32, b"\xff" * 64, id="full-width"),
])
def test_hkdf_extract_is_hmac_of_the_ikm_under_the_salt(salt, ikm):
    """``PRK = HMAC-Hash(salt, IKM)``, confirmed against the stdlib directly."""
    assert hkdf_extract(salt, ikm) == hmac.new(salt, ikm, "sha256").digest()


def test_hkdf_extract_length_follows_the_hash():
    """The PRK is one digest long, for both supported hashes."""
    assert len(hkdf_extract(b"salt", b"ikm")) == hash_length("sha256") == 32
    assert len(hkdf_extract(b"salt", b"ikm", "sha384")) == hash_length("sha384") == 48


# -------------------------------------------------------------------- HKDF-Expand


@pytest.mark.parametrize(("length", "blocks"), [
    pytest.param(0, 0, id="empty"),
    pytest.param(1, 1, id="one-byte"),
    pytest.param(31, 1, id="one-block-minus-one"),
    pytest.param(32, 1, id="exactly-one-block"),
    pytest.param(33, 2, id="two-blocks"),
    pytest.param(64, 2, id="exactly-two-blocks"),
    pytest.param(80, 3, id="three-blocks"),
    pytest.param(96, 3, id="exactly-three-blocks"),
])
def test_hkdf_expand_matches_a_block_by_block_reimplementation(length, blocks):
    """Expand output equals the RFC 5869 block chain for lengths needing 0..3 blocks."""
    prk = bytes(range(32))
    info = b"tls13 independent expand"
    expected = reference_expand(prk, info, length)
    assert hkdf_expand(prk, info, length) == expected
    assert len(expected) == length
    assert (length + 31) // 32 == blocks


def test_hkdf_expand_chains_blocks_with_the_counter_byte():
    """The three blocks are ``T1``, ``HMAC(PRK, T1 || info || 0x02)`` and so on."""
    prk, info = b"\x0b" * 32, b"info"
    t1 = hmac.new(prk, info + b"\x01", "sha256").digest()
    t2 = hmac.new(prk, t1 + info + b"\x02", "sha256").digest()
    t3 = hmac.new(prk, t2 + info + b"\x03", "sha256").digest()

    assert hkdf_expand(prk, info, 32) == t1
    assert hkdf_expand(prk, info, 20) == t1[:20]
    assert hkdf_expand(prk, info, 64) == t1 + t2
    assert hkdf_expand(prk, info, 96) == t1 + t2 + t3
    assert hkdf_expand(prk, info, 80) == (t1 + t2 + t3)[:80]
    # The counter byte is load bearing: block two is not a repeat of block one.
    assert t1 != t2 != t3


def test_hkdf_expand_supports_the_other_configured_hash():
    """A sha384 schedule expands with sha384 blocks, not sha256 ones."""
    prk, info = b"\x0c" * 48, b"sha384 info"
    assert hkdf_expand(prk, info, 100, "sha384") == reference_expand(prk, info, 100, "sha384")
    assert len(hkdf_expand(prk, info, 100, "sha384")) == 100


def test_hkdf_expand_refuses_more_than_the_counter_can_address():
    """``length`` above ``255 * HashLen`` raises rather than wrapping the counter."""
    with pytest.raises(ValueError):
        hkdf_expand(b"prk", b"info", 255 * 32 + 1)
    assert len(hkdf_expand(b"prk", b"info", 255 * 32)) == 255 * 32


# -------------------------------------------------------------- HKDF-Expand-Label


@pytest.mark.parametrize(("label", "context", "length"), [
    pytest.param("c ap traffic", b"\xab" * 32, 32, id="application-traffic"),
    pytest.param("key", b"", 16, id="aes128-key"),
    pytest.param("iv", b"", 12, id="aes128-iv"),
    pytest.param("finished", b"", 32, id="finished-key"),
    pytest.param("exporter", b"ctx", 48, id="exporter"),
])
def test_hkdf_expand_label_builds_the_rfc8446_info_struct(label, context, length):
    """``uint16 length || vec8("tls13 " + label) || vec8(context)``, recomputed here."""
    secret = bytes(range(32))
    assert hkdf_expand_label(secret, label, context, length) == reference_expand_label(
        secret, label, context, length
    )


def test_hkdf_expand_label_info_bytes_have_the_documented_layout():
    """The info string is readable back field by field, prefix included."""
    secret, label, context, length = b"s" * 32, "s hs traffic", b"\x01\x02\x03", 32
    full_label = b"tls13 s hs traffic"
    info = length.to_bytes(2, "big") + bytes([len(full_label)]) + full_label + bytes([len(context)]) + context

    assert hkdf_expand_label(secret, label, context, length) == hkdf_expand(secret, info, length)

    reader = Reader(info)
    assert reader.read_u16() == length
    assert reader.read_vec8() == full_label
    assert reader.read_vec8() == context
    reader.expect_end()
    assert len(full_label) == len(b"tls13 ") + len(label)
    assert full_label.startswith(b"tls13 ")


def test_derive_secret_hashes_to_one_digest_length():
    """``Derive-Secret`` uses the transcript hash as context and returns one digest."""
    secret = b"k" * 32
    transcript_hash = hashlib.sha256(b"ClientHello..ServerHello").digest()
    derived = derive_secret(secret, "derived", transcript_hash)
    assert derived == reference_expand_label(secret, "derived", transcript_hash, 32)
    assert len(derived) == 32


# ------------------------------------------------------------ hybrid secret input


def test_encode_hybrid_secret_is_unambiguous_for_the_classic_ambiguity():
    """Length prefixes make concatenation injective: (01 02, 03) != (01, 02 03)."""
    assert encode_hybrid_secret(b"\x01\x02", b"\x03") != encode_hybrid_secret(b"\x01", b"\x02\x03")


@pytest.mark.parametrize(("left", "right", "other_left", "other_right"), [
    pytest.param(b"\x01\x02", b"\x03", b"\x01", b"\x02\x03", id="split-moved"),
    pytest.param(b"", b"ab", b"a", b"b", id="empty-left"),
    pytest.param(b"ab", b"", b"a", b"b", id="empty-right"),
    pytest.param(b"\x00" * 32, b"\x00" * 32, b"\x00" * 64, b"", id="all-zero"),
])
def test_encode_hybrid_secret_separates_pairs_with_equal_total_length(
    left, right, other_left, other_right
):
    """No two distinct pairs share an encoding, even when the concatenations coincide."""
    assert left + right == other_left + other_right  # the ambiguity being ruled out
    assert encode_hybrid_secret(left, right) != encode_hybrid_secret(other_left, other_right)


def test_encode_hybrid_secret_prefixes_each_component_with_uint16():
    """The encoding is ``u16 |z_ecdh| || z_ecdh || u16 |ss_pq| || ss_pq``."""
    z_ecdh, ss_pq = b"\xaa" * 32, b"\xbb" * 32
    assert encode_hybrid_secret(z_ecdh, ss_pq) == (
        (32).to_bytes(2, "big") + z_ecdh + (32).to_bytes(2, "big") + ss_pq
    )
    assert encode_hybrid_secret(b"", b"") == b"\x00\x00\x00\x00"


# ----------------------------------------------------------------- the schedule


def test_full_schedule_is_seeded_by_z_hybrid_and_separates_the_directions():
    """Every stage of RFC 8446 section 7.1 derives as documented from one hybrid secret."""
    z_hybrid = bytes(range(32)) * 2
    transcript_hash = hashlib.sha256(b"ClientHello || ServerHello").digest()
    schedule = KeySchedule(hash_name="sha256", aead_key_length=16, aead_iv_length=12)

    early = schedule.derive_early_secret()
    assert early == hkdf_extract(bytes(32), bytes(32))  # a full handshake uses a zero PSK

    handshake = schedule.derive_handshake_secret(z_hybrid)
    assert handshake == hkdf_extract(derive_secret(early, "derived", EMPTY_HASH), z_hybrid)

    pair = schedule.derive_handshake_traffic(transcript_hash)
    assert isinstance(pair, TrafficSecretPair)
    assert pair.client == derive_secret(handshake, "c hs traffic", transcript_hash)
    assert pair.server == derive_secret(handshake, "s hs traffic", transcript_hash)
    assert pair.client != pair.server
    assert (schedule.client_handshake_traffic, schedule.server_handshake_traffic) == (
        pair.client,
        pair.server,
    )

    master = schedule.derive_master_secret()
    assert master == hkdf_extract(derive_secret(handshake, "derived", EMPTY_HASH), bytes(32))
    assert master not in (early, handshake)

    # RFC 8446 section 7.1: the application traffic and exporter secrets cover the
    # transcript through the *server* Finished, `res master` through the *client* Finished.
    # Two different hashes here, because they are two different transcript prefixes — an
    # audit of this repository found both being taken from the same, longer one.
    server_finished_hash = hashlib.sha256(b"ClientHello || .. || server Finished").digest()
    application = schedule.derive_application_traffic(server_finished_hash)
    assert application.client == derive_secret(master, "c ap traffic", server_finished_hash)
    assert application.server == derive_secret(master, "s ap traffic", server_finished_hash)
    assert application.client != application.server
    assert application.client != pair.client and application.server != pair.server
    assert schedule.exporter_master_secret == derive_secret(master, "exp master", server_finished_hash)
    assert schedule.resumption_master_secret is None, "res master needs the client Finished"

    client_finished_hash = hashlib.sha256(b"ClientHello || .. || client Finished").digest()
    assert client_finished_hash != server_finished_hash
    assert schedule.derive_resumption_master_secret(
        client_finished_hash
    ) == derive_secret(master, "res master", client_finished_hash)

    keys = {
        early,
        handshake,
        master,
        pair.client,
        pair.server,
        application.client,
        application.server,
        schedule.exporter_master_secret,
        schedule.resumption_master_secret,
    }
    assert len(keys) == 9  # no stage collides with another


def test_a_different_z_hybrid_changes_every_later_value():
    """Both branches of the key exchange reach the traffic secrets: swap Z, lose everything."""
    first = KeySchedule()
    second = KeySchedule()
    z_hybrid = b"\x11" * 64
    other_z = b"\x11" * 63 + b"\x12"
    assert z_hybrid != other_z

    assert first.derive_early_secret() == second.derive_early_secret()  # Z is not involved yet
    assert first.derive_handshake_secret(z_hybrid) != second.derive_handshake_secret(other_z)

    transcript_hash = hashlib.sha256(b"transcript").digest()
    assert first.derive_handshake_traffic(transcript_hash) != second.derive_handshake_traffic(transcript_hash)
    assert first.derive_master_secret() != second.derive_master_secret()
    application_hash = hashlib.sha256(b"full transcript").digest()
    assert first.derive_application_traffic(application_hash) != second.derive_application_traffic(
        application_hash
    )
    assert first.exporter_master_secret != second.exporter_master_secret


@pytest.mark.parametrize(("key_length", "iv_length"), [
    pytest.param(16, 12, id="aes-128-gcm"),
    pytest.param(32, 12, id="aes-256-gcm"),
])
def test_traffic_keys_use_the_configured_aead_lengths(key_length, iv_length):
    """``key``/``iv`` are expanded to the lengths the AEAD suite declares, and differ."""
    schedule = KeySchedule(aead_key_length=key_length, aead_iv_length=iv_length)
    schedule.derive_early_secret()
    schedule.derive_handshake_secret(b"z" * 64)
    pair = schedule.derive_handshake_traffic(hashlib.sha256(b"th").digest())

    key, iv = schedule.traffic_keys(pair.client)
    assert (len(key), len(iv)) == (key_length, iv_length)
    assert key == hkdf_expand_label(pair.client, "key", b"", key_length)
    assert iv == hkdf_expand_label(pair.client, "iv", b"", iv_length)

    server_key, server_iv = schedule.traffic_keys(pair.server)
    assert (len(server_key), len(server_iv)) == (key_length, iv_length)
    assert key != server_key and iv != server_iv


def test_compute_finished_binds_the_transcript_hash_and_the_direction():
    """``verify_data`` is the Finished-key HMAC over the transcript hash, per direction."""
    schedule = KeySchedule()
    schedule.derive_early_secret()
    schedule.derive_handshake_secret(b"z" * 64)
    pair = schedule.derive_handshake_traffic(hashlib.sha256(b"th").digest())
    transcript_hash = hashlib.sha256(b"through CertificateVerify").digest()

    client_finished = schedule.compute_finished(pair.client, transcript_hash)
    assert client_finished == hmac.new(
        schedule.finished_key(pair.client), transcript_hash, "sha256"
    ).digest()
    assert len(client_finished) == 32

    # A changed transcript hash changes the verify_data: this is the binding.
    other_hash = bytes([transcript_hash[0] ^ 0x01]) + transcript_hash[1:]
    assert schedule.compute_finished(pair.client, other_hash) != client_finished
    assert schedule.compute_finished(pair.client, EMPTY_HASH) != client_finished

    # The client and server Finished keys are different expansions of different secrets.
    assert schedule.finished_key(pair.client) != schedule.finished_key(pair.server)
    assert schedule.compute_finished(pair.server, transcript_hash) != client_finished
    assert schedule.finished_key(pair.client) == hkdf_expand_label(pair.client, "finished", b"", 32)


def test_schedule_stages_refuse_to_run_out_of_order():
    """Using a secret before its stage ran raises ``ValueError`` instead of using ``None``."""
    schedule = KeySchedule()
    with pytest.raises(ValueError):
        schedule.derive_handshake_traffic(hashlib.sha256(b"th").digest())
    with pytest.raises(ValueError):
        schedule.derive_master_secret()

    # derive_handshake_secret() may fill in the early secret itself.
    handshake = KeySchedule().derive_handshake_secret(b"z" * 64)
    assert len(handshake) == 32


def test_hash_bytes_matches_the_configured_hash():
    """``hash_bytes`` is the schedule's own hash, used for the pre-derivation salts."""
    assert KeySchedule("sha256").hash_bytes(b"abc") == hashlib.sha256(b"abc").digest()
    assert KeySchedule("sha384").hash_bytes(b"abc") == hashlib.sha384(b"abc").digest()
    with pytest.raises(ValueError):
        KeySchedule("sha3-256").hash_bytes(b"abc")


# ------------------------------------------------------------------- transcript


def test_transcript_hashes_the_concatenated_framing_bytes():
    """The transcript hash covers every byte added, headers included."""
    transcript = Transcript("sha256")
    assert transcript.hash() == hashlib.sha256(b"").digest()
    assert transcript.byte_count == 0 and len(transcript) == 0

    transcript.add(b"\x01\x00\x00\x03abc")  # a 7-byte framed message
    transcript.add(b"\x02\x00\x00\x00")  # a 4-byte framed message
    assert transcript.byte_count == len(transcript) == 11
    assert transcript.hash() == hashlib.sha256(b"\x01\x00\x00\x03abc\x02\x00\x00\x00").digest()


def test_transcript_copy_is_independent_of_the_original():
    """``copy`` hashes a prefix without disturbing the accumulated transcript."""
    transcript = Transcript()
    transcript.add(b"prefix")
    clone = transcript.copy()
    clone.add(b"suffix")

    assert clone.hash() == hashlib.sha256(b"prefixsuffix").digest()
    assert transcript.hash() == hashlib.sha256(b"prefix").digest()
    assert (transcript.byte_count, clone.byte_count) == (6, 12)


def test_transcript_hash_changes_with_every_added_byte():
    """One flipped transcript byte changes the hash: nothing can be stripped silently."""
    transcript = Transcript()
    transcript.add(b"CertificateVerify payload")
    original = transcript.hash()

    tampered = Transcript()
    tampered.add(b"CertificateVerify payloae")
    assert tampered.hash() != original
