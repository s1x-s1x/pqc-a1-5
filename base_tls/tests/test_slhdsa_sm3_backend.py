"""Lazy adapter contracts; real 128-24 signatures are verified from fixtures."""
import os
from pathlib import Path

import pytest

from tls.config import HybridTLSConfig
from tls.credentials import ServerCredentials
from tls.errors import BackendUnavailableError
from tls.pq.slhdsa_sm3 import PARAMETERS, SlhDsaSm3


def test_constructor_is_lightweight(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("constructor called the native loader")
    monkeypatch.setattr(SlhDsaSm3, "_native", forbidden)
    signer = SlhDsaSm3()
    assert signer._signing_contexts == {}
    assert (signer.public_key_bytes, signer.secret_key_bytes, signer.signature_bytes) == (32, 64, 3856)
    assert signer.max_signatures == 1 << 24


@pytest.mark.parametrize("name", PARAMETERS)
def test_reject_lengths_before_any_native_call(name, monkeypatch):
    signer = SlhDsaSm3(name)
    monkeypatch.setattr(signer, "_native", lambda: pytest.fail("native loader reached"))
    assert not signer.verify(b"x"*31, b"message", b"x"*signer.signature_bytes)
    assert not signer.verify(b"x"*32, b"message", b"x"*(signer.signature_bytes-1))
    assert not signer.verify(None, b"message", b"x"*signer.signature_bytes)
    assert not signer.verify(b"x"*32, b"message", None)
    with pytest.raises(ValueError, match="64 bytes"):
        signer.sign(b"x"*63, b"message")


def test_missing_native_library_has_explicit_signing_error(tmp_path):
    signer = SlhDsaSm3(library=tmp_path/"missing-library")
    with pytest.raises(BackendUnavailableError):
        signer.sign(b"x"*64, b"message")


def test_12824_reserved_for_offline_ca_in_config_and_injected_credentials():
    with pytest.raises(ValueError, match="offline CA"):
        HybridTLSConfig(pq_signer="slh-dsa-sm3-128-24")
    with pytest.raises(ValueError, match="offline CA"):
        ServerCredentials(HybridTLSConfig(pq_signer="ml-dsa-44"), pq_signer=SlhDsaSm3())


@pytest.mark.parametrize("name", ["slh-dsa-sm3-128-24", "slh-dsa-sm3-128s"])
@pytest.mark.parametrize("python", [False, True], ids=["native", "independent-python"])
def test_real_preissued_slh_chain(name, python):
    """The normal suite never regenerates limited-budget CA signatures."""
    fixture_root = os.environ.get("A15_ALT_FIXTURES")
    if not fixture_root:
        pytest.skip("set A15_ALT_FIXTURES to generated real offline CA bundles")
    from cryptography import x509
    from tls.alt_chain import verify_alt_chain
    from tls.alt_fixtures import load_fixture
    from tls.pq.signature import get_pq_signer
    import json
    directory = Path(fixture_root)/name
    metadata = json.loads((directory/"fixture.json").read_text())
    pq_signer = get_pq_signer(metadata["handshake_signer"])
    chain, _, _, _ = load_fixture(directory, pq_signer=pq_signer, expected_algorithm=name)
    result = verify_alt_chain(chain.chain_der, x509.load_der_x509_certificate(chain.root_der),
                              "server.example", require_alt_chain=True,
                              expected_algorithm=name, force_python=python)
    assert result.checked_edges == 2 and result.complete
