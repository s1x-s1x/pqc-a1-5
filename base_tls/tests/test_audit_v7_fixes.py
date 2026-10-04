"""V7 findings: negative cases and working controls, independent of audit_v7."""
from dataclasses import replace
import sys

import pytest
from cryptography import x509

from tls.config import HybridTLSConfig
from tls.credentials import CertificateAuthority, ServerCredentials
from tls.errors import DecodeError, HandshakeError
from tls.handshake.client import HybridClient
from tls.handshake.server import HybridServer
from tls.handshake.messages import (
    ClientHello, Certificate, X509Chain, EXTENSION_KEY_SHARE,
    _decode_u16_list,
)
from tls.pq.wots_xmss import XmssSignatureBackend
from tls.wire import Reader, u16, vec8, vec16, vec24
from test_live_checks import plant, load_tool_module, run_tool


def roles(use_x509: bool = False):
    config = HybridTLSConfig(kem='ecdh-kem-placeholder', pq_signer='xmss',
                             xmss_height=1, x509=use_x509)
    authority = CertificateAuthority(config.classical())
    credentials = ServerCredentials(config, identity=b'server.example')
    cert = credentials.bind_to(authority)
    root = x509.load_der_x509_certificate(credentials.chain.root_der) if use_x509 else None
    client = HybridClient(config, authority, trusted_root=root, trusted_name='server.example')
    return client, HybridServer(config, credentials, cert)


@pytest.mark.parametrize('secret', [bytes(range(32)), bytes(range(16)), bytes(range(16,32)),
                                    bytes(range(8,24)), b'x' + bytes(range(32)) + b'y'])
def test_v7_01_containment_at_any_offset_is_rejected(secret):
    with pytest.raises(ValueError, match='independently'):
        XmssSignatureBackend(height=1).keygen_from_seed(secret, public_seed=bytes(range(32)))


def test_v7_01_independent_seeds_sign_and_verify():
    backend = XmssSignatureBackend(height=1)
    secret, public = backend.keygen_from_seed(bytes(range(32)), public_seed=bytes(reversed(range(32))))
    signature = backend.sign(secret, b'control')
    assert backend.verify(public, b'control', signature)
    assert not backend.verify(public, b'changed', signature)


@pytest.mark.parametrize('use_x509,entry', [(False, 0), (True, 0), (True, 1)])
def test_v7_02_unsolicited_extensions_abort_the_actual_flight(use_x509, entry):
    client, server = roles(use_x509)
    client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))

    def inject(name, frame):
        if name != 'Certificate':
            return frame
        if use_x509:
            chain = X509Chain.decode(frame[4:])
            extensions = [() for _ in chain.chain]
            extensions[entry] = ((0x7a7a, b'probe'),)
            return replace(chain, extensions=(), entry_extensions=tuple(extensions)).to_message()
        return replace(Certificate.decode(frame[4:]), extensions=((0x7a7a, b'probe'),)).to_message()

    flight = server.send_authenticated_flight(frame_filter=inject)
    with pytest.raises(HandshakeError, match='CertificateEntry'):
        client.receive_server_flight([record for _, record, _ in flight])


@pytest.mark.parametrize('use_x509', [False, True])
def test_v7_02_empty_entry_extensions_complete_handshake(use_x509):
    client, server = roles(use_x509)
    client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))
    client.receive_server_flight([record for _, record, _ in server.send_authenticated_flight()])
    server.receive_client_finished(client.send_client_finished())


def test_v7_02_x509_preserves_every_entry_and_rejects_malformed_later_entry():
    original = X509Chain((b'leaf', b'issuer'), entry_extensions=(((1, b'a'),), ((2, b'b'),)))
    decoded = X509Chain.decode(original.encode())
    assert decoded.entry_extensions == original.entry_extensions
    assert decoded.encode() == original.encode()
    legacy = X509Chain((b'leaf', b'issuer'), extensions=((1, b'a'),))
    assert X509Chain.decode(legacy.encode()).entry_extensions == (((1, b'a'),), ())
    malformed = vec8(b'') + vec24(vec24(b'leaf') + vec16(b'') + vec24(b'issuer') + vec16(b'\x00'))
    with pytest.raises(DecodeError):
        X509Chain.decode(malformed)


def mutate_key_share(body: bytes, mode: str) -> bytes:
    reader = Reader(body)
    reader.read_bytes(34)
    reader.read_vec8()
    reader.read_vec16()
    reader.read_vec8()
    prefix_len = len(body) - reader.remaining()
    extensions = Reader(reader.read_vec16())
    encoded = b''
    while not extensions.at_end():
        kind, value = extensions.read_u16(), extensions.read_vec16()
        if kind == EXTENSION_KEY_SHARE:
            share = Reader(value).read_vec16()
            value = vec16(share + share) if mode == 'second' else value + b'\x00'
        encoded += u16(kind) + vec16(value)
    return body[:prefix_len] + vec16(encoded)


@pytest.mark.parametrize('mode', ['second', 'trailing'])
def test_v7_03_extra_key_share_data_is_rejected(mode):
    client, _ = roles()
    hello = client.create_client_hello()[4:]
    with pytest.raises(DecodeError):
        ClientHello.decode(mutate_key_share(hello, mode))


def test_v7_03_single_share_remains_accepted():
    client, server = roles()
    client.receive_server_hello(server.receive_client_hello(client.create_client_hello()))
    assert client.server_hello is not None


def test_v7_04_variable_call_requires_reviewed_module_qualified_interface(tmp_path, monkeypatch):
    root = plant(tmp_path, {
        'a.py': 'class Only:\n    def validate_ready(self, value):\n        if not value: raise ValueError()\n',
        'driver.py': 'def run(receiver):\n    receiver.validate_ready(True)\n',
    })
    result = run_tool(root)
    assert result.returncode == 1
    assert 'variable-sole' in result.stdout and 'in run' in result.stdout
    module = load_tool_module()
    monkeypatch.setattr(module, 'INTERFACE_METHODS', {'tls/a.py::Only.validate_ready': 'driver.run configured receiver'})
    monkeypatch.setattr(sys, 'argv', ['audit', '--root', str(root)])
    assert module.main() == 0
    (root / 'tls/b.py').write_text((root / 'tls/a.py').read_text(), encoding='utf-8')
    assert module.main() == 1  # The same class name in another module cannot borrow it.


@pytest.mark.parametrize('attack', ['unused', 'wrong-line', 'wrong-module', 'wrong-mechanism', 'borrow', 'shadow', 'class-method'])
def test_v7_05_declaration_needs_exact_invocation_evidence(tmp_path, monkeypatch, attack):
    definition = 'def validate_probe(value):\n    if not value: raise ValueError()\n'
    driver = 'import tls.a as target\ndef run():\n    getattr(target, "validate_probe")(True)\n'
    root = plant(tmp_path, {'a.py': definition, 'driver.py': driver})
    evidence = ('tls/driver.py', 3, 'getattr-call')
    key = 'tls/a.py::validate_probe'
    if attack == 'unused':
        (root / 'tls/driver.py').write_text(driver.replace('(True)', ''), encoding='utf-8')
    elif attack == 'wrong-line':
        evidence = ('tls/driver.py', 2, 'getattr-call')
    elif attack == 'wrong-module':
        evidence = ('tls/other.py', 3, 'getattr-call')
    elif attack == 'wrong-mechanism':
        evidence = ('tls/driver.py', 3, 'mention')
    elif attack == 'borrow':
        (root / 'tls/b.py').write_text(definition, encoding='utf-8')
    elif attack == 'shadow':
        (root / 'tls/driver.py').write_text(driver.replace('run()', 'run(target)'), encoding='utf-8')
    elif attack == 'class-method':
        (root / 'tls/a.py').write_text('class Holder:\n    def validate_probe(self, value):\n        if not value: raise ValueError()\n', encoding='utf-8')
        key = 'tls/a.py::Holder.validate_probe'
    module = load_tool_module()
    monkeypatch.setattr(module, 'DISPATCH_SITES', {key: evidence})
    monkeypatch.setattr(sys, 'argv', ['audit', '--root', str(root)])
    assert module.main() == 1


@pytest.mark.parametrize('legacy', [False, True])
def test_v7_05_real_dispatch_with_valid_declaration_passes(tmp_path, monkeypatch, legacy):
    """The declaration is valid *and* its site is reachable (v9 tightened this).

    Under v8 this test passed without a declared entry: the tool validated the AST evidence and
    stopped. The fifth review's follow-up (their V8-01 / T1 / T2) showed what that leaves open,
    so v9 requires the declared site to be reachable from an entry. The tree's driver is
    declared as that entry here — which is what a real driver is — and the verdict is unchanged.
    """
    root = plant(tmp_path, {
        'a.py': 'def validate_probe(value):\n    if not value: raise ValueError()\n',
        'driver.py': 'import tls.a as target\ndef run():\n    getattr(target, "validate_probe")(True)\n',
    })
    module = load_tool_module()
    declaration = {'validate_probe': 'legacy real dispatcher'} if legacy else {
        'tls/a.py::validate_probe': ('tls/driver.py', 3, 'getattr-call')}
    monkeypatch.setattr(module, 'GETATTR_DISPATCHED' if legacy else 'DISPATCH_SITES', declaration)
    monkeypatch.setattr(
        sys, 'argv',
        ['audit', '--root', str(root), '--entry', 'tls/driver.py::run'],
    )
    assert module.main() == 0


@pytest.mark.parametrize('prefix', [None, 1, 2])
def test_info_u16_vectors_are_exact(prefix):
    wrap = {None: lambda value: value, 1: vec8, 2: vec16}[prefix]
    assert _decode_u16_list({10: wrap(b'\x00\x1d')}, 10, prefix=prefix) == (29,)
    with pytest.raises(DecodeError):
        _decode_u16_list({10: wrap(b'\x00\x1d\xff')}, 10, prefix=prefix)
    if prefix:
        with pytest.raises(DecodeError):
            _decode_u16_list({10: wrap(b'\x00\x1d') + b'\xff'}, 10, prefix=prefix)


def test_info_cipher_suite_is_validated_during_construction():
    with pytest.raises(ValueError, match='code point'):
        HybridTLSConfig(aead='aes-128-gcm', hash_name='sha384')
    assert HybridTLSConfig().cipher_suite_id == 0x1301
    assert HybridTLSConfig(aead='aes-256-gcm', hash_name='sha384').cipher_suite_id == 0x1302
