"""KEM backends.

ML-KEM (FIPS 203) is the intended post-quantum branch; HQC is available as a
code-based alternative for size/performance comparison. ``ecdh-kem`` exists only
so the protocol spine can run where no post-quantum library is installed: it is
an ECIES-style construction over X25519 and reports ``post_quantum = False``, so
no report can mistake it for a quantum-resistant branch.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

from ..errors import BackendUnavailableError

__all__ = [
    "KEM_BACKENDS",
    "EcdhKemPlaceholder",
    "MlKem",
    "available_kems",
    "get_kem",
]

#: FIPS 203 parameter sets plus one code-based alternative, all reached through
#: ``pqcrypto``'s flat functions ``keygen``/``encaps``/``decaps``.
_PQCRYPTO_KEMS: dict[str, str] = {
    "ml-kem-512": "ml_kem_512",
    "ml-kem-768": "ml_kem_768",
    "ml-kem-1024": "ml_kem_1024",
    "hqc-128": "hqc_128",
    "hqc-192": "hqc_192",
    "hqc-256": "hqc_256",
}

#: Private-use scheme identifiers carried in the pq_key_share extension, so a client
#: and server that selected different KEMs fail on the first flight instead of
#: silently deriving different secrets.
_KEM_SCHEME_IDS: dict[str, int] = {
    "ml-kem-512": 0x0A01,
    "ml-kem-768": 0x0A02,
    "ml-kem-1024": 0x0A03,
    "hqc-128": 0x0A11,
    "hqc-192": 0x0A12,
    "hqc-256": 0x0A13,
    "ecdh-kem-placeholder": 0x0AFF,
}


class MlKem:
    """A KEM exposed by the installed ``pqcrypto`` distribution."""

    def __init__(self, name: str, module_name: str | None = None) -> None:
        module_name = module_name or _PQCRYPTO_KEMS.get(name)
        if module_name is None:
            raise BackendUnavailableError(f"unknown KEM {name!r}; available: {sorted(_PQCRYPTO_KEMS)}")
        try:
            self._module: Any = importlib.import_module(f"pqcrypto.kem.{module_name}")
        except ImportError as error:  # pragma: no cover - depends on the environment
            raise BackendUnavailableError(
                f"KEM {name!r} needs the pqcrypto distribution: {error}"
            ) from error
        self.name = name
        self.scheme_id = _KEM_SCHEME_IDS[name]
        self.post_quantum = True
        self.public_key_bytes = int(self._module.PUBLIC_KEY_SIZE)
        self.ciphertext_bytes = int(self._module.CIPHERTEXT_SIZE)
        self.shared_secret_bytes = int(self._module.SHARED_SECRET_SIZE)

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate a KEM key pair."""
        public_key, secret_key = self._module.keygen()
        return bytes(public_key), bytes(secret_key)

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate to ``public_key``."""
        ciphertext, shared_secret = self._module.encaps(public_key)
        return bytes(ciphertext), bytes(shared_secret)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Decapsulate ``ciphertext``."""
        return bytes(self._module.decaps(secret_key, ciphertext))


class EcdhKemPlaceholder:
    """An ECIES-style KEM over X25519 that is explicitly *not* post-quantum.

    ``ct = ephemeral_public_key`` and ``ss = HKDF(ephemeral_shared_secret ||
    ct || pk)``, so the interface and the failure modes match a real KEM while the
    security assumption does not. It exists to keep the handshake runnable and the
    byte accounting complete on machines without a post-quantum library.
    """

    name = "ecdh-kem-placeholder"
    scheme_id = _KEM_SCHEME_IDS["ecdh-kem-placeholder"]
    post_quantum = False
    public_key_bytes = 32
    ciphertext_bytes = 32
    shared_secret_bytes = 32

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate an X25519 key pair used as a static KEM key pair."""
        secret = x25519.X25519PrivateKey.generate()
        public = secret.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return public, secret.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )

    @staticmethod
    def _derive(shared: bytes, ciphertext: bytes, public_key: bytes) -> bytes:
        return hmac.new(
            b"hybrid-tls13 placeholder kem", shared + ciphertext + public_key, hashlib.sha256
        ).digest()

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsulate by sending a fresh ephemeral share."""
        ephemeral = x25519.X25519PrivateKey.generate()
        ciphertext = ephemeral.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        peer = x25519.X25519PublicKey.from_public_bytes(public_key)
        shared = ephemeral.exchange(peer)
        return ciphertext, self._derive(shared, ciphertext, public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        """Recover the shared secret using the static private key."""
        private = x25519.X25519PrivateKey.from_private_bytes(secret_key)
        peer = x25519.X25519PublicKey.from_public_bytes(ciphertext)
        shared = private.exchange(peer)
        public_key = private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        return self._derive(shared, ciphertext, public_key)


KEM_BACKENDS: dict[str, type] = {
    **{name: MlKem for name in _PQCRYPTO_KEMS},
    EcdhKemPlaceholder.name: EcdhKemPlaceholder,
}


def get_kem(name: str) -> Any:
    """Instantiate the KEM called ``name``."""
    if name not in KEM_BACKENDS:
        raise BackendUnavailableError(
            f"unknown KEM {name!r}; available: {sorted(KEM_BACKENDS)}"
        )
    factory = KEM_BACKENDS[name]
    return factory(name) if factory is MlKem else factory()


def available_kems() -> list[str]:
    """Return the KEM names whose backing module imports in this environment."""
    usable: list[str] = []
    for name in KEM_BACKENDS:
        try:
            get_kem(name)
        except BackendUnavailableError:
            continue
        usable.append(name)
    return sorted(usable)
