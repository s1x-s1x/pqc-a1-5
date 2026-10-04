"""Signature backends for the post-quantum half of CertificateVerify.

Three families are available, which is what makes the hybrid design interesting to
measure: a lattice scheme (Falcon), a module-lattice scheme with larger keys
(ML-DSA), and a stateless-looking hash-based scheme whose one-time signatures are
organized under a Merkle tree (WOTS+/XMSS). All three sign the same CertificateVerify
input, so they are interchangeable behind :class:`~tls.pq.backends.PqSigner`.
"""

from __future__ import annotations

import importlib
from typing import Any

from ..errors import BackendUnavailableError
from .slhdsa_sm3 import SlhDsaSm3, PARAMETERS as _SLH_PARAMETERS

__all__ = [
    "Falcon",
    "MlDsa",
    "SlhDsaSm3",
    "XMSS_HEIGHT_DEFAULT",
    "Xmss",
    "available_pq_signers",
    "get_pq_signer",
]

try:  # pragma: no cover - the exception type exists in every pqcrypto release so far
    from pqcrypto import InvalidSignatureError as _InvalidSignatureError
except ImportError:  # pragma: no cover - fall back to a type that never matches
    _InvalidSignatureError = type("InvalidSignatureError", (Exception,), {})

#: Taller trees cost key-generation time and shrink nothing on the wire.
XMSS_HEIGHT_DEFAULT = 10

#: Private-use scheme identifiers. The hybrid CertificateVerify payload carries its
#: own scheme fields, so these values only need to be distinct within this
#: implementation.
_SCHEME_IDS = {
    "ml-dsa-44": 0x0904,
    "ml-dsa-65": 0x0905,
    "ml-dsa-87": 0x0906,
    "falcon-512": 0x0F51,
    "falcon-1024": 0x0F52,
    "falcon-padded-512": 0x0F53,
    "falcon-padded-1024": 0x0F54,
}

_ML_DSA_MODULES = {
    "ml-dsa-44": "ml_dsa_44",
    "ml-dsa-65": "ml_dsa_65",
    "ml-dsa-87": "ml_dsa_87",
}

_FALCON_MODULES = {
    "falcon-512": "falcon_512",
    "falcon-1024": "falcon_1024",
    "falcon-padded-512": "falcon_padded_512",
    "falcon-padded-1024": "falcon_padded_1024",
}


class MlDsa:
    """ML-DSA (FIPS 204) through the installed ``pqcrypto`` distribution.

    ``pqcrypto`` reports a failed verification by raising, so this wrapper converts
    that into the boolean the protocol expects.
    """

    def __init__(self, name: str) -> None:
        module_name = _ML_DSA_MODULES.get(name)
        if module_name is None:
            raise BackendUnavailableError(f"unknown ML-DSA variant {name!r}")
        try:
            self._module: Any = importlib.import_module(f"pqcrypto.sign.{module_name}")
        except ImportError as error:  # pragma: no cover - depends on the environment
            raise BackendUnavailableError(f"{name} needs the pqcrypto distribution: {error}") from error
        self.name = name
        self.scheme_id = _SCHEME_IDS[name]
        self.post_quantum = True
        self.public_key_bytes = int(self._module.PUBLIC_KEY_SIZE)
        self.signature_bytes = int(self._module.SIGNATURE_SIZE)

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate an ML-DSA key pair."""
        public_key, secret_key = self._module.keygen()
        return bytes(secret_key), bytes(public_key)

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Sign ``message`` with ML-DSA."""
        return bytes(self._module.sign(secret_key, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an ML-DSA signature."""
        try:
            self._module.verify(public_key, message, signature)
        except (_InvalidSignatureError, ValueError):
            return False
        return True


class Falcon:
    """Falcon through the separately installed PQClean provider.

    The provider is a second distribution of the ``pqcrypto`` package name, so it
    is vendored under ``pqcrypto_pqclean`` and reached by appending its directory to
    ``sys.path``; see :mod:`tls.pq.providers`.
    """

    def __init__(self, name: str) -> None:
        module_name = _FALCON_MODULES.get(name)
        if module_name is None:
            raise BackendUnavailableError(f"unknown Falcon variant {name!r}")
        from .providers import use_falcon_provider  # noqa: PLC0415 - optional dependency

        try:
            use_falcon_provider()
            self._module: Any = importlib.import_module(f"pqcrypto_pqclean.sign.{module_name}")
        except ImportError as error:
            raise BackendUnavailableError(
                f"{name} needs the Falcon provider (tools\\install_falcon_provider.ps1): {error}"
            ) from error
        self.name = name
        self.scheme_id = _SCHEME_IDS[name]
        self.post_quantum = True
        self.public_key_bytes = int(self._module.PUBLIC_KEY_SIZE)
        #: Falcon signatures are variable-length; this is the encoding maximum.
        self.signature_bytes = int(self._module.SIGNATURE_SIZE)

    def keygen(self) -> tuple[bytes, bytes]:
        """Generate a Falcon key pair."""
        public_key, secret_key = self._module.generate_keypair()
        return bytes(secret_key), bytes(public_key)

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Sign ``message`` with Falcon."""
        return bytes(self._module.sign(secret_key, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a Falcon signature."""
        try:
            return bool(self._module.verify(public_key, message, signature))
        except (ValueError, TypeError):
            return False


class Xmss:
    """WOTS+ one-time signatures under a Merkle tree, implemented in this package.

    The secret key is stateful: every signature spends one leaf, and exhausting the
    tree raises. That statefulness is a protocol-level property, not an
    implementation detail, so it is surfaced here instead of hidden.
    """

    def __init__(
        self,
        name: str | None = None,
        height: int = XMSS_HEIGHT_DEFAULT,
        n: int = 32,
        w: int = 16,
        hash_name: str = "sha256",
    ) -> None:
        from .wots_xmss import XmssSignatureBackend  # noqa: PLC0415 - heavy import kept lazy

        self._impl = XmssSignatureBackend(height=height, n=n, w=w, hash_name=hash_name)
        self.name = name or f"xmss-{hash_name}-h{height}-w{w}"
        # U-03 v2: fresh public seed + addressed/masked chains. Fail closed
        # across versions instead of accepting the old 0x0E00 + height scheme.
        self.scheme_id = 0xFE00 + height
        self.post_quantum = True
        self.public_key_bytes = int(self._impl.public_key_bytes)
        self.signature_bytes = int(self._impl.signature_bytes)
        self.height = height
        self.max_signatures = int(self._impl.max_signatures)

    def keygen(self) -> tuple[object, bytes]:
        """Generate a tree; this hashes every leaf and is the expensive step."""
        secret_key, public_key = self._impl.keygen()
        return secret_key, bytes(public_key)

    def sign(self, secret_key: object, message: bytes) -> bytes:
        """Spend the next leaf on ``message``."""
        return bytes(self._impl.sign(secret_key, message))

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify by recomputing the root from the leaf and its authentication path."""
        try:
            return bool(self._impl.verify(public_key, message, signature))
        except (ValueError, IndexError):
            return False


def get_pq_signer(name: str, **options: object) -> Any:
    """Instantiate the post-quantum signer called ``name``.

    ``options`` are forwarded to :class:`Xmss` (``height``, ``n``, ``w``) and are
    rejected for the fixed-parameter schemes.
    """
    if name in _ML_DSA_MODULES:
        return MlDsa(name)
    if name in _FALCON_MODULES:
        return Falcon(name)
    if name in _SLH_PARAMETERS:
        return SlhDsaSm3(name, **options)
    if name == "xmss" or name.startswith("xmss-"):
        return Xmss(height=int(options.pop("height", XMSS_HEIGHT_DEFAULT)), **options)  # type: ignore[arg-type]
    raise BackendUnavailableError(
        f"unknown post-quantum signer {name!r}; available: {sorted(available_pq_signers())}"
    )


def available_pq_signers() -> dict[str, str]:
    """Map every advertised signer to ``"ok"`` or the reason it cannot be built."""
    names = ["xmss", *_ML_DSA_MODULES, *_FALCON_MODULES, *_SLH_PARAMETERS]
    report: dict[str, str] = {}
    for name in names:
        try:
            signer = get_pq_signer(name)
        except BackendUnavailableError as error:
            report[name] = str(error)
        except Exception as error:  # noqa: BLE001 - a broken provider must not hide the others
            report[name] = f"{type(error).__name__}: {error}"
        else:
            report[name] = "ok"
            del signer
    return report
