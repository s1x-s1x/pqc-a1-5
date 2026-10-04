"""Handshake configuration: which backend serves each slot of the hybrid scheme."""

from __future__ import annotations

from dataclasses import dataclass, field

from .classical.ecdh import ECDHE_GROUPS
from .classical.signature import ClassicalSigner, get_classical_signer
from .key_schedule.hkdf import HASH_NAMES
from .pq.backends import KemBackend, PqSigner
from .pq.kem import get_kem
from .pq.signature import XMSS_HEIGHT_DEFAULT, get_pq_signer
from .record.aead import AeadSuite, get_aead_suite

__all__ = ["HybridTLSConfig"]

#: TLS 1.3 cipher-suite code points by the parameters they actually name. Closed on
#: purpose: an unknown pair is refused rather than advertised under a name that lies about
#: its key length and hash.
_CIPHER_SUITE_BY_PARAMETERS: dict[tuple[str, str], int] = {
    ("aes-128-gcm", "sha256"): 0x1301,  # TLS_AES_128_GCM_SHA256
    ("aes-256-gcm", "sha384"): 0x1302,  # TLS_AES_256_GCM_SHA384
}


@dataclass(frozen=True)
class HybridTLSConfig:
    """One point in the configuration space the scheme defines.

    The classical and post-quantum halves are selected independently, which is the
    property under test: swapping ``pq_signer`` from Falcon to an XMSS tree must
    change nothing above the signature backend.
    """

    group: str = "x25519"
    classical_signer: str = "ecdsa-p256-sha256"
    kem: str = "ml-kem-768"
    pq_signer: str = "falcon-512"
    aead: str = "aes-128-gcm"
    hash_name: str = "sha256"
    xmss_height: int = XMSS_HEIGHT_DEFAULT
    #: When ``False`` the handshake runs as plain TLS 1.3: no ``pq_key_share``, no
    #: ``pq_ciphertext``, one signature in CertificateVerify, and the raw ECDHE secret
    #: as the key-schedule input. This is the baseline the hybrid profile is measured
    #: against, produced by the same code path rather than estimated from it.
    pq_enabled: bool = True
    #: When ``True`` the Certificate message carries a real X.509 chain (leaf plus
    #: intermediate, both ECDSA P-256) with the post-quantum public key in a private
    #: extension on the leaf, and the client validates the chain for real. When
    #: ``False`` the modelled single-signature certificate is used, which is what the
    #: symbolic models describe and what keeps the minimal profile small. Only the X.509
    #: profile produces byte counts comparable to a deployment.
    x509: bool = False
    #: Alternative CA signatures are checked on X.509 paths independently of
    #: the leaf's CertificateVerify scheme. Fixtures are generated offline.
    alt_chain: str | None = None
    require_alt_chain: bool = False
    alt_fixture: str | None = None
    extra: dict[str, object] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.pq_signer == "slh-dsa-sm3-128-24":
            raise ValueError("limited-use 128-24 is reserved for offline CA signing")
        if (self.alt_chain is not None or self.require_alt_chain or self.alt_fixture is not None) and not self.x509:
            raise ValueError("alternative CA signatures require x509=True")
        if self.alt_chain is not None:
            from .alt_chain import ALGORITHM_OIDS
            if self.alt_chain not in ALGORITHM_OIDS:
                raise ValueError(f"unknown alternative-chain algorithm {self.alt_chain!r}")
        if self.group not in ECDHE_GROUPS:
            raise ValueError(f"unknown group {self.group!r}; available: {sorted(ECDHE_GROUPS)}")
        if self.hash_name not in HASH_NAMES:
            raise ValueError(f"unknown hash {self.hash_name!r}; available: {sorted(HASH_NAMES)}")
        # Validate the advertised suite at construction, before any backend is used.
        _ = self.cipher_suite_id

    def classical(self) -> ClassicalSigner:
        """Instantiate the classical signature backend."""
        return get_classical_signer(self.classical_signer)

    def kem_backend(self) -> KemBackend:
        """Instantiate the KEM backend (the post-quantum branch of the key exchange)."""
        return get_kem(self.kem)  # type: ignore[return-value]

    def pq(self) -> PqSigner:
        """Instantiate the post-quantum signature backend."""
        options = dict(self.extra)
        if self.pq_signer == "xmss" or self.pq_signer.startswith("xmss-"):
            options.setdefault("height", self.xmss_height)
        return get_pq_signer(self.pq_signer, **options)  # type: ignore[return-value]

    def aead_suite(self) -> AeadSuite:
        """Instantiate the AEAD suite."""
        return get_aead_suite(self.aead)

    @property
    def cipher_suite_id(self) -> int:
        """The code point this profile advertises as its cipher suite.

        The mapping is explicit and closed, because a code point is a *claim about the record
        layer*: ``0x1301`` says AES-128-GCM with SHA-256, ``0x1302`` says AES-256-GCM with
        SHA-384. An earlier version returned ``0x1302`` for everything that was not the one
        supported pair, so ``aes-128-gcm`` with ``sha384`` announced
        "TLS_AES_256_GCM_SHA384" while encrypting with 128-bit keys and hashing with SHA-384.
        An independent audit reproduced that end to end (their J1/J3). It is the same class of
        defect as the round-4 transcript-stage bug: a value that agrees between the two halves
        of this harness and is wrong about the standard.
        """
        try:
            return _CIPHER_SUITE_BY_PARAMETERS[(self.aead, self.hash_name)]
        except KeyError:
            raise ValueError(
                f"no TLS 1.3 code point for aead={self.aead!r} with hash={self.hash_name!r}; "
                f"supported: {sorted(_CIPHER_SUITE_BY_PARAMETERS)}"
            ) from None

    def describe(self) -> dict[str, str]:
        """Return a flat, report-friendly description of the profile."""
        return {
            "group": self.group,
            "classical_signer": self.classical_signer,
            "kem": self.kem if self.pq_enabled else "(none)",
            "pq_signer": self.pq_signer if self.pq_enabled else "(none)",
            "aead": self.aead,
            "hash": self.hash_name,
            "pq_enabled": str(self.pq_enabled).lower(),
            "x509": str(self.x509).lower(),
            "alt_chain": self.alt_chain or "(none)",
            "require_alt_chain": str(self.require_alt_chain).lower(),
        }
