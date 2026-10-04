"""Lazy SLH-DSA-SM3 backend; C signs, independent Python can verify.

The constructor allocates no key, tree, native context or process pool.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from ..errors import BackendUnavailableError

PARAMETERS = {
    "slh-dsa-sm3-128s": (1, 0xFEA0, 7856),
    "slh-dsa-sm3-128f": (2, 0xFEA1, 17088),
    "slh-dsa-sm3-128-24": (3, 0xFEA2, 3856),
}
PROJECT_ROOT = Path(__file__).resolve().parents[3]


class SlhDsaSm3:
    post_quantum = True
    public_key_bytes = 32
    secret_key_bytes = 64

    def __init__(self, name="slh-dsa-sm3-128-24", *, library=None, threads=1,
                 force_python=False, backend=0):
        if name not in PARAMETERS:
            raise BackendUnavailableError(f"unknown SLH variant {name!r}")
        if not isinstance(threads, int) or not 1 <= threads <= 1024:
            raise ValueError("SLH thread allocation must be explicit and positive")
        self.name = name
        self.pid, self.scheme_id, self.signature_bytes = PARAMETERS[name]
        self.library = library
        self.threads, self.force_python, self.backend = threads, force_python, backend
        self.max_signatures = 1 << 24 if self.pid == 3 else None
        self._signing_contexts = {}

    @staticmethod
    def _modules():
        if str(PROJECT_ROOT) not in sys.path:
            sys.path.append(str(PROJECT_ROOT))

    def _native(self):
        self._modules()
        from tools.native import NativeSlhDsa
        path = self.library or os.environ.get("SLHDSA_SM3_LIB")
        path = path or PROJECT_ROOT / "build" / ("slhdsa_sm3.dll" if os.name == "nt" else "libslhdsa_sm3.so")
        try:
            return NativeSlhDsa(self.pid, threads=self.threads,
                                flags=self.backend | 0x100, library=path)
        except (OSError, AttributeError, RuntimeError) as error:
            raise BackendUnavailableError(f"SLH native backend unavailable: {error}") from error

    def keygen(self):
        native = self._native()
        try:
            public, secret = native.keygen()
        except Exception:
            native.close()
            raise
        self._signing_contexts[bytes(secret)] = native
        return secret, public

    def sign(self, secret_key: object, message: bytes) -> bytes:
        if not isinstance(secret_key, (bytes, bytearray)) or len(secret_key) != 64:
            raise ValueError("SLH secret key must contain 64 bytes")
        existing = self._signing_contexts.get(bytes(secret_key))
        if existing is not None:
            return existing.sign(bytes(message), bytes(secret_key), context=b"")
        with self._native() as native:
            return native.sign(bytes(message), bytes(secret_key), context=b"")

    def close(self):
        for native in self._signing_contexts.values():
            native.close()
        self._signing_contexts.clear()

    def __del__(self):
        if hasattr(self, "_signing_contexts"):
            self.close()

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        if not isinstance(public_key, (bytes, bytearray)) or not isinstance(signature, (bytes, bytearray)):
            return False
        if len(public_key) != 32 or len(signature) != self.signature_bytes:
            return False
        try:
            if not self.force_python:
                try:
                    with self._native() as native:
                        return bool(native.verify(bytes(message), bytes(signature), bytes(public_key), context=b""))
                except BackendUnavailableError:
                    pass
            self._modules()
            from reference import ReferenceSlhDsa
            with ReferenceSlhDsa(self.pid, workers=1) as model:
                return bool(model.verify(bytes(message), bytes(signature), bytes(public_key), context=b""))
        except (ValueError, TypeError, IndexError, RuntimeError, ImportError, OSError):
            return False
