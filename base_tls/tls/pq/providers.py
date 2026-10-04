"""Locate the dependency trees installed beside this checkout and expose them on ``sys.path``.

Dependencies live inside the project (``.deps`` for the main set, ``.deps-falcon``
for the Falcon provider) because the DSH file sandbox denies writes outside the
workspace, which rules out the global site-packages. The Falcon provider is a
second distribution of the same top-level package name, so it is installed under
the renamed top-level package ``pqcrypto_pqclean``; see
``tools/install_falcon_provider.ps1``.
"""

from __future__ import annotations

import sys
from pathlib import Path

__all__ = ["DEPS_DIR", "FALCON_DEPS_DIR", "PROJECT_ROOT", "falcon_provider_dir", "use_falcon_provider"]

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEPS_DIR = PROJECT_ROOT / ".deps"
FALCON_DEPS_DIR = PROJECT_ROOT / ".deps-falcon"

_FALCON_PACKAGE = "pqcrypto_pqclean"


def falcon_provider_dir() -> Path | None:
    """Return the directory holding the renamed Falcon provider, or ``None``."""
    candidate = FALCON_DEPS_DIR / _FALCON_PACKAGE
    return FALCON_DEPS_DIR if candidate.is_dir() else None


def use_falcon_provider() -> Path:
    """Make the Falcon provider importable and return its directory.

    The directory is appended rather than prepended: the main ``.deps`` tree keeps
    priority for ``pqcrypto``, so importing the provider cannot shadow the ML-KEM
    and ML-DSA modules the rest of the handshake depends on.
    """
    provider = falcon_provider_dir()
    if provider is None:
        raise ImportError(
            "Falcon provider is not installed; run tools\\install_falcon_provider.ps1 "
            f"(expected {FALCON_DEPS_DIR / _FALCON_PACKAGE})"
        )
    entry = str(provider)
    if entry not in sys.path:
        sys.path.append(entry)
    return provider
