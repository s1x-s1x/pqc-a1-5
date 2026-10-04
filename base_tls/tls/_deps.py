"""Put the project-local dependency trees on ``sys.path``.

Dependencies are installed inside the project (``.deps``, ``.deps-falcon``) rather
than into site-packages, because the development sandbox denies writes outside the
workspace. Appending -- never prepending -- keeps the standard library and any
site-packages entries ahead of them, so a local copy can never shadow a real
module.
"""

from __future__ import annotations

import sys
from pathlib import Path

__all__ = ["PROJECT_ROOT", "ensure_dependency_paths"]

PROJECT_ROOT = Path(__file__).resolve().parents[1]

#: Search order matters only for the Falcon provider, which shares the ``pqcrypto``
#: distribution name and is therefore installed under ``pqcrypto_pqclean``.
_DEPENDENCY_DIRS = (PROJECT_ROOT / ".deps", PROJECT_ROOT / ".deps-falcon")


def ensure_dependency_paths() -> list[str]:
    """Append every existing dependency directory to ``sys.path``; return what was added."""
    added: list[str] = []
    for directory in _DEPENDENCY_DIRS:
        if not directory.is_dir():
            continue
        entry = str(directory)
        if entry not in sys.path:
            sys.path.append(entry)
            added.append(entry)
    return added
