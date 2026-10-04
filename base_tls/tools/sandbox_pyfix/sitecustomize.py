"""Make directory creation compatible with the DSH capability-SID file sandbox.

On Windows, ``os.mkdir(path, 0o700)`` makes CPython write a protected DACL that
grants access to the process owner only. The DSH sandbox authorizes file effects
through the capability SID it inherited from the workspace root
(``S-1-4-...:(OI)(CI)(W,D,DC)``), which such a DACL omits. The directory then
becomes untraversable: listing it fails, and every write inside it raises
``PermissionError: [Errno 13]``.

``tempfile.mkdtemp`` creates its directories with mode ``0o700``, so pip, pytest,
and any library that stages files in a temp tree fail inside the sandbox. Passing
the default mode instead lets the new directory inherit the workspace ACEs, which
leaves it fully usable.

Importing this module (as ``sitecustomize``) patches ``os.mkdir`` process-wide, so
``os.makedirs``, ``pathlib.Path.mkdir``, and ``tempfile`` all pick it up.

When the patch applies — it is deliberately narrow
--------------------------------------------------

The patch *widens* directory permissions, so it stays off unless these hold:

1. **The platform is Windows** (``os.name == "nt"``). The DACL behaviour it works
   around does not exist elsewhere, so on any other platform this module does
   nothing at all -- not even when the switch below asks for it.
2. **A DSH sandbox is present** -- ``DSH_SESSION_ID``, or any ``DSH_SANDBOX*``
   variable -- unless the switch below says otherwise. On a normal machine the
   patch is inert, which is what lets this directory sit on ``PYTHONPATH`` without
   changing anything.
3. **It is not switched off explicitly.** ``DSH_SANDBOX_PYFIX=0`` (also ``false``,
   ``no``, ``off``) disables it even inside the sandbox; ``DSH_SANDBOX_PYFIX=1``
   (also ``true``, ``yes``, ``on``) forces it on **on Windows**, which is the
   documented way to opt in where the auto-detection does not fire.

An earlier version patched unconditionally, and a static security review was right
that it must not. A later audit asked for the platform limit and an explicit switch,
which is rules 1 and 3; a red-team pass then found that the switch was consulted
*before* the platform check (TB-1), so "explicitly enabled" widened permissions on
Unix too. Rule 1 is now unconditional and the tests check all three combinations.
"""

from __future__ import annotations

import os

_ORIGINAL_MKDIR = os.mkdir

_TRUTHY = frozenset({"1", "true", "yes", "on"})
_FALSY = frozenset({"0", "false", "no", "off"})


def _mkdir_with_inheritable_dacl(
    path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
    mode: int = 0o777,
    *args: object,
    **kwargs: object,
) -> None:
    """Create ``path``, ignoring any caller-supplied restrictive ``mode``."""
    _ORIGINAL_MKDIR(path, 0o777, *args, **kwargs)  # type: ignore[arg-type]


def _patch_is_wanted() -> bool:
    """Decide whether this process should carry the widened ``os.mkdir``.

    The platform is checked **first**, before the explicit switch: this module exists for one
    Windows DACL behaviour, and "explicitly enabled" must not widen directory permissions on a
    platform where the workaround has no meaning. A red-team review of the verification
    environment (their TB-1) found the old order had the switch win on Linux and macOS, which
    contradicted the file's own "Windows only" summary; the switch now only decides whether an
    *eligible* process patches.
    """
    if os.name != "nt":
        return False
    switch = os.environ.get("DSH_SANDBOX_PYFIX", "").strip().lower()
    if switch in _FALSY:
        return False
    if switch in _TRUTHY:
        return True
    return bool(os.environ.get("DSH_SESSION_ID")) or any(
        name.startswith("DSH_SANDBOX") for name in os.environ
    )


if _patch_is_wanted():
    os.mkdir = _mkdir_with_inheritable_dacl  # type: ignore[assignment]
