"""Failure types shared by the handshake implementation."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Any, TypeVar


class HybridTLSError(Exception):
    """Base class for every failure this package raises."""


class DecodeError(HybridTLSError):
    """A byte string could not be parsed as the message it claims to be."""


class HandshakeError(HybridTLSError):
    """A handshake step failed.

    ``step`` names the check that failed so callers and tests can assert on the
    specific rejection rather than on a message string.
    """

    def __init__(self, step: str, reason: str) -> None:
        super().__init__(f"{step}: {reason}")
        self.step = step
        self.reason = reason


class BackendUnavailableError(HybridTLSError):
    """A requested cryptographic backend is not installed in this environment."""


_F = TypeVar("_F", bound=Callable[..., Any])


def named_errors(step: str) -> Callable[[_F], _F]:
    """Turn anything a peer can provoke into a :class:`HandshakeError` carrying ``step``.

    This package documents one error contract: a handshake that fails raises a
    ``HybridTLSError`` subclass. An independent audit showed seven classes of malformed input
    leaving that contract through ``KeyError``, ``ValueError``, ``TypeError`` and
    ``x509.ExtensionNotFound``, so a caller that catches what the documentation promises
    crashes instead of being told which step refused (their V-11…V-16).

    The individual sites are fixed; this is the **backstop**, applied to the methods that
    take peer input off the wire. It is deliberately not a substitute for those fixes: an
    error that only this decorator catches carries less information than one raised where the
    problem was found, and `tests/test_protocol_checks.py` asserts the specific steps.
    """

    def decorate(function: _F) -> _F:
        @functools.wraps(function)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return function(*args, **kwargs)
            except HybridTLSError:
                raise
            except Exception as error:  # noqa: BLE001 - this is the boundary
                raise HandshakeError(
                    step, f"unhandled {type(error).__name__}: {error}"
                ) from error

        return wrapper  # type: ignore[return-value]

    return decorate
