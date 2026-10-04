"""Shared fixtures for the hybrid TLS 1.3 test suite.

The module does two jobs:

* put the project root on ``sys.path`` so the suite runs from any working
  directory (every test module imports ``tls.*``);
* publish the small set of fast :class:`~tls.config.HybridTLSConfig` profiles the
  handshake tests reuse through the ``fast_profiles`` fixture.

Each profile completes a whole handshake in milliseconds, which is what keeps the
suite's runtime budget. The XMSS profile deliberately uses height 6 (64 leaves):
key generation hashes ``2**height`` WOTS+ public keys, so the default height of 10
would cost roughly a second per key pair while exercising exactly the same code
paths as the smaller tree.
"""

from __future__ import annotations

import re
import shutil
import sys
import uuid
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tls.config import HybridTLSConfig  # noqa: E402  (import follows the sys.path fix-up)
from tls.pq.signature import available_pq_signers  # noqa: E402

#: Merkle tree height used by the XMSS profiles in this suite. Every test that
#: needs a stateful signer uses this height instead of the library default.
XMSS_TEST_HEIGHT = 6

#: Falcon lives in a second provider that is not part of the main dependency set
#: (`pqcrypto` 1.0.0 has ML-KEM and ML-DSA but no Falcon). A missing optional backend
#: must not turn the suite red, so the Falcon profile is dropped and every test whose
#: id mentions falcon is skipped with the command that installs it. Without this, a
#: fresh checkout reports two dozen failures that are really one missing wheel.
FALCON_AVAILABLE = available_pq_signers().get("falcon-512") == "ok"

#: The profile names below are the keys tests parametrize over.
DEFAULT_PQ_SIGNER = "falcon-512" if FALCON_AVAILABLE else "ml-dsa-44"
DEFAULT_PROFILE_NAME = f"ml-kem-768+{DEFAULT_PQ_SIGNER}"

PROFILES: dict[str, HybridTLSConfig] = {
    "ml-kem-512+ml-dsa-44": HybridTLSConfig(kem="ml-kem-512", pq_signer="ml-dsa-44"),
    "ml-kem-768+ml-dsa-44": HybridTLSConfig(kem="ml-kem-768", pq_signer="ml-dsa-44"),
    "ml-kem-768+xmss-h6": HybridTLSConfig(
        kem="ml-kem-768", pq_signer="xmss", xmss_height=XMSS_TEST_HEIGHT
    ),
}
# One profile per KEM with the default signer, so the default-signer path is always
# covered and the placeholder-KEM test always has a configuration to run -- on a machine
# with Falcon and on one without it.
PROFILES[f"ml-kem-768+{DEFAULT_PQ_SIGNER}"] = HybridTLSConfig(
    kem="ml-kem-768", pq_signer=DEFAULT_PQ_SIGNER
)
PROFILES[f"ecdh-kem-placeholder+{DEFAULT_PQ_SIGNER}"] = HybridTLSConfig(
    kem="ecdh-kem-placeholder", pq_signer=DEFAULT_PQ_SIGNER
)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip every test that names Falcon when its provider is absent.

    Matching on the node id rather than on a marker means a test added later is covered
    automatically: if its id says falcon, it needs the provider.
    """
    if FALCON_AVAILABLE:
        return
    skip = pytest.mark.skip(
        reason="falcon-512 needs the Falcon provider: tools/install_falcon_provider.ps1"
    )
    for item in items:
        if "falcon" in item.nodeid.lower():
            item.add_marker(skip)


@pytest.fixture(scope="session")
def fast_profiles() -> dict[str, HybridTLSConfig]:
    """Return the reusable fast profiles keyed by name.

    The configs are frozen dataclasses, so sharing one instance across tests
    cannot leak state between them.
    """
    return dict(PROFILES)


@pytest.fixture(scope="session")
def default_profile(fast_profiles: dict[str, HybridTLSConfig]) -> HybridTLSConfig:
    """Return the profile used by tests that only need one working configuration."""
    return fast_profiles[DEFAULT_PROFILE_NAME]


#: The scratch root this suite uses instead of the platform temp directory. It sits *beside* the
#: checkout rather than inside it, because two of the review rounds' harnesses copy this tree with
#: `shutil.copytree` and an ignore list that does not know about scratch directories: a leftover
#: scratch tree inside the checkout made those copies fail, which is how a run of the audit's own
#: cases first reported `HARNESS-BROKEN` for the wrong reason. Keeping scratch outside the tree
#: removes that class of interference entirely.
SCRATCH_ROOT = PROJECT_ROOT.parent / ".v9-scratch" / "pytest-work"


@pytest.fixture
def tmp_path(request: pytest.FixtureRequest) -> Path:
    """A per-test scratch directory, in place of pytest's own ``tmp_path``.

    pytest's built-in fixture creates its base directory with mode ``0o700``. On Windows a
    capability-SID sandbox (the DSH one this project is developed in) cannot traverse a directory
    with that DACL, so ``tmp_path`` errors at setup with ``PermissionError`` -- an environment
    property, not a test failure, and one an independent verifier will hit if their sandbox does
    the same. The improvement plan asks for the verifier's environment to be *recorded*, and for
    the suite to be *runnable* there, so this fixture keeps the same contract as the built-in one
    (a unique empty directory per test) while creating it in the checkout.

    What it gives up: pytest's numbered retention directory, so nothing is kept for inspection.
    That is a deliberate trade, and `validation/README.md` records both the before (39 setup
    errors in a patch-free environment) and the after (full suite green).
    """
    SCRATCH_ROOT.mkdir(parents=True, exist_ok=True)
    # A parametrised test's name carries its parameter id, which can contain path-hostile
    # characters (`:` above all); keep the readable part and hash the rest.
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", request.node.name)[:60]
    unique = SCRATCH_ROOT / f"{safe}-{uuid.uuid4().hex[:8]}"
    unique.mkdir(parents=True)
    try:
        yield unique
    finally:
        shutil.rmtree(unique, ignore_errors=True)
