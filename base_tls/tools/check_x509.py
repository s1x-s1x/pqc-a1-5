"""Print the measured classical-versus-hybrid comparison over a real X.509 chain.

Used by ``tools/verify_all.ps1`` as a single check, and useful on its own:

    python tools/check_x509.py
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tls.config import HybridTLSConfig  # noqa: E402
from tls.handshake.connection import measured_pq_deltas  # noqa: E402


def main() -> int:
    """Print the baseline, the hybrid size, the delta, and the ratio."""
    comparison = measured_pq_deltas(HybridTLSConfig(x509=True))
    baseline = int(comparison["baseline_bytes"])
    hybrid = int(comparison["hybrid_bytes"])
    print(f"BASELINE {baseline}")
    print(f"HYBRID {hybrid}")
    print(f"TOTAL {comparison['total']}")
    print(f"RATIO {hybrid / baseline:.3f}")
    for name, delta in sorted(comparison["per_message"].items()):  # type: ignore[union-attr]
        print(f"  {name} {delta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
