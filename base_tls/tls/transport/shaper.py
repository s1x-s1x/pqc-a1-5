"""Network shaping: give the loopback transport a round trip, a bandwidth, and loss.

Loopback latency measures the harness, not a network. This module adds the two terms
that actually decide a handshake's wall time — the round trip and the serialization
delay of the bytes — so the numbers can be placed beside a real deployment's, and so a
prediction can be checked against the measurement.

The conditions default to the ones the KEMTLS line of work reports, which is what makes
the comparison meaningful: 31.1 ms and 195.6 ms RTT, at 1000 Mbps and 10 Mbps.

Loss is modelled as a retransmission timeout added to the record that would be lost,
not as real TCP retransmission: the bytes still arrive, once, after a penalty. That
reproduces loss's *latency* effect and nothing else, and it is stated rather than
implied. TCP itself is not modelled at all.
"""

from __future__ import annotations

import contextlib
import ctypes
import random
import sys
import time
from dataclasses import dataclass, field
from typing import Iterator

__all__ = [
    "DEFAULT_PROFILES",
    "LINK_PROFILES",
    "LinkProfile",
    "ShapedLink",
    "high_resolution_sleep",
]


@contextlib.contextmanager
def high_resolution_sleep() -> Iterator[None]:
    """Ask the OS for a 1 ms timer while a shaped run is in progress.

    Windows schedules sleeps on a ~15.6 ms tick by default, so a shaped run that sleeps
    for a 97.8 ms one-way delay can overshoot by most of a tick -- per sleep, several
    times per handshake. That noise is larger than the effect a shaped measurement is
    usually trying to resolve, which makes the numbers look like the link is not being
    modelled at all. ``timeBeginPeriod(1)`` removes it. On other platforms this is a
    no-op, and the timer is always released afterwards.
    """
    if sys.platform != "win32":  # pragma: no cover - platform dependent
        yield
        return
    winmm = ctypes.WinDLL("winmm")  # type: ignore[attr-defined]
    raised = winmm.timeBeginPeriod(1) == 0
    try:
        yield
    finally:
        if raised:
            winmm.timeEndPeriod(1)


@dataclass(frozen=True)
class LinkProfile:
    """One emulated link."""

    name: str
    rtt_ms: float
    bandwidth_mbps: float
    loss_percent: float = 0.0
    #: Time a lost record costs before its retransmission, if loss is non-zero.
    retransmit_timeout_ms: float = 200.0

    @property
    def one_way_ms(self) -> float:
        """Propagation delay in one direction."""
        return self.rtt_ms / 2.0

    def serialization_ms(self, nbytes: int) -> float:
        """Time to clock ``nbytes`` onto the link at this bandwidth."""
        if self.bandwidth_mbps <= 0:
            raise ValueError("bandwidth must be positive")
        return nbytes * 8.0 / (self.bandwidth_mbps * 1_000_000.0) * 1000.0

    def one_way_for(self, nbytes: int) -> float:
        """Delay before ``nbytes`` sent now have arrived: propagation plus serialization."""
        return self.one_way_ms + self.serialization_ms(nbytes)

    def predict_handshake_ms(self, client_first_flight: int, server_flight: int) -> float:
        """Predicted time from ClientHello leaving to the server being authenticated.

        A 1-RTT handshake is exactly one round trip plus the serialization time of the
        client's first flight and the server's answer. That is a prediction from the
        link's arithmetic, not a fit to the measurement, which is what lets the measured
        value be checked against it.
        """
        return (
            self.one_way_for(client_first_flight)
            + self.one_way_for(server_flight)
        )

    def predict_round_trip_ms(self, client_bytes: int, server_bytes: int) -> float:
        """Predicted time of the handshake plus one application exchange, i.e. two rounds."""
        return 2.0 * (self.one_way_for(client_bytes) + self.one_way_for(server_bytes))


#: The conditions the KEMTLS measurements use, plus a lossy variant.
LINK_PROFILES: dict[str, LinkProfile] = {
    "lan": LinkProfile("lan", rtt_ms=0.05, bandwidth_mbps=10_000.0),
    "wan-fast": LinkProfile("wan-fast", rtt_ms=31.1, bandwidth_mbps=1000.0),
    "wan-slow": LinkProfile("wan-slow", rtt_ms=195.6, bandwidth_mbps=10.0),
    "wan-lossy": LinkProfile("wan-lossy", rtt_ms=31.1, bandwidth_mbps=1000.0, loss_percent=0.5),
}

DEFAULT_PROFILES = ("lan", "wan-fast", "wan-slow")


@dataclass
class ShapedLink:
    """Applies a :class:`LinkProfile` to flights of records.

    A flight is a group of records one peer sends back to back: the delay it imposes is
    one propagation delay plus the serialization time of the whole group, not one
    propagation delay per record. Real TCP pipelines a flight, and charging a round trip
    per record would invent round trips the protocol does not take — which would make the
    1-RTT claim untestable, since the model itself would have added the extra ones.

    ``transmit`` accumulates; ``flush`` blocks and returns the seconds slept. The random
    source is seeded, so a lossy run is reproducible.
    """

    profile: LinkProfile
    records_sent: int = 0
    bytes_sent: int = 0
    records_lost: int = 0
    seconds_slept: float = 0.0
    _pending: int = field(default=0, init=False, repr=False)
    _random: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._random = random.Random(f"hybrid-tls13/{self.profile.name}")

    @property
    def pending_bytes(self) -> int:
        """Bytes handed to ``transmit`` and not yet flushed."""
        return self._pending

    def transmit(self, nbytes: int) -> None:
        """Add one record to the flight being built."""
        self.records_sent += 1
        self.bytes_sent += nbytes
        self._pending += nbytes

    def flush(self) -> float:
        """Block for the flight's delay and return the seconds slept."""
        if self._pending == 0:
            return 0.0
        delay_ms = self.profile.one_way_for(self._pending)
        if self.profile.loss_percent > 0 and self._random.random() < self.profile.loss_percent / 100.0:
            # The flight still arrives, one retransmission timeout later. This models
            # loss's latency cost, not TCP's recovery mechanics.
            self.records_lost += 1
            delay_ms += self.profile.retransmit_timeout_ms
        self._pending = 0
        seconds = delay_ms / 1000.0
        time.sleep(seconds)
        self.seconds_slept += seconds
        return seconds

    def reset(self) -> None:
        """Clear the counters and reseed, so runs are independent and repeatable."""
        self.records_sent = 0
        self.bytes_sent = 0
        self.records_lost = 0
        self.seconds_slept = 0.0
        self._pending = 0
        self._random = random.Random(f"hybrid-tls13/{self.profile.name}")
