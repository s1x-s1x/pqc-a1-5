"""The link shaper's arithmetic, and the flight grouping that makes it meaningful.

The shaper exists so a latency claim is checkable. These tests pin the arithmetic that
the prediction uses, and the one structural decision that would silently invalidate it:
a flight is charged one propagation delay, not one per record.
"""

from __future__ import annotations

import pytest

from tls.transport.shaper import LINK_PROFILES, LinkProfile, ShapedLink


def test_serialization_matches_the_bandwidth_definition() -> None:
    """Serialization time is bytes over bandwidth, with no hidden factor."""
    link = LinkProfile("t", rtt_ms=100.0, bandwidth_mbps=10.0)
    # 10 Mbps is 1.25 MB/s, so 1250 bytes take 1 ms.
    assert link.serialization_ms(1250) == pytest.approx(1.0, abs=1e-9)
    assert link.serialization_ms(12_500) == pytest.approx(10.0, abs=1e-9)


def test_one_way_is_half_the_round_trip() -> None:
    """Propagation in one direction is half the RTT, which is what a flight pays."""
    link = LinkProfile("t", rtt_ms=195.6, bandwidth_mbps=10.0)
    assert link.one_way_ms == pytest.approx(97.8)
    assert link.one_way_for(0) == pytest.approx(97.8)


def test_handshake_prediction_is_one_round_trip_plus_both_flights() -> None:
    """The 1-RTT prediction: both one-way legs, no more."""
    link = LinkProfile("t", rtt_ms=195.6, bandwidth_mbps=10.0)
    predicted = link.predict_handshake_ms(1400, 3000)

    assert predicted == pytest.approx(195.6 + link.serialization_ms(1400) + link.serialization_ms(3000))
    # A second round trip is what the prediction must NOT contain.
    assert predicted < 2 * link.rtt_ms


def test_round_trip_prediction_is_exactly_twice_the_handshake_legs() -> None:
    """The full measured span covers handshake plus one application exchange."""
    link = LinkProfile("t", rtt_ms=31.1, bandwidth_mbps=1000.0)
    assert link.predict_round_trip_ms(1400, 3000) == pytest.approx(
        2 * link.predict_handshake_ms(1400, 3000)
    )


def test_zero_bandwidth_is_rejected() -> None:
    """A link with no bandwidth cannot carry anything, and says so."""
    with pytest.raises(ValueError):
        LinkProfile("t", rtt_ms=1.0, bandwidth_mbps=0.0).serialization_ms(1)


def test_a_flight_is_charged_one_propagation_delay_not_one_per_record() -> None:
    """The structural decision: four records in one flight cost one one-way delay.

    Charging per record would invent three extra round trips for a TLS 1.3 server flight
    and make the 1-RTT claim untestable, because the model itself would have added them.
    """
    link = LinkProfile("t", rtt_ms=100.0, bandwidth_mbps=10_000.0)
    shaper = ShapedLink(link)
    for _ in range(4):
        shaper.transmit(100)
    slept = shaper.flush()

    assert slept == pytest.approx(0.050 + link.serialization_ms(400) / 1000.0, abs=1e-3)
    assert shaper.records_sent == 4
    assert shaper.bytes_sent == 400
    assert shaper.pending_bytes == 0


def test_flush_with_nothing_pending_does_not_sleep() -> None:
    """An empty flush is free, so a caller can flush unconditionally."""
    shaper = ShapedLink(LinkProfile("t", rtt_ms=1000.0, bandwidth_mbps=10.0))
    assert shaper.flush() == 0.0
    assert shaper.seconds_slept == 0.0


def test_counters_separate_flights() -> None:
    """Two flights pay two propagation delays, which is the handshake's shape."""
    link = LinkProfile("t", rtt_ms=100.0, bandwidth_mbps=10_000.0)
    shaper = ShapedLink(link)
    shaper.transmit(100)
    first = shaper.flush()
    shaper.transmit(100)
    second = shaper.flush()

    assert first == pytest.approx(second, abs=1e-3)
    assert shaper.seconds_slept == pytest.approx(first + second, abs=1e-6)


def test_seeded_loss_makes_a_lossy_run_reproducible() -> None:
    """Loss is drawn from a seeded source, so a lossy measurement can be repeated."""
    link = LINK_PROFILES["wan-lossy"]
    first = ShapedLink(link)
    second = ShapedLink(link)
    for _ in range(50):
        first.transmit(100)
        first.flush()
        second.transmit(100)
        second.flush()

    assert first.records_lost == second.records_lost
    assert first.seconds_slept == pytest.approx(second.seconds_slept)

    # A lossy run costs at least as much as the lossless one on the same RTT.
    lossless = ShapedLink(LinkProfile("t", rtt_ms=link.rtt_ms, bandwidth_mbps=link.bandwidth_mbps))
    for _ in range(50):
        lossless.transmit(100)
        lossless.flush()
    assert first.seconds_slept >= lossless.seconds_slept


def test_reset_returns_the_shaper_to_its_starting_state() -> None:
    """Reset clears counters and reseeds, so runs do not contaminate each other."""
    shaper = ShapedLink(LINK_PROFILES["wan-lossy"])
    for _ in range(20):
        shaper.transmit(100)
        shaper.flush()
    before = shaper.records_lost
    shaper.reset()

    assert (shaper.records_sent, shaper.bytes_sent, shaper.records_lost, shaper.pending_bytes) == (0, 0, 0, 0)
    for _ in range(20):
        shaper.transmit(100)
        shaper.flush()
    assert shaper.records_lost == before


def test_default_link_profiles_match_the_published_conditions() -> None:
    """The shipped conditions are the ones the KEMTLS line of work reports."""
    assert LINK_PROFILES["wan-fast"].rtt_ms == pytest.approx(31.1)
    assert LINK_PROFILES["wan-fast"].bandwidth_mbps == pytest.approx(1000.0)
    assert LINK_PROFILES["wan-slow"].rtt_ms == pytest.approx(195.6)
    assert LINK_PROFILES["wan-slow"].bandwidth_mbps == pytest.approx(10.0)
