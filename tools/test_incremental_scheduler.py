"""Deterministic structural checks; no native kernel and no clock measurement."""
from __future__ import annotations

import json
from itertools import repeat
import sys
import unittest

from incremental_scheduler import (
    F, H, Key, Limits, MockClock, Scheduler, Shape, Status, Token,
    mock_wots_endpoints, wots_plan,
)


def key(number: int = 0, midstate: int | None = None) -> Key:
    return Key(bytes([number]) * 32, bytes([number if midstate is None else midstate]) * 32)


def request(scheduler: Scheduler, expected: int = 1, number: int = 0,
            valid: bool = True) -> Token:
    admission = scheduler.admit(key(number), expected, root_matches=valid)
    if admission.status != Status.ACCEPTED or admission.token is None:
        raise AssertionError(admission)
    return admission.token


def enqueue(scheduler: Scheduler, token: Token, task_id: int = 0,
            shape: Shape = F, **kwargs: object) -> Status:
    owner = scheduler.slots[token.slot]
    assert owner is not None
    return scheduler.enqueue(token, task_id, shape, key=owner.key,
                             address=bytes([task_id % 256]) * 32,
                             payload=bytes([task_id % 256]) * shape.input_bytes, **kwargs)


class SchedulerTests(unittest.TestCase):
    def test_batch_matrix_and_finite_max(self) -> None:
        for count in (1, 2, 4, 7, 8, 9, 64):
            with self.subTest(count=count):
                scheduler = Scheduler()
                tokens = [request(scheduler, valid=index % 3 != 0) for index in range(count)]
                for token in tokens:
                    self.assertEqual(enqueue(scheduler, token), Status.ACCEPTED)
                if count < 8:
                    self.assertIsNone(scheduler.poll())
                packets = []
                while (packet := scheduler.poll()) is not None:
                    packets.append(packet)
                    scheduler.complete(packet.packet_id, [True] * len(packet.active))
                    scheduler.assert_invariants()
                scheduler.clock.advance_to(10)
                while (packet := scheduler.poll()) is not None:
                    packets.append(packet)
                    self.assertEqual(len(packet.lanes), 8)
                    self.assertTrue(all(task is None for task in packet.lanes[len(packet.active):]))
                    scheduler.complete(packet.packet_id, [True] * len(packet.active))
                    scheduler.assert_invariants()
                self.assertEqual(len(packets), (count + 7) // 8)
                self.assertEqual([task.token for packet in packets for task in packet.active], tokens)
                for index, token in enumerate(tokens):
                    self.assertEqual(scheduler.result(token), Status.INVALID if index % 3 == 0 else Status.VALID)
                    self.assertEqual(scheduler.slots[token.slot].commits, 1)
                self.assertEqual(scheduler.reserved_tasks(), 0)

    def test_four_request_fors_dependencies_and_structural_count(self) -> None:
        scheduler = Scheduler()
        tokens = [request(scheduler, 150, valid=index != 2) for index in range(4)]
        packets = 0
        for stage in range(25):
            for token in tokens:
                for tree in range(6):
                    task_id = stage * 6 + tree
                    dependencies = () if stage == 0 else (task_id - 6,)
                    self.assertEqual(enqueue(scheduler, token, task_id, F if stage == 0 else H,
                                             dependencies=dependencies), Status.ACCEPTED)
            stage_packets = []
            while (packet := scheduler.poll()) is not None:
                stage_packets.append(packet)
            self.assertEqual(len(stage_packets), 3)
            self.assertTrue(all(len(packet.active) == 8 for packet in stage_packets))
            # Completion order can differ from dispatch order without owner changes.
            for packet in reversed(stage_packets):
                scheduler.complete(packet.packet_id, [True] * 8)
                packets += 1
            scheduler.assert_invariants()
        self.assertEqual(packets, 75)
        self.assertEqual(4 * 25, 100)  # V1's four separate six-lane packets/stage.
        for index, token in enumerate(tokens):
            self.assertEqual(scheduler.result(token), Status.INVALID if index == 2 else Status.VALID)

    def test_dependency_is_not_ready_until_parent_completed(self) -> None:
        scheduler = Scheduler()
        token = request(scheduler, 2)
        self.assertEqual(enqueue(scheduler, token, 1, H, dependencies=(0,)), Status.NOT_READY)
        self.assertEqual(enqueue(scheduler, token, 0), Status.ACCEPTED)
        scheduler.clock.advance_to(10)
        first = scheduler.poll()
        self.assertIsNotNone(first)
        self.assertEqual(enqueue(scheduler, token, 1, H, dependencies=(0,)), Status.NOT_READY)
        scheduler.complete(first.packet_id, [True])
        self.assertEqual(enqueue(scheduler, token, 1, H, dependencies=(0,)), Status.ACCEPTED)
        scheduler.clock.advance_to(30)
        final = scheduler.poll()
        scheduler.complete(final.packet_id, [True])
        self.assertEqual(scheduler.result(token), Status.VALID)

    def test_full_flush_and_deadline_equation(self) -> None:
        scheduler = Scheduler()
        one = request(scheduler)
        self.assertEqual(enqueue(scheduler, one, deadline=8, remaining=5), Status.ACCEPTED)
        task = next(iter(scheduler.queues.values()))[0]
        self.assertEqual(task.flush, min(0 + 10, 8 - 5))
        scheduler.clock.advance_to(2)
        self.assertIsNone(scheduler.poll())
        scheduler.clock.advance_to(3)
        self.assertEqual(len(scheduler.poll().active), 1)

    def test_overdue_estimate_flushes_immediately(self) -> None:
        scheduler = Scheduler()
        token = request(scheduler)
        self.assertEqual(enqueue(scheduler, token, deadline=3, remaining=9), Status.ACCEPTED)
        self.assertEqual(len(scheduler.poll().active), 1)

    def test_partial_timeout_and_optional_compatible_fill(self) -> None:
        scheduler = Scheduler()
        urgent = request(scheduler)
        fill = [request(scheduler) for _ in range(2)]
        self.assertEqual(enqueue(scheduler, urgent, 0, H, deadline=0), Status.ACCEPTED)
        for token in fill:
            self.assertEqual(enqueue(scheduler, token, 0, H), Status.ACCEPTED)
        packet = scheduler.poll()
        self.assertEqual(len(packet.active), 3)
        self.assertEqual(packet.active[0].token, urgent)
        self.assertEqual(packet.lanes[3:], (None,) * 5)

    def test_expired_queue_precedes_full_unexpired_queue(self) -> None:
        scheduler = Scheduler()
        for _ in range(8):
            self.assertEqual(enqueue(scheduler, request(scheduler)), Status.ACCEPTED)
        urgent = request(scheduler)
        self.assertEqual(enqueue(scheduler, urgent, 0, H, deadline=0), Status.ACCEPTED)
        self.assertEqual(scheduler.poll().shape, H)
        self.assertEqual(scheduler.poll().shape, F)

    def test_fair_round_robin_among_expired_queues(self) -> None:
        scheduler = Scheduler(Limits(per_request=32))
        first = request(scheduler, 20)
        second = request(scheduler, 2)
        third = request(scheduler, 2, number=1)
        for task_id in range(20):
            self.assertEqual(enqueue(scheduler, first, task_id, deadline=0), Status.ACCEPTED)
        for task_id in range(2):
            self.assertEqual(enqueue(scheduler, second, task_id, H, deadline=0), Status.ACCEPTED)
            self.assertEqual(enqueue(scheduler, third, task_id, deadline=0), Status.ACCEPTED)
        packets = [scheduler.poll() for _ in range(4)]
        self.assertEqual([(packet.key, packet.shape) for packet in packets],
                         [(key(), F), (key(), H), (key(1), F), (key(), F)])
        scheduler.assert_invariants()

    def test_key_midstate_and_shape_partition(self) -> None:
        scheduler = Scheduler()
        identities = [key(), key(1), key(0, 2)]
        for identity in identities:
            for shape in (F, H):
                admission = scheduler.admit(identity, 1)
                self.assertEqual(admission.status, Status.ACCEPTED)
                self.assertEqual(scheduler.enqueue(admission.token, 0, shape, key=identity,
                                                   address=b"a" * 32, payload=b"p" * shape.input_bytes,
                                                   deadline=0), Status.ACCEPTED)
        packets = [scheduler.poll() for _ in range(6)]
        self.assertEqual({(packet.key, packet.shape) for packet in packets},
                         {(identity, shape) for identity in identities for shape in (F, H)})
        self.assertTrue(all(len(packet.active) == 1 for packet in packets))

    def test_mismatched_key_is_rejected(self) -> None:
        scheduler = Scheduler()
        token = request(scheduler)
        self.assertEqual(scheduler.enqueue(token, 0, F, key=key(1), address=b"a" * 32,
                                          payload=b"p" * 16), Status.BAD_INPUT)
        self.assertEqual(scheduler.reserved_tasks(), 0)
        self.assertEqual(scheduler.result(token), Status.PENDING)

    def test_request_limit_and_key_limit_are_resource_errors(self) -> None:
        scheduler = Scheduler(Limits(requests=2, keys=1))
        tokens = [request(scheduler) for _ in range(2)]
        self.assertEqual(scheduler.admit(key(), 1).status, Status.RESOURCE)
        self.assertEqual(scheduler.admit(key(1), 1).status, Status.RESOURCE)
        self.assertTrue(all(scheduler.result(token) == Status.PENDING for token in tokens))

    def test_task_limit_and_retry_preserve_task_identity(self) -> None:
        scheduler = Scheduler(Limits(tasks=2, per_request=2))
        tokens = [request(scheduler) for _ in range(3)]
        for token in tokens[:2]:
            self.assertEqual(enqueue(scheduler, token, deadline=0), Status.ACCEPTED)
        self.assertEqual(enqueue(scheduler, tokens[2]), Status.RESOURCE)
        packet = scheduler.poll()
        self.assertEqual(enqueue(scheduler, tokens[2]), Status.RESOURCE)
        scheduler.complete(packet.packet_id, [True, False])
        self.assertEqual(enqueue(scheduler, tokens[2]), Status.ACCEPTED)
        self.assertEqual(scheduler.result(tokens[1]), Status.INVALID)
        scheduler.assert_invariants()

    def test_per_request_outstanding_cap(self) -> None:
        scheduler = Scheduler(Limits(per_request=3))
        token = request(scheduler, 4)
        for task_id in range(3):
            self.assertEqual(enqueue(scheduler, token, task_id, deadline=0), Status.ACCEPTED)
        self.assertEqual(enqueue(scheduler, token, 3), Status.RESOURCE)
        packet = scheduler.poll()
        self.assertEqual(enqueue(scheduler, token, 3), Status.RESOURCE)
        scheduler.complete(packet.packet_id, [True] * 3)
        self.assertEqual(enqueue(scheduler, token, 3), Status.ACCEPTED)

    def test_packet_capacity_keeps_remaining_tasks_queued(self) -> None:
        scheduler = Scheduler(Limits(packets=1))
        first, second = request(scheduler), request(scheduler, number=1)
        self.assertEqual(enqueue(scheduler, first, deadline=0), Status.ACCEPTED)
        self.assertEqual(enqueue(scheduler, second, deadline=0), Status.ACCEPTED)
        packet = scheduler.poll()
        self.assertIsNone(scheduler.poll())
        self.assertEqual(scheduler.reserved_tasks(), 2)
        scheduler.complete(packet.packet_id, [True])
        self.assertEqual(len(scheduler.poll().active), 1)

    def test_cancel_queued_and_generation_reuse(self) -> None:
        scheduler = Scheduler(Limits(requests=1, keys=1))
        previous = request(scheduler)
        self.assertEqual(enqueue(scheduler, previous), Status.ACCEPTED)
        self.assertEqual(scheduler.cancel(previous), Status.CANCELLED)
        self.assertEqual(scheduler.reserved_tasks(), 0)
        replacement = request(scheduler)
        self.assertEqual(previous.slot, replacement.slot)
        self.assertEqual(replacement.generation, previous.generation + 1)
        self.assertEqual(scheduler.result(previous), Status.STALE)
        self.assertEqual(enqueue(scheduler, previous), Status.STALE)
        scheduler.assert_invariants()

    def test_cancel_running_late_result_and_capacity_reservation(self) -> None:
        scheduler = Scheduler(Limits(requests=1, keys=1, tasks=1, per_request=1))
        previous = request(scheduler)
        self.assertEqual(enqueue(scheduler, previous, deadline=0), Status.ACCEPTED)
        old_packet = scheduler.poll()
        self.assertEqual(scheduler.cancel(previous), Status.CANCELLED)
        replacement = request(scheduler)
        self.assertEqual(enqueue(scheduler, replacement), Status.RESOURCE)
        result = scheduler.complete(old_packet.packet_id, [False])
        self.assertEqual((result.accepted, result.ignored, result.committed), (0, 1, ()))
        self.assertEqual(scheduler.result(replacement), Status.PENDING)
        self.assertEqual(enqueue(scheduler, replacement, deadline=0), Status.ACCEPTED)
        current_packet = scheduler.poll()
        scheduler.complete(current_packet.packet_id, [True])
        self.assertEqual(scheduler.result(replacement), Status.VALID)
        scheduler.assert_invariants()

    def test_cancelled_running_key_retains_key_budget(self) -> None:
        scheduler = Scheduler(Limits(requests=1, keys=1))
        token = request(scheduler)
        self.assertEqual(enqueue(scheduler, token, deadline=0), Status.ACCEPTED)
        packet = scheduler.poll()
        scheduler.cancel(token)
        self.assertEqual(scheduler.admit(key(1), 1).status, Status.RESOURCE)
        scheduler.complete(packet.packet_id, [True])
        self.assertEqual(scheduler.admit(key(1), 1).status, Status.ACCEPTED)

    def test_mixed_results_and_failure_does_not_cancel_valid_request(self) -> None:
        scheduler = Scheduler()
        good, bad = request(scheduler, 2), request(scheduler, 2)
        for token in (good, bad):
            for task_id in range(2):
                self.assertEqual(enqueue(scheduler, token, task_id, deadline=0), Status.ACCEPTED)
        packet = scheduler.poll()
        outcomes = [task.token != bad or task.task_id != 0 for task in packet.active]
        result = scheduler.complete(packet.packet_id, outcomes)
        self.assertEqual(set(result.committed), {good, bad})
        self.assertEqual(scheduler.result(good), Status.VALID)
        self.assertEqual(scheduler.result(bad), Status.INVALID)

    def test_commit_once_and_bad_completion_preserves_running_packet(self) -> None:
        scheduler = Scheduler()
        token = request(scheduler)
        self.assertEqual(enqueue(scheduler, token, deadline=0), Status.ACCEPTED)
        packet = scheduler.poll()
        self.assertEqual(scheduler.complete(packet.packet_id, []).status, Status.BAD_INPUT)
        self.assertIn(packet.packet_id, scheduler.running)
        result = scheduler.complete(packet.packet_id, [True])
        self.assertEqual(result.committed, (token,))
        self.assertEqual(scheduler.complete(packet.packet_id, [False]).status, Status.STALE)
        self.assertEqual(scheduler.slots[token.slot].commits, 1)
        self.assertEqual(scheduler.cancel(token), Status.STALE)

    def test_future_ready_and_clock_monotonicity(self) -> None:
        scheduler = Scheduler()
        token = request(scheduler)
        self.assertEqual(enqueue(scheduler, token, ready=5), Status.NOT_READY)
        scheduler.clock.advance_to(5)
        self.assertEqual(enqueue(scheduler, token, ready=5), Status.ACCEPTED)
        with self.assertRaises(ValueError):
            scheduler.clock.advance_to(4)
        with self.assertRaises(ValueError):
            MockClock().advance_to(1.0)
        with self.assertRaises(ValueError):
            MockClock().advance_to(2**63)

    def test_invalid_shapes_bounds_and_duplicate_tasks(self) -> None:
        for primitive, size in (("PRF", 16), ("F", 32), ("H", 16), ("T", 1088)):
            with self.assertRaises(ValueError):
                Shape(primitive, size)
        for kwargs in ({"tasks": 0}, {"requests": 4097}, {"delta_f": -1}, {"keys": 3, "requests": 2}):
            with self.assertRaises(ValueError):
                Limits(**kwargs)
        scheduler = Scheduler()
        self.assertEqual(scheduler.admit(key(), 0).status, Status.BAD_INPUT)
        self.assertEqual(scheduler.admit(key(), 257).status, Status.BAD_INPUT)
        token = request(scheduler)
        self.assertEqual(enqueue(scheduler, token), Status.ACCEPTED)
        self.assertEqual(enqueue(scheduler, token), Status.BAD_INPUT)
        self.assertEqual(enqueue(scheduler, token, 1), Status.BAD_INPUT)
        self.assertEqual(scheduler.result(Token(1000, 1)), Status.STALE)

    def test_generation_counter_does_not_wrap(self) -> None:
        scheduler = Scheduler(Limits(requests=1, keys=1))
        scheduler.generations[0] = 2**64 - 1
        self.assertEqual(scheduler.admit(key(), 1).status, Status.RESOURCE)

    def test_bounded_iterators_and_input_payload_limits(self) -> None:
        scheduler = Scheduler()
        token = request(scheduler, 2)
        self.assertEqual(enqueue(scheduler, token, 1, dependencies=repeat(0)), Status.BAD_INPUT)
        self.assertEqual(scheduler.enqueue(token, 0, F, key=key(), address=b"a" * 31,
                                          payload=b"p" * 16), Status.BAD_INPUT)
        self.assertEqual(scheduler.enqueue(token, 0, F, key=key(), address=b"a" * 32,
                                          payload=b"p" * 17), Status.BAD_INPUT)
        self.assertEqual(enqueue(scheduler, token, deadline=2**63), Status.BAD_INPUT)
        self.assertEqual(enqueue(scheduler, token, deadline=0), Status.ACCEPTED)
        packet = scheduler.poll()
        self.assertEqual(scheduler.complete(packet.packet_id, repeat(True)).status, Status.BAD_INPUT)
        self.assertIn(packet.packet_id, scheduler.running)
        scheduler.assert_invariants()

    def test_uint64_sequence_saturation_is_resource_status(self) -> None:
        scheduler = Scheduler()
        token = request(scheduler)
        scheduler.sequence = 2**64 - 1
        self.assertEqual(enqueue(scheduler, token), Status.RESOURCE)
        scheduler.sequence = 0
        self.assertEqual(enqueue(scheduler, token, deadline=0), Status.ACCEPTED)
        scheduler.packet_sequence = 2**64 - 1
        self.assertIsNone(scheduler.poll())
        self.assertEqual(scheduler.reserved_tasks(), 1)
        scheduler.assert_invariants()


class WotsTests(unittest.TestCase):
    def test_w0_w1_original_endpoint_order_and_logical_counts(self) -> None:
        for remaining in ((0,) * 68, (1,) * 68, (2,) * 68, (3,) * 68,
                          tuple(chain % 4 for chain in range(68)),
                          tuple((chain * 7 + chain // 8) % 4 for chain in range(68))):
            signature = tuple(bytes([chain]) * 16 for chain in range(68))
            expected = tuple(bytes([(chain + sum(chain + step + 1 for step in range(count))) % 256]) * 16
                             for chain, count in enumerate(remaining))
            self.assertEqual(mock_wots_endpoints(signature, remaining, "W0"), expected)
            self.assertEqual(mock_wots_endpoints(signature, remaining, "W1"), expected)
            for mode in ("W0", "W1"):
                plan = wots_plan(remaining, mode)
                self.assertEqual(plan.logical_f, sum(remaining))
                self.assertEqual(sum(map(len, plan.packets)), sum(remaining))
                self.assertTrue(all(1 <= len(packet) <= 8 for packet in plan.packets))
                self.assertEqual(plan.physical_lanes, 8 * len(plan.packets))
            self.assertEqual(len(b"".join(expected)), 1088)

    def test_stable_buckets_zero_step_and_buffer_accounting(self) -> None:
        remaining = tuple(chain % 4 for chain in range(68))
        w0, w1 = wots_plan(remaining, "W0"), wots_plan(remaining, "W1")
        for count, bucket in enumerate(w1.buckets):
            self.assertEqual(bucket, tuple(chain for chain in range(68) if remaining[chain] == count))
            self.assertEqual(tuple(sorted(bucket)), bucket)
        self.assertFalse(any(remaining[chain] == 0 for packet in w1.packets for chain in packet))
        self.assertEqual(w0.endpoint_buffer_bytes, 128)
        self.assertEqual(w1.endpoint_buffer_bytes, 1088)
        self.assertEqual(len(w0.packets), 27)
        self.assertEqual(len(w1.packets), 18)

    def test_wots_bounds(self) -> None:
        for remaining in ((0,) * 67, (0,) * 69, (4,) * 68, (-1,) * 68, (True,) * 68):
            with self.assertRaises(ValueError):
                wots_plan(remaining, "W1")
        with self.assertRaises(ValueError):
            wots_plan((0,) * 68, "W2")
        with self.assertRaises(ValueError):
            mock_wots_endpoints((b"short",) * 68, (0,) * 68, "W1")
        with self.assertRaises(ValueError):
            wots_plan(repeat(0), "W1")


if __name__ == "__main__":
    # Direct invocation also avoids TestCase.run's internal perf_counter calls.
    result = unittest.TestResult()
    for case_type in (SchedulerTests, WotsTests):
        for name in unittest.defaultTestLoader.getTestCaseNames(case_type):
            case = case_type(name)
            result.startTest(case)
            try:
                getattr(case, name)()
            except AssertionError:
                result.addFailure(case, sys.exc_info())
            except Exception:
                result.addError(case, sys.exc_info())
            else:
                result.addSuccess(case)
            finally:
                result.stopTest(case)
    print(json.dumps({"status": "passed" if result.wasSuccessful() else "failed",
                      "tests": result.testsRun, "failures": result.failures,
                      "errors": result.errors, "mock_clock_only": True,
                      "native_crypto_calls": 0, "performance_samples": 0}, ensure_ascii=True))
    raise SystemExit(0 if result.wasSuccessful() else 1)
