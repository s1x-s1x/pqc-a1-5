"""Bounded V2/W1 structural simulator. Only explicit integer mock-clock ticks.

This module never invokes native crypto, sleeps, reads time, or measures speed.
Limits are illustrative simulator inputs, not a production workload decision.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from itertools import islice
from typing import Iterable


class Status(str, Enum):
    ACCEPTED = "ACCEPTED"
    PENDING = "PENDING"
    VALID = "VALID"
    INVALID = "INVALID"
    CANCELLED = "CANCELLED"
    RESOURCE = "RESOURCE"
    STALE = "STALE"
    NOT_READY = "NOT_READY"
    BAD_INPUT = "BAD_INPUT"


@dataclass(frozen=True)
class Limits:
    requests: int = 64
    keys: int = 4
    tasks: int = 512
    packets: int = 64
    per_request: int = 8
    tasks_per_signature: int = 256
    delta_f: int = 10
    delta_h: int = 20

    def __post_init__(self) -> None:
        for name in ("requests", "keys", "tasks", "packets", "per_request", "tasks_per_signature"):
            value = getattr(self, name)
            if type(value) is not int or not 1 <= value <= 4096:
                raise ValueError(f"{name} must be an integer in 1..4096")
        if self.per_request > self.tasks or self.keys > self.requests:
            raise ValueError("inconsistent resource limits")
        for value in (self.delta_f, self.delta_h):
            if type(value) is not int or not 0 <= value <= 2**31:
                raise ValueError("delta must be an integer in 0..2^31")


@dataclass(frozen=True)
class Key:
    public_key: bytes
    midstate_id: bytes
    parameter: int = 3
    algorithm: str = "SM3"

    def __post_init__(self) -> None:
        if type(self.public_key) is not bytes or type(self.midstate_id) is not bytes or \
                len(self.public_key) != 32 or len(self.midstate_id) != 32:
            raise ValueError("key and mock midstate identity must each be 32 bytes")
        if self.parameter != 3 or self.algorithm != "SM3":
            raise ValueError("first-stage simulation supports pid3 SM3 only")


@dataclass(frozen=True)
class Shape:
    primitive: str
    input_bytes: int
    domain: int = 3

    def __post_init__(self) -> None:
        if (self.primitive, self.input_bytes, self.domain) not in (("F", 16, 3), ("H", 32, 3)):
            raise ValueError("only original FORS F/H shapes are modeled")


F = Shape("F", 16)
H = Shape("H", 32)


@dataclass(frozen=True)
class Token:
    slot: int
    generation: int


@dataclass(frozen=True)
class Admission:
    status: Status
    token: Token | None = None


@dataclass
class Request:
    token: Token
    key: Key
    expected: int
    root_matches: bool
    status: Status = Status.PENDING
    seen: set[int] = field(default_factory=set)
    done: set[int] = field(default_factory=set)
    failed: bool = False
    outstanding: int = 0
    commits: int = 0


@dataclass(frozen=True)
class Task:
    token: Token
    task_id: int
    key: Key
    shape: Shape
    address: bytes
    payload: bytes
    output_slot: int
    ready: int
    deadline: int
    remaining: int
    flush: int
    sequence: int
    dependencies: tuple[int, ...]


@dataclass(frozen=True)
class Packet:
    packet_id: int
    key: Key
    shape: Shape
    lanes: tuple[Task | None, ...]

    @property
    def active(self) -> tuple[Task, ...]:
        return tuple(task for task in self.lanes if task is not None)


@dataclass(frozen=True)
class Completion:
    status: Status
    accepted: int = 0
    ignored: int = 0
    committed: tuple[Token, ...] = ()


class MockClock:
    def __init__(self) -> None:
        self.now = 0

    def advance_to(self, tick: int) -> None:
        if type(tick) is not int or not self.now <= tick <= 2**63 - 1:
            raise ValueError("mock clock must be monotonic integer ticks")
        self.now = tick


class Scheduler:
    """One-thread state machine; production concurrent synchronization is deferred."""

    def __init__(self, limits: Limits = Limits()) -> None:
        self.limits = limits
        self.clock = MockClock()
        self.slots: list[Request | None] = [None] * limits.requests
        self.generations = [0] * limits.requests
        self.queues: dict[tuple[Key, Shape], list[Task]] = {}
        self.order: deque[tuple[Key, Shape]] = deque()
        self.running: dict[int, Packet] = {}
        self.sequence = 0
        self.packet_sequence = 0

    def _request(self, token: Token) -> Request | None:
        if not 0 <= token.slot < len(self.slots):
            return None
        request = self.slots[token.slot]
        return request if request is not None and request.token == token else None

    def _live_keys(self) -> set[Key]:
        keys = {request.key for request in self.slots if request and request.status == Status.PENDING}
        keys.update(key for key, _ in self.queues)
        keys.update(packet.key for packet in self.running.values())
        return keys

    def reserved_tasks(self) -> int:
        return sum(map(len, self.queues.values())) + sum(len(packet.active) for packet in self.running.values())

    def admit(self, key: Key, expected: int, *, root_matches: bool = True) -> Admission:
        if not isinstance(key, Key) or type(expected) is not int or not 1 <= expected <= self.limits.tasks_per_signature:
            return Admission(Status.BAD_INPUT)
        if type(root_matches) is not bool:
            return Admission(Status.BAD_INPUT)
        keys = self._live_keys()
        if key not in keys and len(keys) >= self.limits.keys:
            return Admission(Status.RESOURCE)
        for slot, previous in enumerate(self.slots):
            if previous is None or previous.status != Status.PENDING:
                if self.generations[slot] == 2**64 - 1:
                    continue
                self.generations[slot] += 1
                token = Token(slot, self.generations[slot])
                self.slots[slot] = Request(token, key, expected, root_matches)
                return Admission(Status.ACCEPTED, token)
        return Admission(Status.RESOURCE)

    def enqueue(self, token: Token, task_id: int, shape: Shape, *, key: Key,
                address: bytes, payload: bytes, ready: int | None = None,
                deadline: int = 1000, remaining: int = 0,
                dependencies: Iterable[int] = ()) -> Status:
        request = self._request(token)
        if request is None or request.status != Status.PENDING:
            return Status.STALE
        ready = self.clock.now if ready is None else ready
        dependencies = tuple(islice(dependencies, request.expected + 1))
        if not isinstance(shape, Shape) or len(dependencies) > request.expected:
            return Status.BAD_INPUT
        if key != request.key or type(task_id) is not int or not 0 <= task_id < request.expected:
            return Status.BAD_INPUT
        if task_id in request.seen or len(address) != 32 or len(payload) != shape.input_bytes:
            return Status.BAD_INPUT
        if any(type(x) is not int or not 0 <= x <= 2**63 - 1 for x in (ready, deadline, remaining)):
            return Status.BAD_INPUT
        if any(type(x) is not int or not 0 <= x < request.expected or x == task_id for x in dependencies):
            return Status.BAD_INPUT
        if ready > self.clock.now or any(x not in request.done for x in dependencies):
            return Status.NOT_READY
        if request.outstanding >= self.limits.per_request or self.reserved_tasks() >= self.limits.tasks:
            return Status.RESOURCE
        if self.sequence == 2**64 - 1:
            return Status.RESOURCE
        self.sequence += 1
        delta = self.limits.delta_f if shape == F else self.limits.delta_h
        flush = min(ready + delta, deadline - remaining)
        task = Task(token, task_id, key, shape, bytes(address), bytes(payload),
                    task_id, ready, deadline, remaining, flush, self.sequence, dependencies)
        group = (key, shape)
        if group not in self.queues:
            self.queues[group] = []
            self.order.append(group)
        self.queues[group].append(task)
        request.seen.add(task_id)
        request.outstanding += 1
        return Status.ACCEPTED

    def poll(self) -> Packet | None:
        if len(self.running) >= self.limits.packets or self.packet_sequence == 2**64 - 1:
            return None
        expired = {group for group in self.order if any(t.flush <= self.clock.now for t in self.queues[group])}
        candidates = expired or {group for group in self.order if len(self.queues[group]) >= 8}
        if not candidates:
            return None
        # Round robin among expired compatible queues, then optional same-shape fill.
        while self.order[0] not in candidates:
            self.order.rotate(-1)
        group = self.order[0]
        self.order.rotate(-1)
        tasks = self.queues[group]
        tasks.sort(key=lambda t: (t.flush > self.clock.now, t.flush, t.ready, t.sequence))
        selected = tuple(tasks[:8])
        del tasks[:8]
        if not tasks:
            del self.queues[group]
            self.order.remove(group)
        self.packet_sequence += 1
        packet = Packet(self.packet_sequence, *group, selected + (None,) * (8 - len(selected)))
        self.running[packet.packet_id] = packet
        return packet

    def complete(self, packet_id: int, outcomes: Iterable[bool]) -> Completion:
        packet = self.running.get(packet_id)
        if packet is None:
            return Completion(Status.STALE)
        outcomes = tuple(islice(outcomes, len(packet.active) + 1))
        if len(outcomes) != len(packet.active) or any(type(value) is not bool for value in outcomes):
            return Completion(Status.BAD_INPUT)
        del self.running[packet_id]
        accepted = ignored = 0
        committed = []
        for task, passed in zip(packet.active, outcomes):
            request = self._request(task.token)
            if request is None or request.status != Status.PENDING or task.task_id in request.done:
                ignored += 1
                continue
            request.outstanding -= 1
            request.done.add(task.task_id)
            request.failed |= not passed
            accepted += 1
            if len(request.done) == request.expected:
                request.status = Status.INVALID if request.failed or not request.root_matches else Status.VALID
                request.commits += 1
                committed.append(request.token)
        return Completion(Status.ACCEPTED, accepted, ignored, tuple(committed))

    def cancel(self, token: Token) -> Status:
        request = self._request(token)
        if request is None or request.status != Status.PENDING:
            return Status.STALE
        request.status = Status.CANCELLED
        for group in tuple(self.queues):
            self.queues[group] = [task for task in self.queues[group] if task.token != token]
            if not self.queues[group]:
                del self.queues[group]
                self.order.remove(group)
        request.outstanding = 0
        # Running packets retain old-generation identities and reserved capacity
        # until completion; cancel/reuse cannot accumulate unbounded tombstones.
        return Status.CANCELLED

    def result(self, token: Token) -> Status:
        request = self._request(token)
        return request.status if request else Status.STALE

    def assert_invariants(self) -> None:
        assert self.reserved_tasks() <= self.limits.tasks
        assert len(self.running) <= self.limits.packets
        assert len(self._live_keys()) <= self.limits.keys
        assert set(self.order) == set(self.queues)
        assert len(self.order) == len(self.queues)
        for request in self.slots:
            if request is not None:
                assert len(request.seen) <= request.expected <= self.limits.tasks_per_signature
                assert request.done <= request.seen
                assert 0 <= request.outstanding <= self.limits.per_request
                assert request.commits <= 1
        for packet in self.running.values():
            assert len(packet.lanes) == 8
            assert all(task.key == packet.key and task.shape == packet.shape for task in packet.active)


@dataclass(frozen=True)
class WotsPlan:
    mode: str
    buckets: tuple[tuple[int, ...], ...]
    packets: tuple[tuple[int, ...], ...]
    logical_f: int
    physical_lanes: int
    endpoint_buffer_bytes: int


def wots_plan(remaining: Iterable[int], mode: str) -> WotsPlan:
    remaining = tuple(islice(remaining, 69))
    if len(remaining) != 68 or any(type(value) is not int or not 0 <= value <= 3 for value in remaining):
        raise ValueError("pid3 WOTS has 68 chains with public remaining steps 0..3")
    if mode not in ("W0", "W1"):
        raise ValueError("only W0 and full-buffer W1 are modeled")
    buckets = tuple(tuple(chain for chain, count in enumerate(remaining) if count == n) for n in range(4))
    packets = []
    if mode == "W0":
        for first in range(0, 68, 8):
            group = tuple(range(first, min(first + 8, 68)))
            for step in range(max(remaining[chain] for chain in group)):
                packets.append(tuple(chain for chain in group if remaining[chain] > step))
    else:
        for count in range(1, 4):
            for first in range(0, len(buckets[count]), 8):
                group = buckets[count][first:first + 8]
                packets.extend([group] * count)
    return WotsPlan(mode, buckets, tuple(packets), sum(remaining), len(packets) * 8,
                    128 if mode == "W0" else 1088)


def mock_wots_endpoints(signature: Iterable[bytes], remaining: Iterable[int], mode: str) -> tuple[bytes, ...]:
    """Public toy transition, no SM3. Return endpoints in original chain order.

    The simulator retains all endpoints to compare equality; buffer_bytes above
    models the proposed production layouts and is not Python memory measured.
    """
    signature, remaining = tuple(islice(signature, 69)), tuple(islice(remaining, 69))
    if len(signature) != 68 or any(len(element) != 16 for element in signature):
        raise ValueError("68 signature elements of 16 bytes are required")
    plan = wots_plan(remaining, mode)
    endpoints = list(signature)
    completed = [0] * 68
    for packet in plan.packets:
        for chain in packet:
            step = completed[chain]
            endpoints[chain] = bytes((value + chain + step + 1) % 256 for value in endpoints[chain])
            completed[chain] += 1
    assert completed == list(remaining)
    return tuple(endpoints)
