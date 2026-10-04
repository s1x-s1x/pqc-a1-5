"""Durable per-key signing reservations for the shared experimental CA.

Reservations charge before signing; failures and crashes never refund charges.
Guarded transactional counters make ordinary operations independent of history
length. Opening a ledger and ``audit()`` perform full historical reconciliation.
All issuers must share the database. Copies, restoration, and arbitrary database
replacement still require external authenticity and anti-rollback controls.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import uuid


class BudgetError(RuntimeError):
    pass


_ALGORITHMS = {
    **{f"slh-dsa-{hash_name}-{parameter}": f"a15:slh:pid:{pid}"
       for hash_name, parameter, pid in (
           ("sm3", "128s", 1), ("sm3", "128f", 2), ("sm3", "128-24", 3),
           ("sha2", "128s", 101), ("sha2", "128f", 102),
           ("sha2", "128-24", 103), ("sm3", "toy", 201))},
    "ml-dsa-44": "oid:2.16.840.1.101.3.4.3.17",
}
_STATES = ("reserved", "committed", "failed")
_TABLES = {
    "keys": """CREATE TABLE keys(
        key_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL,
        public_key BLOB NOT NULL, limit_text TEXT NOT NULL,
        used_text TEXT NOT NULL, created_utc TEXT NOT NULL)""",
    "reservations": """CREATE TABLE reservations(
        receipt TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES keys(key_id),
        ordinal_text TEXT NOT NULL, message_sha256 TEXT NOT NULL,
        reserved_utc TEXT NOT NULL, status TEXT NOT NULL,
        signature_sha256 TEXT, finished_utc TEXT,
        UNIQUE(key_id, ordinal_text))""",
    "ledger_metadata": """CREATE TABLE ledger_metadata(
        name TEXT PRIMARY KEY, value TEXT NOT NULL)""",
    "identity_migrations": """CREATE TABLE identity_migrations(
        legacy_key_id TEXT PRIMARY KEY, canonical_key_id TEXT NOT NULL,
        legacy_algorithm TEXT NOT NULL, legacy_limit_text TEXT NOT NULL,
        legacy_used_text TEXT NOT NULL, migrated_utc TEXT NOT NULL)""",
    "ledger_counts": """CREATE TABLE ledger_counts(
        key_id TEXT PRIMARY KEY REFERENCES keys(key_id),
        consumed_text TEXT NOT NULL, reserved_text TEXT NOT NULL,
        committed_text TEXT NOT NULL, failed_text TEXT NOT NULL)""",
}


def canonical_algorithm(algorithm):
    if not isinstance(algorithm, str) or algorithm.lower() not in _ALGORITHMS:
        raise ValueError("unsupported signing-budget algorithm")
    return algorithm.lower()


def _number(value, *, positive=False):
    # TEXT arithmetic preserves the 2**64 lifetime allowance beyond int64.
    if (not isinstance(value, str) or not value or
            any(c not in "0123456789" for c in value) or
            (len(value) > 1 and value.startswith("0")) or
            (positive and value == "0")):
        raise BudgetError("ledger decimal counter or ordinal is malformed")
    return int(value)


def _digest(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _sql_normalized(sql):
    # SQLite retains source formatting in sqlite_master. Ignore formatting and
    # keyword case only outside quoted tokens: literal case/space changes alter
    # guard semantics and must never compare equal.
    parts = re.split(r'''('(?:''|[^'])*'|"(?:""|[^"])*"|`(?:``|[^`])*`|\[[^\]]*\])''', sql)
    return "".join(part if index % 2 else "".join(part.split()).lower()
                   for index, part in enumerate(parts)).rstrip(";")


def _guard(name, event, condition="1"):
    return f"""CREATE TRIGGER {name} BEFORE {event}
        WHEN {condition} BEGIN
        SELECT RAISE(ABORT, 'guarded ledger mutation rejected'); END"""


_TRIGGERS = {
    "a15_keys_insert": _guard("a15_keys_insert", "INSERT ON keys", """
        _a15_write_mode() != 'reserve' OR NEW.used_text != '0'
        OR NEW.algorithm != lower(NEW.algorithm)
        OR NEW.key_id != _a15_key_id(NEW.algorithm, NEW.public_key)
        OR NOT _a15_valid_limit(NEW.algorithm, NEW.limit_text)
        OR length(NEW.public_key) = 0 OR length(NEW.created_utc) = 0"""),
    "a15_keys_update": _guard("a15_keys_update", "UPDATE ON keys", """
        _a15_write_mode() != 'reserve'
        OR NEW.key_id IS NOT OLD.key_id OR NEW.algorithm IS NOT OLD.algorithm
        OR NEW.public_key IS NOT OLD.public_key OR NEW.limit_text IS NOT OLD.limit_text
        OR NEW.created_utc IS NOT OLD.created_utc
        OR NEW.used_text != _a15_step(OLD.used_text, 1)"""),
    "a15_keys_delete": _guard("a15_keys_delete", "DELETE ON keys"),
    "a15_keys_seed": """CREATE TRIGGER a15_keys_seed AFTER INSERT ON keys BEGIN
        INSERT INTO ledger_counts VALUES(NEW.key_id, '0', '0', '0', '0'); END""",
    "a15_reservations_insert": _guard("a15_reservations_insert", "INSERT ON reservations", """
        _a15_write_mode() != 'reserve' OR length(NEW.receipt) = 0
        OR NEW.ordinal_text != _a15_step((SELECT used_text FROM keys WHERE key_id=NEW.key_id), 1)
        OR NOT _a15_valid_digest(NEW.message_sha256) OR length(NEW.reserved_utc) = 0
        OR NEW.status != 'reserved' OR NEW.signature_sha256 IS NOT NULL
        OR NEW.finished_utc IS NOT NULL"""),
    "a15_reservations_update": _guard("a15_reservations_update", "UPDATE ON reservations", """
        _a15_write_mode() != 'finish' OR OLD.status != 'reserved'
        OR NEW.receipt IS NOT OLD.receipt OR NEW.key_id IS NOT OLD.key_id
        OR NEW.ordinal_text IS NOT OLD.ordinal_text
        OR NEW.message_sha256 IS NOT OLD.message_sha256
        OR NEW.reserved_utc IS NOT OLD.reserved_utc
        OR NEW.status NOT IN ('committed', 'failed')
        OR NEW.finished_utc IS NULL OR length(NEW.finished_utc) = 0
        OR (NEW.status = 'committed' AND NOT _a15_valid_digest(NEW.signature_sha256))
        OR (NEW.status = 'failed' AND NEW.signature_sha256 IS NOT NULL)"""),
    "a15_reservations_delete": _guard("a15_reservations_delete", "DELETE ON reservations"),
    "a15_reservations_charge": """CREATE TRIGGER a15_reservations_charge
        AFTER INSERT ON reservations BEGIN
        UPDATE ledger_counts SET consumed_text=_a15_step(consumed_text, 1),
            reserved_text=_a15_step(reserved_text, 1) WHERE key_id=NEW.key_id;
        UPDATE keys SET used_text=_a15_step(used_text, 1) WHERE key_id=NEW.key_id;
        END""",
    "a15_reservations_finish": """CREATE TRIGGER a15_reservations_finish
        AFTER UPDATE ON reservations BEGIN
        UPDATE ledger_counts SET reserved_text=_a15_step(reserved_text, -1),
            committed_text=_a15_step(committed_text, CASE WHEN NEW.status='committed' THEN 1 ELSE 0 END),
            failed_text=_a15_step(failed_text, CASE WHEN NEW.status='failed' THEN 1 ELSE 0 END)
            WHERE key_id=NEW.key_id; END""",
    "a15_counts_insert": _guard("a15_counts_insert", "INSERT ON ledger_counts", """
        _a15_write_mode() != 'reserve' OR NEW.consumed_text != '0'
        OR NEW.reserved_text != '0' OR NEW.committed_text != '0' OR NEW.failed_text != '0'"""),
    "a15_counts_update": _guard("a15_counts_update", "UPDATE ON ledger_counts", """
        NEW.key_id IS NOT OLD.key_id OR NOT (
          (_a15_write_mode()='reserve'
           AND NEW.consumed_text=_a15_step(OLD.consumed_text, 1)
           AND NEW.reserved_text=_a15_step(OLD.reserved_text, 1)
           AND NEW.committed_text IS OLD.committed_text AND NEW.failed_text IS OLD.failed_text)
          OR (_a15_write_mode()='finish' AND NEW.consumed_text IS OLD.consumed_text
           AND NEW.reserved_text=_a15_step(OLD.reserved_text, -1)
           AND ((NEW.committed_text=_a15_step(OLD.committed_text, 1) AND NEW.failed_text IS OLD.failed_text)
             OR (NEW.failed_text=_a15_step(OLD.failed_text, 1) AND NEW.committed_text IS OLD.committed_text))))"""),
    "a15_counts_delete": _guard("a15_counts_delete", "DELETE ON ledger_counts"),
}
for _table in ("ledger_metadata", "identity_migrations"):
    for _event in ("INSERT", "UPDATE", "DELETE"):
        _name = f"a15_{_table}_{_event.lower()}"
        _TRIGGERS[_name] = _guard(_name, f"{_event} ON {_table}")


class SigningBudget:
    def __init__(self, database):
        self.path = Path(database).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write_modes = {}
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute("BEGIN IMMEDIATE")
            try:
                tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                version = (db.execute("SELECT value FROM ledger_metadata WHERE name='integrity_schema'").fetchone()
                           if "ledger_metadata" in tables else None)
                if version is not None:
                    if version[0] != "3":
                        raise BudgetError("unsupported ledger integrity schema")
                    # Existing protected ledgers must retain the guards; never
                    # silently reinstall a missing trigger or reset a counter.
                    self._check_schema(db)
                    self.ledger_uuid = self._read_uuid(db)
                    self._audit_state(db, compare_counts=True)
                else:
                    if "ledger_counts" in tables or db.execute("SELECT 1 FROM sqlite_master WHERE type='trigger'").fetchone():
                        raise BudgetError("unversioned ledger integrity schema differs")
                    for name, ddl in _TABLES.items():
                        if name not in tables:
                            db.execute(ddl)
                    identity = db.execute("SELECT value FROM ledger_metadata WHERE name='identity_schema'").fetchone()
                    existing_uuid = db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()
                    if identity is not None and existing_uuid is None:
                        raise BudgetError("existing ledger UUID is missing")
                    if existing_uuid is None:
                        db.execute("INSERT INTO ledger_metadata VALUES('ledger_uuid',?)", (uuid.uuid4().hex,))
                    self.ledger_uuid = self._read_uuid(db)
                    self._migrate_identity(db)
                    states = self._audit_state(db, compare_counts=False)
                    for identifier, counts in states.items():
                        db.execute("INSERT INTO ledger_counts VALUES(?,?,?,?,?)",
                                   (identifier, *(str(counts[name]) for name in ("consumed", *_STATES))))
                    db.execute("INSERT INTO ledger_metadata VALUES('integrity_schema','3')")
                    for ddl in _TRIGGERS.values():
                        db.execute(ddl)
                    self._check_schema(db)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    @staticmethod
    def _read_uuid(db):
        row = db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()
        if row is None or not isinstance(row[0], str) or len(row[0]) != 32 or any(c not in "0123456789abcdef" for c in row[0]):
            raise BudgetError("ledger UUID is malformed")
        return row[0]

    def _migrate_identity(self, db):
        version = db.execute("SELECT value FROM ledger_metadata WHERE name='identity_schema'").fetchone()
        if version:
            if version[0] != "2":
                raise BudgetError("unsupported ledger identity schema")
            return
        groups = {}
        for row in db.execute("SELECT key_id,algorithm,public_key,limit_text,used_text,created_utc FROM keys").fetchall():
            old_id, algorithm, public, limit, used, created = row
            name = canonical_algorithm(algorithm)
            identifier = self.key_id(name, public)
            legacy_id = hashlib.sha256(algorithm.encode("ascii") + b"\0" + bytes(public)).hexdigest()
            if old_id not in (identifier, legacy_id):
                raise BudgetError("legacy key identity reconciliation failed")
            maximum = 1 << (24 if name.endswith("128-24") else 64)
            if not 0 < _number(limit, positive=True) <= maximum:
                raise BudgetError("legacy key allowance is invalid")
            actual = db.execute("SELECT COUNT(*) FROM reservations WHERE key_id=?", (old_id,)).fetchone()[0]
            if actual != _number(used):
                raise BudgetError("legacy ledger count reconciliation failed")
            groups.setdefault(identifier, []).append(row)
        now = datetime.now(timezone.utc).isoformat()
        for identifier, aliases in groups.items():
            name, public = canonical_algorithm(aliases[0][1]), aliases[0][2]
            limit, used = min(int(r[3]) for r in aliases), sum(int(r[4]) for r in aliases)
            created = min(r[5] for r in aliases)
            receipts = []
            for row in aliases:
                receipts.extend(db.execute("SELECT receipt,reserved_utc FROM reservations WHERE key_id=?", (row[0],)).fetchall())
            ordered = sorted(receipts, key=lambda row: (row[1], row[0]))
            db.execute("INSERT OR IGNORE INTO keys VALUES(?,?,?,?,?,?)", (identifier, name, public, str(limit), str(used), created))
            for ordinal, (receipt, _) in enumerate(ordered, 1):
                db.execute("UPDATE reservations SET key_id=?,ordinal_text=? WHERE receipt=?", (identifier, str(-ordinal), receipt))
            for ordinal, (receipt, _) in enumerate(ordered, 1):
                db.execute("UPDATE reservations SET ordinal_text=? WHERE receipt=?", (str(ordinal), receipt))
            for row in aliases:
                db.execute("INSERT INTO identity_migrations VALUES(?,?,?,?,?,?)", (row[0], identifier, row[1], row[3], row[4], now))
                if row[0] != identifier:
                    db.execute("DELETE FROM keys WHERE key_id=?", (row[0],))
            db.execute("UPDATE keys SET algorithm=?,limit_text=?,used_text=?,created_utc=? WHERE key_id=?", (name, str(limit), str(used), created, identifier))
        db.execute("INSERT INTO ledger_metadata VALUES('identity_schema','2')")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=60, isolation_level=None)
        state = {"mode": "read"}
        self._write_modes[id(db)] = state
        db.create_function("_a15_write_mode", 0, lambda: state["mode"])
        db.create_function("_a15_step", 2, self._step)
        db.create_function("_a15_key_id", 2, self.key_id)
        db.create_function("_a15_valid_limit", 2, self._valid_limit)
        db.create_function("_a15_valid_digest", 1, _digest)
        try:
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA busy_timeout=60000")
            yield db
        finally:
            self._write_modes.pop(id(db), None)
            db.close()

    @staticmethod
    def _step(value, delta):
        result = _number(value) + delta
        if result < 0:
            raise BudgetError("ledger counter underflow")
        return str(result)

    @staticmethod
    def _valid_limit(algorithm, value):
        maximum = 1 << (24 if canonical_algorithm(algorithm).endswith("128-24") else 64)
        return 0 < _number(value, positive=True) <= maximum

    @contextmanager
    def _mutation(self, db, mode):
        state = self._write_modes[id(db)]
        previous, state["mode"] = state["mode"], mode
        try:
            yield
        finally:
            state["mode"] = previous

    @staticmethod
    def key_id(algorithm, public_key):
        name = canonical_algorithm(algorithm)
        return hashlib.sha256(_ALGORITHMS[name].encode("ascii") + b"\0" + bytes(public_key)).hexdigest()

    @staticmethod
    def _check_schema(db):
        actual_tables = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
        if any(name not in actual_tables or _sql_normalized(actual_tables[name]) != _sql_normalized(ddl)
               for name, ddl in _TABLES.items()):
            raise BudgetError("ledger table integrity schema differs")
        placeholders = ",".join("?" for _ in _TABLES)
        triggers = dict(db.execute(f"SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name IN ({placeholders})", tuple(_TABLES)))
        if (set(triggers) != set(_TRIGGERS) or
                any(_sql_normalized(triggers[name]) != _sql_normalized(ddl) for name, ddl in _TRIGGERS.items())):
            raise BudgetError("ledger integrity trigger missing or altered")
        versions = dict(db.execute("SELECT name,value FROM ledger_metadata WHERE name IN ('identity_schema','integrity_schema')"))
        if versions != {"identity_schema": "2", "integrity_schema": "3"}:
            raise BudgetError("ledger integrity schema version differs")

    def _check_uuid(self, db):
        row = db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()
        if row is None or row[0] != self.ledger_uuid:
            raise BudgetError("live ledger UUID changed")

    def _key_state(self, db, identifier):
        row = db.execute("SELECT k.algorithm,k.public_key,k.limit_text,k.used_text,"
                         "c.consumed_text,c.reserved_text,c.committed_text,c.failed_text "
                         "FROM keys k LEFT JOIN ledger_counts c ON c.key_id=k.key_id WHERE k.key_id=?", (identifier,)).fetchone()
        if row is None or row[4] is None:
            raise BudgetError("ledger key counter is missing")
        algorithm, public, limit, used = row[:4]
        if algorithm != canonical_algorithm(algorithm) or identifier != self.key_id(algorithm, public) or not public:
            raise BudgetError("receipt canonical key identity differs")
        if not self._valid_limit(algorithm, limit):
            raise BudgetError("ledger key allowance is invalid")
        counters = [_number(v) for v in row[3:]]
        if counters[0] != counters[1] or sum(counters[2:]) != counters[1]:
            raise BudgetError("ledger counter reconciliation failed")
        # Two indexed endpoint reads bound this check independently of history.
        if counters[0] and any(db.execute("SELECT 1 FROM reservations WHERE key_id=? AND ordinal_text=?",
                                         (identifier, ordinal)).fetchone() is None
                               for ordinal in {"1", used}):
            raise BudgetError("ledger ordinal endpoint reconciliation failed")
        return {"algorithm": algorithm, "public": public, "limit": int(limit),
                "used": counters[0], "states": dict(zip(_STATES, counters[2:]))}

    @staticmethod
    def _check_reservation(row):
        receipt, identifier, ordinal, message, reserved, status, signature, finished = row
        ordinal = _number(ordinal, positive=True)
        if (not isinstance(receipt, str) or not receipt or not _digest(message) or
                not isinstance(reserved, str) or not reserved or status not in _STATES):
            raise BudgetError("ledger reservation is malformed")
        if status == "reserved":
            valid = signature is None and finished is None
        else:
            valid = (isinstance(finished, str) and bool(finished) and
                     (_digest(signature) if status == "committed" else signature is None))
        if not valid:
            raise BudgetError("ledger reservation status or signature digest is malformed")
        return ordinal

    def _audit_state(self, db, *, compare_counts):
        """Full O(history) checkpoint; never called by reserve/finish/validate."""
        states = {}
        for identifier, algorithm, public, limit, used, created in db.execute("SELECT * FROM keys"):
            if (algorithm != canonical_algorithm(algorithm) or identifier != self.key_id(algorithm, public)
                    or not public or not self._valid_limit(algorithm, limit) or not isinstance(created, str) or not created):
                raise BudgetError("ledger canonical key or allowance reconciliation failed")
            states[identifier] = {"consumed": 0, **dict.fromkeys(_STATES, 0),
                                  "used": _number(used), "max_ordinal": 0}
        for row in db.execute("SELECT receipt,key_id,ordinal_text,message_sha256,reserved_utc,status,signature_sha256,finished_utc FROM reservations"):
            ordinal = self._check_reservation(row)
            if row[1] not in states:
                raise BudgetError("ledger reservation key reconciliation failed")
            state = states[row[1]]
            state["consumed"] += 1
            state[row[5]] += 1
            state["max_ordinal"] = max(state["max_ordinal"], ordinal)
        for state in states.values():
            # Canonical positive decimal ordinals plus the unique index imply
            # no gaps when count==maximum. Migration never refunds overruns.
            if state["consumed"] != state["used"] or state["max_ordinal"] != state["used"]:
                raise BudgetError("ledger full history count or ordinal reconciliation failed")
        if compare_counts:
            counters = {row[0]: tuple(_number(v) for v in row[1:]) for row in db.execute("SELECT * FROM ledger_counts")}
            if set(counters) != set(states) or any(counters[k] != tuple(v[n] for n in ("consumed", *_STATES)) for k, v in states.items()):
                raise BudgetError("ledger full history counter reconciliation failed")
        return states

    def audit(self):
        """Explicit full checkpoint, including internal ordinals and all states."""
        with self.connection() as db:
            db.execute("BEGIN")
            try:
                self._check_uuid(db)
                self._check_schema(db)
                states = self._audit_state(db, compare_counts=True)
                result = {"ledger_uuid": self.ledger_uuid, "keys": len(states),
                          "reservations": sum(s["consumed"] for s in states.values()),
                          "states": {name: sum(s[name] for s in states.values()) for name in _STATES}}
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def reserve(self, algorithm, public_key, message, *, limit=None):
        algorithm = canonical_algorithm(algorithm)
        public_key = bytes(public_key)
        if not public_key:
            raise ValueError("public key must have content")
        maximum = 1 << (24 if algorithm.endswith("128-24") else 64)
        limit = maximum if limit is None else limit
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit <= maximum:
            raise ValueError("budget limit must be positive and within the parameter allowance")
        identifier, receipt = self.key_id(algorithm, public_key), uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._check_uuid(db)
                self._check_schema(db)
                with self._mutation(db, "reserve"):
                    db.execute("INSERT OR IGNORE INTO keys VALUES(?,?,?,?,?,?)",
                               (identifier, algorithm, public_key, str(limit), "0", now))
                    state = self._key_state(db, identifier)
                    if (state["algorithm"], state["public"], state["limit"]) != (algorithm, public_key, limit):
                        raise BudgetError("registered key or budget limit differs; explicit migration required")
                    if state["used"] >= limit:
                        raise BudgetError("signing budget exhausted; rotate the key")
                    db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)",
                               (receipt, identifier, str(state["used"] + 1), hashlib.sha256(bytes(message)).hexdigest(),
                                now, "reserved", None, None))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return receipt

    def validate_receipt(self, receipt, *, algorithm=None, public_key=None,
                         message=None, message_sha256=None, signature=None,
                         signature_sha256=None, statuses=("committed",)):
        return self.validate_receipts([dict(receipt=receipt, algorithm=algorithm, public_key=public_key,
            message=message, message_sha256=message_sha256, signature=signature,
            signature_sha256=signature_sha256, statuses=statuses)])[0]

    def validate_receipts(self, requests):
        """Validate bound receipts in order in one consistent read transaction.

        One schema/UUID check and one indexed invariant check per distinct key.
        Duplicate requests are allowed; callers enforce operation uniqueness.
        Results retain the single-receipt evidence schema. No history scan.
        """
        requests = list(requests)
        allowed = {"receipt", "algorithm", "public_key", "message", "message_sha256", "signature", "signature_sha256", "statuses"}
        for index, request in enumerate(requests):
            if not isinstance(request, dict) or set(request) - allowed or not isinstance(request.get("receipt"), str) or not request["receipt"]:
                raise ValueError("receipt validation request is malformed")
            statuses = request.get("statuses", ("committed",))
            if not isinstance(statuses, (tuple, list, set, frozenset)) or not statuses or any(status not in _STATES for status in statuses):
                raise ValueError("receipt validation statuses are malformed")
            requests[index] = {**request, "statuses": tuple(statuses)}
        with self.connection() as db:
            db.execute("BEGIN")
            try:
                self._check_uuid(db)
                self._check_schema(db)
                cache, results = {}, []
                for request in requests:
                    receipt = request["receipt"]
                    row = db.execute("SELECT receipt,key_id,ordinal_text,message_sha256,reserved_utc,status,signature_sha256,finished_utc "
                                     "FROM reservations WHERE receipt=?", (receipt,)).fetchone()
                    if row is None or row[5] not in request.get("statuses", ("committed",)):
                        raise BudgetError("receipt missing or status differs from preserved operation")
                    ordinal = self._check_reservation(row)
                    if row[1] not in cache:
                        cache[row[1]] = self._key_state(db, row[1])
                    state = cache[row[1]]
                    if ordinal > state["used"] or state["states"][row[5]] == 0:
                        raise BudgetError("receipt ledger counter reconciliation failed")
                    algorithm, public = request.get("algorithm"), request.get("public_key")
                    if algorithm is not None and state["algorithm"] != canonical_algorithm(algorithm):
                        raise BudgetError("receipt algorithm differs")
                    if public is not None and state["public"] != bytes(public):
                        raise BudgetError("receipt public key differs")
                    for kind, actual in (("message", row[3]), ("signature", row[6])):
                        value, digest = request.get(kind), request.get(kind + "_sha256")
                        if value is not None:
                            computed = hashlib.sha256(bytes(value)).hexdigest()
                            if digest is not None and digest != computed:
                                raise BudgetError(f"receipt {kind} supplied digest differs")
                            digest = computed
                        if digest is not None and actual != digest:
                            raise BudgetError(f"receipt {kind} digest differs")
                    results.append({"ledger_uuid": self.ledger_uuid, "receipt": receipt, "key_id": row[1],
                        "algorithm": state["algorithm"], "public_key_sha256": hashlib.sha256(state["public"]).hexdigest(),
                        "message_sha256": row[3], "status": row[5], "signature_sha256": row[6]})
                db.execute("COMMIT")
                return results
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def finish(self, receipt, signature=None):
        status = "committed" if signature is not None else "failed"
        digest = hashlib.sha256(bytes(signature)).hexdigest() if signature is not None else None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._check_uuid(db)
                self._check_schema(db)
                row = db.execute("SELECT key_id,status FROM reservations WHERE receipt=?", (receipt,)).fetchone()
                if row is None or row[1] != "reserved":
                    raise BudgetError("reservation missing or already finalized")
                state = self._key_state(db, row[0])
                if state["states"]["reserved"] == 0:
                    raise BudgetError("receipt ledger counter reconciliation failed")
                with self._mutation(db, "finish"):
                    changed = db.execute("UPDATE reservations SET status=?,signature_sha256=?,finished_utc=? "
                                         "WHERE receipt=? AND status='reserved'",
                                         (status, digest, datetime.now(timezone.utc).isoformat(), receipt)).rowcount
                    if changed != 1:
                        raise BudgetError("reservation missing or already finalized")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def callback(self, algorithm, public_key, message):
        return self.reserve(algorithm, public_key, message)

    def status(self):
        """Read guarded per-key counters; use audit() for full history checks."""
        with self.connection() as db:
            db.execute("BEGIN")
            try:
                self._check_uuid(db)
                self._check_schema(db)
                result = []
                for identifier, in db.execute("SELECT key_id FROM keys ORDER BY key_id"):
                    state = self._key_state(db, identifier)
                    result.append({"key_id": identifier, "algorithm": state["algorithm"], "limit": state["limit"],
                        "used": state["used"], "remaining": state["limit"] - state["used"],
                        "states": {k: v for k, v in state["states"].items() if v}, "count_reconciled": True})
                db.execute("COMMIT")
                return result
            except BaseException:
                db.execute("ROLLBACK")
                raise


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("--audit", action="store_true", help="perform full history reconciliation")
    args = parser.parse_args()
    budget = SigningBudget(args.database)
    print(json.dumps(budget.audit() if args.audit else budget.status(), indent=2))
