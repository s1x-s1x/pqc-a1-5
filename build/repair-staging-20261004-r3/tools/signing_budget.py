"""Durable per-key signing reservations for the shared experimental CA.

Every reservation consumes budget before the signing computation starts. Crashes
and failed signatures never refund it. All cooperating issuers must use this
same database; offline copies and restored databases need external reconciliation.
"""
import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid


class BudgetError(RuntimeError):
    pass


# Stable identities are independent of caller spelling (CLI and CA use different
# capitalization). Unknown names fail closed rather than creating another quota.
_ALGORITHMS = {
    **{f"slh-dsa-{hash_name}-{parameter}": f"a15:slh:pid:{pid}"
       for hash_name, parameter, pid in (
           ("sm3", "128s", 1), ("sm3", "128f", 2), ("sm3", "128-24", 3),
           ("sha2", "128s", 101), ("sha2", "128f", 102),
           ("sha2", "128-24", 103), ("sm3", "toy", 201))},
    "ml-dsa-44": "oid:2.16.840.1.101.3.4.3.17",
}


def canonical_algorithm(algorithm):
    if not isinstance(algorithm, str) or algorithm.lower() not in _ALGORITHMS:
        raise ValueError("unsupported signing-budget algorithm")
    return algorithm.lower()


class SigningBudget:
    def __init__(self, database):
        self.path = Path(database).resolve()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connection() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS keys(
                  key_id TEXT PRIMARY KEY, algorithm TEXT NOT NULL,
                  public_key BLOB NOT NULL, limit_text TEXT NOT NULL,
                  used_text TEXT NOT NULL, created_utc TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reservations(
                  receipt TEXT PRIMARY KEY, key_id TEXT NOT NULL REFERENCES keys(key_id),
                  ordinal_text TEXT NOT NULL, message_sha256 TEXT NOT NULL,
                  reserved_utc TEXT NOT NULL, status TEXT NOT NULL,
                  signature_sha256 TEXT, finished_utc TEXT,
                  UNIQUE(key_id, ordinal_text));
                CREATE TABLE IF NOT EXISTS ledger_metadata(
                  name TEXT PRIMARY KEY, value TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS identity_migrations(
                  legacy_key_id TEXT PRIMARY KEY, canonical_key_id TEXT NOT NULL,
                  legacy_algorithm TEXT NOT NULL, legacy_limit_text TEXT NOT NULL,
                  legacy_used_text TEXT NOT NULL, migrated_utc TEXT NOT NULL);
            """)
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT OR IGNORE INTO ledger_metadata VALUES('ledger_uuid',?)", (uuid.uuid4().hex,))
                self._migrate_identity(db)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
            self.ledger_uuid = db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()[0]
            if len(self.ledger_uuid) != 32 or any(c not in "0123456789abcdef" for c in self.ledger_uuid):
                raise BudgetError("ledger UUID is malformed")

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
            if not 0 < int(limit) <= maximum or int(used) < 0:
                raise BudgetError("legacy key allowance is invalid")
            actual = db.execute("SELECT COUNT(*) FROM reservations WHERE key_id=?", (old_id,)).fetchone()[0]
            if actual != int(used):
                raise BudgetError("legacy ledger count reconciliation failed")
            groups.setdefault(identifier, []).append(row)
        now = datetime.now(timezone.utc).isoformat()
        # Preserve every receipt/status/digest. Re-number the merged ordinals in
        # historical time order; never refund charges, including failed calls.
        for identifier, aliases in groups.items():
            name = canonical_algorithm(aliases[0][1])
            public = aliases[0][2]
            limit = min(int(row[3]) for row in aliases)
            used = sum(int(row[4]) for row in aliases)
            created = min(row[5] for row in aliases)
            receipts = []
            for row in aliases:
                receipts.extend(db.execute("SELECT receipt,reserved_utc FROM reservations WHERE key_id=?", (row[0],)).fetchall())
            db.execute("INSERT OR IGNORE INTO keys VALUES(?,?,?,?,?,?)", (identifier, name, public, str(limit), str(used), created))
            for ordinal, (receipt, _) in enumerate(sorted(receipts, key=lambda row: (row[1], row[0])), 1):
                # Negative temporary ordinals prevent collisions if a canonical
                # row already exists in the legacy database.
                db.execute("UPDATE reservations SET key_id=?,ordinal_text=? WHERE receipt=?", (identifier, str(-ordinal), receipt))
            for ordinal, (receipt, _) in enumerate(sorted(receipts, key=lambda row: (row[1], row[0])), 1):
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
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=60000")
        try:
            yield db
        finally:
            db.close()

    @staticmethod
    def key_id(algorithm, public_key):
        name = canonical_algorithm(algorithm)
        return hashlib.sha256(_ALGORITHMS[name].encode("ascii") + b"\0" + bytes(public_key)).hexdigest()

    def reserve(self, algorithm, public_key, message, *, limit=None):
        algorithm = canonical_algorithm(algorithm)
        public_key = bytes(public_key)
        if not public_key:
            raise ValueError("public key must have content")
        maximum = 1 << (24 if algorithm.lower().endswith("128-24") else 64)
        limit = maximum if limit is None else limit
        if not isinstance(limit, int) or isinstance(limit, bool) or not 0 < limit <= maximum:
            raise ValueError("budget limit must be positive and within the parameter allowance")
        identifier, receipt = self.key_id(algorithm, public_key), uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._check_uuid(db)
                db.execute("INSERT OR IGNORE INTO keys VALUES(?,?,?,?,?,?)",
                           (identifier, algorithm, public_key, str(limit), "0", now))
                row = db.execute("SELECT algorithm,public_key,limit_text,used_text FROM keys WHERE key_id=?",
                                 (identifier,)).fetchone()
                if row[:2] != (algorithm, public_key) or int(row[2]) != limit:
                    raise BudgetError("registered key or budget limit differs; explicit migration required")
                used = int(row[3])
                actual = db.execute("SELECT COUNT(*) FROM reservations WHERE key_id=?", (identifier,)).fetchone()[0]
                if actual != used:
                    raise BudgetError("ledger count reconciliation failed")
                if used >= limit:
                    raise BudgetError("signing budget exhausted; rotate the key")
                db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)",
                           (receipt, identifier, str(used + 1), hashlib.sha256(bytes(message)).hexdigest(),
                            now, "reserved", None, None))
                db.execute("UPDATE keys SET used_text=? WHERE key_id=?", (str(used + 1), identifier))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return receipt

    def validate_receipt(self, receipt, *, algorithm=None, public_key=None,
                         message=None, message_sha256=None, signature=None,
                         signature_sha256=None, statuses=("committed",)):
        """Reconcile one preserved operation against this live ledger.

        Digest arguments allow benchmark JSONL to audit RNG validation without
        publishing the validation key or signature. This does not make restored
        or copied ledgers globally monotonic; external anti-rollback is separate.
        """
        with self.connection() as db:
            db.execute("BEGIN")
            self._check_uuid(db)
            row = db.execute("SELECT r.key_id,k.algorithm,k.public_key,r.message_sha256,r.status,"
                             "r.signature_sha256,k.used_text,(SELECT COUNT(*) FROM reservations WHERE key_id=k.key_id) "
                             "FROM reservations r JOIN keys k ON k.key_id=r.key_id WHERE receipt=?", (receipt,)).fetchone()
            if row is None or row[4] not in statuses:
                raise BudgetError("receipt missing or status differs from preserved operation")
            if int(row[6]) != row[7]:
                raise BudgetError("receipt ledger count reconciliation failed")
            if row[0] != self.key_id(row[1], row[2]):
                raise BudgetError("receipt canonical key identity differs")
            if algorithm is not None and row[1] != canonical_algorithm(algorithm):
                raise BudgetError("receipt algorithm differs")
            if public_key is not None and row[2] != bytes(public_key):
                raise BudgetError("receipt public key differs")
            message_digest = hashlib.sha256(bytes(message)).hexdigest() if message is not None else message_sha256
            signature_digest = hashlib.sha256(bytes(signature)).hexdigest() if signature is not None else signature_sha256
            if message_digest is not None and row[3] != message_digest:
                raise BudgetError("receipt message digest differs")
            if signature_digest is not None and row[5] != signature_digest:
                raise BudgetError("receipt signature digest differs")
            if row[4] == "committed" and (not isinstance(row[5], str) or len(row[5]) != 64):
                raise BudgetError("committed receipt lacks signature digest")
            return {"ledger_uuid": self.ledger_uuid, "receipt": receipt, "key_id": row[0],
                    "algorithm": row[1], "public_key_sha256": hashlib.sha256(row[2]).hexdigest(),
                    "message_sha256": row[3], "status": row[4], "signature_sha256": row[5]}

    def _check_uuid(self, db):
        row = db.execute("SELECT value FROM ledger_metadata WHERE name='ledger_uuid'").fetchone()
        if row is None or row[0] != self.ledger_uuid:
            raise BudgetError("live ledger UUID changed")

    def finish(self, receipt, signature=None):
        status = "committed" if signature is not None else "failed"
        digest = hashlib.sha256(bytes(signature)).hexdigest() if signature is not None else None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                self._check_uuid(db)
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
        """Fixture-builder hook; the charged reservation remains auditable."""
        return self.reserve(algorithm, public_key, message)

    def status(self):
        with self.connection() as db:
            keys = db.execute("SELECT key_id,algorithm,limit_text,used_text FROM keys ORDER BY key_id").fetchall()
            result = []
            for key_id, algorithm, limit, used in keys:
                states = dict(db.execute("SELECT status,COUNT(*) FROM reservations WHERE key_id=? GROUP BY status", (key_id,)))
                result.append({"key_id": key_id, "algorithm": algorithm, "limit": int(limit),
                               "used": int(used), "remaining": int(limit) - int(used), "states": states,
                               "count_reconciled": sum(states.values()) == int(used)})
            return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    args = parser.parse_args()
    print(json.dumps(SigningBudget(args.database).status(), indent=2))
