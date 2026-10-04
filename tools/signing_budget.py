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
            """)

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
        return hashlib.sha256(algorithm.encode("ascii") + b"\0" + bytes(public_key)).hexdigest()

    def reserve(self, algorithm, public_key, message, *, limit=None):
        public_key = bytes(public_key)
        if not public_key:
            raise ValueError("public key must have content")
        maximum = 1 << (24 if algorithm.lower().endswith("128-24") else 64)
        limit = maximum if limit is None else limit
        if not isinstance(limit, int) or not 0 < limit <= maximum:
            raise ValueError("budget limit must be positive and within the parameter allowance")
        identifier, receipt = self.key_id(algorithm, public_key), uuid.uuid4().hex
        now = datetime.now(timezone.utc).isoformat()
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
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

    def finish(self, receipt, signature=None):
        status = "committed" if signature is not None else "failed"
        digest = hashlib.sha256(bytes(signature)).hexdigest() if signature is not None else None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            try:
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
