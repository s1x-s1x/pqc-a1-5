"""Guarded ledger regression using synthetic bytes, never native signing/time."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager
import hashlib
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from signing_budget import SigningBudget, BudgetError, _TABLES

ALGORITHM = "slh-dsa-sm3-128-24"
PUBLIC = b"synthetic public"
MESSAGE = b"synthetic message"
STAMP = "2026-10-04T00:00:00+00:00"
DIGEST = hashlib.sha256(MESSAGE).hexdigest()


def seed_identity_v2(path, count, *, limit=None, algorithm=ALGORITHM,
                     counts_as_states=False):
    """Historical fixture, not a new-ledger bypass or a signing benchmark."""
    limit = limit if limit is not None else max(3, count + 2)
    identifier = SigningBudget.key_id(algorithm, PUBLIC)
    with closing(sqlite3.connect(path)) as db, db:
        for name, ddl in _TABLES.items():
            if name != "ledger_counts":
                db.execute(ddl)
        db.executemany("INSERT INTO ledger_metadata VALUES(?,?)", (("ledger_uuid", "a"*32), ("identity_schema", "2")))
        db.execute("INSERT INTO keys VALUES(?,?,?,?,?,?)", (identifier, algorithm, PUBLIC, str(limit), str(count), STAMP))
        db.executemany("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)", (
            (f"synthetic-{index}", identifier, str(index), DIGEST, STAMP,
             ("committed", "failed", "reserved")[index % 3] if counts_as_states else "reserved",
             DIGEST if counts_as_states and index % 3 == 0 else None,
             STAMP if counts_as_states and index % 3 != 2 else None)
            for index in range(1, count + 1)))
    return identifier


@contextmanager
def count_vm(budget):
    """Count SQLite VM instructions only; don't collect wall-clock samples."""
    original, state, statements = budget.connection, {"opcodes": 0}, []
    @contextmanager
    def connection():
        with original() as db:
            def tick():
                state["opcodes"] += 1
                return 0
            db.set_progress_handler(tick, 1)
            db.set_trace_callback(statements.append)
            try:
                yield db
            finally:
                db.set_progress_handler(None, 0)
                db.set_trace_callback(None)
    with patch.object(budget, "connection", connection):
        yield state, statements


class GuardedBudget(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a15-guarded-budget-")
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "ledger.sqlite"

    def reserve(self, budget, message=MESSAGE, **kwargs):
        return budget.reserve(ALGORITHM, PUBLIC, message, **kwargs)

    def bypass(self, table, statement, values=()):
        """Simulate deliberate corruption by removing/restoring all table guards."""
        with closing(sqlite3.connect(self.path)) as db, db:
            triggers = db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)).fetchall()
            for name, _ddl in triggers:
                db.execute(f"DROP TRIGGER {name}")
            db.execute(statement, values)
            for _name, ddl in triggers:
                db.execute(ddl)

    def test_identity_v2_migration_and_reopen_preserve_receipts_uuid_states(self):
        identifier = seed_identity_v2(self.path, 12, counts_as_states=True)
        with closing(sqlite3.connect(self.path)) as db:
            before = db.execute("SELECT * FROM reservations ORDER BY receipt").fetchall()
        budget = SigningBudget(self.path)
        self.assertEqual(budget.ledger_uuid, "a"*32)
        self.assertEqual(budget.audit()["states"], {"reserved": 4, "committed": 4, "failed": 4})
        with budget.connection() as db:
            self.assertEqual(db.execute("SELECT * FROM reservations ORDER BY receipt").fetchall(), before)
            self.assertEqual(db.execute("SELECT * FROM ledger_counts").fetchone(), (identifier, "12", "4", "4", "4"))
        self.assertEqual(SigningBudget(self.path).audit(), budget.audit())
        receipt = self.reserve(budget, limit=14)
        self.assertEqual(budget.validate_receipt(receipt, statuses=("reserved",))["status"], "reserved")
        budget.finish(receipt)
        self.assertEqual(budget.audit()["reservations"], 13)

    def test_bad_v2_history_is_rejected_without_partial_schema_migration(self):
        seed_identity_v2(self.path, 3)
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("UPDATE reservations SET ordinal_text='7' WHERE receipt='synthetic-2'")
        with self.assertRaisesRegex(BudgetError, "ordinal reconciliation"):
            SigningBudget(self.path)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertIsNone(db.execute("SELECT name FROM sqlite_master WHERE name='ledger_counts'").fetchone())
            self.assertIsNone(db.execute("SELECT value FROM ledger_metadata WHERE name='integrity_schema'").fetchone())

    def test_failure_and_crash_remain_consumed_after_reopen(self):
        budget = SigningBudget(self.path)
        first, second = self.reserve(budget, limit=3), self.reserve(budget, limit=3)
        budget.finish(first)
        budget = SigningBudget(self.path)  # second simulates a killed issuer.
        third = self.reserve(budget, limit=3)
        budget.finish(third, b"synthetic signature")
        self.assertEqual(budget.audit()["states"], dict(reserved=1, committed=1, failed=1))
        self.assertEqual(budget.validate_receipt(second, statuses=("reserved",))["status"], "reserved")
        with self.assertRaisesRegex(BudgetError, "exhausted"):
            self.reserve(budget, limit=3)

    def test_api_connection_blocks_destructive_and_counter_writes(self):
        budget = SigningBudget(self.path)
        receipt = self.reserve(budget)
        attempts = (
            "DELETE FROM reservations", "UPDATE reservations SET ordinal_text='2'",
            "UPDATE reservations SET message_sha256='bad'", "UPDATE reservations SET status='failed'",
            "UPDATE keys SET used_text='0'", "UPDATE keys SET limit_text='1'", "DELETE FROM keys",
            "UPDATE ledger_counts SET consumed_text='0'", "DELETE FROM ledger_counts",
            "UPDATE ledger_metadata SET value='bad'", "DELETE FROM ledger_metadata",
            "INSERT INTO ledger_metadata VALUES('x','y')",
            "INSERT INTO identity_migrations VALUES('a','b','c','1','1','now')")
        with budget.connection() as db:
            for statement in attempts:
                with self.subTest(statement=statement), self.assertRaisesRegex(sqlite3.DatabaseError, "guarded ledger"):
                    db.execute(statement)
        self.assertEqual(budget.audit()["reservations"], 1)
        budget.finish(receipt)

    def test_external_sqlite_connection_also_blocks_normal_writes(self):
        budget = SigningBudget(self.path)
        self.reserve(budget)
        with closing(sqlite3.connect(self.path)) as db:
            for statement in ("DELETE FROM reservations", "UPDATE reservations SET status='failed'", "UPDATE keys SET used_text='0'", "UPDATE ledger_counts SET consumed_text='0'"):
                with self.subTest(statement=statement), self.assertRaises(sqlite3.DatabaseError):
                    db.execute(statement)
        self.assertEqual(budget.audit()["reservations"], 1)

    def test_missing_or_changed_trigger_rejected_on_every_api_and_reopen(self):
        budget = SigningBudget(self.path)
        receipt = self.reserve(budget)
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("DROP TRIGGER a15_reservations_delete")
        for operation in (lambda: self.reserve(budget), lambda: budget.finish(receipt),
                          lambda: budget.validate_receipt(receipt, statuses=("reserved",)),
                          lambda: budget.validate_receipts([]), budget.status, budget.audit,
                          lambda: SigningBudget(self.path)):
            with self.assertRaisesRegex(BudgetError, "trigger missing or altered"):
                operation()
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("CREATE TRIGGER a15_reservations_delete BEFORE DELETE ON reservations BEGIN SELECT 1; END")
        with self.assertRaisesRegex(BudgetError, "trigger missing or altered"):
            self.reserve(budget)

    def test_used_counter_or_state_counter_corruption_rejected(self):
        budget = SigningBudget(self.path)
        receipt = self.reserve(budget)
        self.bypass("keys", "UPDATE keys SET used_text='0'")
        with self.assertRaisesRegex(BudgetError, "counter reconciliation"):
            budget.validate_receipt(receipt, statuses=("reserved",))
        self.bypass("keys", "UPDATE keys SET used_text='1'")
        self.bypass("ledger_counts", "UPDATE ledger_counts SET failed_text='1'")
        with self.assertRaisesRegex(BudgetError, "counter reconciliation"):
            self.reserve(budget)
        with self.assertRaisesRegex(BudgetError, "counter reconciliation"):
            budget.audit()

    def test_altered_trigger_literal_case_or_space_is_rejected(self):
        budget = SigningBudget(self.path)
        with closing(sqlite3.connect(self.path)) as db:
            ddl = db.execute("SELECT sql FROM sqlite_master WHERE name='a15_keys_insert'").fetchone()[0]
        for literal in ("'RESERVE'", "' reserve'", "'reserve '"):
            with self.subTest(literal=literal):
                with closing(sqlite3.connect(self.path)) as db:
                    db.execute("DROP TRIGGER a15_keys_insert")
                    db.execute(ddl.replace("'reserve'", literal))
                with self.assertRaisesRegex(BudgetError, "trigger missing or altered"):
                    self.reserve(budget)
                with self.assertRaisesRegex(BudgetError, "trigger missing or altered"):
                    SigningBudget(self.path)
                with closing(sqlite3.connect(self.path)) as db:
                    db.execute("DROP TRIGGER a15_keys_insert")
                    db.execute(ddl)

    def test_full_audit_detects_internal_deletion_and_ordinal_gap(self):
        seed_identity_v2(self.path, 4)
        budget = SigningBudget(self.path)
        self.bypass("reservations", "UPDATE reservations SET ordinal_text='8' WHERE receipt='synthetic-2'")
        with self.assertRaisesRegex(BudgetError, "ordinal reconciliation"):
            budget.audit()
        with self.assertRaisesRegex(BudgetError, "ordinal reconciliation"):
            SigningBudget(self.path)
        self.bypass("reservations", "UPDATE reservations SET ordinal_text='2' WHERE receipt='synthetic-2'")
        self.bypass("reservations", "DELETE FROM reservations WHERE receipt='synthetic-2'")
        with self.assertRaisesRegex(BudgetError, "count or ordinal reconciliation"):
            budget.audit()

    def test_counter_sum_consistent_with_used_but_wrong_states_detected_on_audit(self):
        budget = SigningBudget(self.path)
        receipt = self.reserve(budget)
        self.bypass("ledger_counts", "UPDATE ledger_counts SET reserved_text='0',committed_text='1'")
        with self.assertRaisesRegex(BudgetError, "receipt ledger counter"):
            budget.finish(receipt)
        with self.assertRaisesRegex(BudgetError, "receipt ledger counter"):
            budget.validate_receipt(receipt, statuses=("reserved",))
        with self.assertRaisesRegex(BudgetError, "full history counter"):
            budget.audit()

    def test_endpoint_deletion_detected_without_history_scan(self):
        seed_identity_v2(self.path, 4)
        budget = SigningBudget(self.path)
        self.bypass("reservations", "DELETE FROM reservations WHERE receipt='synthetic-4'")
        with self.assertRaisesRegex(BudgetError, "endpoint"):
            self.reserve(budget, limit=6)

    def test_cross_instance_concurrency_preserves_exact_allowance_and_states(self):
        ledger_a, ledger_b = SigningBudget(self.path), SigningBudget(self.path)
        def attempt(index):
            try:
                budget = ledger_a if index % 2 else ledger_b
                receipt = budget.reserve(ALGORITHM.upper() if index % 2 else ALGORITHM, PUBLIC, str(index).encode(), limit=17)
                if index % 3 == 0:
                    budget.finish(receipt)
                elif index % 3 == 1:
                    budget.finish(receipt, b"synthetic signature")
                return receipt
            except BudgetError as error:
                if "exhausted" not in str(error):
                    raise
                return None
        with ThreadPoolExecutor(max_workers=8) as pool:
            receipts = list(filter(None, pool.map(attempt, range(48))))
        self.assertEqual(len(receipts), 17)
        self.assertEqual(len(set(receipts)), 17)
        self.assertEqual(ledger_b.audit()["reservations"], 17)
        self.assertEqual(ledger_a.status()[0]["remaining"], 0)

    def test_batch_results_order_duplicates_bindings_and_empty_validation(self):
        budget = SigningBudget(self.path)
        first, second = self.reserve(budget), self.reserve(budget, b"other message")
        budget.finish(first, b"synthetic signature")
        budget.finish(second)
        requests = [{"receipt": second, "statuses": ("failed",)}, {"receipt": first, "signature": b"synthetic signature"}, {"receipt": first}]
        result = budget.validate_receipts(requests)
        self.assertEqual([v["receipt"] for v in result], [second, first, first])
        self.assertEqual(result[1], budget.validate_receipt(first))
        self.assertEqual(budget.validate_receipts([]), [])
        with self.assertRaisesRegex(BudgetError, "message digest"):
            budget.validate_receipts([{ "receipt": first, "message": b"different"}])
        with self.assertRaisesRegex(BudgetError, "supplied digest"):
            budget.validate_receipt(first, message=MESSAGE, message_sha256="0"*64)
        for request in ({}, {"receipt": first, "statuses": "committed"}, {"receipt": first, "statuses": ()}, {"receipt": first, "extra": 1}):
            with self.assertRaises(ValueError):
                budget.validate_receipts([request])

    def test_text_counter_allowance_above_signed_int64(self):
        seed_identity_v2(self.path, 1, algorithm="slh-dsa-sm3-128s", limit=1 << 64)
        budget = SigningBudget(self.path)
        receipt = budget.reserve("slh-dsa-sm3-128s", PUBLIC, MESSAGE)
        budget.finish(receipt, b"synthetic signature")
        self.assertEqual(budget.status()[0]["limit"], 1 << 64)
        self.assertEqual(budget.status()[0]["used"], 2)
        self.assertEqual(SigningBudget._step(str((1 << 63) - 1), 1), str(1 << 63))
        self.assertEqual(SigningBudget._step(str((1 << 64) - 1), 1), str(1 << 64))

    def test_hot_paths_vm_counts_do_not_scale_with_history_or_use_count_query(self):
        results = []
        for count in (1, 1000, 10000):
            path = Path(self.temp.name) / f"history-{count}.sqlite"
            seed_identity_v2(path, count)
            budget = SigningBudget(path)
            with count_vm(budget) as (reserve_count, reserve_sql):
                receipt = self.reserve(budget, limit=count + 2 if count > 1 else 3)
            with count_vm(budget) as (receipt_count, receipt_sql):
                budget.validate_receipt(receipt, statuses=("reserved",))
            requests = [{"receipt": f"synthetic-{i}", "statuses": ("reserved",)} for i in range(1, min(count, 20) + 1)]
            with count_vm(budget) as (batch_count, batch_sql):
                budget.validate_receipts(requests)
            self.assertFalse(any("COUNT(" in sql.upper() for sql in reserve_sql + receipt_sql + batch_sql))
            results.append((reserve_count["opcodes"], receipt_count["opcodes"], batch_count["opcodes"]))
        # Differences from B-tree height remain bounded, vs 30k VM instructions
        # per call for the old linear COUNT at 10k same-key reservations.
        self.assertLess(max(r[0] for r in results) - min(r[0] for r in results), 200)
        self.assertLess(max(r[1] for r in results) - min(r[1] for r in results), 200)
        self.assertLess(results[-1][2], 6000)


if __name__ == "__main__":
    # Test bytes and VM instructions only; performance timers fail explicitly.
    with patch("time.perf_counter_ns", side_effect=AssertionError("performance timer forbidden")):
        unittest.main(verbosity=2)
