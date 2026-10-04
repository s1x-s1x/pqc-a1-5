"""SQLite and preserved-evidence checks; no native code or performance samples."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
import copy
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bench_cpu as cpu
import bench_cuda as cuda
from signing_budget import SigningBudget, BudgetError, canonical_algorithm


class BudgetRepair(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="a15-budget-repair-")
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.path = self.folder / "ledger.sqlite"
        self.public = b"p"*32
        self.message = b"\x00\x01cm"
        self.signature = b"signature"

    def legacy(self, *, corrupt=False, limits=(1, 1)):
        db = sqlite3.connect(self.path)
        db.executescript("""
          CREATE TABLE keys(key_id TEXT PRIMARY KEY,algorithm TEXT NOT NULL,
            public_key BLOB NOT NULL,limit_text TEXT NOT NULL,used_text TEXT NOT NULL,created_utc TEXT NOT NULL);
          CREATE TABLE reservations(receipt TEXT PRIMARY KEY,key_id TEXT NOT NULL REFERENCES keys(key_id),
            ordinal_text TEXT NOT NULL,message_sha256 TEXT NOT NULL,reserved_utc TEXT NOT NULL,
            status TEXT NOT NULL,signature_sha256 TEXT,finished_utc TEXT,UNIQUE(key_id,ordinal_text));
        """)
        for index, algorithm in enumerate(("SLH-DSA-SM3-128-24", "slh-dsa-sm3-128-24")):
            identifier = hashlib.sha256(algorithm.encode()+b"\0"+self.public).hexdigest()
            used = "2" if corrupt and index == 0 else "1"
            db.execute("INSERT INTO keys VALUES(?,?,?,?,?,?)", (identifier, algorithm, self.public, str(limits[index]), used, "2026-01-01"))
            db.execute("INSERT INTO reservations VALUES(?,?,?,?,?,?,?,?)",
                (f"old-{index}", identifier, "1", cpu.sha(self.message), f"2026-01-0{index+1}",
                 "committed" if index == 0 else "failed", cpu.sha(self.signature) if index == 0 else None, "2026-01-03"))
        db.commit(); db.close()

    def test_aliases_share_one_small_allowance(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("SLH-DSA-SM3-128-24", self.public, self.message, limit=1)
        budget.finish(receipt, self.signature)
        with self.assertRaisesRegex(BudgetError, "exhausted"):
            budget.reserve("slh-dsa-sm3-128-24", self.public, self.message, limit=1)
        self.assertEqual(len(budget.status()), 1)
        self.assertEqual(budget.validate_receipt(receipt, algorithm="SLH-DSA-SM3-128-24",
            public_key=self.public, message=self.message, signature=self.signature)["algorithm"], "slh-dsa-sm3-128-24")

    def test_legacy_alias_migration_retains_all_charges_and_receipts(self):
        self.legacy()
        budget = SigningBudget(self.path)
        row = budget.status()[0]
        self.assertEqual((row["used"], row["limit"], row["remaining"]), (2, 1, -1))
        self.assertTrue(row["count_reconciled"])
        self.assertEqual(row["states"], {"committed": 1, "failed": 1})
        budget.validate_receipt("old-0", public_key=self.public, signature=self.signature)
        budget.validate_receipt("old-1", statuses=("failed",))
        self.assertEqual(SigningBudget(self.path).ledger_uuid, budget.ledger_uuid)
        with self.assertRaisesRegex(BudgetError, "exhausted"):
            budget.reserve("SLH-DSA-SM3-128-24", self.public, self.message, limit=1)
        with budget.connection() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM identity_migrations").fetchone()[0], 2)
            self.assertEqual({x[0] for x in db.execute("SELECT ordinal_text FROM reservations")}, {"1", "2"})

    def test_migration_uses_stricter_limit(self):
        self.legacy(limits=(7, 3))
        budget = SigningBudget(self.path)
        self.assertEqual(budget.status()[0]["limit"], 3)
        receipt = budget.reserve("slh-dsa-sm3-128-24", self.public, self.message, limit=3)
        budget.finish(receipt)
        with self.assertRaises(BudgetError):
            budget.reserve("SLH-DSA-SM3-128-24", self.public, self.message, limit=3)

    def test_bad_legacy_count_fails_transactionally(self):
        self.legacy(corrupt=True)
        with self.assertRaisesRegex(BudgetError, "reconciliation"):
            SigningBudget(self.path)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM keys").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM reservations").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM ledger_metadata").fetchone()[0], 0)

    def test_parallel_alias_calls_consume_exact_limit_even_on_failure(self):
        budget = SigningBudget(self.path)
        def attempt(index):
            try:
                ledger = SigningBudget(self.path)
                name = "SLH-DSA-SM3-128-24" if index % 2 else "slh-dsa-sm3-128-24"
                receipt = ledger.reserve(name, self.public, str(index).encode(), limit=7)
                ledger.finish(receipt, self.signature if index % 2 else None)
                return True
            except BudgetError:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            self.assertEqual(sum(pool.map(attempt, range(32))), 7)
        self.assertEqual(budget.status()[0]["used"], 7)
        self.assertTrue(budget.status()[0]["count_reconciled"])

    def test_allowlist_and_bool_limits(self):
        budget = SigningBudget(self.path)
        for name in ("SLH-DSA-SM3-128-24 ", "invented-128-24", "slh-dsa-sha2-unknown"):
            with self.assertRaises(ValueError): budget.reserve(name, self.public, self.message)
        with self.assertRaises(ValueError): budget.reserve("slh-dsa-sm3-128-24", self.public, self.message, limit=True)
        self.assertEqual(canonical_algorithm("ML-DSA-44"), "ml-dsa-44")
        self.assertEqual(SigningBudget.key_id("ML-DSA-44", self.public), SigningBudget.key_id("ml-dsa-44", self.public))

    def test_receipt_checks_every_bound_field(self):
        budget = SigningBudget(self.path)
        receipt = budget.reserve("slh-dsa-sm3-128-24", self.public, self.message)
        with self.assertRaises(BudgetError): budget.validate_receipt(receipt)
        budget.finish(receipt, self.signature)
        for fields in ({"algorithm": "slh-dsa-sm3-128s"}, {"public_key": b"other"},
                       {"message": b"other"}, {"signature": b"other"}):
            with self.assertRaises(BudgetError): budget.validate_receipt(receipt, **fields)
        with self.assertRaises(BudgetError): budget.finish(receipt, self.signature)

    def evidence(self):
        budget = SigningBudget(self.path)
        case = cpu.case_record(3, "sign", samples=1, family="unit")
        inputs = {"pk": self.public, "message": b"m", "context": b"c"}
        binding = cpu.budget_binding(budget, case, inputs)
        receipt = budget.reserve(cpu.ALGORITHMS[3], self.public, self.message)
        budget.finish(receipt, self.signature)
        path = self.folder/"p3-fixture.json"
        path.write_text(json.dumps({k: v.hex() for k, v in inputs.items()}))
        input_hashes = {k: cpu.sha(v) for k, v in inputs.items()}
        sample = {"kind": "sample", "sample_index": 0, "passed": True, "duration_ns": 100,
                  "receipt": receipt, "budget_evidence": budget.validate_receipt(receipt),
                  "result_sha256": cpu.sha(self.signature), "input_hashes": input_hashes,
                  "actual_backend": 5, "end_to_end_ns": 100, "kernel_ns": 40,
                  "cuda_stats": {"kernel_ns": 40, "timing_enabled": 1, "kernel_launches": 1, "device_hashes": 1}}
        complete = {"kind": "case_complete", "ledger_uuid": budget.ledger_uuid,
                    "samples": [100], **cpu.summary([100]), "kernel_samples": [40], "kernel_summary": cpu.summary([40])}
        records = [{"kind": "case_start", "ledger_uuid": budget.ledger_uuid},
                   {"kind": "inputs_ready", "ledger_uuid": budget.ledger_uuid, "budget_binding": binding,
                    "input_hashes": input_hashes, "input_files": {str(path): cpu.file_sha(path)}}, sample, complete]
        return budget, case, records

    def test_complete_cpu_and_cuda_check_live_receipts_before_skip(self):
        budget, case, records = self.evidence()
        self.assertTrue(cpu.validate_completed(records, case, self.folder, budget))
        self.assertTrue(cuda.validate_completed(records, case, self.folder, budget))
        with budget.connection() as db: db.execute("UPDATE reservations SET signature_sha256=?", ("0"*64,))
        for checker in (cpu.validate_completed, cuda.validate_completed):
            with self.assertRaisesRegex(ValueError, "live receipt"):
                checker(records, case, self.folder, budget)

    def test_new_database_rejects_complete_and_partial_resume(self):
        budget, case, records = self.evidence()
        other = SigningBudget(self.folder/"other.sqlite")
        self.assertNotEqual(other.ledger_uuid, budget.ledger_uuid)
        for evidence in (records, records[:-1]):
            with self.assertRaisesRegex(ValueError, "ledger UUID"):
                cpu.validate_preserved_budget(evidence, case, other)

    def test_sample_digest_and_duplicate_receipt_rejected(self):
        budget, case, records = self.evidence()
        changed = copy.deepcopy(records); changed[2]["result_sha256"] = "0"*64
        with self.assertRaisesRegex(ValueError, "signature differs"):
            cpu.validate_preserved_budget(changed, case, budget)
        changed = records+[dict(records[2])]
        with self.assertRaisesRegex(ValueError, "reused"):
            cpu.validate_preserved_budget(changed, case, budget)

    def test_live_uuid_replacement_rejected(self):
        budget = SigningBudget(self.path)
        with budget.connection() as db: db.execute("UPDATE ledger_metadata SET value=? WHERE name='ledger_uuid'", ("0"*32,))
        with self.assertRaisesRegex(BudgetError, "UUID changed"):
            budget.reserve("slh-dsa-sm3-128-24", self.public, self.message)

    def test_fixture_signature_reconciliation(self):
        budget, case, records = self.evidence()
        receipt = records[2]["receipt"]
        saved = {"receipt": receipt, "ledger_uuid": budget.ledger_uuid, "sig": self.signature.hex(),
                 "fixture_sha256": cpu.file_sha(self.folder/"p3-fixture.json")}
        cpu.atomic_json(self.folder/"p3-signature.json", saved)
        cpu.validate_fixture_receipts(self.folder, 3, budget)
        saved["ledger_uuid"] = "0"*32
        (self.folder/"p3-signature.json").write_text(json.dumps(saved))
        with self.assertRaisesRegex(ValueError, "ledger/input binding"):
            cpu.validate_fixture_receipts(self.folder, 3, budget)


if __name__ == "__main__":
    with patch.object(cpu, "NativeSlhDsa", side_effect=AssertionError("native forbidden")), \
         patch.object(cuda, "NativeSlhDsa", side_effect=AssertionError("native forbidden")), \
         patch.object(cpu.time, "perf_counter_ns", side_effect=AssertionError("performance timer forbidden")):
        unittest.main(verbosity=2)
