"""Non-timing checks of published anchors, counter accounting and constraints."""

from dataclasses import replace
from decimal import Decimal, localcontext
from fractions import Fraction
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.count_model import cache_model, sign_model, verify_model
from tools.incremental_parameters import (
    Budgets, CANDIDATES, Candidate, ResourceProfile, USAGE_LIMIT, Workload,
    analytical_cost, analytical_row, authentication_calls, excluded_constraints,
    minimax_regret, pareto_relations, region_difference, resources,
    validate_candidate, verify_upstream_readme,
)
from tools.security_terms import fors_probability


class FormulaTests(unittest.TestCase):
    def test_published_size_and_fors_anchors(self):
        anchors = ((3856, 301989889), (3920, 44040193),
                   (4016, 12582913), (4048, 3538945))
        for candidate, (size, fors) in zip(CANDIDATES, anchors):
            row = analytical_row(candidate, 12)
            self.assertEqual((row["signature_bytes"], row["fors_sign_calls"]), (size, fors))

    def test_authentication_cost_by_independent_sibling_tree_enumeration(self):
        for t in range(14):
            # Authentication sibling trees have heights 0..t-1. Each leaf
            # produces 68 PRFs, 204 F steps and one T; each tree has L-1 H.
            enumerated = sum((68 + 204 + 1) * (1 << height) + ((1 << height) - 1)
                             for height in range(t))
            self.assertEqual(authentication_calls(t), enumerated)
        self.assertEqual(authentication_calls(12), 1122018)
        self.assertEqual(authentication_calls(10), 280292)
        self.assertEqual(authentication_calls(12) - authentication_calls(10), 841726)

    def test_cache_storage_anchors_and_counted_vs_uninstrumented_load(self):
        a, b = (analytical_row(CANDIDATES[0], t) for t in (10, 12))
        self.assertEqual((a["cache_file_bytes"], b["cache_file_bytes"]), (65632, 16480))
        self.assertEqual((a["cache_node_ram_bytes"], b["cache_node_ram_bytes"]), (131056, 32752))
        self.assertEqual(a["cache_load_calls"] - b["cache_load_calls"], 3072)
        self.assertEqual(a["cache_load_checksum_compressions_uninstrumented"]
                         - b["cache_load_checksum_compressions_uninstrumented"], 768)
        self.assertEqual(a["cache_load_total_hash_compressions"]
                         - b["cache_load_total_hash_compressions"], 3840)

    def test_costs_agree_with_implemented_counter_model_at_wots_extremes(self):
        fields = ("prf", "prf_msg", "h_msg", "f", "h", "t")
        for candidate in CANDIDATES:
            p = candidate.model_parameter()
            for t in (10, 12):
                row = analytical_row(candidate, t)
                for steps in (0, 108, 204):
                    sign = sign_model(p, 64, (steps,), t, verify_after_sign=True)["counts"]
                    verify = verify_model(p, 64, (steps,))["counts"]
                    # Complete sign+self-verify has fixed total F capacity.
                    self.assertEqual(sum(sign[name] for name in fields), row["sign_calls_with_ref_self_verify"])
                    self.assertEqual(sign["compress"], row["sign_compressions_with_ref_self_verify"])
                    expectation = row["wots_uniform_chain_steps"]
                    self.assertEqual(sum(verify[name] for name in fields) + steps - expectation, row["verify_calls"])
                    self.assertEqual(verify["compress"] + steps - expectation, row["verify_compressions"])

    def test_cache_compression_saving_is_distinct_from_primitive_saving(self):
        x, y = (analytical_row(CANDIDATES[-1], t) for t in (12, 10))
        self.assertEqual(x["sign_calls_with_ref_self_verify"] - y["sign_calls_with_ref_self_verify"], 841726)
        self.assertEqual(x["sign_compressions_with_ref_self_verify"] - y["sign_compressions_with_ref_self_verify"], 893950)
        # A larger cache changes storage/reconstruction, not full keygen work.
        self.assertEqual(x["keygen_or_cache_build_calls"], y["keygen_or_cache_build_calls"])
        self.assertEqual(x["keygen_or_cache_build_compressions"], y["keygen_or_cache_build_compressions"])

    def test_q1_probability_has_independent_closed_form(self):
        for candidate in CANDIDATES:
            probability = fors_probability(candidate.h, candidate.a, candidate.k, 1, precision=100)
            with localcontext() as context:
                context.prec = 200
                exact = Decimal(2) ** -(candidate.h + candidate.a * candidate.k)
            self.assertLessEqual(Decimal(probability["probability_lower"]), exact)
            self.assertGreaterEqual(Decimal(probability["probability_upper"]), exact)
            self.assertFalse(probability["is_full_EUF_CMA_bound"])

    def test_reject_unfrozen_structures_or_levels(self):
        for candidate in (replace(CANDIDATES[0], d=2), replace(CANDIDATES[0], a=25),
                          replace(CANDIDATES[0], k=1 << 20), replace(CANDIDATES[0], a=21)):
            with self.assertRaises(ValueError):
                validate_candidate(candidate)
        for t in (-1, 0, 11, 23):
            with self.assertRaises(ValueError):
                analytical_row(CANDIDATES[0], t)


class ResourceTests(unittest.TestCase):
    def setUp(self):
        self.row = analytical_row(CANDIDATES[0], 12)
        self.profile = ResourceProfile()

    def test_shared_tables_are_not_charged_once_per_worker(self):
        one = resources(self.row, "AF", self.profile)
        four = resources(self.row, "AF", replace(self.profile, workers=4))
        self.assertEqual(four["shared_public_bytes"], one["shared_public_bytes"])
        self.assertEqual(four["modeled_total_live_bytes"] - one["modeled_total_live_bytes"],
                         3 * one["workspace_bytes_per_worker"])
        copies = resources(self.row, "AF", replace(self.profile, public_table_copies=2))
        self.assertEqual(copies["shared_public_bytes"], 2 * one["shared_public_bytes"])

    def test_cache_scales_with_active_keys(self):
        one = resources(self.row, "F8", self.profile)
        four = resources(self.row, "F8", replace(self.profile, active_keys=4))
        self.assertEqual(four["modeled_total_live_bytes"] - one["modeled_total_live_bytes"], 3 * 32752)
        self.assertEqual(four["cache_files_bytes"], 4 * 16480)

    def test_smaller_secret_representation_does_not_claim_smaller_total(self):
        a8 = resources(self.row, "A8", self.profile)
        af = resources(self.row, "AF", self.profile)
        self.assertEqual((a8["persistent_secret_schedule_bytes_per_worker"],
                          af["persistent_secret_schedule_bytes_per_worker"]), (2176, 272))
        self.assertEqual(af["modeled_total_live_bytes"], a8["modeled_total_live_bytes"])
        self.assertEqual(af["stream_object_reserved_bytes_per_worker"], 2304)
        self.assertEqual(af["public_tables_and_atomic_state_reserved_bytes_per_copy"], 53676)
        self.assertFalse(af["is_measured_peak_memory"])

    def test_each_constraint_accepts_boundary_and_rejects_one_above(self):
        m = resources(self.row, "AF", self.profile)
        budget = Budgets(total_memory_bytes=m["modeled_total_live_bytes"],
                         cache_files_bytes=m["cache_files_bytes"], signature_bytes=3856,
                         per_worker_workspace_bytes=m["workspace_bytes_per_worker"])
        self.assertEqual(excluded_constraints(self.row, USAGE_LIMIT, "AF", self.profile, budget), [])
        for field, reason in (("total_memory_bytes", "modeled_total_memory"),
                              ("cache_files_bytes", "aggregate_cache_files"),
                              ("signature_bytes", "signature_size"),
                              ("per_worker_workspace_bytes", "per_worker_workspace")):
            smaller = replace(budget, **{field: getattr(budget, field) - 1})
            self.assertEqual(excluded_constraints(self.row, USAGE_LIMIT, "AF", self.profile, smaller), [reason])
        self.assertEqual(excluded_constraints(self.row, USAGE_LIMIT + 1, "AF", self.profile, budget),
                         ["strict_per_key_lifetime_signatures"])

    def test_four_keys_budget_changes_cache_feasibility(self):
        profile = ResourceProfile(active_keys=4, workers=4)
        t10 = analytical_row(CANDIDATES[0], 10)
        self.assertIn("modeled_total_memory", excluded_constraints(t10, 1, "AF", profile, Budgets()))
        self.assertEqual(excluded_constraints(self.row, 1, "AF", profile, Budgets()), [])

    def test_native_applicability_and_explicit_reserve(self):
        neighbor = analytical_row(CANDIDATES[-1], 12)
        self.assertEqual(excluded_constraints(neighbor, 1, "F8", self.profile,
                                             Budgets(require_native_parameter=True)), ["native_parameter_absent"])
        extra = resources(self.row, "F8", replace(self.profile, auxiliary_workspace_per_worker=20000))
        base = resources(self.row, "F8", self.profile)
        self.assertEqual(extra["modeled_total_live_bytes"] - base["modeled_total_live_bytes"], 3616)
        for profile in (replace(self.profile, workers=0), replace(self.profile, active_keys=-1)):
            with self.assertRaises(ValueError):
                resources(self.row, "AF", profile)


class SelectionTests(unittest.TestCase):
    def test_exact_sign_vs_verify_boundary_with_ref_self_verify(self):
        x, y = (analytical_row(c, 10) for c in (CANDIDATES[0], CANDIDATES[-1]))
        difference = region_difference(x, y)
        self.assertEqual(difference["sign"], 298450932)
        self.assertEqual(difference["external_verify"], -12)
        self.assertEqual(difference["bytes"], -192)
        tie = Workload(1, 24870911, 0)
        self.assertEqual(analytical_cost(x, tie), analytical_cost(y, tie))
        self.assertLess(analytical_cost(x, replace(tie, external_verifications=24870912)),
                        analytical_cost(y, replace(tie, external_verifications=24870912)))
        self.assertGreater(analytical_cost(x, replace(tie, external_verifications=24870910)),
                           analytical_cost(y, replace(tie, external_verifications=24870910)))

    def test_cache_prepare_interaction_depends_on_usage(self):
        t10, t12 = (analytical_row(CANDIDATES[0], t) for t in (10, 12))
        self.assertGreater(analytical_cost(t10, Workload(0, 0, 0)),
                           analytical_cost(t12, Workload(0, 0, 0)))
        self.assertLess(analytical_cost(t10, Workload(1, 0, 0)),
                        analytical_cost(t12, Workload(1, 0, 0)))

    def test_pareto_includes_storage_and_does_not_discard_small_cache(self):
        rows = [analytical_row(c, t) for c in CANDIDATES for t in (10, 12)]
        self.assertTrue(all(not values for values in pareto_relations(rows).values()))
        duplicate = dict(rows[0], configuration="deliberately-worse", signature_bytes=9999)
        relations = pareto_relations(rows + [duplicate])
        self.assertIn(rows[0]["configuration"], relations["deliberately-worse"])

    def test_minimax_regret_uses_same_candidates_in_every_scenario(self):
        rows = [analytical_row(c, 12) for c in (CANDIDATES[0], CANDIDATES[-1])]
        scenarios = (Workload(1, 0, 0), Workload(1, 1 << 30, 0))
        result = minimax_regret(rows, scenarios)
        for row in rows:
            independent_regret = max(analytical_cost(row, scenario)
                                     - min(analytical_cost(y, scenario) for y in rows)
                                     for scenario in scenarios)
            self.assertEqual(result["worst_regret"][row["configuration"]], independent_regret)
        self.assertEqual(result["minimax_ids"], [rows[0]["configuration"]])
        with self.assertRaises(ValueError):
            minimax_regret([], scenarios)

    def test_workload_cost_is_exact_and_float_weights_rejected(self):
        row = analytical_row(CANDIDATES[0], 12)
        value = analytical_cost(row, Workload(1, 3, 7, Fraction(1, 17)))
        self.assertIsInstance(value, Fraction)
        for workload in (Workload(-1, 0, 0), Workload(1, 0, 0, 0.5)):
            with self.assertRaises(ValueError):
                analytical_cost(row, workload)

    def test_pinned_upstream_table_changes_are_detected(self):
        text = "\n".join("| " + c.upstream_id + " | 22 | 1 | 22 | " + str(c.a) + " | "
                         + str(c.k) + " | 2 | 21 | " + str(c.model_parameter().signature_bytes)
                         + " | ignored | ignored | ignored | ignored |" for c in CANDIDATES)
        self.assertEqual(len(verify_upstream_readme(text)), 4)
        for changed in (text.replace("3856", "3857"), text.replace("| 24 | 6 |", "| 23 | 6 |"),
                        text + "\n" + text.splitlines()[0]):
            with self.assertRaises(ValueError):
                verify_upstream_readme(changed)


if __name__ == "__main__":
    unittest.main()
