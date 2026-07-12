from __future__ import annotations

import math
import unittest

import numpy as np
from scipy import stats as scipy_stats

from pipeline import stats


class EffectLabelTests(unittest.TestCase):
    def test_boundaries(self) -> None:
        # _effect_label uses strict "<" against each threshold, so a value
        # exactly on a threshold falls into the *next* (larger) bucket.
        self.assertEqual("negligible", stats._effect_label(0.0))
        self.assertEqual("negligible", stats._effect_label(0.05))
        self.assertEqual("small", stats._effect_label(0.1))
        self.assertEqual("small", stats._effect_label(0.29))
        self.assertEqual("medium", stats._effect_label(0.3))
        self.assertEqual("medium", stats._effect_label(0.49))
        self.assertEqual("large", stats._effect_label(0.5))
        self.assertEqual("large", stats._effect_label(0.99))

    def test_uses_absolute_value(self) -> None:
        self.assertEqual("large", stats._effect_label(-0.6))
        self.assertEqual("small", stats._effect_label(-0.1))


class BhFdrCorrectTests(unittest.TestCase):
    def test_empty_input(self) -> None:
        self.assertEqual([], stats._bh_fdr_correct([]))

    def test_matches_scipy_directly(self) -> None:
        p_values = [0.005, 0.011, 0.02, 0.04, 0.13, 0.15, 0.36, 0.4, 0.45, 0.5]
        got = stats._bh_fdr_correct(p_values)
        expected = [float(p) for p in scipy_stats.false_discovery_control(p_values, method="bh")]
        self.assertEqual(len(p_values), len(got))
        for g, e in zip(got, expected):
            self.assertAlmostEqual(g, e, places=10)

    def test_adjusted_p_never_below_raw_p(self) -> None:
        p_values = [0.001, 0.2, 0.03, 0.5, 0.049]
        adjusted = stats._bh_fdr_correct(p_values)
        for raw, adj in zip(p_values, adjusted):
            self.assertGreaterEqual(adj, raw - 1e-12)

    def test_monotonic_in_sorted_order(self) -> None:
        # BH-adjusted p-values are non-decreasing when raw p-values are sorted ascending.
        p_values = sorted([0.5, 0.001, 0.3, 0.02, 0.049, 0.4])
        adjusted = stats._bh_fdr_correct(p_values)
        for earlier, later in zip(adjusted, adjusted[1:]):
            self.assertLessEqual(earlier, later + 1e-12)


class IsValidPTests(unittest.TestCase):
    def test_rejects_none_nan_and_out_of_range(self) -> None:
        self.assertFalse(stats._is_valid_p(None))
        self.assertFalse(stats._is_valid_p(float("nan")))
        self.assertFalse(stats._is_valid_p(-0.0001))
        self.assertFalse(stats._is_valid_p(1.0001))
        self.assertFalse(stats._is_valid_p("0.5"))

    def test_accepts_valid_probabilities(self) -> None:
        self.assertTrue(stats._is_valid_p(0.0))
        self.assertTrue(stats._is_valid_p(1.0))
        self.assertTrue(stats._is_valid_p(0.5))
        self.assertTrue(stats._is_valid_p(1))  # int is fine


class CleanTests(unittest.TestCase):
    def test_filters_none_and_nan_and_converts_to_float(self) -> None:
        out = stats._clean([1, None, "2.5", float("nan"), 3, "not-a-number"])
        self.assertEqual([1.0, 2.5, 3.0], out)


class WmwTieSumTests(unittest.TestCase):
    def test_no_ties_is_zero(self) -> None:
        self.assertEqual(0.0, stats._wmw_tie_sum([1.0, 2.0, 3.0, 4.0]))

    def test_known_tie_pattern(self) -> None:
        # value 1.0 appears 3 times -> 3^3 - 3 = 24; all other values unique -> 0.
        self.assertEqual(24.0, stats._wmw_tie_sum([1.0, 1.0, 1.0, 2.0, 3.0]))

    def test_empty_input(self) -> None:
        self.assertEqual(0.0, stats._wmw_tie_sum([]))


class WmwPowerCoefficientTests(unittest.TestCase):
    def test_none_for_insufficient_n(self) -> None:
        self.assertIsNone(stats._wmw_power_coefficient(1, 5))
        self.assertIsNone(stats._wmw_power_coefficient(5, 1))
        self.assertIsNone(stats._wmw_power_coefficient(None, 5))

    def test_matches_closed_form_with_no_ties(self) -> None:
        n_a, n_b = 10, 12
        N = n_a + n_b
        expected = math.sqrt(3.0 * n_a * n_b / (N + 1))
        self.assertAlmostEqual(expected, stats._wmw_power_coefficient(n_a, n_b, tie_sum=0.0), places=10)

    def test_ties_reduce_the_coefficient(self) -> None:
        # More ties -> smaller effective variance denominator inflation ->
        # the "(N+1) - tie_term" divisor shrinks -> coefficient grows.
        n_a, n_b = 10, 10
        no_ties = stats._wmw_power_coefficient(n_a, n_b, tie_sum=0.0)
        with_ties = stats._wmw_power_coefficient(n_a, n_b, tie_sum=500.0)
        self.assertGreater(with_ties, no_ties)


class RunMannWhitneyTests(unittest.TestCase):
    def test_insufficient_n_returns_all_none(self) -> None:
        result = stats.run_mannwhitney([1.0], [1.0, 2.0, 3.0])
        self.assertEqual(1, result["n_a"])
        self.assertIsNone(result["mw_statistic"])
        self.assertIsNone(result["p_value"])
        self.assertIsNone(result["effect_size_r"])

    def test_completely_separated_groups_give_r_equal_1(self) -> None:
        # Every value in group A exceeds every value in group B -> maximal
        # rank-biserial effect size, r = +1.
        result = stats.run_mannwhitney([10.0, 20.0, 30.0], [1.0, 2.0, 3.0])
        self.assertEqual(9.0, result["mw_statistic"])  # n_a * n_b, max possible U
        self.assertEqual(1.0, result["effect_size_r"])
        self.assertEqual("large", result["effect_label"])

    def test_fully_tied_groups_do_not_crash_and_give_p_one(self) -> None:
        # Degenerate case that historically produced a NaN from scipy's
        # asymptotic method (0/0 in the variance term) -- run_mannwhitney
        # must detect the NaN and fall back to method="exact", which
        # correctly returns p=1.0 (no evidence of a difference) rather than
        # propagating NaN into the FDR-correction pipeline.
        result = stats.run_mannwhitney([10.0] * 6, [10.0] * 6)
        self.assertIsNotNone(result["p_value"])
        self.assertFalse(math.isnan(result["p_value"]))
        self.assertEqual(1.0, result["p_value"])
        self.assertEqual(0.0, result["effect_size_r"])

    def test_power_and_mde_are_populated_for_valid_comparison(self) -> None:
        result = stats.run_mannwhitney([10.0, 20.0, 30.0, 5.0, 15.0], [1.0, 2.0, 3.0, 4.0, 6.0])
        self.assertIsInstance(result["power"], float)
        self.assertIsInstance(result["mde_r_80"], float)
        self.assertGreaterEqual(result["mde_r_80"], 0.0)


class ComputeSpearmanTests(unittest.TestCase):
    def test_insufficient_n_returns_none(self) -> None:
        result = stats.compute_spearman([1, 2], [1, 2])
        self.assertIsNone(result["spearman_r"])
        self.assertEqual(2, result["n"])

    def test_perfect_monotonic_relationship(self) -> None:
        result = stats.compute_spearman([1, 2, 3, 4, 5], [2, 4, 6, 8, 10])
        self.assertEqual(1.0, result["spearman_r"])
        self.assertLess(result["p_value"], 0.05)

    def test_skips_none_and_nan_pairs(self) -> None:
        x = [1, 2, None, 4, 5]
        y = [2, 4, 6, float("nan"), 10]
        result = stats.compute_spearman(x, y)
        self.assertEqual(3, result["n"])  # only (1,2), (2,4), (5,10) survive


class DunnPosthocTests(unittest.TestCase):
    def test_fewer_than_two_groups_returns_empty(self) -> None:
        self.assertEqual({}, stats.dunn_posthoc({"only_group": [1.0, 2.0, 3.0]}))

    def test_returns_all_pairwise_comparisons_with_expected_keys(self) -> None:
        groups = {
            "low": [1.0, 2.0, 3.0, 2.0],
            "mid": [4.0, 5.0, 6.0, 5.0],
            "high": [10.0, 11.0, 12.0, 11.0],
        }
        result = stats.dunn_posthoc(groups)
        # 3 groups -> C(3,2) = 3 pairwise comparisons
        self.assertEqual(3, len(result))
        for pair_result in result.values():
            for key in ("Z", "p_adj", "significant", "effect_size_r_approx", "power", "mde_r_80"):
                self.assertIn(key, pair_result)

    def test_highest_group_has_positive_z_vs_lowest(self) -> None:
        groups = {
            "low": [1.0, 1.0, 2.0, 1.0, 2.0],
            "high": [20.0, 21.0, 19.0, 22.0, 20.0],
        }
        result = stats.dunn_posthoc(groups)
        self.assertIn("low vs high", result)
        # "low" has the smaller mean rank, so Z for "low vs high" should be negative.
        self.assertLess(result["low vs high"]["Z"], 0)


class ComputeDescriptiveStatsTests(unittest.TestCase):
    def test_empty_input(self) -> None:
        result = stats.compute_descriptive_stats([])
        self.assertEqual(0, result["n"])
        self.assertIsNone(result["mean"])

    def test_known_values(self) -> None:
        result = stats.compute_descriptive_stats([1, 2, 3, 4, 5])
        self.assertEqual(5, result["n"])
        self.assertEqual(3.0, result["mean"])
        self.assertEqual(3.0, result["median"])

    def test_filters_none_before_computing(self) -> None:
        result = stats.compute_descriptive_stats([1, None, 2, None, 3])
        self.assertEqual(3, result["n"])
        self.assertEqual(2.0, result["mean"])


class NanToNoneTests(unittest.TestCase):
    def test_replaces_nan_and_infinity(self) -> None:
        obj = {
            "a": float("nan"),
            "b": float("inf"),
            "c": float("-inf"),
            "d": 1.5,
            "e": [1.0, float("nan"), {"f": float("inf")}],
        }
        cleaned = stats._nan_to_none(obj)
        self.assertIsNone(cleaned["a"])
        self.assertIsNone(cleaned["b"])
        self.assertIsNone(cleaned["c"])
        self.assertEqual(1.5, cleaned["d"])
        self.assertEqual([1.0, None, {"f": None}], cleaned["e"])

    def test_leaves_finite_values_and_non_floats_untouched(self) -> None:
        obj = {"n": 5, "s": "hello", "f": 2.5, "none": None}
        self.assertEqual(obj, stats._nan_to_none(obj))


class BuildDesignMatrixTests(unittest.TestCase):
    def _repo(self, category: str, ag_specific: bool, stars: float, contributors: float, scorecard: float | None) -> dict:
        return {
            "category": category,
            "ag_specific": ag_specific,
            "scorecard_overall": scorecard,
            "github_metrics": {"stars": stars, "contributor_count": contributors},
        }

    def test_drops_dummy_column_for_category_absent_after_listwise_deletion(self) -> None:
        # "GhostCategory" only has repos with a missing outcome (None
        # scorecard), so it should vanish from the design matrix's dummy
        # columns entirely -- regression test for the bug where an all-zero
        # dummy column understated that coefficient's standard error instead
        # of being correctly omitted as unidentifiable.
        # Needs >= n_params + 5 retained rows to build at all (n_params = 1
        # intercept + 1 dummy["Other"] + 3 covariates = 5, so >= 10 retained).
        repos = [
            self._repo("Reference", True, 100, 10, 5.0),
            self._repo("Reference", False, 200, 20, 6.0),
            self._repo("Reference", True, 120, 12, 5.5),
            self._repo("Reference", False, 220, 22, 6.5),
            self._repo("Reference", True, 140, 14, 5.2),
            self._repo("Other", True, 150, 15, 4.0),
            self._repo("Other", False, 250, 25, 7.0),
            self._repo("Other", True, 130, 13, 4.5),
            self._repo("Other", False, 230, 23, 6.8),
            self._repo("Other", True, 160, 16, 4.2),
            self._repo("GhostCategory", True, 50, 5, None),  # outcome missing -> dropped
            self._repo("GhostCategory", False, 60, 6, None),  # outcome missing -> dropped
        ]
        built = stats._build_design_matrix(
            repos, lambda r: r["scorecard_overall"], category_reference="Reference"
        )
        self.assertIsNotNone(built)
        y, X, names = built
        self.assertEqual(10, len(y))  # 12 rows minus the 2 with missing outcome
        self.assertNotIn("category[GhostCategory]", names)
        self.assertIn("category[Other]", names)

    def test_returns_none_when_too_few_retained_rows(self) -> None:
        repos = [self._repo("A", True, 100, 10, 5.0), self._repo("A", False, 200, 20, 6.0)]
        built = stats._build_design_matrix(repos, lambda r: r["scorecard_overall"], category_reference="A")
        self.assertIsNone(built)

    def test_rows_missing_ag_specific_are_dropped(self) -> None:
        # Single category "A" (the reference) -> n_params = 1 intercept + 0
        # dummies + 3 covariates = 4, so needs >= 9 retained rows to build.
        repos = [
            self._repo("A", True, 100, 10, 5.0),
            self._repo("A", False, 200, 20, 6.0),
            {"category": "A", "ag_specific": None, "scorecard_overall": 5.0,
             "github_metrics": {"stars": 100, "contributor_count": 10}},
            self._repo("A", True, 110, 11, 5.1),
            self._repo("A", False, 210, 21, 6.1),
            self._repo("A", True, 120, 12, 5.2),
            self._repo("A", False, 220, 22, 6.2),
            self._repo("A", True, 130, 13, 5.3),
            self._repo("A", False, 230, 23, 6.3),
            self._repo("A", True, 140, 14, 5.4),
        ]
        built = stats._build_design_matrix(repos, lambda r: r["scorecard_overall"], category_reference="A")
        self.assertIsNotNone(built)
        y, X, names = built
        self.assertEqual(9, len(y))  # 10 rows minus the 1 with ag_specific=None


class OlsFitTests(unittest.TestCase):
    def test_basic_fit_has_expected_shape_and_se_type(self) -> None:
        rng = np.random.default_rng(0)
        n = 40
        x1 = rng.normal(size=n)
        x2 = rng.integers(0, 2, size=n).astype(float)
        y = 2.0 * x1 + 1.5 * x2 + 3.0 + rng.normal(scale=0.1, size=n)
        X = np.column_stack([np.ones(n), x1, x2])
        names = ["intercept", "x1", "x2"]
        fit = stats._ols_fit(y, X, names)
        self.assertIsNotNone(fit)
        self.assertEqual("HC3", fit["se_type"])
        self.assertEqual(n, fit["n"])
        self.assertEqual(n - 3, fit["dof"])
        self.assertEqual(3, len(fit["coefficients"]))
        x1_coef = next(c for c in fit["coefficients"] if c["term"] == "x1")
        self.assertAlmostEqual(2.0, x1_coef["coef"], delta=0.2)
        self.assertIsNotNone(x1_coef["ci_lo"])
        self.assertIsNotNone(x1_coef["ci_hi"])
        self.assertLess(x1_coef["ci_lo"], x1_coef["coef"])
        self.assertGreater(x1_coef["ci_hi"], x1_coef["coef"])

    def test_returns_none_when_not_enough_degrees_of_freedom(self) -> None:
        X = np.array([[1.0, 2.0], [1.0, 3.0]])
        y = np.array([1.0, 2.0])
        self.assertIsNone(stats._ols_fit(y, X, ["intercept", "x1"]))


if __name__ == "__main__":
    unittest.main()
