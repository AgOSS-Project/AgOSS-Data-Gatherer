"""Tests for control_search/matching.py -- covariate feature engineering
(age_years, _to_feature_row log1p transforms), standardization
(_standardize, including the zero-variance clamp), group filtering
(group_keys_for), and the Mahalanobis-distance-based eligibility/caliper
matching (compute_eligibility) that pairs each dataset repo with same-
language control candidates. Includes a regression test for a NameError
bug in the "closest rejected candidate" diagnostic branch, and a
correctness lock-in test comparing the module's vectorized Mahalanobis
distances against an independently computed
scipy.spatial.distance.mahalanobis value.

control_search/'s own modules import each other by bare module name (e.g.
`import matching`, not `from control_search import matching`), each file
adding its own directory to sys.path at import time rather than relying on
control_search/'s __init__.py. We replicate that same sys.path setup here
before importing the module under test, for consistency with how every
other module in this codebase imports it.
"""
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

import numpy as np
from scipy.spatial.distance import mahalanobis

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CONTROL_SEARCH_DIR = _PROJECT_ROOT / "control_search"
for _p in (str(_PROJECT_ROOT), str(_CONTROL_SEARCH_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import matching  # noqa: E402  (import after sys.path manipulation, matches project convention)


class AgeYearsTests(unittest.TestCase):
    def test_none_input(self) -> None:
        """Verify None and empty-string inputs return None rather than raising."""
        self.assertIsNone(matching.age_years(None))
        self.assertIsNone(matching.age_years(""))

    def test_malformed_input(self) -> None:
        """Verify an unparseable date string returns None instead of raising."""
        self.assertIsNone(matching.age_years("not-a-date"))

    def test_valid_iso_date_gives_positive_age(self) -> None:
        """Verify a well-formed past ISO timestamp yields a positive float age in years."""
        age = matching.age_years("2015-01-01T00:00:00Z")
        self.assertIsInstance(age, float)
        self.assertGreater(age, 5.0)  # comfortably more than 5 years before any plausible "now"

    def test_never_negative(self) -> None:
        """Verify a future "created_at" timestamp clamps age to 0.0 instead of going negative."""
        age = matching.age_years("2099-01-01T00:00:00Z")
        self.assertEqual(0.0, age)


class ToFeatureRowTests(unittest.TestCase):
    def test_known_values_are_log1p_transformed(self) -> None:
        """Verify _to_feature_row applies log1p to stars/forks/contributors/commits/codebase_bytes."""
        cov = {
            "stars": 99.0, "forks": 9.0, "created_at": "2015-01-01T00:00:00Z",
            "contributor_count": 6.0, "commit_activity_52w": 19.0, "codebase_bytes": 999.0,
        }
        row = matching._to_feature_row(cov)
        self.assertAlmostEqual(math.log1p(99.0), row["log_stars"], places=10)
        self.assertAlmostEqual(math.log1p(9.0), row["log_forks"], places=10)
        self.assertAlmostEqual(math.log1p(6.0), row["log_contributor_count"], places=10)
        self.assertAlmostEqual(math.log1p(19.0), row["log_commit_activity_52w"], places=10)
        self.assertAlmostEqual(math.log1p(999.0), row["log_codebase_bytes"], places=10)

    def test_missing_fields_default_to_zero(self) -> None:
        """Verify an empty covariate dict produces a feature row with all-zero values instead of raising KeyError."""
        row = matching._to_feature_row({})
        self.assertEqual(0.0, row["log_stars"])
        self.assertEqual(0.0, row["log_forks"])
        self.assertEqual(0.0, row["age_years"])
        self.assertEqual(0.0, row["log_contributor_count"])


class StandardizeTests(unittest.TestCase):
    def test_mean_and_std_match_manual_computation(self) -> None:
        """Verify _standardize's computed per-feature mean/std match values computed independently with numpy."""
        rows = [
            {f: v for f, v in zip(matching.ALL_FEATURES, [1.0, 2.0, 3.0, 4.0, 5.0, 6.0])},
            {f: v for f, v in zip(matching.ALL_FEATURES, [3.0, 4.0, 5.0, 6.0, 7.0, 8.0])},
            {f: v for f, v in zip(matching.ALL_FEATURES, [5.0, 6.0, 7.0, 8.0, 9.0, 10.0])},
        ]
        mat, mean, std = matching._standardize(rows)
        expected_mean = np.array([3.0, 4.0, 5.0, 6.0, 7.0, 8.0])
        np.testing.assert_allclose(mean, expected_mean)
        expected_std = np.full(6, np.std([1.0, 3.0, 5.0], ddof=0))
        np.testing.assert_allclose(std, expected_std)

    def test_zero_variance_column_does_not_divide_by_zero(self) -> None:
        """Verify a feature column with zero variance clamps std to 1.0 instead of causing a division by zero."""
        # Every row identical on one feature -> std would be 0 -> must clamp to 1.0.
        rows = [
            {f: 5.0 for f in matching.ALL_FEATURES},
            {f: 5.0 for f in matching.ALL_FEATURES},
        ]
        mat, mean, std = matching._standardize(rows)
        self.assertTrue(np.all(std == 1.0))


class GroupKeysForTests(unittest.TestCase):
    def test_filters_by_group(self) -> None:
        """Verify group_keys_for returns all/ag_specific-only/non_ag_specific-only keys correctly, treating None as excluded from both specific groups."""
        all_keys = ["a", "b", "c", "d"]
        ag = {"a": True, "b": False, "c": True, "d": None}
        self.assertEqual(["a", "b", "c", "d"], matching.group_keys_for(all_keys, ag, "all"))
        self.assertEqual(["a", "c"], matching.group_keys_for(all_keys, ag, "ag_specific"))
        self.assertEqual(["b"], matching.group_keys_for(all_keys, ag, "non_ag_specific"))


class ComputeEligibilityTests(unittest.TestCase):
    """Covers the compute_eligibility() code paths, including the exact
    regression scenario for the NameError('diff' is not defined) bug fixed
    in this session: a dataset repo with at least one same-language control
    candidate that falls outside the caliper used to crash the "closest
    rejected candidate" diagnostic branch."""

    def _cov(self, language: str, stars: float, forks: float, contributors: float,
              commits: float, codebase_bytes: float, created_at: str = "2015-01-01T00:00:00Z") -> dict:
        """Build a covariate dict fixture shaped like the ones compute_eligibility expects."""
        return {
            "language": language, "created_at": created_at,
            "stars": stars, "forks": forks, "contributor_count": contributors,
            "commit_activity_52w": commits, "codebase_bytes": codebase_bytes,
        }

    def test_empty_control_pool(self) -> None:
        """Verify a dataset repo with no control candidates at all gets an "empty_control_pool" diagnostic and zero eligible matches."""
        dataset = {"org/repo": self._cov("Python", 100, 20, 10, 50, 500_000)}
        result = matching.compute_eligibility(dataset, {})
        self.assertEqual([], result.eligible["org/repo"])
        diag = result.unmatched_diagnostics["org/repo"]
        self.assertEqual("empty_control_pool", diag["reason"])

    def test_no_language_match(self) -> None:
        """Verify a dataset repo with only different-language controls gets a "no_language_match" diagnostic and no closest candidate."""
        dataset = {"org/repo": self._cov("Python", 100, 20, 10, 50, 500_000)}
        control = {"org/ctrl": self._cov("Go", 100, 20, 10, 50, 500_000)}
        result = matching.compute_eligibility(dataset, control)
        self.assertEqual([], result.eligible["org/repo"])
        diag = result.unmatched_diagnostics["org/repo"]
        self.assertEqual("no_language_match", diag["reason"])
        self.assertIsNone(diag["closest_candidate"])

    def test_close_same_language_candidate_is_matched(self) -> None:
        """Verify a same-language candidate with close covariates is eligible while a different-language candidate is excluded."""
        dataset = {"org/repo": self._cov("Python", 100, 20, 10, 50, 500_000)}
        control = {
            "org/close": self._cov("Python", 105, 22, 11, 52, 510_000),
            "org/wrong-lang": self._cov("Go", 100, 20, 10, 50, 500_000),
        }
        result = matching.compute_eligibility(dataset, control, caliper_quantile=0.99)
        self.assertIn("org/close", result.eligible["org/repo"])
        self.assertNotIn("org/wrong-lang", result.eligible["org/repo"])
        self.assertIsNone(result.unmatched_diagnostics["org/repo"])

    def test_rejected_same_language_candidate_does_not_crash(self) -> None:
        """Regression test for the NameError bug: a dataset repo with same-
        language candidates that are ALL rejected by the caliper must still
        produce a valid 'closest rejected candidate' diagnostic instead of
        crashing on an undefined `diff` variable. An extremely tight caliper
        (quantile≈0) guarantees rejection regardless of the exact covariate
        values chosen here."""
        dataset = {
            "org/repo": self._cov("Python", 100, 20, 10, 50, 500_000),
        }
        control = {
            "org/big": self._cov("Python", 50_000, 8_000, 500, 3_000, 80_000_000),
            "org/small": self._cov("Python", 1, 0, 1, 0, 1_000),
            "org/other-lang": self._cov("Go", 100, 20, 10, 50, 500_000),
        }
        result = matching.compute_eligibility(dataset, control, caliper_quantile=1e-9)

        self.assertEqual([], result.eligible["org/repo"])
        diag = result.unmatched_diagnostics["org/repo"]
        self.assertIsNotNone(diag)
        self.assertEqual("no_candidate_within_caliper", diag["reason"])
        self.assertIn(diag["closest_candidate"], ("org/big", "org/small"))
        self.assertIsInstance(diag["closest_distance"], float)
        self.assertGreaterEqual(diag["closest_distance"], 0.0)
        self.assertIsInstance(diag["exceeded_covariates"], list)
        for item in diag["exceeded_covariates"]:
            self.assertIn("feature", item)
            self.assertIn("label", item)
            self.assertIn("z_diff", item)

    def test_sensitivity_table_present_for_every_dataset_repo(self) -> None:
        """Verify every dataset repo gets a sensitivity_table entry with tight/primary/loose caliper bands, regardless of match outcome."""
        dataset = {
            "org/a": self._cov("Python", 100, 20, 10, 50, 500_000),
            "org/b": self._cov("Rust", 200, 40, 20, 100, 1_000_000),
        }
        control = {"org/c": self._cov("Python", 110, 21, 11, 51, 510_000)}
        result = matching.compute_eligibility(dataset, control)
        for key in dataset:
            self.assertIn(key, result.sensitivity_table)
            for band in ("tight", "primary", "loose"):
                self.assertIn(band, result.sensitivity_table[key])


class MahalanobisDistanceCorrectnessTests(unittest.TestCase):
    """Locks in the cdist-based vectorization introduced this session against
    an independently-computed scipy.spatial.distance.mahalanobis value, so a
    future refactor of the hot distance-computation path can't silently
    change the numbers without a test failing."""

    def test_matches_independent_scipy_mahalanobis_computation(self) -> None:
        """Verify compute_eligibility's internal pairwise distances match scipy's mahalanobis() computed independently on the same standardized data."""
        rng = np.random.default_rng(1)
        dataset = {
            f"org/ds{i}": {
                "language": "Python", "created_at": "2015-01-01T00:00:00Z",
                "stars": float(rng.integers(1, 1000)), "forks": float(rng.integers(0, 200)),
                "contributor_count": float(rng.integers(1, 100)),
                "commit_activity_52w": float(rng.integers(0, 500)),
                "codebase_bytes": float(rng.integers(1000, 10_000_000)),
            }
            for i in range(3)
        }
        control = {
            f"org/ctrl{i}": {
                "language": "Python", "created_at": "2016-01-01T00:00:00Z",
                "stars": float(rng.integers(1, 1000)), "forks": float(rng.integers(0, 200)),
                "contributor_count": float(rng.integers(1, 100)),
                "commit_activity_52w": float(rng.integers(0, 500)),
                "codebase_bytes": float(rng.integers(1000, 10_000_000)),
            }
            for i in range(8)
        }

        # Very loose caliper so every same-language pair is "eligible" and
        # therefore present in result.distances.
        result = matching.compute_eligibility(dataset, control, caliper_quantile=0.999999, max_eligible=20)

        # Independently reproduce the same standardization + ridge-stabilized
        # inverse covariance the module computes internally, then compare a
        # handful of pairs' distances against scipy's own mahalanobis().
        dataset_rows = [matching._to_feature_row(dataset[k]) for k in dataset]
        control_rows = [matching._to_feature_row(control[k]) for k in control]
        all_rows = dataset_rows + control_rows
        mat, mean, std = matching._standardize(all_rows)
        z = (mat - mean) / std
        cov = np.cov(z, rowvar=False)
        cov = cov + np.eye(cov.shape[0]) * 1e-6
        inv_cov = np.linalg.pinv(cov)

        n_dataset = len(dataset_rows)
        z_dataset = z[:n_dataset]
        z_control = z[n_dataset:]

        checked_any = False
        for i, dkey in enumerate(dataset):
            for j, ckey in enumerate(control):
                if ckey not in result.distances.get(dkey, {}):
                    continue
                expected = mahalanobis(z_dataset[i], z_control[j], inv_cov)
                actual = result.distances[dkey][ckey]
                self.assertAlmostEqual(expected, actual, places=8)
                checked_any = True
        self.assertTrue(checked_any, "test setup produced no eligible pairs to check")


if __name__ == "__main__":
    unittest.main()
