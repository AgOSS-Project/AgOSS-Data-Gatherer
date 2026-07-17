"""Eligibility (hard exact-match gate + Mahalanobis caliper), covariate balance
diagnostics, and repeated random matched-pair effect estimation.

Methodology (see the project plan for full rationale):
  - Hard gate: exact primary-language match (coarsened exact matching). A
    dataset repo with zero same-language candidates has zero eligible
    controls -- there is no ecosystem-bucket fallback, since matching against
    a different-language proxy would reintroduce the confound matching is
    meant to remove. Unmatched repos are reported separately, not dropped
    silently.
  - Soft ranking: Mahalanobis distance over six standardized covariates (log
    stars, log forks, age, log contributor count, log recent commit
    activity, log codebase size), chosen over raw Euclidean distance because
    it accounts for covariate correlation and is the standard choice in the
    matching literature for a small covariate set and modest sample size.
    release_count and dependency_count are excluded as plausible mediators
    of ag-specific status rather than confounds (per-repo vuln_density
    normalizes for dependency count at the outcome layer instead);
    owner_is_org was dropped as the noisiest of the original covariates and
    a weak driver of caliper failures.
  - Caliper threshold: chi-squared distribution with degrees of freedom =
    number of covariates (squared Mahalanobis distances are asymptotically
    chi-squared distributed under joint normality).
  - Balance diagnostics: standardized mean difference (SMD) per covariate,
    before (dataset vs. full pool) and after (vs. matched-eligible controls),
    following the Rosenbaum/Rubin/Austin convention.
  - Primary estimate: deterministic top-k nearest-neighbor matching (no
    random re-assignment), with a nonparametric bootstrap CI over the
    matched pairs themselves.
  - Secondary robustness check: repeated random matching across many seeds,
    drawing k controls at random from the eligible pool per repo, reported
    as median + [2.5, 97.5] percentile interval -- tests whether the
    conclusion survives looser, non-optimal matching assignment.
"""

from __future__ import annotations

import logging
import math
import random
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
from scipy import stats as scipy_stats
from scipy.spatial.distance import cdist

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
for _p in (str(_PROJECT_ROOT), str(_THIS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pipeline.models import RepoEntry
from pipeline.stats import _bh_fdr_correct, _effect_label, _ols_fit, bootstrap_ci

logger = logging.getLogger("control_search.matching")

CONTINUOUS_COVARIATES = [
    "log_stars", "log_forks", "age_years", "log_contributor_count",
    "log_commit_activity_52w", "log_codebase_bytes",
]
ALL_FEATURES = CONTINUOUS_COVARIATES

# Human-readable labels for the standardized matching features, used in the
# "why didn't this repo match" diagnostics.
FEATURE_LABELS = {
    "log_stars": "star count",
    "log_forks": "fork count",
    "age_years": "repository age",
    "log_contributor_count": "contributor count",
    "log_commit_activity_52w": "recent commit activity",
    "log_codebase_bytes": "codebase size",
}

# Threshold (in standardized units) above which a covariate is considered to
# have meaningfully contributed to a rejected candidate's distance, for the
# "why didn't this repo match" / "closest rejected candidate" diagnostics.
DIAGNOSTIC_Z_THRESHOLD = 1.0

# Sample size above which the Wilcoxon signed-rank test uses the normal
# approximation instead of the exact distribution (standard convention: exact
# below ~20-25). Pins scipy's 'auto' selection, which can otherwise pick the
# exact combinatorial calculation and blow up to multi-hour runtimes on
# unfavorable tie/zero patterns at this dataset's size.
WILCOXON_EXACT_MAX_N = 25

# Covariates shown in the raw before/after distribution plots — same
# dimensions as ALL_FEATURES but in human-scale (un-logged, un-standardized)
# units for readability.
RAW_COVARIATE_LABELS = {
    "stars": "Stars",
    "forks": "Forks",
    "age_years": "Repository Age (years)",
    "contributor_count": "Contributors",
    "commit_activity_52w": "Commits (last 52 weeks)",
    "codebase_bytes": "Codebase Size (bytes)",
}

def age_years(created_at: str | None) -> float | None:
    """Return repository age in years from an ISO created_at timestamp, or None if unparseable/missing."""
    if not created_at:
        return None
    try:
        created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    return max(0.0, (now - created).days / 365.25)


def _to_feature_row(cov: dict[str, Any]) -> dict[str, float]:
    """Convert raw covariates into the standardized (log1p'd) feature dict
    used for Mahalanobis distance and eligibility matching."""
    stars = float(cov.get("stars") or 0)
    forks = float(cov.get("forks") or 0)
    age = age_years(cov.get("created_at"))
    # log1p'd like stars/forks: right-skewed GitHub activity counts (e.g.
    # commit_activity_52w has mean 807 vs. median 10) would otherwise let a
    # few outlier repos dominate the Mahalanobis covariance matrix.
    contributor_count = float(cov.get("contributor_count") or 0)
    commit_activity_52w = float(cov.get("commit_activity_52w") or 0)
    # codebase_bytes (total non-notebook language bytes) is at least as
    # right-skewed as stars/forks -- a handful of large monorepos vs. many
    # small single-purpose tools -- so it gets the same log1p treatment.
    codebase_bytes = float(cov.get("codebase_bytes") or 0)
    return {
        "log_stars": math.log1p(max(0.0, stars)),
        "log_forks": math.log1p(max(0.0, forks)),
        "age_years": age if age is not None else 0.0,
        "log_contributor_count": math.log1p(max(0.0, contributor_count)),
        "log_commit_activity_52w": math.log1p(max(0.0, commit_activity_52w)),
        "log_codebase_bytes": math.log1p(max(0.0, codebase_bytes)),
        "release_count": float(cov.get("release_count") or 0),
        "dependency_count": float(cov.get("dependency_count") or 0),
        "owner_is_org": 1.0 if str(cov.get("owner_type") or "").lower() == "organization" else 0.0,
    }


def raw_covariate_value(cov: dict[str, Any], feature: str) -> float | None:
    """Human-scale (un-logged, un-standardized) value of a matching covariate,
    for the before/after distribution plots."""
    if feature == "stars":
        v = cov.get("stars")
    elif feature == "forks":
        v = cov.get("forks")
    elif feature == "age_years":
        return age_years(cov.get("created_at"))
    elif feature == "contributor_count":
        v = cov.get("contributor_count")
    elif feature == "commit_activity_52w":
        v = cov.get("commit_activity_52w")
    elif feature == "codebase_bytes":
        v = cov.get("codebase_bytes")
    elif feature == "release_count":
        v = cov.get("release_count")
    elif feature == "dependency_count":
        v = cov.get("dependency_count")
    elif feature == "owner_is_org":
        return 1.0 if str(cov.get("owner_type") or "").lower() == "organization" else 0.0
    else:
        return None
    return float(v) if v is not None else None


def _standardize(rows: list[dict[str, float]]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Stack feature rows into a matrix and return (matrix, mean, std), pinning
    zero-variance columns to std=1 to avoid a divide-by-zero downstream."""
    mat = np.array([[r[f] for f in ALL_FEATURES] for r in rows], dtype=float)
    mean = mat.mean(axis=0)
    std = mat.std(axis=0, ddof=0)
    std[std == 0] = 1.0
    return mat, mean, std


@dataclass
class EligibilityResult:
    """Result of compute_eligibility(): per-dataset-repo eligible controls,
    sensitivity counts, caliper thresholds, distances, and unmatched diagnostics."""
    eligible: dict[str, list[str]] = field(default_factory=dict)
    sensitivity_table: dict[str, dict[str, int]] = field(default_factory=dict)
    caliper_chi2: dict[str, float] = field(default_factory=dict)
    # dataset_key -> {control_key: Mahalanobis distance}, one entry per key in
    # `eligible[dataset_key]` (i.e. only for pairs within the primary caliper).
    # Distance here is the actual (non-squared) Mahalanobis distance, sqrt(d2).
    distances: dict[str, dict[str, float]] = field(default_factory=dict)
    # dataset_key -> diagnostic dict for repos with zero eligible controls
    # ("why didn't this repo match" + "closest rejected candidate"), or None
    # for repos that matched successfully. See compute_eligibility().
    unmatched_diagnostics: dict[str, dict[str, Any] | None] = field(default_factory=dict)


def group_keys_for(all_keys: list[str], dataset_ag_specific: dict[str, bool | None], group: str) -> list[str]:
    """Filter dataset keys down to a group ('all' / 'ag_specific' / 'non_ag_specific'),
    matching the same grouping convention used in run_seeds()."""
    if group == "ag_specific":
        return [k for k in all_keys if dataset_ag_specific.get(k) is True]
    if group == "non_ag_specific":
        return [k for k in all_keys if dataset_ag_specific.get(k) is False]
    return list(all_keys)


def compute_eligibility(
    dataset_covariates: dict[str, dict[str, Any]],
    control_covariates: dict[str, dict[str, Any]],
    *,
    caliper_quantile: float = 0.5,
    tight_quantile: float = 0.25,
    loose_quantile: float = 0.75,
    max_eligible: int = 20,
) -> EligibilityResult:
    """Hard exact-language gate (no ecosystem-bucket fallback) + Mahalanobis-distance caliper."""
    dataset_keys = list(dataset_covariates.keys())
    control_keys = list(control_covariates.keys())

    # Repos with a failed GitHub metadata fetch (fetch_error set) have no
    # trustworthy covariates -- exclude them rather than let _to_feature_row's
    # `or 0` fallbacks fake "zero stars, brand new" as real data.
    bad_dataset_keys = {k for k in dataset_keys if dataset_covariates[k].get("fetch_error")}
    good_dataset_keys = [k for k in dataset_keys if k not in bad_dataset_keys]
    good_control_keys = [k for k in control_keys if not control_covariates[k].get("fetch_error")]
    fetch_failed_diagnostic = {
        "reason": "covariate_fetch_failed",
        "reason_label": "GitHub metadata fetch failed for this repo -- covariates unavailable",
        "closest_candidate": None, "closest_distance": None, "exceeded_covariates": [],
    }

    if not good_control_keys:
        return EligibilityResult(
            eligible={k: [] for k in dataset_keys},
            sensitivity_table={k: {"tight": 0, "primary": 0, "loose": 0} for k in dataset_keys},
            caliper_chi2={},
            distances={k: {} for k in dataset_keys},
            unmatched_diagnostics={
                k: (
                    dict(fetch_failed_diagnostic) if k in bad_dataset_keys else {
                        "reason": "empty_control_pool",
                        "reason_label": "Control pool is empty",
                        "closest_candidate": None, "closest_distance": None, "exceeded_covariates": [],
                    }
                )
                for k in dataset_keys
            },
        )

    dataset_keys, control_keys = good_dataset_keys, good_control_keys
    dataset_rows = [_to_feature_row(dataset_covariates[k]) for k in dataset_keys]
    control_rows = [_to_feature_row(control_covariates[k]) for k in control_keys]

    all_rows = dataset_rows + control_rows
    mat, mean, std = _standardize(all_rows)
    z = (mat - mean) / std

    n_dataset = len(dataset_rows)
    z_dataset = z[:n_dataset]
    z_control = z[n_dataset:]

    cov = np.cov(z, rowvar=False)
    cov = cov + np.eye(cov.shape[0]) * 1e-6  # numerical stability
    inv_cov = np.linalg.pinv(cov)

    df = len(ALL_FEATURES)
    thresholds = {
        "tight": float(scipy_stats.chi2.ppf(tight_quantile, df)),
        "primary": float(scipy_stats.chi2.ppf(caliper_quantile, df)),
        "loose": float(scipy_stats.chi2.ppf(loose_quantile, df)),
    }

    dataset_langs_raw = [(dataset_covariates[k].get("language") or "").strip().lower() for k in dataset_keys]
    control_langs_raw = [(control_covariates[k].get("language") or "").strip().lower() for k in control_keys]

    eligible: dict[str, list[str]] = {}
    sensitivity_table: dict[str, dict[str, int]] = {}
    distances: dict[str, dict[str, float]] = {}
    unmatched_diagnostics: dict[str, dict[str, Any] | None] = {}

    # Full dataset x control squared-Mahalanobis-distance matrix in one call.
    # VI is passed explicitly (this function's ridge-stabilized inverse
    # covariance) so the numerical-stability epsilon above is honored.
    d2_matrix = cdist(z_dataset, z_control, metric="mahalanobis", VI=inv_cov) ** 2

    for i, dkey in enumerate(dataset_keys):
        d2 = d2_matrix[i]  # squared Mahalanobis distance from this dataset repo to every control

        # Hard gate: exact primary-language match only. A dataset repo with no
        # same-language candidate in the control pool has zero eligible
        # controls -- there is no ecosystem-bucket fallback -- and is dropped
        # into the unmatched cohort below.
        mask = np.array([lang == dataset_langs_raw[i] and lang != "" for lang in control_langs_raw])

        sens = {}
        for label in ("tight", "primary", "loose"):
            sens[label] = int(np.sum(mask & (d2 <= thresholds[label])))
        sensitivity_table[dkey] = sens

        primary_mask = mask & (d2 <= thresholds["primary"])
        idxs = np.where(primary_mask)[0]
        idxs = idxs[np.argsort(d2[idxs])][:max_eligible]
        eligible[dkey] = [control_keys[j] for j in idxs]
        distances[dkey] = {control_keys[j]: float(np.sqrt(max(0.0, d2[j]))) for j in idxs}

        # "Why didn't this repo match" / "closest rejected candidate" diagnostics —
        # only computed for repos that ended up with zero eligible controls.
        if eligible[dkey]:
            unmatched_diagnostics[dkey] = None
        elif not mask.any():
            unmatched_diagnostics[dkey] = {
                "reason": "no_language_match",
                "reason_label": "No control-pool repo shares this exact primary language",
                "closest_candidate": None,
                "closest_distance": None,
                "exceeded_covariates": [],
            }
        else:
            masked_idxs = np.where(mask)[0]
            closest_local = int(masked_idxs[np.argmin(d2[masked_idxs])])
            # Per-covariate standardized difference to just this one rejected
            # candidate (cheap: O(n_features), not the full O(n_control) diff
            # matrix) -- explains *which* covariate(s) pushed it outside the
            # caliper. Sign is dataset-minus-control; only abs() is used below.
            closest_diff = z_dataset[i] - z_control[closest_local]
            exceeded = [
                (ALL_FEATURES[j], float(abs(closest_diff[j])))
                for j in range(len(ALL_FEATURES))
                if abs(closest_diff[j]) > DIAGNOSTIC_Z_THRESHOLD
            ]
            exceeded.sort(key=lambda t: -t[1])
            unmatched_diagnostics[dkey] = {
                "reason": "no_candidate_within_caliper",
                "reason_label": (
                    f"Closest candidate's {FEATURE_LABELS.get(exceeded[0][0], exceeded[0][0])} was too "
                    "different (exceeded the matching caliper)"
                    if exceeded else
                    "Closest candidate was outside the overall matching caliper"
                ),
                "closest_candidate": control_keys[closest_local],
                "closest_distance": float(np.sqrt(max(0.0, d2[closest_local]))),
                "exceeded_covariates": [
                    {"feature": f, "label": FEATURE_LABELS.get(f, f), "z_diff": round(z, 3)}
                    for f, z in exceeded
                ],
            }

    # Add back the fetch-failed dataset repos filtered out above -- they never
    # entered the distance computation, so they need their own zero-eligible
    # entries added here rather than being silently absent from the result.
    for k in bad_dataset_keys:
        eligible[k] = []
        sensitivity_table[k] = {"tight": 0, "primary": 0, "loose": 0}
        distances[k] = {}
        unmatched_diagnostics[k] = dict(fetch_failed_diagnostic)

    return EligibilityResult(
        eligible=eligible,
        sensitivity_table=sensitivity_table, caliper_chi2=thresholds,
        distances=distances, unmatched_diagnostics=unmatched_diagnostics,
    )


def compute_balance(
    dataset_covariates: dict[str, dict[str, Any]],
    control_covariates: dict[str, dict[str, Any]],
    eligibility: EligibilityResult,
    *,
    dataset_keys_filter: list[str] | None = None,
    k: int | None = None,
) -> dict[str, dict[str, float | None]]:
    """Standardized mean difference (SMD) per covariate, before (dataset vs.
    full control pool) vs after (dataset vs. the union of each repo's top-k
    matched controls) matching. k=None instead uses the full caliper-eligible
    union. dataset_keys_filter restricts the dataset side to a subgroup."""
    keys = dataset_keys_filter if dataset_keys_filter is not None else list(dataset_covariates.keys())
    dataset_rows = [_to_feature_row(dataset_covariates[k2]) for k2 in keys if k2 in dataset_covariates]
    pool_rows = [_to_feature_row(v) for v in control_covariates.values()]

    eligible_subset = {
        dk: (v[:k] if k is not None else v)
        for dk, v in eligibility.eligible.items() if dk in keys
    }
    matched_keys = sorted({c for lst in eligible_subset.values() for c in lst})
    # No `or pool_rows` fallback: zero matched controls must surface as
    # smd_after=None, not silently fall back to the full pool.
    matched_rows = [_to_feature_row(control_covariates[mk]) for mk in matched_keys if mk in control_covariates]

    def _smd(a: list[dict], b: list[dict], feature: str) -> float | None:
        """Standardized mean difference between two feature-value samples,
        or None if either sample has fewer than 2 rows."""
        if len(a) < 2 or len(b) < 2:
            return None
        av = np.array([r[feature] for r in a], dtype=float)
        bv = np.array([r[feature] for r in b], dtype=float)
        pooled_var = (av.var(ddof=1) + bv.var(ddof=1)) / 2.0
        if pooled_var <= 0:
            return 0.0
        return float((av.mean() - bv.mean()) / math.sqrt(pooled_var))

    balance: dict[str, dict[str, float | None]] = {}
    for feature in ALL_FEATURES:
        balance[feature] = {
            "smd_before": _smd(dataset_rows, pool_rows, feature),
            "smd_after": _smd(dataset_rows, matched_rows, feature),
        }
    return balance


def compute_matching_quality(
    eligibility: EligibilityResult,
    n_dataset_repos: int,
    *,
    k_options: tuple[int, ...] = (1, 3, 5),
    dataset_keys_filter: list[str] | None = None,
) -> dict[str, Any]:
    """Summary stats on match *quality* (nearest-match Mahalanobis distance),
    distinct from raw eligible-control counts. dataset_keys_filter restricts
    to a subgroup; avg_controls_per_repo is reported per k_options value so
    the dashboard's k selector doesn't need to recompute anything."""
    keys = dataset_keys_filter if dataset_keys_filter is not None else list(eligibility.eligible.keys())
    matched_keys = [dk for dk in keys if eligibility.eligible.get(dk)]
    n_matched = len(matched_keys)

    nearest_distances: list[float] = []
    for dk in matched_keys:
        dists = sorted(eligibility.distances.get(dk, {}).values())
        if dists:
            nearest_distances.append(dists[0])

    def _r4(fn, vals: list[float]) -> float | None:
        """Apply fn to vals and round to 4 decimals, or None if vals is empty."""
        return round(float(fn(vals)), 4) if vals else None

    avg_controls_per_repo_by_k: dict[str, float | None] = {
        str(kval): _r4(np.mean, [
            float(min(kval, len(eligibility.eligible.get(dk, [])))) for dk in matched_keys
        ])
        for kval in k_options
    }

    # Repos dropped specifically because no control repo shares their exact
    # primary language (as opposed to having a language match but failing the
    # Mahalanobis caliper) — the hard-gate cost, reported transparently since
    # these repos never get a chance at a match regardless of caliper width.
    n_dropped_no_language_match = sum(
        1 for dk in keys
        if (eligibility.unmatched_diagnostics.get(dk) or {}).get("reason") == "no_language_match"
    )

    # Caliper sensitivity, aggregated over this group — answers "is the
    # matched-pool composition an artifact of one arbitrary caliper width."
    # eligibility.sensitivity_table already holds per-repo eligible-count at
    # the tight/primary/loose calipers (computed once in compute_eligibility,
    # cheap to aggregate here — no extra Scorecard/dependency collection).
    caliper_sensitivity: dict[str, dict[str, float | None]] = {}
    for label in ("tight", "primary", "loose"):
        counts = [float(eligibility.sensitivity_table.get(dk, {}).get(label, 0)) for dk in keys]
        n_with_any = sum(1 for c in counts if c > 0)
        caliper_sensitivity[label] = {
            "avg_eligible_controls": _r4(np.mean, counts),
            "pct_repos_matched": round(100.0 * n_with_any / len(keys), 1) if keys else None,
        }

    return {
        "n_successfully_matched": n_matched,
        "avg_controls_per_repo_by_k": avg_controls_per_repo_by_k,
        "n_dropped_no_language_match": n_dropped_no_language_match,
        "mean_nearest_distance": _r4(np.mean, nearest_distances),
        "median_nearest_distance": _r4(np.median, nearest_distances),
        "max_nearest_distance": _r4(np.max, nearest_distances),
        "nearest_distances": [round(d, 4) for d in nearest_distances],
        "caliper_sensitivity": caliper_sensitivity,
    }


def characterize_unmatched(
    dataset_covariates: dict[str, dict[str, Any]],
    eligibility: EligibilityResult,
) -> dict[str, Any]:
    """Compare covariate profiles of matched vs. unmatched dataset repos, to
    check whether unmatched repos are systematically different (e.g. larger,
    older) from matched ones. Reports both mean- and median-based
    unmatched/matched ratios per covariate, since the unmatched group is
    often small enough for a mean ratio to be skewed by one outlier."""
    matched_keys = [k for k, v in eligibility.eligible.items() if v]
    unmatched_keys = [k for k, v in eligibility.eligible.items() if not v]

    def _stats_for(keys: list[str], feature: str) -> dict[str, Any]:
        """Mean/median/count of one raw covariate's values across keys, skipping missing values."""
        vals = [
            v for k in keys
            if k in dataset_covariates and (v := raw_covariate_value(dataset_covariates[k], feature)) is not None
        ]
        if not vals:
            return {"mean": None, "median": None, "n": 0}
        return {"mean": round(float(np.mean(vals)), 2), "median": round(float(np.median(vals)), 2), "n": len(vals)}

    def _ratio(numerator: float | None, denominator: float | None) -> float | None:
        """Return numerator/denominator rounded to 2 decimals, or None if either is missing/zero."""
        if numerator is None or denominator in (None, 0):
            return None
        return round(numerator / denominator, 2)

    by_covariate: dict[str, dict[str, Any]] = {}
    for feature in RAW_COVARIATE_LABELS:
        matched_stats = _stats_for(matched_keys, feature)
        unmatched_stats = _stats_for(unmatched_keys, feature)
        by_covariate[feature] = {
            "matched": matched_stats,
            "unmatched": unmatched_stats,
            "unmatched_to_matched_mean_ratio": _ratio(unmatched_stats["mean"], matched_stats["mean"]),
            "unmatched_to_matched_median_ratio": _ratio(unmatched_stats["median"], matched_stats["median"]),
        }

    return {
        "n_matched": len(matched_keys),
        "n_unmatched": len(unmatched_keys),
        "by_covariate": by_covariate,
    }


def compute_covariate_distributions(
    dataset_covariates: dict[str, dict[str, Any]],
    control_covariates: dict[str, dict[str, Any]],
    eligibility: EligibilityResult,
    *,
    dataset_keys_filter: list[str] | None = None,
    k: int | None = None,
) -> dict[str, dict[str, list[float]]]:
    """Raw (human-scale, un-logged) covariate values for the before/after
    distribution plots: dataset group vs full control pool (before), and
    dataset group vs its matched controls at k (top-k nearest-eligible per
    repo, unioned across the group -- same "actually used" sample as
    compute_balance(k=...), not the full caliper-eligible superset). Pass
    k=None for the full-eligible-union behavior instead."""
    keys = dataset_keys_filter if dataset_keys_filter is not None else list(dataset_covariates.keys())
    eligible_subset = {
        dk: (v[:k] if k is not None else v)
        for dk, v in eligibility.eligible.items() if dk in keys
    }
    matched_keys = sorted({c for lst in eligible_subset.values() for c in lst})

    out: dict[str, dict[str, list[float]]] = {}
    for feature in RAW_COVARIATE_LABELS:
        dataset_vals = [
            v for dk in keys
            if (v := raw_covariate_value(dataset_covariates.get(dk, {}), feature)) is not None
        ]
        pool_vals = [
            v for cov in control_covariates.values()
            if (v := raw_covariate_value(cov, feature)) is not None
        ]
        matched_vals = [
            v for ck in matched_keys
            if ck in control_covariates and (v := raw_covariate_value(control_covariates[ck], feature)) is not None
        ]
        out[feature] = {
            "dataset": dataset_vals,
            "control_pool": pool_vals,
            "matched_controls": matched_vals,
        }
    return out


def build_standard_groups(
    eligibility: EligibilityResult,
    dataset_ag_specific: dict[str, bool | None],
    dataset_category: dict[str, str] | None = None,
) -> dict[str, list[str]]:
    """Build the standard group->dataset-keys mapping: all / ag_specific /
    non_ag_specific, plus one group per distinct category if dataset_category
    is supplied. Category groups use the raw category string as the group
    name (already unique, human-readable, and non-colliding with the fixed
    three names)."""
    all_keys = list(eligibility.eligible.keys())
    groups: dict[str, list[str]] = {
        name: group_keys_for(all_keys, dataset_ag_specific, name)
        for name in ("all", "ag_specific", "non_ag_specific")
    }
    if dataset_category:
        categories = sorted({c for c in dataset_category.values() if c})
        for cat in categories:
            groups[cat] = [dk for dk in eligibility.eligible if dataset_category.get(dk) == cat]
    return groups


def run_seeds(
    eligibility: EligibilityResult,
    outcomes: dict[str, dict[str, float | None]],
    groups: dict[str, list[str]],
    metrics: list[str],
    *,
    k: int = 3,
    n_seeds: int = 1000,
) -> dict[str, Any]:
    """Repeated random matched-pair sampling: each seed independently draws k
    controls per dataset repo from its own eligible pool (a control may be
    drawn by more than one repo in the same seed -- expected, not a bug).
    Returns per group/metric the list of seed-level (median diff, Wilcoxon p,
    rank-biserial r) tuples."""
    seed_diffs: dict[str, dict[str, list[float]]] = {g: {m: [] for m in metrics} for g in groups}
    seed_wilcoxon: dict[str, dict[str, list[dict]]] = {g: {m: [] for m in metrics} for g in groups}

    dataset_order_base = list(eligibility.eligible.keys())

    for seed in range(n_seeds):
        rng = random.Random(seed)
        order = list(dataset_order_base)
        rng.shuffle(order)
        assignment: dict[str, list[str]] = {}

        for dkey in order:
            candidates = eligibility.eligible.get(dkey, [])
            if not candidates:
                assignment[dkey] = []
                continue
            if len(candidates) >= k:
                chosen = rng.sample(candidates, k)
            else:
                chosen = list(candidates)
                while len(chosen) < k and candidates:
                    chosen.append(rng.choice(candidates))  # allow replacement from this repo's own eligible set
            assignment[dkey] = chosen

        for metric in metrics:
            for group, dkeys in groups.items():
                diffs: list[float] = []
                for dkey in dkeys:
                    controls = assignment.get(dkey, [])
                    if not controls:
                        continue
                    dval = outcomes.get(dkey, {}).get(metric)
                    cvals = [outcomes.get(c, {}).get(metric) for c in controls]
                    cvals = [v for v in cvals if v is not None]
                    if dval is None or not cvals:
                        continue
                    diffs.append(float(dval) - (sum(cvals) / len(cvals)))

                if not diffs:
                    continue
                seed_diffs[group][metric].append(float(np.median(diffs)))

                if len(diffs) >= 3 and any(d != 0 for d in diffs):
                    n = len(diffs)
                    try:
                        method = "exact" if n <= WILCOXON_EXACT_MAX_N else "approx"
                        _, p = scipy_stats.wilcoxon(diffs, method=method)
                        pos = sum(1 for d in diffs if d > 0)
                        neg = sum(1 for d in diffs if d < 0)
                        r_rb = (pos - neg) / n if n else None
                        seed_wilcoxon[group][metric].append({"p": float(p), "r_rb": r_rb})
                    except Exception:
                        pass

    return {"diffs": seed_diffs, "wilcoxon": seed_wilcoxon}


def summarize(
    seed_results: dict[str, Any],
    metrics: list[str],
    *,
    headline_metrics: set[str] | None = None,
) -> dict[str, dict[str, dict]]:
    """Aggregate per-seed diffs/Wilcoxon results into median + [2.5,97.5]
    percentile interval per metric per group, with BH-FDR correction across
    metrics. Also reports seed-to-seed stability (spread + sign-agreement
    fraction) and attaches full per-seed values for headline_metrics only."""
    diffs = seed_results["diffs"]
    wilcoxon = seed_results["wilcoxon"]
    headline_metrics = headline_metrics or set()

    out: dict[str, dict[str, dict]] = {}
    for group, per_metric_diffs in diffs.items():
        out[group] = {}
        raw_p_for_fdr: list[float] = []
        metric_order: list[str] = []

        for metric in metrics:
            dvals = per_metric_diffs.get(metric, [])
            wvals = wilcoxon.get(group, {}).get(metric, [])
            if not dvals:
                out[group][metric] = {
                    "median_diff": None, "ci_lo": None, "ci_hi": None,
                    "effect_size_rank_biserial": None, "effect_label": None,
                    "p_value_median": None, "pct_seeds_significant": None,
                    "n_seeds_used": 0, "seed_to_seed_sd": None,
                    "pct_seeds_same_sign": None, "seed_stable": None,
                }
                continue

            median_diff = float(np.median(dvals))
            ci_lo = float(np.percentile(dvals, 2.5))
            ci_hi = float(np.percentile(dvals, 97.5))
            r_vals = [w["r_rb"] for w in wvals if w.get("r_rb") is not None]
            p_vals = [w["p"] for w in wvals if w.get("p") is not None]
            median_r = float(np.median(r_vals)) if r_vals else None
            median_p = float(np.median(p_vals)) if p_vals else None
            pct_sig = float(np.mean([p < 0.05 for p in p_vals])) if p_vals else None

            seed_sd = float(np.std(dvals, ddof=1)) if len(dvals) > 1 else None
            sign_ref = 1 if median_diff > 0 else (-1 if median_diff < 0 else 0)
            same_sign = [
                1 if ((d > 0 and sign_ref > 0) or (d < 0 and sign_ref < 0) or (d == 0 and sign_ref == 0)) else 0
                for d in dvals
            ]
            pct_same_sign = float(np.mean(same_sign))

            out[group][metric] = {
                "median_diff": round(median_diff, 4),
                "ci_lo": round(ci_lo, 4),
                "ci_hi": round(ci_hi, 4),
                "effect_size_rank_biserial": round(median_r, 4) if median_r is not None else None,
                "effect_label": _effect_label(median_r) if median_r is not None else None,
                "p_value_median": round(median_p, 6) if median_p is not None else None,
                "pct_seeds_significant": round(pct_sig, 4) if pct_sig is not None else None,
                "n_seeds_used": len(dvals),
                "seed_to_seed_sd": round(seed_sd, 4) if seed_sd is not None else None,
                "pct_seeds_same_sign": round(pct_same_sign, 4),
                "seed_stable": pct_same_sign >= 0.95,
            }
            if metric in headline_metrics:
                out[group][metric]["seed_values"] = [round(d, 4) for d in dvals]
            if median_p is not None:
                raw_p_for_fdr.append(median_p)
                metric_order.append(metric)

        adjusted = _bh_fdr_correct(raw_p_for_fdr)
        for metric, p_adj in zip(metric_order, adjusted):
            out[group][metric]["p_adjusted_fdr"] = round(p_adj, 6)
            out[group][metric]["significant_fdr"] = p_adj < 0.05

    return out


def run_deterministic(
    eligibility: EligibilityResult,
    outcomes: dict[str, dict[str, float | None]],
    groups: dict[str, list[str]],
    metrics: list[str],
    *,
    k: int = 3,
) -> dict[str, Any]:
    """Deterministic top-k nearest-neighbor matched-pair differences -- the
    primary/headline estimate.

    Each dataset repo is paired with its k closest eligible controls by
    Mahalanobis distance (eligibility.eligible is already sorted
    nearest-first per compute_eligibility()), with no random re-assignment.
    Compare with run_seeds()/summarize(), which draw controls at random from
    the same eligible pool across many seeds as a secondary robustness check.
    """
    diffs: dict[str, dict[str, list[float]]] = {g: {m: [] for m in metrics} for g in groups}

    for metric in metrics:
        for group, dkeys in groups.items():
            for dkey in dkeys:
                nearest = eligibility.eligible.get(dkey, [])[:k]
                if not nearest:
                    continue
                dval = outcomes.get(dkey, {}).get(metric)
                cvals = [outcomes.get(c, {}).get(metric) for c in nearest]
                cvals = [v for v in cvals if v is not None]
                if dval is None or not cvals:
                    continue
                diffs[group][metric].append(float(dval) - (sum(cvals) / len(cvals)))

    return {"diffs": diffs}


def summarize_deterministic(
    det_results: dict[str, Any],
    metrics: list[str],
    *,
    headline_metrics: set[str] | None = None,
    n_bootstrap: int = 2000,
    bootstrap_seed: int = 0,
) -> dict[str, dict[str, dict]]:
    """Aggregate deterministic top-k matched-pair differences into a headline
    point estimate + interval per metric per group. Since nearest-neighbor
    selection has no seed-to-seed spread, uncertainty instead comes from a
    nonparametric bootstrap over the matched pairs; significance from a
    Wilcoxon signed-rank test with BH-FDR correction, as in summarize()."""
    diffs = det_results["diffs"]
    headline_metrics = headline_metrics or set()
    rng = random.Random(bootstrap_seed)

    out: dict[str, dict[str, dict]] = {}
    for group, per_metric_diffs in diffs.items():
        out[group] = {}
        raw_p_for_fdr: list[float] = []
        metric_order: list[str] = []

        for metric in metrics:
            dvals = per_metric_diffs.get(metric, [])
            n = len(dvals)
            if n == 0:
                out[group][metric] = {
                    "median_diff": None, "ci_lo": None, "ci_hi": None,
                    "effect_size_rank_biserial": None, "effect_label": None,
                    "p_value": None, "n_matched_pairs": 0,
                }
                continue

            median_diff = float(np.median(dvals))

            ci_lo = ci_hi = None
            if n >= 2:
                boot_medians = [
                    float(np.median([dvals[rng.randrange(n)] for _ in range(n)]))
                    for _ in range(n_bootstrap)
                ]
                ci_lo = float(np.percentile(boot_medians, 2.5))
                ci_hi = float(np.percentile(boot_medians, 97.5))

            r_rb = None
            p_value = None
            if n >= 3 and any(d != 0 for d in dvals):
                try:
                    method = "exact" if n <= WILCOXON_EXACT_MAX_N else "approx"
                    _, p_value = scipy_stats.wilcoxon(dvals, method=method)
                    p_value = float(p_value)
                    pos = sum(1 for d in dvals if d > 0)
                    neg = sum(1 for d in dvals if d < 0)
                    r_rb = (pos - neg) / n
                except Exception:
                    pass

            out[group][metric] = {
                "median_diff": round(median_diff, 4),
                "ci_lo": round(ci_lo, 4) if ci_lo is not None else None,
                "ci_hi": round(ci_hi, 4) if ci_hi is not None else None,
                "effect_size_rank_biserial": round(r_rb, 4) if r_rb is not None else None,
                "effect_label": _effect_label(r_rb) if r_rb is not None else None,
                "p_value": round(p_value, 6) if p_value is not None else None,
                "n_matched_pairs": n,
            }
            if p_value is not None:
                raw_p_for_fdr.append(p_value)
                metric_order.append(metric)

        adjusted = _bh_fdr_correct(raw_p_for_fdr)
        for metric, p_adj in zip(metric_order, adjusted):
            out[group][metric]["p_adjusted_fdr"] = round(p_adj, 6)
            out[group][metric]["significant_fdr"] = p_adj < 0.05

    return out


# ---------------------------------------------------------------------------
# Repository-level matching diagnostics, unmatched-repo sensitivity bounds,
# and regression-adjusted estimate -- all three take the same {dataset_key:
# [selected control keys]} mapping run_deterministic() uses internally, so
# each repo's contribution always comes from its actual matched controls.
# ---------------------------------------------------------------------------

def matching_diagnostics(
    assigned: dict[str, list[str]],
    eligibility: EligibilityResult,
    dataset_covariates: dict[str, dict[str, Any]],
    control_covariates: dict[str, dict[str, Any]],
    dataset_keys: list[str],
    display_by_key: dict[str, RepoEntry],
) -> list[dict[str, Any]]:
    """Per-dataset-repo diagnostics row: eligible vs. selected control counts,
    Mahalanobis distance to the nearest eligible control vs. mean distance to
    selected controls, and the raw star/fork gap to selected controls' mean."""
    rows: list[dict[str, Any]] = []
    for dk in dataset_keys:
        entry = display_by_key[dk]
        eligible_controls = eligibility.eligible.get(dk, [])
        selected_controls = assigned.get(dk, [])
        distances = eligibility.distances.get(dk, {})

        distance_nearest = min(distances.values()) if distances else None
        selected_distances = [distances[c] for c in selected_controls if c in distances]
        avg_distance = (sum(selected_distances) / len(selected_distances)) if selected_distances else None

        d_stars = dataset_covariates.get(dk, {}).get("stars")
        d_forks = dataset_covariates.get(dk, {}).get("forks")
        sel_stars = [
            v for c in selected_controls
            if (v := control_covariates.get(c, {}).get("stars")) is not None
        ]
        sel_forks = [
            v for c in selected_controls
            if (v := control_covariates.get(c, {}).get("forks")) is not None
        ]
        delta_stars = (d_stars - (sum(sel_stars) / len(sel_stars))) if d_stars is not None and sel_stars else None
        delta_forks = (d_forks - (sum(sel_forks) / len(sel_forks))) if d_forks is not None and sel_forks else None

        rows.append({
            "repo_key": dk,
            "display_name": entry.display_name,
            "repo_url": entry.repo_url,
            "category": entry.category,
            "ag_specific": entry.ag_specific,
            "n_eligible_controls": len(eligible_controls),
            "n_selected_controls": len(selected_controls),
            "distance_nearest": round(distance_nearest, 4) if distance_nearest is not None else None,
            "avg_distance": round(avg_distance, 4) if avg_distance is not None else None,
            "delta_stars": round(delta_stars, 1) if delta_stars is not None else None,
            "delta_forks": round(delta_forks, 1) if delta_forks is not None else None,
        })
    return rows


# Direction each headline metric is scored in -- True means a higher value is
# WORSE (vulnerability/exposure counts); False means higher is better
# (Scorecard-derived checks). Same set run_matched_comparison.py's
# HEADLINE_METRICS names and the dashboard's own FOREST_PLOT_METRICS
# (pipeline/report/template.html) already use for the same "which extreme
# favors the treated side" question -- kept in sync deliberately.
HEADLINE_METRIC_WORSE_IF_HIGHER = {
    "scorecard_overall": False,
    "check_Dependency-Update-Tool": False,
    "check_Signed-Releases": False,
    "check_Maintained": False,
    "check_Vulnerabilities": False,
    "vuln_count": True,
    "vuln_density": True,
    "kev_exploitable_count": True,
}


def _median(values: list[float]) -> float | None:
    """Compute the median of a list of floats, or None if empty."""
    if not values:
        return None
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2.0


def unmatched_sensitivity_analysis(
    assigned: dict[str, list[str]],
    dataset_keys: list[str],
    outcomes: dict[str, dict[str, float | None]],
    display_by_key: dict[str, RepoEntry],
    metrics: list[str],
) -> dict[str, Any]:
    """Best-case/worst-case bound on the median matched-pair difference if
    currently-unmatched dataset repos (derived from `assigned`) had been
    matched, imputed from the most/least favorable *observed* outcome among
    other matched repos' selected controls in the same category (falling
    back to the full pool, flagged via used_category_pool=False). Accounts
    for metric direction via HEADLINE_METRIC_WORSE_IF_HIGHER.
    "direction_robust" is True only when both bounds keep the observed
    median's sign."""
    matched_keys = [dk for dk in dataset_keys if assigned.get(dk)]
    unmatched_keys = [dk for dk in dataset_keys if not assigned.get(dk)]

    real_diffs: dict[str, list[float]] = {m: [] for m in metrics}
    category_pool: dict[str, dict[str, list[float]]] = {}
    all_pool: dict[str, list[float]] = {m: [] for m in metrics}

    for dk in matched_keys:
        controls = assigned[dk]
        cat = display_by_key[dk].category or "Unknown"
        for m in metrics:
            dval = outcomes.get(dk, {}).get(m)
            cvals = [v for c in controls if (v := outcomes.get(c, {}).get(m)) is not None]
            if cvals:
                category_pool.setdefault(cat, {}).setdefault(m, []).extend(cvals)
                all_pool[m].extend(cvals)
            if dval is not None and cvals:
                real_diffs[m].append(float(dval) - sum(cvals) / len(cvals))

    imputed_best: dict[str, list[float]] = {m: list(real_diffs[m]) for m in metrics}
    imputed_worst: dict[str, list[float]] = {m: list(real_diffs[m]) for m in metrics}

    per_repo: list[dict[str, Any]] = []
    for dk in unmatched_keys:
        entry = display_by_key[dk]
        cat = entry.category or "Unknown"
        row: dict[str, Any] = {
            "repo_key": dk, "display_name": entry.display_name, "repo_url": entry.repo_url, "category": cat,
            "metrics": {},
        }
        for m in metrics:
            dval = outcomes.get(dk, {}).get(m)
            used_category_pool = bool(category_pool.get(cat, {}).get(m))
            pool = category_pool.get(cat, {}).get(m) or all_pool.get(m) or []
            if dval is None or not pool:
                row["metrics"][m] = {"imputed_best": None, "imputed_worst": None, "used_category_pool": None}
                continue
            worse_if_higher = HEADLINE_METRIC_WORSE_IF_HIGHER.get(m, False)
            best_control = max(pool) if worse_if_higher else min(pool)
            worst_control = min(pool) if worse_if_higher else max(pool)
            diff_best = float(dval) - best_control
            diff_worst = float(dval) - worst_control
            row["metrics"][m] = {
                "imputed_best": round(diff_best, 4),
                "imputed_worst": round(diff_worst, 4),
                "used_category_pool": used_category_pool,
            }
            imputed_best[m].append(diff_best)
            imputed_worst[m].append(diff_worst)
        per_repo.append(row)

    def _sign(x: float | None) -> int:
        """Return the sign of x as -1/0/1, treating None as 0."""
        if x is None:
            return 0
        return 1 if x > 0 else (-1 if x < 0 else 0)

    by_metric: dict[str, Any] = {}
    for m in metrics:
        observed_median = _median(real_diffs[m])
        best_median = _median(imputed_best[m])
        worst_median = _median(imputed_worst[m])
        obs_sign = _sign(observed_median)
        by_metric[m] = {
            "worse_if_higher": HEADLINE_METRIC_WORSE_IF_HIGHER.get(m, False),
            "n_observed": len(real_diffs[m]),
            "n_best_case": len(imputed_best[m]),
            "n_worst_case": len(imputed_worst[m]),
            "observed_median": round(observed_median, 4) if observed_median is not None else None,
            "best_case_median": round(best_median, 4) if best_median is not None else None,
            "worst_case_median": round(worst_median, 4) if worst_median is not None else None,
            "direction_robust": bool(
                obs_sign != 0 and _sign(best_median) == obs_sign and _sign(worst_median) == obs_sign
            ),
        }

    return {
        "n_matched": len(matched_keys),
        "n_unmatched": len(unmatched_keys),
        "per_repo": per_repo,
        "by_metric": by_metric,
    }


# The two covariates flagged as still "Imbalanced" (|SMD| > 0.25) after
# matching in the Covariate Balance table, regardless of k -- see
# regression_adjusted_estimate() below.
REGRESSION_ADJUSTMENT_COVARIATES = ["log_stars", "log_forks"]


def regression_adjusted_estimate(
    assigned: dict[str, list[str]],
    outcomes: dict[str, dict[str, float | None]],
    dataset_covariates: dict[str, dict[str, Any]],
    control_covariates: dict[str, dict[str, Any]],
    metrics: list[str],
) -> dict[str, Any]:
    """Regression-adjusted matching estimate: on the matched sample, fit
    outcome ~ treatment + log_stars + log_forks via OLS (HC3 robust SE) per
    headline metric, adjusting for covariates that remain imbalanced after
    matching. Compares matching_only (mean unadjusted pair difference) vs.
    matching_plus_regression (the OLS treatment coefficient), reporting
    "same_direction" (do the two signs agree) and "significant_both" (do
    both independently reject the null) as separate checks, since a
    CI-overlap test alone can mask a sign disagreement."""
    treated_keys = [dk for dk, ctrls in assigned.items() if ctrls]
    distinct_controls = sorted({c for ctrls in assigned.values() for c in ctrls})

    by_metric: dict[str, Any] = {}
    for m in metrics:
        diffs: list[float] = []
        for dk in treated_keys:
            dval = outcomes.get(dk, {}).get(m)
            cvals = [v for c in assigned[dk] if (v := outcomes.get(c, {}).get(m)) is not None]
            if dval is not None and cvals:
                diffs.append(float(dval) - sum(cvals) / len(cvals))

        matching_only_mean = (sum(diffs) / len(diffs)) if diffs else None
        mo_ci_lo, mo_ci_hi = bootstrap_ci(diffs, np.mean) if diffs else (None, None)

        rows: list[list[float]] = []
        ys: list[float] = []
        for dk in treated_keys:
            val = outcomes.get(dk, {}).get(m)
            if val is None:
                continue
            feats = _to_feature_row(dataset_covariates.get(dk, {}))
            rows.append([1.0, 1.0, feats["log_stars"], feats["log_forks"]])
            ys.append(val)
        for ck in distinct_controls:
            val = outcomes.get(ck, {}).get(m)
            if val is None:
                continue
            feats = _to_feature_row(control_covariates.get(ck, {}))
            rows.append([1.0, 0.0, feats["log_stars"], feats["log_forks"]])
            ys.append(val)

        # Same "some slack beyond the parameter count" rule
        # pipeline.stats._build_design_matrix uses (4 params here: intercept,
        # treatment, log_stars, log_forks).
        fit = None
        if len(ys) >= 4 + 5:
            fit = _ols_fit(np.array(ys, dtype=float), np.array(rows, dtype=float),
                            ["intercept", "treatment"] + REGRESSION_ADJUSTMENT_COVARIATES)

        reg_coef = reg_se = reg_p = reg_ci_lo = reg_ci_hi = None
        vifs: dict[str, float | None] = {}
        if fit:
            for c in fit["coefficients"]:
                if c["term"] == "treatment":
                    reg_coef, reg_se, reg_p = c["coef"], c["se"], c["p_value"]
                    reg_ci_lo, reg_ci_hi = c["ci_lo"], c["ci_hi"]
                elif c["term"] in REGRESSION_ADJUSTMENT_COVARIATES:
                    vifs[c["term"]] = c["vif"]

        mo_significant = None
        if (
            mo_ci_lo is not None and mo_ci_hi is not None
            and not math.isnan(mo_ci_lo) and not math.isnan(mo_ci_hi)
        ):
            mo_significant = not (mo_ci_lo <= 0 <= mo_ci_hi)
        reg_significant = (reg_p < 0.05) if reg_p is not None else None

        same_direction = None
        if matching_only_mean is not None and reg_coef is not None and matching_only_mean != 0 and reg_coef != 0:
            same_direction = (matching_only_mean > 0) == (reg_coef > 0)

        significant_both = None
        if mo_significant is not None and reg_significant is not None:
            significant_both = bool(mo_significant and reg_significant)

        by_metric[m] = {
            "n_matched_pairs": len(diffs),
            "matching_only_mean": round(matching_only_mean, 4) if matching_only_mean is not None else None,
            "matching_only_ci_lo": round(mo_ci_lo, 4) if mo_ci_lo is not None and not math.isnan(mo_ci_lo) else None,
            "matching_only_ci_hi": round(mo_ci_hi, 4) if mo_ci_hi is not None and not math.isnan(mo_ci_hi) else None,
            "regression_n": fit["n"] if fit else None,
            "regression_coef": reg_coef,
            "regression_se": reg_se,
            "regression_ci_lo": reg_ci_lo,
            "regression_ci_hi": reg_ci_hi,
            "regression_p_value": reg_p,
            "log_stars_vif": vifs.get("log_stars"),
            "log_forks_vif": vifs.get("log_forks"),
            "matching_only_significant": mo_significant,
            "regression_significant": reg_significant,
            "same_direction": same_direction,
            "significant_both": significant_both,
        }

    return {
        "n_treated": len(treated_keys),
        "n_distinct_controls": len(distinct_controls),
        "covariates": REGRESSION_ADJUSTMENT_COVARIATES,
        "by_metric": by_metric,
    }
