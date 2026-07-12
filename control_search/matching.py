"""Eligibility (hard exact-match gate + Mahalanobis caliper), covariate balance
diagnostics, and repeated random matched-pair effect estimation.

Methodology (see the project plan for full rationale):
  - Hard gate: exact primary-language match (coarsened exact matching). A
    dataset repo with zero same-language candidates in the control pool has
    zero eligible controls, full stop -- there is no ecosystem-bucket
    fallback. It is dropped from the matched comparison and reported in the
    "unmatched" cohort instead, since averaging a repo against a
    same-Mahalanobis-distance-but-different-language "control" would
    reintroduce exactly the kind of confound matching is meant to remove.
  - Soft ranking: Mahalanobis distance over standardized covariates (log
    stars, log forks, age, contributor count, recent commit activity, log
    codebase size). Mahalanobis distance is used instead of raw Euclidean
    distance because it accounts for correlation between covariates (e.g.
    stars and forks), and is the standard choice in the matching literature
    (Rosenbaum & Rubin; King & Nielsen 2019) for a small covariate set with a
    modest treated sample size — more transparent and stable here than
    fitting a propensity-score model. Codebase size (total non-notebook
    language bytes from GitHub's /languages breakdown, log1p'd for the same
    right-skew reason as the other count covariates) was added because it
    captures a project-scale dimension the popularity/activity covariates
    don't: a small, single-purpose tool can be highly starred without being
    large, and vice versa, so two repos with similar stars/forks/contributors
    could still differ substantially in how big the actual codebase is. It's
    treated as a covariate rather than a mediator for the same reason
    stars/forks/contributor_count are: codebase scale is a structural
    project characteristic, not a downstream consequence of ag-specific
    status the way dependency_count/release_count were judged to be below.
    release_count and dependency_count were
    deliberately excluded: both are plausible mediators (downstream of
    ag-specific status rather than a nuisance confound of it) and
    dependency_count was already well-balanced pre-matching (SMD ~0.07) while
    getting worse post-matching, so including them risked partialling out
    part of the effect being measured without correcting a real imbalance in
    return. See per-repo `vuln_density` for a dependency-count normalization
    that happens at the outcome layer instead. owner_is_org (org-vs-individual
    GitHub account type) was also dropped: it's the noisiest of the original
    8 covariates (a proxy for institutional backing, not a verified measure
    of it) and not the main driver of caliper failures -- log_stars/log_forks
    account for more of those than owner_is_org does.
  - Caliper threshold: set via the chi-squared distribution with degrees of
    freedom = number of covariates, since squared Mahalanobis distances are
    asymptotically chi-squared distributed under joint normality.
  - Balance diagnostics: standardized mean difference (SMD) per covariate,
    dataset group vs. control pool (before) and vs. matched-eligible controls
    (after), following the Rosenbaum/Rubin/Austin convention (|SMD| < 0.1 well
    balanced, 0.1-0.25 acceptable, > 0.25 imbalanced).
  - Primary estimate: deterministic top-k nearest-neighbor matching. Each
    dataset repo is paired with its k closest eligible controls (by
    Mahalanobis distance -- eligibility.eligible is already sorted
    nearest-first), with no random re-assignment. This is the standard,
    defensible estimator in the matching literature (Rosenbaum & Rubin) and
    is what's reported as the headline effect. Uncertainty on this point
    estimate comes from a nonparametric bootstrap over the matched pairs
    themselves (resampling which dataset repos ended up in the sample), not
    from varying which control was picked -- nearest-neighbor selection
    itself has nothing random to average over.
  - Secondary robustness check: repeated random matching. For each of many
    seeds, k controls are drawn *at random* from the full eligible pool per
    dataset repo (without replacement within a seed where possible), and the
    matched-pair difference is aggregated into a per-seed effect. This
    answers a different question than the primary estimate -- "does the
    conclusion survive even under looser, non-optimal matching assignment"
    -- and is reported as a robustness check (median + [2.5, 97.5]
    percentile interval across seeds), not as the headline number.
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

from pipeline.stats import _bh_fdr_correct, _effect_label

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
# approximation instead of the exact distribution. Below this threshold the
# exact test is both standard nonparametric-statistics practice (widely cited
# convention: exact below ~20-25, approximation adequate above it) and cheap
# to compute; above it, scipy's own 'auto' method selection can still pick
# the exact combinatorial calculation for unfavorable tie/zero patterns, which
# has a documented performance cliff (a sub-second call can become a
# multi-hour one) at exactly the sample sizes this dataset has grown into.
# Pinning an explicit cutoff replaces 'auto' with a bounded, disclosable rule
# rather than trading away rigor for speed.
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
    if not created_at:
        return None
    try:
        created = datetime.fromisoformat(str(created_at).replace("Z", "+00:00"))
    except Exception:
        return None
    now = datetime.now(timezone.utc)
    return max(0.0, (now - created).days / 365.25)


def _to_feature_row(cov: dict[str, Any]) -> dict[str, float]:
    stars = float(cov.get("stars") or 0)
    forks = float(cov.get("forks") or 0)
    age = age_years(cov.get("created_at"))
    # contributor_count and commit_activity_52w are log1p'd for the same
    # reason stars/forks are: all four are right-skewed GitHub activity
    # counts (commit_activity_52w here has mean 807 vs. median 10 across
    # the dataset -- more skewed than stars), and Mahalanobis distance
    # assumes roughly elliptical covariate distributions. Left on a raw
    # scale, a handful of outlier repos dominate the covariance matrix and
    # the algorithm has little sensitivity to differences among
    # typical-sized repos on these two covariates -- see the post-match
    # balance writeup for the SMD-worsening effect this caused pre-fix.
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
    mat = np.array([[r[f] for f in ALL_FEATURES] for r in rows], dtype=float)
    mean = mat.mean(axis=0)
    std = mat.std(axis=0, ddof=0)
    std[std == 0] = 1.0
    return mat, mean, std


@dataclass
class EligibilityResult:
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

    if not control_keys:
        return EligibilityResult(
            eligible={k: [] for k in dataset_keys},
            sensitivity_table={k: {"tight": 0, "primary": 0, "loose": 0} for k in dataset_keys},
            caliper_chi2={},
            distances={k: {} for k in dataset_keys},
            unmatched_diagnostics={
                k: {
                    "reason": "empty_control_pool",
                    "reason_label": "Control pool is empty",
                    "closest_candidate": None, "closest_distance": None, "exceeded_covariates": [],
                }
                for k in dataset_keys
            },
        )

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

    # Full dataset x control squared-Mahalanobis-distance matrix in one call,
    # via scipy.spatial.distance.cdist(metric="mahalanobis", VI=inv_cov) --
    # replaces a from-scratch per-row np.einsum computation (verified to
    # match it to floating-point precision: max abs diff ~1e-14 on synthetic
    # data). VI is passed explicitly (this function's own ridge-stabilized
    # inverse covariance) rather than left for cdist to recompute, so the
    # numerical-stability epsilon above is still honored.
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
    """Standardized mean difference (SMD) per covariate, before vs after matching.

    'Before' = dataset group vs the full control candidate pool.
    'After'  = dataset group vs the controls actually used at k -- each
    dataset repo's top-k nearest-eligible controls (eligibility.eligible is
    already sorted nearest-first), unioned across the group. Pass k=None to
    fall back to the full caliper-eligible union instead (i.e. every
    candidate that passed the caliper, not just the k actually used
    downstream) -- kept only for callers that explicitly want that broader
    view; the headline dashboard now always passes an explicit k so "after"
    reflects the same matched sample the effect estimates use, not a
    diagnostic-only superset that can look better *or* worse than what's
    really being compared (see run_matched_comparison.py's per-k balance).

    Pass dataset_keys_filter to restrict the dataset side to a subgroup (e.g.
    ag_specific only) — the control pool side is never filtered, since the
    pool itself doesn't change per group, only which dataset repos we're
    comparing it against.
    """
    keys = dataset_keys_filter if dataset_keys_filter is not None else list(dataset_covariates.keys())
    dataset_rows = [_to_feature_row(dataset_covariates[k2]) for k2 in keys if k2 in dataset_covariates]
    pool_rows = [_to_feature_row(v) for v in control_covariates.values()]

    eligible_subset = {
        dk: (v[:k] if k is not None else v)
        for dk, v in eligibility.eligible.items() if dk in keys
    }
    matched_keys = sorted({c for lst in eligible_subset.values() for c in lst})
    matched_rows = [_to_feature_row(control_covariates[mk]) for mk in matched_keys if mk in control_covariates] or pool_rows

    def _smd(a: list[dict], b: list[dict], feature: str) -> float | None:
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
    """Summary statistics describing how *good* the matches are, distinct from
    raw eligible-control counts — the nearest-match Mahalanobis distance is
    the direct answer to "how similar is this repo's best control, really."

    Pass dataset_keys_filter to restrict to a subgroup (e.g. ag_specific only);
    n_dataset_repos should then be the size of that subgroup, not the total.
    avg_controls_per_repo is reported per k_options value (not a single fixed
    k) so the dashboard's k selector can show the right number for whichever
    k is currently chosen, without recomputing anything.
    """
    keys = dataset_keys_filter if dataset_keys_filter is not None else list(eligibility.eligible.keys())
    matched_keys = [dk for dk in keys if eligibility.eligible.get(dk)]
    n_matched = len(matched_keys)

    nearest_distances: list[float] = []
    for dk in matched_keys:
        dists = sorted(eligibility.distances.get(dk, {}).values())
        if dists:
            nearest_distances.append(dists[0])

    def _r4(fn, vals: list[float]) -> float | None:
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
    """Compare covariate profiles of matched vs. unmatched dataset repos —
    answers "are the repos that couldn't be matched systematically different
    (e.g. larger, older) from the ones that were," which would mean the
    matched-comparison sample isn't fully representative of the whole
    dataset. Pure aggregation over already-fetched covariates; no new data
    collection needed."""
    matched_keys = [k for k, v in eligibility.eligible.items() if v]
    unmatched_keys = [k for k, v in eligibility.eligible.items() if not v]

    def _stats_for(keys: list[str], feature: str) -> dict[str, Any]:
        vals = [
            v for k in keys
            if k in dataset_covariates and (v := raw_covariate_value(dataset_covariates[k], feature)) is not None
        ]
        if not vals:
            return {"mean": None, "median": None, "n": 0}
        return {"mean": round(float(np.mean(vals)), 2), "median": round(float(np.median(vals)), 2), "n": len(vals)}

    by_covariate: dict[str, dict[str, Any]] = {}
    for feature in RAW_COVARIATE_LABELS:
        matched_stats = _stats_for(matched_keys, feature)
        unmatched_stats = _stats_for(unmatched_keys, feature)
        ratio = None
        if matched_stats["mean"] not in (None, 0) and unmatched_stats["mean"] is not None:
            ratio = round(unmatched_stats["mean"] / matched_stats["mean"], 2)
        by_covariate[feature] = {"matched": matched_stats, "unmatched": unmatched_stats, "unmatched_to_matched_ratio": ratio}

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
    """Repeated random matched-pair sampling.

    Each seed draws k controls per dataset repo from its full eligible pool
    (without replacement within the seed where possible, allowing replacement
    only when the eligible pool is too small). Returns, per group (as defined
    by the caller-supplied `groups` mapping — see build_standard_groups()) and
    per metric, the list of seed-level (median paired difference, Wilcoxon p,
    rank-biserial r) tuples.
    """
    seed_diffs: dict[str, dict[str, list[float]]] = {g: {m: [] for m in metrics} for g in groups}
    seed_wilcoxon: dict[str, dict[str, list[dict]]] = {g: {m: [] for m in metrics} for g in groups}

    dataset_order_base = list(eligibility.eligible.keys())

    for seed in range(n_seeds):
        rng = random.Random(seed)
        order = list(dataset_order_base)
        rng.shuffle(order)
        used: set[str] = set()
        assignment: dict[str, list[str]] = {}

        for dkey in order:
            candidates = eligibility.eligible.get(dkey, [])
            if not candidates:
                assignment[dkey] = []
                continue
            unused = [c for c in candidates if c not in used]
            if len(unused) >= k:
                chosen = rng.sample(unused, k)
            else:
                chosen = list(unused)
                while len(chosen) < k and candidates:
                    chosen.append(rng.choice(candidates))  # allow replacement from full eligible set
            assignment[dkey] = chosen
            used.update(chosen)

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
    """Aggregate per-seed diffs/Wilcoxon results into median + [2.5,97.5] percentile
    interval per metric per group, then apply BH-FDR correction across metrics
    within each group (reusing the same helper the existing ag_vs_nonag
    comparison in pipeline/stats.py already uses, for consistent methodology).

    Also reports seed-to-seed stability: the standard deviation of the
    per-seed median-paired-difference, and the fraction of seeds whose
    difference has the same sign as the overall median — the latter directly
    answers "would a different random seed have flipped the conclusion,"
    which matters more for reader trust than raw variance. Metrics in
    headline_metrics also get their full per-seed value list attached (for
    the seed-distribution chart) — this is capped to a curated subset since
    including it for all ~30 metrics would bloat the output considerably.
    """
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
    """Aggregate deterministic top-k matched-pair differences into a point
    estimate + uncertainty interval per metric per group -- the headline
    result reported alongside (not derived from) the repeated-random-seed
    robustness check in summarize().

    Nearest-neighbor selection is deterministic -- there's exactly one set of
    matched pairs, not one per seed -- so there's no seed-to-seed spread to
    report here. Uncertainty on the point estimate instead comes from a
    standard nonparametric bootstrap over the matched pairs themselves
    (resampling which dataset repos ended up in the sample with replacement),
    which is the customary way to attach a CI to a deterministic-match
    estimate. Effect size and significance come from a single Wilcoxon
    signed-rank test on the fixed set of paired differences, then BH-FDR
    correction across metrics within each group, same as summarize().
    """
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
