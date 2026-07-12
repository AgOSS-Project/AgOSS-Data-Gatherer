"""Statistical analysis — bootstrap CIs, Mann-Whitney tests, Kruskal-Wallis, and Spearman correlations.

Writes outputs/processed/statistical_analysis.json.
"""

from __future__ import annotations

import json
import logging
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import numpy as np
import statsmodels.api as sm
from scikit_posthocs import posthoc_dunn as _sk_posthoc_dunn
from scipy import stats as scipy_stats
from statsmodels.stats.outliers_influence import variance_inflation_factor

from pipeline import config

logger = logging.getLogger("pipeline.stats")

STAT_ANALYSIS_FILE = config.PROCESSED_DIR / "statistical_analysis.json"

N_BOOTSTRAP = 2000
CI_LEVEL = 0.95

_EFFECT_THRESHOLDS = [(0.1, "negligible"), (0.3, "small"), (0.5, "medium")]


def _effect_label(r: float) -> str:
    r = abs(r)
    for threshold, label in _EFFECT_THRESHOLDS:
        if r < threshold:
            return label
    return "large"


def _bh_fdr_correct(p_values: list[float]) -> list[float]:
    """Benjamini-Hochberg FDR correction. Input must be a list of non-None floats.

    Thin wrapper around scipy.stats.false_discovery_control(method="bh")
    (available since scipy 1.11, already this project's minimum pinned
    version) -- verified to match a from-scratch implementation exactly
    across several test cases before this swap. Kept as a same-named,
    same-signature function since control_search/matching.py imports it
    directly.
    """
    if not p_values:
        return []
    return [float(p) for p in scipy_stats.false_discovery_control(p_values, method="bh")]


def _is_valid_p(p) -> bool:
    """True if p is a real, finite probability in [0, 1].

    `p is not None` alone lets NaN through (NaN is not None in Python), and
    scipy.stats.false_discovery_control raises on any input outside [0, 1] --
    concretely hit by check_Packaging/check_Signed-Releases, where every
    single repo scores a perfect 10 and scipy's mannwhitneyu asymptotic
    p-value is a 0/0 in that fully-tied case (run_mannwhitney() falls back to
    the exact method when it detects this, so this filter is now more of a
    defensive backstop than a live code path -- but every FDR-family
    collection point below uses it rather than `is not None` alone, so a
    NaN from a future edge case degrades to "excluded from this family"
    instead of crashing the whole statistical_analysis.json run).
    """
    return p is not None and isinstance(p, (int, float)) and not math.isnan(p) and 0.0 <= p <= 1.0


def _clean(values: list) -> list[float]:
    out = []
    for v in values:
        if v is None:
            continue
        try:
            f = float(v)
            if not math.isnan(f):
                out.append(f)
        except (TypeError, ValueError):
            pass
    return out


def bootstrap_ci(
    data: list[float],
    func: Callable[[np.ndarray], float],
    n: int = N_BOOTSTRAP,
    ci: float = CI_LEVEL,
    seed: int = 42,
) -> tuple[float, float]:
    """95% percentile bootstrap CI for an arbitrary statistic, via
    scipy.stats.bootstrap(method="percentile") -- same resampling-with-
    replacement + percentile-interval design as the from-scratch version
    this replaced; exact resampled draws differ since scipy's internal RNG
    sequence isn't bit-for-bit identical to a hand-rolled rng.choice loop
    at the same seed, so CI bounds shift slightly (still a valid bootstrap
    CI, just not byte-identical to the old numbers).
    """
    if len(data) < 2:
        val = float(func(np.array(data))) if data else float("nan")
        return val, val
    arr = np.array(data, dtype=float)
    rng = np.random.default_rng(seed)
    result = scipy_stats.bootstrap(
        (arr,), func, n_resamples=n, confidence_level=ci,
        method="percentile", vectorized=False, random_state=rng,
    )
    return float(result.confidence_interval.low), float(result.confidence_interval.high)


def _bootstrap_r_ci(
    a: list[float],
    b: list[float],
    n: int = N_BOOTSTRAP,
    ci: float = CI_LEVEL,
    seed: int = 42,
) -> tuple[float, float]:
    """Bootstrap 95% CI for the rank-biserial r from a Mann-Whitney comparison,
    via scipy.stats.bootstrap on the two samples independently
    (paired=False -- a and b are each resampled on their own, same design as
    the from-scratch loop this replaced)."""
    arr_a = np.array(a, dtype=float)
    arr_b = np.array(b, dtype=float)

    def _r_stat(s_a: np.ndarray, s_b: np.ndarray) -> float:
        u = float(scipy_stats.mannwhitneyu(s_a, s_b, alternative="two-sided").statistic)
        return (2 * u) / (len(s_a) * len(s_b)) - 1.0

    rng = np.random.default_rng(seed)
    try:
        result = scipy_stats.bootstrap(
            (arr_a, arr_b), _r_stat, n_resamples=n, confidence_level=ci,
            method="percentile", vectorized=False, paired=False, random_state=rng,
        )
    except Exception:
        return float("nan"), float("nan")
    return float(result.confidence_interval.low), float(result.confidence_interval.high)


def _wmw_tie_sum(pooled: list[float]) -> float:
    """Sum_i (t_i^3 - t_i) over the pooled (both-groups) sample, where t_i is
    the number of observations tied at the i-th distinct value -- the
    standard tie-correction term for the Wilcoxon-Mann-Whitney variance
    (0 if there are no ties). Same quantity dunn_posthoc() computes for its
    own tie correction, factored out here so both call sites share it."""
    if not pooled:
        return 0.0
    _, counts = np.unique(np.asarray(pooled, dtype=float), return_counts=True)
    return float(sum(int(c) ** 3 - int(c) for c in counts if c > 1))


def _wmw_power_coefficient(n_a: int | None, n_b: int | None, tie_sum: float = 0.0) -> float | None:
    """Coefficient linking the rank-biserial effect size r to the
    standardized-test-statistic non-centrality for a two-sided
    Wilcoxon-Mann-Whitney test:

        z_beta = coefficient * |r| - z_{alpha/2}
        power  = Phi(z_beta)

    Derived (not a fitted/hardcoded constant) from the exact finite-sample
    variance of the Mann-Whitney U statistic -- the same formula given in
    Noether (1987), reproduced in Zhao et al. (2008) and in NCSS/PASS's
    "Mann-Whitney U or Wilcoxon Rank-Sum Tests (Noether)" reference (which
    this was cross-checked against, matching its two worked examples to
    3-4 decimal places):

        Var(U) = (n_a n_b / 12) * [(N+1) - tie_sum / (N(N-1))]      N = n_a+n_b
        coefficient = n_a n_b / (2 * sqrt(Var(U)))
                    = sqrt(3 n_a n_b / [(N+1) - tie_sum/(N(N-1))])

    This is a closed-form function of n_a, n_b (and, when supplied, the
    actual tie count), evaluated fresh every call -- it is NOT re-fit per
    dataset, so it automatically tracks whatever n_a/n_b this particular
    comparison has, rather than assuming a fixed large-N/no-ties
    simplification. That simplification (tie_sum=0 AND N+1 rounded down to
    N) is exactly what collapses this formula to sqrt(1.5 * n_h) with
    n_h = 2/(1/n_a+1/n_b) the harmonic mean -- an earlier version of this
    function hardcoded that simplified constant. This exact version
    corrects two real, verified-by-simulation gaps in that earlier version:
    dropping the "+1" term (matters when N is small, negligible once N is
    in the hundreds) and ignoring ties (small, second-order effect; moves
    predictions in the right direction but rarely by much).

    IMPORTANT REMAINING CAVEAT, inherent to Noether's method itself (not
    fixed by the "exact" variance above, and not something a different
    formula can fix without abandoning the nonparametric/distribution-free
    property that makes this test useful in the first place): Var(U) here is
    the NULL-hypothesis variance. Noether's method substitutes it for the
    true (and generally smaller, and analytically intractable without
    assuming a specific parametric alternative) variance under the
    alternative, which is only accurate for "local" alternatives -- i.e.
    effect sizes not too far from 0. Monte Carlo simulation confirms this
    directly: at small-to-moderate r (<~0.5) this formula tracks simulated
    power closely, but at large r (>~0.7 -- which several of this dataset's
    own naive ag-vs-non-ag comparisons reach, e.g. scorecard_overall
    r=-0.87, stars_count r=-0.96) it increasingly UNDERSTATES true power
    (e.g. at n_a=n_b=5, r=0.95: this formula predicts power=0.70 against a
    simulated 0.92). Read power/MDE values as a lower bound / conservative
    estimate once |r| exceeds roughly 0.5-0.6, not a precise figure --
    true power for those large-effect comparisons is probably higher than
    reported here.
    """
    if n_a is None or n_b is None or n_a < 2 or n_b < 2:
        return None
    N = n_a + n_b
    tie_term = (tie_sum / (N * (N - 1))) if N > 1 else 0.0
    inner = (N + 1) - tie_term
    if inner <= 0:
        return None
    return math.sqrt(3.0 * n_a * n_b / inner)


def _wmw_power(n_a: int | None, n_b: int | None, r: float | None, alpha: float = 0.05, tie_sum: float = 0.0) -> float | None:
    """Achieved (retrospective/observed) power for a two-sided
    Wilcoxon-Mann-Whitney test at the actual n_a, n_b and an observed (or
    hypothesized) rank-biserial effect size r. See _wmw_power_coefficient()
    for the derivation.

    Prefer _wmw_mde() over this for interpretation: retrospective power
    computed from an observed effect is a near-deterministic function of the
    p-value and is widely regarded in the statistics literature as
    uninformative-to-misleading on its own (Hoenig & Heisey 2001) -- this is
    retained for completeness/intuition, not as the primary metric.
    """
    if r is None or math.isnan(r):
        return None
    coef = _wmw_power_coefficient(n_a, n_b, tie_sum)
    if coef is None:
        return None
    z_alpha = float(scipy_stats.norm.ppf(1 - alpha / 2))
    z_beta = coef * abs(r) - z_alpha
    return round(float(scipy_stats.norm.cdf(z_beta)), 4)


def _wmw_mde(n_a: int | None, n_b: int | None, power: float = 0.80, alpha: float = 0.05, tie_sum: float = 0.0) -> float | None:
    """Minimum detectable rank-biserial |r| at the given power/alpha for the
    actual n_a, n_b -- the companion query to _wmw_power(): "how big would
    the true effect need to be for this sample size to reliably detect it."
    See _wmw_power_coefficient() for the derivation."""
    coef = _wmw_power_coefficient(n_a, n_b, tie_sum)
    if coef is None:
        return None
    z_alpha = float(scipy_stats.norm.ppf(1 - alpha / 2))
    z_beta = float(scipy_stats.norm.ppf(power))
    return round(float((z_alpha + z_beta) / coef), 4)


def compute_descriptive_stats(values: list) -> dict:
    clean = _clean(values)
    n = len(clean)
    if n == 0:
        return {
            "n": 0,
            "mean": None, "mean_ci_lo": None, "mean_ci_hi": None,
            "median": None, "median_ci_lo": None, "median_ci_hi": None,
            "iqr": None, "iqr_ci_lo": None, "iqr_ci_hi": None,
        }

    def _iqr(x: np.ndarray) -> float:
        return float(np.percentile(x, 75) - np.percentile(x, 25))

    mean_val = float(np.mean(clean))
    median_val = float(np.median(clean))
    iqr_val = _iqr(np.array(clean))

    mean_lo, mean_hi = bootstrap_ci(clean, np.mean)
    median_lo, median_hi = bootstrap_ci(clean, np.median)
    iqr_lo, iqr_hi = bootstrap_ci(clean, _iqr)

    def _r4(x: float) -> float:
        return round(x, 4)

    return {
        "n": n,
        "mean": _r4(mean_val), "mean_ci_lo": _r4(mean_lo), "mean_ci_hi": _r4(mean_hi),
        "median": _r4(median_val), "median_ci_lo": _r4(median_lo), "median_ci_hi": _r4(median_hi),
        "iqr": _r4(iqr_val), "iqr_ci_lo": _r4(iqr_lo), "iqr_ci_hi": _r4(iqr_hi),
    }


def run_mannwhitney(group_a: list, group_b: list) -> dict:
    a = _clean(group_a)
    b = _clean(group_b)
    n_a, n_b = len(a), len(b)
    if n_a < 2 or n_b < 2:
        return {
            "n_a": n_a, "n_b": n_b,
            "mw_statistic": None, "p_value": None,
            "effect_size_r": None, "effect_size_r_ci_lo": None, "effect_size_r_ci_hi": None,
            "effect_label": None, "significant": None,
            "power": None, "mde_r_80": None,
        }
    result = scipy_stats.mannwhitneyu(a, b, alternative="two-sided")
    u = float(result.statistic)
    p = float(result.pvalue)
    if math.isnan(p):
        # method="auto" picks the normal approximation once n is past a small
        # threshold, and that approximation's variance term is a 0/0 when
        # every value in the pooled sample is identical (e.g. a check where
        # literally every repo scores a perfect 10) -- U is still
        # well-defined there (it's just the midpoint, r=0), but scipy's
        # asymptotic p-value comes back NaN. The exact permutation method
        # handles this degenerate case correctly (verified: returns p=1.0,
        # the mathematically correct "no evidence of a difference" answer
        # when both groups are indistinguishable) and is cheap here
        # specifically because a fully-tied input is the trivial case for
        # exact computation, not the expensive one. Falling back only when
        # NaN is actually hit keeps this from paying the exact method's
        # general large-n cost on every call.
        result = scipy_stats.mannwhitneyu(a, b, alternative="two-sided", method="exact")
        p = float(result.pvalue)
    # scipy returns U1 (U for the first/ag group); r = 2*U1/(n_a*n_b) - 1
    # so positive r means group A (ag) ranks higher, negative means group B (non-ag) ranks higher
    r = (2 * u) / (n_a * n_b) - 1.0
    r_lo, r_hi = _bootstrap_r_ci(a, b)
    # Real tie count from this comparison's own pooled data (not assumed/
    # dropped) -- see _wmw_power_coefficient() for why this matters at small n.
    tie_sum = _wmw_tie_sum(a + b)
    return {
        "n_a": n_a, "n_b": n_b,
        "mw_statistic": round(u, 4),
        "p_value": round(p, 6),
        "effect_size_r": round(r, 4),
        "effect_size_r_ci_lo": round(r_lo, 4) if not math.isnan(r_lo) else None,
        "effect_size_r_ci_hi": round(r_hi, 4) if not math.isnan(r_hi) else None,
        "effect_label": _effect_label(r),
        "significant": p < 0.05,
        # Achieved power at the observed n/r, and the minimum effect size this
        # n could reliably detect at 80% power -- both via the exact
        # finite-sample/tie-corrected Wilcoxon-Mann-Whitney variance (see
        # _wmw_power_coefficient()), alpha=0.05 (the nominal per-test alpha,
        # not the FDR threshold, since power is a property of the test as run).
        "power": _wmw_power(n_a, n_b, r, tie_sum=tie_sum),
        "mde_r_80": _wmw_mde(n_a, n_b, tie_sum=tie_sum),
    }


def dunn_posthoc(groups: dict[str, list[float]]) -> dict[str, dict]:
    """Dunn's post-hoc pairwise test with Bonferroni correction, via
    scikit-posthocs.posthoc_dunn (Dunn 1964; tie-corrected per Glantz 2012)
    -- the library's internal formula was checked against this project's
    earlier from-scratch implementation and matches exactly, including tie
    correction, on both real and synthetic data.

    posthoc_dunn returns only a symmetric p-value matrix (no signed
    Z-statistic, and no power/MDE), so this wrapper still does two things
    of its own on top of the library call: recovers the sign of each pair's
    difference from the pooled mean ranks (the library only exposes
    |difference|), and attaches this project's own power/MDE calculation
    (see _wmw_power_coefficient) -- neither is part of Dunn's test itself,
    so no library provides them bundled with it either.

    groups: { category_name: [float, ...] }  (pre-cleaned values)
    """
    group_names = list(groups.keys())
    if len(group_names) < 2:
        return {}

    all_vals: list[float] = []
    group_labels: list[str] = []
    for name, vals in groups.items():
        all_vals.extend(vals)
        group_labels.extend([name] * len(vals))

    N = len(all_vals)
    if N < 3:
        return {}

    # Mean rank per group (pooled ranking) -- used only to recover the SIGN
    # of each pairwise difference, since posthoc_dunn computes its
    # Z-statistic from an absolute rank difference.
    ranks = scipy_stats.rankdata(all_vals)
    group_ranks: dict[str, list[float]] = {name: [] for name in group_names}
    for rank, label in zip(ranks, group_labels):
        group_ranks[label].append(rank)
    mean_ranks = {name: float(np.mean(r)) for name, r in group_ranks.items()}
    n_per = {name: len(r) for name, r in group_ranks.items()}

    values_by_group = [groups[name] for name in group_names]
    # sort=False: group order in the input list is preserved 1:1 in the
    # returned DataFrame's row/column position (verified), so positional
    # .iloc indexing below lines up with group_names without relying on
    # pandas' internal sort/label behavior.
    raw_p = _sk_posthoc_dunn(values_by_group, p_adjust=None, sort=False)
    adj_p = _sk_posthoc_dunn(values_by_group, p_adjust="bonferroni", sort=False)

    n_pairs = len(group_names) * (len(group_names) - 1) // 2
    # Power/MDE below are evaluated at the Bonferroni-adjusted alpha actually
    # applied to each pair's significance call, not the nominal 0.05 -- using
    # the real decision threshold rather than a looser one.
    alpha_adj = (0.05 / n_pairs) if n_pairs else 0.05
    results: dict[str, dict] = {}

    for i, g1 in enumerate(group_names):
        for j, g2 in enumerate(group_names[i + 1:], start=i + 1):
            p_raw = float(raw_p.iloc[i, j])
            p_adj = float(adj_p.iloc[i, j])
            # |Z| from the raw two-sided p-value (inverse of p = 2*(1-Phi(|Z|)));
            # clip away from exactly 0/1 so isf() doesn't hit +-inf on a
            # (rare) exact tie or an exact p=1.
            p_raw_clipped = min(max(p_raw, 1e-300), 1.0)
            sign = 1.0 if mean_ranks[g1] >= mean_ranks[g2] else -1.0
            z = sign * float(scipy_stats.norm.isf(p_raw_clipped / 2.0))
            n1, n2 = n_per[g1], n_per[g2]
            # Rosenthal's (1991) Z-to-r conversion (r = Z / sqrt(N)) gives an
            # approximate rank-biserial-scale effect size for this pair, which
            # feeds the same power/MDE formula used for the Mann-Whitney
            # comparisons -- Dunn's test itself has no closed-form effect size
            # the way a single two-sample test does. The power/MDE call below
            # uses tie_sum=0 (not a pooled, all-K-groups tie count): a
            # repo's rank position depends on every other category too, not
            # just the pair being compared, so a pair-specific tie
            # correction isn't well-defined here -- this still gets the
            # finite-sample "+1" correction (the dominant error source at
            # small n, per simulation) but not a pair-specific tie correction.
            n_pair_total = n1 + n2
            r_approx = (z / math.sqrt(n_pair_total)) if n_pair_total > 0 else None
            results[f"{g1} vs {g2}"] = {
                "Z": round(z, 4),
                "p_adj": round(p_adj, 6),
                "significant": p_adj < 0.05,
                "effect_size_r_approx": round(r_approx, 4) if r_approx is not None else None,
                "power": _wmw_power(n1, n2, r_approx, alpha=alpha_adj),
                "mde_r_80": _wmw_mde(n1, n2, power=0.80, alpha=alpha_adj),
            }

    return results


def run_kruskal_wallis_with_dunn(
    metric: str,
    categories: dict[str, list[dict]],
    gm: Callable,
) -> dict:
    """Kruskal-Wallis H test + Dunn's post-hoc for a metric across all categories."""
    group_vals: dict[str, list[float]] = {}
    for cat, repos in categories.items():
        vals = _clean([gm(r, metric) for r in repos])
        if vals:
            group_vals[cat] = vals

    if len(group_vals) < 2:
        return {"H": None, "p": None, "significant": None, "dunn_posthoc": {}}

    groups_list = list(group_vals.values())
    try:
        stat, p = scipy_stats.kruskal(*groups_list)
    except Exception:
        return {"H": None, "p": None, "significant": None, "dunn_posthoc": {}}

    posthoc = dunn_posthoc(group_vals)

    return {
        "H": round(float(stat), 4),
        "p": round(float(p), 6),
        "significant": float(p) < 0.05,
        "dunn_posthoc": posthoc,
    }


def compute_spearman(x: list, y: list) -> dict:
    pairs = [
        (xi, yi) for xi, yi in zip(x, y)
        if xi is not None and yi is not None
        and not math.isnan(float(xi)) and not math.isnan(float(yi))
    ]
    n = len(pairs)
    if n < 3:
        return {"spearman_r": None, "p_value": None, "n": n}
    xs, ys = zip(*pairs)
    res = scipy_stats.spearmanr(xs, ys)
    r = float(res.statistic)
    p = float(res.pvalue)
    # scipy returns NaN for constant-input arrays; map to None so JSON stays valid
    return {
        "spearman_r": round(r, 4) if not math.isnan(r) else None,
        "p_value": round(p, 6) if not math.isnan(p) else None,
        "n": n,
    }


# ---------------------------------------------------------------------------
# Data extraction helpers
# ---------------------------------------------------------------------------

def _vuln_counts_from_dep(dep_data: dict) -> dict[str, int]:
    """Map repo_url → vulnerabilities_total from dependency_analysis.json.

    Repos with status "failed" (e.g. no GitHub dependency graph available)
    are excluded rather than treated as 0 vulnerabilities -- we never
    queried their dependencies, so 0 would be indistinguishable from a
    repo that was actually scanned and found clean.
    """
    counts: dict[str, int] = {}
    for repo in dep_data.get("repos", []):
        url = repo.get("repo_url", "")
        if url and repo.get("status") != "failed":
            counts[url] = int(repo.get("vulnerabilities_total", 0))
    return counts


def _vuln_densities_from_dep(dep_data: dict) -> dict[str, float]:
    """Map repo_url → vuln_density (vulns / packages_queryable).

    See _vuln_counts_from_dep: repos with no successful dependency scan
    are excluded rather than coded as density 0.
    """
    densities: dict[str, float] = {}
    for repo in dep_data.get("repos", []):
        url = repo.get("repo_url", "")
        if not url or repo.get("status") == "failed":
            continue
        vulns = int(repo.get("vulnerabilities_total", 0))
        queryable = int(repo.get("packages_queryable", 0))
        densities[url] = (vulns / queryable) if queryable > 0 else 0.0
    return densities


def _kev_counts_from_dep(dep_data: dict, kev_summary_path: Path) -> dict[str, int]:
    """Map repo_url → count of that repo's dependency vulnerabilities that are
    in the CISA Known Exploited Vulnerabilities (KEV) catalog.

    Reuses outputs/processed/kev_summary.json, already computed by
    pipeline/exploit.py earlier in the same pipeline run, rather than
    re-fetching and re-matching the KEV catalog here. Repos with a failed
    dependency scan are excluded (same reasoning as _vuln_counts_from_dep --
    their dependencies, and therefore their KEV exposure, were never actually
    queried, so 0 would be indistinguishable from "scanned and clean"). Repos
    with a successful scan but zero KEV matches are coded 0, not missing.
    """
    valid_urls = {
        repo.get("repo_url", "") for repo in dep_data.get("repos", [])
        if repo.get("repo_url") and repo.get("status") != "failed"
    }
    counts: dict[str, int] = {url: 0 for url in valid_urls}
    if not kev_summary_path.exists():
        return counts
    try:
        kev_summary = json.loads(kev_summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return counts
    exploitable_repos = ((kev_summary or {}).get("summary") or {}).get("exploitable_repos") or []
    for repo in exploitable_repos:
        url = repo.get("repo_url", "")
        if url in counts:
            counts[url] = len(repo.get("vulnerabilities") or [])
    return counts


def _stars(repo: dict) -> float | None:
    """Extract stars count from directly-collected GitHub metrics."""
    return _github_metric(repo, "stars")


def _github_metric(repo: dict, key: str) -> float | None:
    metrics = repo.get("github_metrics") or {}
    if not isinstance(metrics, dict):
        return None
    val = metrics.get(key)
    if val is None:
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _check_score(repo: dict, check: str) -> float | None:
    checks = repo.get("scorecard_checks") or {}
    if not isinstance(checks, dict):
        return None
    entry = checks.get(check)
    if not isinstance(entry, dict):
        return None
    score = entry.get("score")
    if score is None:
        return None
    s = int(score)
    return float(s) if s >= 0 else None


def _get_metric(
    repo: dict,
    metric: str,
    vuln_counts: dict[str, int],
    vuln_densities: dict[str, float],
    kev_counts: dict[str, int] | None = None,
) -> float | None:
    if metric == "scorecard_overall":
        val = repo.get("scorecard_overall")
        if val is not None:
            f = float(val)
            return f if f >= 0 else None
        return None
    if metric == "vuln_count":
        v = vuln_counts.get(repo.get("repo_url", ""))
        return float(v) if v is not None else None
    if metric == "vuln_density":
        v = vuln_densities.get(repo.get("repo_url", ""))
        return float(v) if v is not None else None
    if metric == "kev_exploitable_count":
        if kev_counts is None:
            return None
        v = kev_counts.get(repo.get("repo_url", ""))
        return float(v) if v is not None else None
    if metric == "stars_count":
        return _stars(repo)
    if metric.startswith("check_"):
        return _check_score(repo, metric[6:])
    return _github_metric(repo, metric)


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

CORE_METRICS = [
    "scorecard_overall",
    "contributor_count",
    "commit_count",
    "issues_opened",
    "issues_closed",
    "prs_merged",
    "vuln_count",
    "vuln_density",
    "stars_count",
    "kev_exploitable_count",
]

SCATTER_PAIRS = {
    "scorecard_vs_contributors": ("scorecard_overall", "contributor_count"),
    "scorecard_vs_stars": ("scorecard_overall", "stars_count"),
    "scorecard_vs_vulns": ("scorecard_overall", "vuln_count"),
    "scorecard_vs_commits": ("scorecard_overall", "commit_count"),
    "contributors_vs_vulns": ("contributor_count", "vuln_count"),
    "issues_opened_vs_closed": ("issues_opened", "issues_closed"),
    "scorecard_vs_vuln_density": ("scorecard_overall", "vuln_density"),
    "scorecard_vs_kev": ("scorecard_overall", "kev_exploitable_count"),
    "vulns_vs_kev": ("vuln_count", "kev_exploitable_count"),
}

KW_METRICS = [
    "scorecard_overall",
    "contributor_count",
    "commit_count",
    "issues_opened",
    "issues_closed",
    "prs_merged",
    "vuln_count",
    "vuln_density",
    "kev_exploitable_count",
]


def _nan_to_none(obj):
    """Recursively replace float NaN/Infinity with None so json.dumps produces
    standard-compliant JSON (Python's json module happily emits the literal
    `Infinity`/`-Infinity` for float('inf') by default, which isn't valid
    JSON and breaks strict parsers -- also caught here defensively, alongside
    NaN, even though no current code path is known to produce it)."""
    if isinstance(obj, dict):
        return {k: _nan_to_none(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_nan_to_none(v) for v in obj]
    if isinstance(obj, float) and not math.isfinite(obj):
        return None
    return obj


# ---------------------------------------------------------------------------
# Joint regression model — disentangles category, ag_specific, and scale
# ---------------------------------------------------------------------------
#
# The univariate Mann-Whitney/Kruskal-Wallis tests above can't separate
# category from ag_specific, since the two are entangled in this dataset (two
# categories -- Domain-specific agricultural platform, Data Processing
# Libraries/Tools -- have zero non-ag members). This is an ordinary least
# squares model, fit from scratch with numpy/scipy (no statsmodels dependency
# -- see requirements.txt) that regresses each outcome on category (dummy
# coded), ag_specific, and two scale covariates (log stars, log contributor
# count) simultaneously, so each term's coefficient is the partial effect
# holding the others fixed.

JOINT_MODEL_COVARIATES = ["ag_specific", "log_stars", "log_contributor_count"]


def _compute_vifs(X: np.ndarray, names: list[str]) -> dict[str, float | None]:
    """Variance inflation factor per non-intercept column, via
    statsmodels.stats.outliers_influence.variance_inflation_factor (regresses
    each column on every other column, including the intercept, and takes
    1/(1-R^2) of that regression). High VIFs (conventionally > 5-10) flag
    collinearity that makes individual coefficients unstable -- relevant
    here since category and ag_specific overlap by construction in this
    dataset."""
    vifs: dict[str, float | None] = {}
    for j, name in enumerate(names):
        if name == "intercept":
            continue
        try:
            vif = float(variance_inflation_factor(X, j))
            vifs[name] = round(vif, 2) if math.isfinite(vif) else None
        except Exception:
            vifs[name] = None
    return vifs


def _ols_fit(y: np.ndarray, X: np.ndarray, names: list[str]) -> dict | None:
    """Ordinary least squares via statsmodels.OLS, with HC3
    heteroskedasticity-consistent (robust) standard errors rather than the
    classical homoskedastic estimator, plus per-coefficient t-tests,
    R^2/adjusted R^2, and VIFs. Returns None if there aren't enough residual
    degrees of freedom (n - p <= 0) to fit at all.

    Point estimates (coefficients, R^2, adjusted R^2, degrees of freedom)
    are identical either way -- cov_type only changes how the standard
    errors (and therefore t/p/CI) are computed, not the fit itself (verified
    directly: same .params/.rsquared/.df_resid under cov_type="HC3" vs the
    default). HC3 was chosen over the classical estimator because GitHub
    activity/security metrics are essentially guaranteed to be
    heteroskedastic (variance scales with project size) even after the
    log1p transforms already applied to stars/contributors/vuln outcomes,
    and over the milder HC0-HC2 corrections because HC3 down-weights
    high-leverage points more aggressively via (1-h_ii)^2 in the
    denominator, which is the standard recommendation for small-to-moderate
    samples like this dataset's (n=55-66) -- see Long & Ervin (2000), "Using
    Heteroscedasticity Consistent Standard Errors in the Linear Regression
    Model," The American Statistician 54(3), 217-224, and MacKinnon & White
    (1985) for the original HC0-HC3 family. This project's own earlier
    from-scratch numpy implementation (classical SEs only) was cross-checked
    against statsmodels' classical (non-robust) fit on this exact dataset
    and matched to 4 decimal places before this swap to HC3, confirming the
    swap changes the SE estimator deliberately, not by implementation error.

    Note statsmodels sets use_t=False for HC-family covariance (confirmed
    directly, not assumed): p-values and the 95% CI below are computed
    against the standard normal (z) reference distribution, not Student's t,
    which is the standard convention for asymptotic robust-SE inference --
    the "t" field name is kept only because that's statsmodels' own
    attribute name (it's coef/se either way); it is not literally a
    t-statistic evaluated against a t-distribution here.
    """
    n, p = X.shape
    dof = n - p
    if dof <= 0:
        return None

    model = sm.OLS(y, X).fit(cov_type="HC3")
    vifs = _compute_vifs(X, names)
    # conf_int() -- not a manual coef +/- t_crit*se reconstruction -- since
    # it correctly follows use_t=False (z-based) for HC3, which a hand-rolled
    # t-distribution-based CI would get wrong (verified: a manual t-based CI
    # does not match statsmodels' own HC3 conf_int(), a z-based one does).
    ci = model.conf_int(alpha=0.05)
    coefficients = []
    for i, name in enumerate(names):
        se_i = float(model.bse[i])
        t_stat = float(model.tvalues[i]) if se_i > 0 and math.isfinite(model.tvalues[i]) else None
        p_value = float(model.pvalues[i]) if t_stat is not None and math.isfinite(model.pvalues[i]) else None
        ci_lo = float(ci[i, 0]) if math.isfinite(ci[i, 0]) else None
        ci_hi = float(ci[i, 1]) if math.isfinite(ci[i, 1]) else None
        coefficients.append({
            "term": name,
            "coef": round(float(model.params[i]), 4),
            "se": round(se_i, 4) if se_i > 0 else None,
            "t": round(t_stat, 4) if t_stat is not None else None,
            "p_value": round(p_value, 6) if p_value is not None else None,
            "ci_lo": round(ci_lo, 4) if ci_lo is not None else None,
            "ci_hi": round(ci_hi, 4) if ci_hi is not None else None,
            "vif": vifs.get(name),
        })

    return {
        "n": n,
        "dof": dof,
        "r_squared": round(float(model.rsquared), 4),
        "adj_r_squared": round(float(model.rsquared_adj), 4),
        "se_type": "HC3",
        "coefficients": coefficients,
    }


def _build_design_matrix(
    repos: list[dict],
    outcome_fn: Callable[[dict], float | None],
    category_reference: str,
) -> tuple[np.ndarray, np.ndarray, list[str]] | None:
    """Build (y, X, term_names) for the joint model:

        outcome ~ category (dummy-coded, category_reference held out)
                 + ag_specific + log1p(stars) + log1p(contributor_count)

    Rows missing the outcome, ag_specific, stars, or contributor_count are
    dropped listwise (a repo with a valid outcome but unknown ag_specific
    status, for instance, can't be placed in the design matrix at all).

    Dummy columns are built from the categories actually present *after*
    that listwise deletion, not from the full repo list -- if every member
    of some category happened to drop out for this particular outcome (e.g.
    a category whose repos all failed dependency collection, for a
    vuln_count/vuln_density model), including a dummy for it anyway would be
    an all-zero column: technically not rank-deficient on its own, but
    np.linalg.pinv resolves that direction via its zero-singular-value
    convention rather than reporting it as truly unidentifiable, which understates
    that coefficient's standard error rather than surfacing the problem.
    Dropping the column outright is the correct fix -- there's no data to
    estimate that category's effect from in this particular model anyway.
    """
    # First pass: collect retained rows (listwise deletion), deferring the
    # dummy-category columns until we know which categories actually survive.
    retained: list[tuple[str, bool, float, float, float]] = []  # (category, ag, stars, contributors, y)
    for r in repos:
        y = outcome_fn(r)
        if y is None or math.isnan(y):
            continue
        ag = r.get("ag_specific")
        if ag is not True and ag is not False:
            continue
        stars = _stars(r)
        contributors = _github_metric(r, "contributor_count")
        if stars is None or contributors is None:
            continue
        cat = r.get("category") or "Unknown"
        retained.append((cat, ag, stars, contributors, y))

    categories_present = sorted({t[0] for t in retained})
    dummy_categories = [c for c in categories_present if c != category_reference]

    rows: list[list[float]] = []
    ys: list[float] = []
    for cat, ag, stars, contributors, y in retained:
        row = [1.0]  # intercept
        row.extend(1.0 if cat == dc else 0.0 for dc in dummy_categories)
        row.append(1.0 if ag else 0.0)
        row.append(math.log1p(max(0.0, stars)))
        row.append(math.log1p(max(0.0, contributors)))
        rows.append(row)
        ys.append(y)

    # Require some minimum slack in degrees of freedom beyond the parameter
    # count, or the fit is too fragile to report.
    n_params = 1 + len(dummy_categories) + len(JOINT_MODEL_COVARIATES)
    if len(ys) < n_params + 5:
        return None

    names = ["intercept"] + [f"category[{dc}]" for dc in dummy_categories] + JOINT_MODEL_COVARIATES
    return np.array(ys, dtype=float), np.array(rows, dtype=float), names


def run_all(merged_repos_path: Path, dep_analysis_path: Path) -> Path:
    """Compute all statistics and write statistical_analysis.json."""
    logger.info("Running statistical analysis …")

    merged_data: list[dict] = json.loads(merged_repos_path.read_text(encoding="utf-8"))

    dep_data: dict = {}
    dep_data_exists = False
    if dep_analysis_path.exists():
        dep_data = json.loads(dep_analysis_path.read_text(encoding="utf-8"))
        dep_data_exists = True

    vuln_counts = _vuln_counts_from_dep(dep_data)
    vuln_densities = _vuln_densities_from_dep(dep_data)
    kev_counts = _kev_counts_from_dep(dep_data, config.PROCESSED_DIR / "kev_summary.json")
    analyzed_urls: set[str] = set(vuln_counts.keys())

    # Discover Scorecard check names from data
    check_names: set[str] = set()
    for repo in merged_data:
        checks = repo.get("scorecard_checks") or {}
        if isinstance(checks, dict):
            check_names.update(checks.keys())
    check_name_list = sorted(check_names)

    all_metrics = CORE_METRICS + [f"check_{c}" for c in check_name_list]

    def gm(repo: dict, metric: str) -> float | None:
        return _get_metric(repo, metric, vuln_counts, vuln_densities, kev_counts)

    # ── Group by category and ag_specific ─────────────────────────────────
    categories: dict[str, list[dict]] = {}
    ag_groups: dict[str, list[dict]] = {"yes": [], "no": [], "unknown": []}

    for repo in merged_data:
        cat = repo.get("category") or "Unknown"
        categories.setdefault(cat, []).append(repo)
        ag_raw = repo.get("ag_specific")
        if ag_raw is True or str(ag_raw).lower() in ("yes", "true", "1"):
            ag_groups["yes"].append(repo)
        elif ag_raw is False or str(ag_raw).lower() in ("no", "false", "0"):
            ag_groups["no"].append(repo)
        else:
            ag_groups["unknown"].append(repo)

    # ── Descriptive stats by category ─────────────────────────────────────
    by_category: dict[str, dict] = {}
    for cat, repos in categories.items():
        by_category[cat] = {}
        for metric in all_metrics:
            vals = [gm(r, metric) for r in repos]
            by_category[cat][metric] = compute_descriptive_stats(vals)

    # ── Descriptive stats by ag_specific ──────────────────────────────────
    by_ag_specific: dict[str, dict] = {}
    for group, repos in ag_groups.items():
        by_ag_specific[group] = {}
        for metric in all_metrics:
            vals = [gm(r, metric) for r in repos]
            by_ag_specific[group][metric] = compute_descriptive_stats(vals)

    # ── Mann-Whitney: ag yes vs no ─────────────────────────────────────────
    mw_results: dict[str, dict] = {}
    for metric in all_metrics:
        yes_vals = [gm(r, metric) for r in ag_groups["yes"]]
        no_vals = [gm(r, metric) for r in ag_groups["no"]]
        mw_results[metric] = run_mannwhitney(yes_vals, no_vals)

    # BH-FDR correction across all Mann-Whitney tests
    _valid_mw = [m for m in all_metrics if _is_valid_p(mw_results[m].get("p_value"))]
    _raw_p = [mw_results[m]["p_value"] for m in _valid_mw]
    _adj_p = _bh_fdr_correct(_raw_p)
    for _m, _ap in zip(_valid_mw, _adj_p):
        mw_results[_m]["p_adjusted_fdr"] = round(_ap, 6)
        mw_results[_m]["significant_fdr"] = _ap < 0.05

    # ── Kruskal-Wallis + Dunn's across categories ─────────────────────────
    kruskal_wallis: dict[str, dict] = {}
    for metric in KW_METRICS:
        kruskal_wallis[metric] = run_kruskal_wallis_with_dunn(metric, categories, gm)

    # BH-FDR correction across all Kruskal-Wallis omnibus tests, same family-wide
    # treatment already applied to the Mann-Whitney tests above -- "significant"
    # stays the raw p<0.05 flag; p_adjusted_fdr/significant_fdr are the corrected
    # ones. Dunn's post-hoc pairwise p-values already get their own Bonferroni
    # correction inside dunn_posthoc() and are untouched by this.
    _valid_kw = [m for m in KW_METRICS if _is_valid_p(kruskal_wallis[m].get("p"))]
    _raw_p_kw = [kruskal_wallis[m]["p"] for m in _valid_kw]
    _adj_p_kw = _bh_fdr_correct(_raw_p_kw)
    for _m, _ap in zip(_valid_kw, _adj_p_kw):
        kruskal_wallis[_m]["p_adjusted_fdr"] = round(_ap, 6)
        kruskal_wallis[_m]["significant_fdr"] = _ap < 0.05

    # ── Per-check Kruskal-Wallis + Dunn's across categories ────────────────
    # Same test as kruskal_wallis above, but per individual Scorecard check
    # (Branch-Protection, Signed-Releases, etc.) rather than only the
    # aggregate scorecard_overall -- answers "which specific practice differs
    # by stack layer" instead of just "does the aggregate score differ."
    # Kept as its own dict/FDR family rather than folded into KW_METRICS,
    # since it's conceptually a different family of tests (per-practice, not
    # per-outcome) and mixing the two families into one FDR correction would
    # make each test's power depend on how many checks happen to exist.
    kruskal_wallis_checks: dict[str, dict] = {}
    for check in check_name_list:
        kruskal_wallis_checks[f"check_{check}"] = run_kruskal_wallis_with_dunn(
            f"check_{check}", categories, gm
        )

    _valid_kwc = [m for m in kruskal_wallis_checks if _is_valid_p(kruskal_wallis_checks[m].get("p"))]
    _raw_p_kwc = [kruskal_wallis_checks[m]["p"] for m in _valid_kwc]
    _adj_p_kwc = _bh_fdr_correct(_raw_p_kwc)
    for _m, _ap in zip(_valid_kwc, _adj_p_kwc):
        kruskal_wallis_checks[_m]["p_adjusted_fdr"] = round(_ap, 6)
        kruskal_wallis_checks[_m]["significant_fdr"] = _ap < 0.05

    # ── Joint regression models ─────────────────────────────────────────────
    # Disentangles category and ag_specific (which overlap in this dataset --
    # two categories have zero non-ag members) by controlling for both
    # simultaneously, plus scale (log stars, log contributors), in one model
    # per outcome. vuln_count/vuln_density are heavily right-skewed count-ish
    # data, so they're modeled as log1p(outcome) ~ ... (a log-linear model);
    # scorecard_overall is modeled on its native 0-10 scale.
    category_counts = Counter(r.get("category") or "Unknown" for r in merged_data)
    reference_category = category_counts.most_common(1)[0][0] if category_counts else "Unknown"

    def _log1p_metric(metric_name: str) -> Callable[[dict], float | None]:
        def f(r: dict) -> float | None:
            v = gm(r, metric_name)
            return math.log1p(v) if v is not None and v >= 0 else None
        return f

    joint_model_specs: dict[str, Callable[[dict], float | None]] = {
        "scorecard_overall": lambda r: gm(r, "scorecard_overall"),
        "vuln_count_log1p": _log1p_metric("vuln_count"),
        "vuln_density_log1p": _log1p_metric("vuln_density"),
    }

    joint_models: dict[str, dict | None] = {}
    for outcome_name, outcome_fn in joint_model_specs.items():
        built = _build_design_matrix(merged_data, outcome_fn, reference_category)
        if built is None:
            joint_models[outcome_name] = None
            continue
        y, X, names = built
        fit = _ols_fit(y, X, names)
        if fit is not None:
            fit["reference_category"] = reference_category
            fit["outcome_transform"] = "log1p" if outcome_name.endswith("_log1p") else "none"
        joint_models[outcome_name] = fit

    # BH-FDR correction across the ag_specific coefficient's p-value across
    # the 3 outcome models -- a defensible "family" here since it's the same
    # underlying question ("does ag-specific status predict this outcome
    # after controlling for category and scale") asked of 3 different
    # outcomes, distinct from the category coefficients (which aren't a
    # comparable family across models since the dummy set differs by
    # reference category choice, held fixed here, but the hypothesis being
    # tested per dummy is specific to that one category contrast).
    _ag_coef_entries = []
    for _outcome_name, _fit in joint_models.items():
        if not _fit:
            continue
        for _c in _fit["coefficients"]:
            if _c["term"] == "ag_specific" and _is_valid_p(_c["p_value"]):
                _ag_coef_entries.append(_c)
    _adj_ag = _bh_fdr_correct([_c["p_value"] for _c in _ag_coef_entries])
    for _c, _ap in zip(_ag_coef_entries, _adj_ag):
        _c["p_adjusted_fdr"] = round(_ap, 6)
        _c["significant_fdr"] = _ap < 0.05

    # ── Full correlation matrix across CORE_METRICS ───────────────────────
    # Computed first (not after "correlations" below) because every
    # SCATTER_PAIRS entry is a pair drawn from CORE_METRICS -- i.e. the same
    # test already appears once in this matrix. BH-FDR is applied once,
    # across the C(10,2)=45 unique off-diagonal pairs (the diagonal is
    # self-correlation, r=1 by construction, not a real hypothesis test and
    # excluded from the family), and "correlations" below reuses these
    # already-corrected results by lookup instead of recomputing the same
    # test a second time under a second, differently-sized (and therefore
    # differently BH-corrected) family -- the same pair getting two
    # different "corrected" p-values depending on which JSON key a reader
    # looks at would be actively misleading.
    def get_all(metric: str) -> list:
        return [gm(r, metric) for r in merged_data]

    metric_vals = {m: get_all(m) for m in CORE_METRICS}
    correlation_matrix: dict[str, dict] = {m1: {} for m1 in CORE_METRICS}
    _unique_pair_results: dict[tuple[str, str], dict] = {}

    for i, m1 in enumerate(CORE_METRICS):
        for j, m2 in enumerate(CORE_METRICS):
            if i == j:
                n_valid = len(_clean(metric_vals[m1]))
                correlation_matrix[m1][m2] = {
                    "spearman_r": 1.0 if n_valid else None, "p_value": None, "n": n_valid,
                    "p_adjusted_fdr": None, "significant_fdr": None,
                }
                continue
            key = (m1, m2) if i < j else (m2, m1)
            if key not in _unique_pair_results:
                _unique_pair_results[key] = compute_spearman(metric_vals[key[0]], metric_vals[key[1]])
            correlation_matrix[m1][m2] = dict(_unique_pair_results[key])

    _valid_corr = [k for k, v in _unique_pair_results.items() if _is_valid_p(v.get("p_value"))]
    _raw_p_corr = [_unique_pair_results[k]["p_value"] for k in _valid_corr]
    _adj_p_corr = _bh_fdr_correct(_raw_p_corr)
    for key, ap in zip(_valid_corr, _adj_p_corr):
        _unique_pair_results[key]["p_adjusted_fdr"] = round(ap, 6)
        _unique_pair_results[key]["significant_fdr"] = ap < 0.05
        for m1, m2 in (key, key[::-1]):
            correlation_matrix[m1][m2]["p_adjusted_fdr"] = _unique_pair_results[key]["p_adjusted_fdr"]
            correlation_matrix[m1][m2]["significant_fdr"] = _unique_pair_results[key]["significant_fdr"]

    # ── Named scatter-pair correlations (dashboard subtitles) -- looked up
    # from the matrix above, not recomputed; see comment above.
    correlations: dict[str, dict] = {}
    for pair_key, (m1, m2) in SCATTER_PAIRS.items():
        correlations[pair_key] = dict(correlation_matrix[m1][m2])

    # ── Per-repo check scores for heatmap ─────────────────────────────────
    per_repo_checks: list[dict] = []
    for repo in merged_data:
        row: dict = {
            "display_name": repo.get("display_name") or repo.get("repo_name", ""),
            "category": repo.get("category") or "Unknown",
            "ag_specific": repo.get("ag_specific"),
        }
        for check in check_name_list:
            row[f"check_{check}"] = _check_score(repo, check)
        per_repo_checks.append(row)

    # ── Per-repo raw values for boxplots / quality flags ──────────────────
    per_repo_raw: list[dict] = []
    for repo in merged_data:
        repo_url = repo.get("repo_url", "")
        dep_failed = dep_data_exists and bool(repo_url) and repo_url not in analyzed_urls

        row = {
            "display_name": repo.get("display_name") or repo.get("repo_name", ""),
            "category": repo.get("category") or "Unknown",
            "ag_specific": repo.get("ag_specific"),
            "dep_failed": dep_failed,
            "github_metrics_reliable": bool(repo.get("github_metrics_collected")),
        }
        for metric in CORE_METRICS:
            row[metric] = gm(repo, metric)
        per_repo_raw.append(row)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_repos": len(merged_data),
        "metrics": all_metrics,
        "check_names": check_name_list,
        "group_sizes_total": {g: len(repos) for g, repos in ag_groups.items()},
        "data_notes": (
            f"Total repos by ag_specific: yes={len(ag_groups['yes'])}, "
            f"no={len(ag_groups['no'])}, unknown={len(ag_groups['unknown'])}. "
            "Mann-Whitney n_a and n_b reflect only repos with valid (non-null, non-negative) "
            "metric values after cleaning; repos with failed Scorecard collection "
            "(raw score = -1) are excluded from scorecard-based comparisons, so n_b in "
            "the Mann-Whitney result may be smaller than the total non-ag repo count. "
            "p_adjusted_fdr uses Benjamini-Hochberg FDR correction applied simultaneously "
            f"across all {len(_valid_mw)} Mann-Whitney tests. Kruskal-Wallis omnibus "
            f"p-values are likewise BH-FDR corrected across all {len(_valid_kw)} "
            "category-comparison tests (separately from the Mann-Whitney family above); "
            "Dunn's post-hoc pairwise p-values keep their own per-metric Bonferroni "
            "correction, unaffected by this. kev_exploitable_count is the per-repo count of "
            "dependency vulnerabilities that are in the CISA KEV catalog, reused from "
            "kev_summary.json; repos with a failed dependency scan are excluded from it the "
            "same way they're excluded from vuln_count/vuln_density. "
            f"kruskal_wallis_checks repeats the Kruskal-Wallis+Dunn battery across all "
            f"{len(check_name_list)} individual Scorecard checks (not just the aggregate "
            f"score), BH-FDR corrected as its own family of {len(_valid_kwc)} tests, separate "
            "from kruskal_wallis above. Achieved 'power' and 'mde_r_80' (minimum detectable "
            "rank-biserial |r| at 80% power) on Mann-Whitney results use the exact finite-sample "
            "Wilcoxon-Mann-Whitney variance formula (Noether 1987; Zhao et al. 2008), computed "
            "fresh from each comparison's actual n_a/n_b and real tie count -- not a fixed/"
            "hardcoded constant, so it's automatically consistent as the dataset grows or "
            "shrinks. Dunn post-hoc power/MDE use the same formula from each pair's own n1/n2 "
            "(tie count not included there -- a pair's rank position depends on every category "
            "in the Kruskal-Wallis pool, not just the pair, so a pair-specific tie correction "
            "isn't well-defined the way it is for a standalone two-sample comparison) and the "
            "Bonferroni-adjusted alpha actually applied to that pair's significance call; "
            "Mann-Whitney power/MDE use the nominal alpha=0.05. This is Noether's method, which "
            "substitutes the null-hypothesis variance of the U statistic for the (generally "
            "smaller, analytically intractable without assuming a parametric alternative) true "
            "variance under the alternative -- accurate for small-to-moderate effect sizes, but "
            "increasingly UNDERSTATES true power as |r| grows past roughly 0.5-0.6 (verified by "
            "simulation). Several of this dataset's own naive ag-vs-non-ag comparisons have |r| "
            "in that range (e.g. scorecard_overall r=-0.87, stars_count r=-0.96) -- for those, "
            "read the reported power as a conservative lower bound, not a precise figure; true "
            "power is probably higher. Most reliable as a rough guide at very small category "
            "sizes (n as low as 5) combined with small-to-moderate effect sizes, not an exact "
            "nonparametric power calculation in general. TREAT 'mde_r_80' AS THE PRIMARY METRIC "
            "OF THE TWO, NOT 'power'. Retrospective/observed power (computed from the effect size "
            "actually seen in this sample, as 'power' is here) is a near-deterministic function "
            "of the p-value -- a low observed p-value mechanically produces high observed power "
            "and vice versa, so it adds little information beyond the p-value itself and is "
            "widely criticized in the statistics literature as uninformative or actively "
            "misleading when used to argue 'this result wasn't significant because power was "
            "low' (that reasoning is circular: power computed post hoc from a small observed "
            "effect will always look low). See Hoenig & Heisey (2001), 'The Abuse of Power: The "
            "Pervasive Fallacy of Power Calculations for Data Analysis,' The American "
            "Statistician 55(1), 19-24. mde_r_80 does not have this problem -- it depends only "
            "on n_a/n_b (and alpha), not on the effect actually observed, so it answers the "
            "design question 'what effect size could this sample size have reliably detected' "
            "independent of what was found. 'power' is retained for completeness and because it "
            "is the more immediately intuitive of the two, but conclusions about whether a "
            "non-significant category/check comparison reflects a true null versus insufficient "
            "sample size should be drawn from mde_r_80, not from 'power'. "
            "joint_models are ordinary least squares regressions (statsmodels.OLS) of each "
            "outcome on category "
            f"(dummy-coded, reference category = '{reference_category}', the most common "
            "category in this dataset) + ag_specific + log1p(stars) + log1p(contributor_count) "
            "simultaneously -- this is what actually separates 'is it category or is it "
            "ag-specific status' rather than the univariate MW/KW tests above, which can't, "
            "since two categories in this dataset have zero non-ag members. Standard errors use "
            "the HC3 heteroskedasticity-consistent (robust) estimator (se_type field on each "
            "model), not the classical homoskedastic one -- GitHub activity/security metrics are "
            "essentially guaranteed to be heteroskedastic (variance scales with project size) "
            "even after the log1p transforms below, and HC3 is the standard choice over milder "
            "HC0-HC2 corrections at this dataset's sample size (see Long & Ervin 2000). "
            "Coefficients, R-squared, and degrees of freedom are unaffected by this choice -- "
            "only the standard errors/t/p-values/CI are. Each coefficient also reports a 95% CI "
            "(ci_lo/ci_hi) consistent with the HC3 SE (statsmodels' own conf_int(), not a "
            "hand-reconstructed one -- HC-family covariance uses the normal/z reference "
            "distribution rather than Student's t, which a manual coef +/- t_crit*se CI would "
            "get wrong). vuln_count and "
            "vuln_density are log1p-transformed as the outcome (log-linear model) given their "
            "heavy right skew; scorecard_overall is modeled on its native scale. Check each "
            "model's VIF column for collinearity before trusting an individual coefficient -- "
            "category and ag_specific are expected to show some inflation given the overlap "
            "above. The ag_specific coefficient's p-value is BH-FDR corrected across the 3 "
            "outcome models as its own family; category coefficients are not (not a comparable "
            "cross-model family). A model is omitted (null) if there weren't enough complete "
            "cases to fit it with positive residual degrees of freedom. "
            f"correlation_matrix's {len(_valid_corr)} unique off-diagonal pairs (the C(10,2)=45 "
            "distinct pairs among the 10 CORE_METRICS -- the diagonal is self-correlation, "
            "r=1 by construction, not a real test, and excluded) are BH-FDR corrected as their "
            "own family; p_adjusted_fdr/significant_fdr on each cell reflect that correction, "
            "mirrored across both (m1,m2) and (m2,m1). 'correlations' (the named scatter-pair "
            "subset shown in the dashboard) reuses these same corrected results by lookup rather "
            "than recomputing -- every named pair is already one of the 45 matrix pairs, so "
            "recomputing would let the identical test carry two different 'corrected' p-values "
            "depending on which JSON key is read."
        ),
        "by_category": by_category,
        "by_ag_specific": by_ag_specific,
        "comparisons": {
            "ag_vs_nonag": mw_results,
        },
        "kruskal_wallis": kruskal_wallis,
        "kruskal_wallis_checks": kruskal_wallis_checks,
        "joint_models": joint_models,
        "correlations": correlations,
        "correlation_matrix": correlation_matrix,
        "per_repo_checks": per_repo_checks,
        "per_repo_raw": per_repo_raw,
    }

    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    STAT_ANALYSIS_FILE.write_text(
        json.dumps(_nan_to_none(output), indent=2, default=str), encoding="utf-8"
    )
    logger.info("Statistical analysis written to %s", STAT_ANALYSIS_FILE)
    return STAT_ANALYSIS_FILE
