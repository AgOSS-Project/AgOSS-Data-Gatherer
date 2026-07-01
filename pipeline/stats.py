"""Statistical analysis — bootstrap CIs, Mann-Whitney tests, Kruskal-Wallis, and Spearman correlations.

Writes outputs/processed/statistical_analysis.json.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import numpy as np
from scipy import stats as scipy_stats

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
    """Benjamini-Hochberg FDR correction. Input must be a list of non-None floats."""
    m = len(p_values)
    if m == 0:
        return []
    sorted_idx = sorted(range(m), key=lambda i: p_values[i])
    adjusted = [0.0] * m
    min_adj = 1.0
    for rank_from_end, idx in enumerate(reversed(sorted_idx)):
        bh_rank = m - rank_from_end  # rank 1..m by ascending p-value
        adj_p = min(min_adj, p_values[idx] * m / bh_rank)
        min_adj = adj_p
        adjusted[idx] = min(1.0, adj_p)
    return adjusted


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
    if len(data) < 2:
        val = float(func(np.array(data))) if data else float("nan")
        return val, val
    arr = np.array(data, dtype=float)
    rng = np.random.default_rng(seed)
    samples = rng.choice(arr, size=(n, len(arr)), replace=True)
    estimates = np.apply_along_axis(func, 1, samples)
    alpha = (1 - ci) / 2
    return (
        float(np.nanpercentile(estimates, alpha * 100)),
        float(np.nanpercentile(estimates, (1 - alpha) * 100)),
    )


def _bootstrap_r_ci(
    a: list[float],
    b: list[float],
    n: int = N_BOOTSTRAP,
    ci: float = CI_LEVEL,
    seed: int = 42,
) -> tuple[float, float]:
    """Bootstrap 95% CI for the rank-biserial r from a Mann-Whitney comparison."""
    arr_a = np.array(a, dtype=float)
    arr_b = np.array(b, dtype=float)
    rng = np.random.default_rng(seed)
    r_samples: list[float] = []
    for _ in range(n):
        s_a = rng.choice(arr_a, size=len(arr_a), replace=True)
        s_b = rng.choice(arr_b, size=len(arr_b), replace=True)
        try:
            u_boot = float(scipy_stats.mannwhitneyu(s_a, s_b, alternative="two-sided").statistic)
            r_samples.append((2 * u_boot) / (len(s_a) * len(s_b)) - 1.0)
        except Exception:
            pass
    if len(r_samples) < 10:
        return float("nan"), float("nan")
    alpha = (1 - ci) / 2
    return float(np.percentile(r_samples, alpha * 100)), float(np.percentile(r_samples, (1 - alpha) * 100))


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
        }
    result = scipy_stats.mannwhitneyu(a, b, alternative="two-sided")
    u = float(result.statistic)
    p = float(result.pvalue)
    # scipy returns U1 (U for the first/ag group); r = 2*U1/(n_a*n_b) - 1
    # so positive r means group A (ag) ranks higher, negative means group B (non-ag) ranks higher
    r = (2 * u) / (n_a * n_b) - 1.0
    r_lo, r_hi = _bootstrap_r_ci(a, b)
    return {
        "n_a": n_a, "n_b": n_b,
        "mw_statistic": round(u, 4),
        "p_value": round(p, 6),
        "effect_size_r": round(r, 4),
        "effect_size_r_ci_lo": round(r_lo, 4) if not math.isnan(r_lo) else None,
        "effect_size_r_ci_hi": round(r_hi, 4) if not math.isnan(r_hi) else None,
        "effect_label": _effect_label(r),
        "significant": p < 0.05,
    }


def dunn_posthoc(groups: dict[str, list[float]]) -> dict[str, dict]:
    """Dunn's post-hoc pairwise test with Bonferroni correction.

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

    ranks = scipy_stats.rankdata(all_vals)

    group_ranks: dict[str, list[float]] = {name: [] for name in group_names}
    for rank, label in zip(ranks, group_labels):
        group_ranks[label].append(rank)

    mean_ranks = {name: float(np.mean(r)) for name, r in group_ranks.items()}
    n_per = {name: len(r) for name, r in group_ranks.items()}

    # Tie correction
    _, counts = np.unique(all_vals, return_counts=True)
    tie_sum = float(sum(int(c) ** 3 - int(c) for c in counts if c > 1))
    denom = 12.0 * (N - 1) if N > 1 else 1.0
    S = (N * (N + 1) / 12.0) - (tie_sum / denom)
    if S <= 0:
        S = 1.0

    n_pairs = len(group_names) * (len(group_names) - 1) // 2
    results: dict[str, dict] = {}

    for i, g1 in enumerate(group_names):
        for g2 in group_names[i + 1:]:
            n1, n2 = n_per[g1], n_per[g2]
            se = math.sqrt(S * (1.0 / n1 + 1.0 / n2))
            z = (mean_ranks[g1] - mean_ranks[g2]) / se if se > 0 else 0.0
            p_raw = 2.0 * (1.0 - float(scipy_stats.norm.cdf(abs(z))))
            p_adj = min(1.0, p_raw * n_pairs)
            results[f"{g1} vs {g2}"] = {
                "Z": round(z, 4),
                "p_adj": round(p_adj, 6),
                "significant": p_adj < 0.05,
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
    """Map repo_url → vulnerabilities_total from dependency_analysis.json."""
    counts: dict[str, int] = {}
    for repo in dep_data.get("repos", []):
        url = repo.get("repo_url", "")
        if url:
            counts[url] = int(repo.get("vulnerabilities_total", 0))
    return counts


def _vuln_densities_from_dep(dep_data: dict) -> dict[str, float]:
    """Map repo_url → vuln_density (vulns / packages_queryable)."""
    densities: dict[str, float] = {}
    for repo in dep_data.get("repos", []):
        url = repo.get("repo_url", "")
        if not url:
            continue
        vulns = int(repo.get("vulnerabilities_total", 0))
        queryable = int(repo.get("packages_queryable", 0))
        densities[url] = (vulns / queryable) if queryable > 0 else 0.0
    return densities


def _stars(repo: dict) -> float | None:
    """Extract stars count; checks aggregate_summary first, then top-level stars key."""
    metrics = repo.get("augur_metrics") or {}
    summary = metrics.get("aggregate_summary")
    if isinstance(summary, list) and summary:
        val = summary[0].get("stars_count")
        if val is not None:
            try:
                return float(val)
            except (TypeError, ValueError):
                pass
    # Fallback: top-level "stars" key set by GitHub API fallback in merger
    val = metrics.get("stars")
    if val is not None:
        try:
            return float(val)
        except (TypeError, ValueError):
            pass
    return None


def _augur(repo: dict, key: str) -> float | None:
    metrics = repo.get("augur_metrics") or {}
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
) -> float | None:
    if metric == "scorecard_overall":
        val = repo.get("scorecard_overall")
        if val is not None:
            f = float(val)
            return f if f >= 0 else None
        return None
    if metric == "vuln_count":
        return float(vuln_counts.get(repo.get("repo_url", ""), 0))
    if metric == "vuln_density":
        return float(vuln_densities.get(repo.get("repo_url", ""), 0.0))
    if metric == "stars_count":
        return _stars(repo)
    if metric.startswith("check_"):
        return _check_score(repo, metric[6:])
    return _augur(repo, metric)


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
]

SCATTER_PAIRS = {
    "scorecard_vs_contributors": ("scorecard_overall", "contributor_count"),
    "scorecard_vs_stars": ("scorecard_overall", "stars_count"),
    "scorecard_vs_vulns": ("scorecard_overall", "vuln_count"),
    "scorecard_vs_commits": ("scorecard_overall", "commit_count"),
    "contributors_vs_vulns": ("contributor_count", "vuln_count"),
    "issues_opened_vs_closed": ("issues_opened", "issues_closed"),
    "scorecard_vs_vuln_density": ("scorecard_overall", "vuln_density"),
}

KW_METRICS = ["scorecard_overall", "vuln_count", "vuln_density"]


def _nan_to_none(obj):
    """Recursively replace float NaN with None so json.dumps produces valid JSON."""
    if isinstance(obj, dict):
        return {k: _nan_to_none(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_nan_to_none(v) for v in obj]
    if isinstance(obj, float) and math.isnan(obj):
        return None
    return obj


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
        return _get_metric(repo, metric, vuln_counts, vuln_densities)

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
    _valid_mw = [m for m in all_metrics if mw_results[m].get("p_value") is not None]
    _raw_p = [mw_results[m]["p_value"] for m in _valid_mw]
    _adj_p = _bh_fdr_correct(_raw_p)
    for _m, _ap in zip(_valid_mw, _adj_p):
        mw_results[_m]["p_adjusted_fdr"] = round(_ap, 6)
        mw_results[_m]["significant_fdr"] = _ap < 0.05

    # ── Kruskal-Wallis + Dunn's across categories ─────────────────────────
    kruskal_wallis: dict[str, dict] = {}
    for metric in KW_METRICS:
        kruskal_wallis[metric] = run_kruskal_wallis_with_dunn(metric, categories, gm)

    # ── Spearman correlations (scatter pairs) ─────────────────────────────
    def get_all(metric: str) -> list:
        return [gm(r, metric) for r in merged_data]

    correlations: dict[str, dict] = {}
    for pair_key, (m1, m2) in SCATTER_PAIRS.items():
        correlations[pair_key] = compute_spearman(get_all(m1), get_all(m2))

    # ── Full correlation matrix across CORE_METRICS ───────────────────────
    correlation_matrix: dict[str, dict] = {}
    for m1 in CORE_METRICS:
        correlation_matrix[m1] = {}
        x_vals = get_all(m1)
        for m2 in CORE_METRICS:
            y_vals = get_all(m2)
            correlation_matrix[m1][m2] = compute_spearman(x_vals, y_vals)

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

        augur_status = repo.get("augur_status") or ""
        augur_ready = repo.get("augur_ready")
        if augur_ready is True or str(augur_status).lower() in ("ready", "partial"):
            augur_reliable = True
        elif augur_ready is False or augur_status:
            augur_reliable = False
        else:
            augur_reliable = None

        row = {
            "display_name": repo.get("display_name") or repo.get("repo_name", ""),
            "category": repo.get("category") or "Unknown",
            "ag_specific": repo.get("ag_specific"),
            "dep_failed": dep_failed,
            "augur_reliable": augur_reliable,
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
            f"across all {len(_valid_mw)} Mann-Whitney tests."
        ),
        "by_category": by_category,
        "by_ag_specific": by_ag_specific,
        "comparisons": {
            "ag_vs_nonag": mw_results,
        },
        "kruskal_wallis": kruskal_wallis,
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
