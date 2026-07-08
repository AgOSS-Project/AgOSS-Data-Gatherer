"""Saturation analysis — rarefaction curves to assess whether N=42 repos is sufficient.

Writes outputs/processed/saturation_analysis.json.
"""

from __future__ import annotations

import json
import logging
import math
from datetime import datetime, timezone
from pathlib import Path

import numpy as np

from pipeline import config

logger = logging.getLogger("pipeline.saturation")

SATURATION_FILE = config.PROCESSED_DIR / "saturation_analysis.json"
N_ITER = 500
SEED = 42


def _sample_sizes(n_total: int) -> list[int]:
    """Steps of 5 up to n_total, always including n_total itself."""
    sizes = list(range(5, n_total, 5))
    if not sizes or sizes[-1] != n_total:
        sizes.append(n_total)
    return sizes


def _vuln_counts_from_dep(dep_data: dict) -> dict[str, int]:
    # Repos with status "failed" (e.g. no GitHub dependency graph) have no
    # real vulnerability data and are excluded rather than coded as 0 --
    # see pipeline/stats.py's _vuln_counts_from_dep for the same fix.
    counts: dict[str, int] = {}
    for repo in dep_data.get("repos", []):
        url = repo.get("repo_url", "")
        if url and repo.get("status") != "failed":
            counts[url] = int(repo.get("vulnerabilities_total", 0))
    return counts


def _agg(vals: list[float]) -> dict:
    arr = np.array(vals, dtype=float)
    return {
        "mean": round(float(np.mean(arr)), 4),
        "ci_lo": round(float(np.percentile(arr, 2.5)), 4),
        "ci_hi": round(float(np.percentile(arr, 97.5)), 4),
    }


def run_saturation(merged_repos_path: Path, dep_analysis_path: Path) -> Path:
    """Bootstrap rarefaction across sample sizes and write saturation_analysis.json."""
    logger.info("Running saturation analysis (N_ITER=%d) …", N_ITER)

    merged_data: list[dict] = json.loads(merged_repos_path.read_text(encoding="utf-8"))

    dep_data: dict = {}
    if dep_analysis_path.exists():
        dep_data = json.loads(dep_analysis_path.read_text(encoding="utf-8"))

    vuln_counts = _vuln_counts_from_dep(dep_data)
    n_total = len(merged_data)
    sample_sizes = _sample_sizes(n_total)

    rng = np.random.default_rng(SEED)

    metric_results: dict[str, dict] = {
        "mean_scorecard": {},
        "pct_with_vulns": {},
        "mean_vuln_count": {},
        "n_unique_categories": {},
    }

    for k_raw in sample_sizes:
        k = min(k_raw, n_total)

        scores_iter: list[float] = []
        vuln_pct_iter: list[float] = []
        vuln_count_iter: list[float] = []
        cat_count_iter: list[float] = []

        for _ in range(N_ITER):
            indices = rng.choice(n_total, size=k, replace=False)
            sample = [merged_data[i] for i in indices]

            # Mean scorecard (skip missing / negative)
            scores = []
            for r in sample:
                sc = r.get("scorecard_overall")
                if sc is not None:
                    try:
                        f = float(sc)
                        if not math.isnan(f) and f >= 0:
                            scores.append(f)
                    except (TypeError, ValueError):
                        pass
            scores_iter.append(float(np.mean(scores)) if scores else 0.0)

            # % repos with any vulnerability (only over repos with real dependency data)
            vuln_vals = [vuln_counts[url] for r in sample if (url := r.get("repo_url", "")) in vuln_counts]
            if vuln_vals:
                vuln_pct_iter.append(100.0 * sum(v > 0 for v in vuln_vals) / len(vuln_vals))
                vuln_count_iter.append(float(np.mean(vuln_vals)))
            else:
                vuln_pct_iter.append(0.0)
                vuln_count_iter.append(0.0)

            # Unique categories seen
            cats = {r.get("category") or "Unknown" for r in sample}
            cat_count_iter.append(float(len(cats)))

        key = str(k)
        metric_results["mean_scorecard"][key] = _agg(scores_iter)
        metric_results["pct_with_vulns"][key] = _agg(vuln_pct_iter)
        metric_results["mean_vuln_count"][key] = _agg(vuln_count_iter)
        metric_results["n_unique_categories"][key] = _agg(cat_count_iter)

    output = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "n_total": n_total,
        "n_iter": N_ITER,
        "sample_sizes": sample_sizes,
        "metrics": metric_results,
    }

    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    SATURATION_FILE.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    logger.info("Saturation analysis written to %s", SATURATION_FILE)
    return SATURATION_FILE
