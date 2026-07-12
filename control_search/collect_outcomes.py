"""Collect outcome metrics for the matched-comparison analysis.

Dependency-based outcomes (vuln_count, vuln_density) are already produced by
covariates.attach_dependency_counts() for the full control pool — that call is
shared with the matching-covariate step, since SBOM+OSV analysis is one atomic
batched operation regardless of which subset ultimately gets compared. This
module only needs to additionally:
  1. Run Scorecard (the expensive per-repo subprocess step) for the eligible
     union of control repos — not the whole candidate pool.
  2. Cross-reference the CISA KEV catalog against the already-collected
     dependency data to get a per-repo exploitable-vulnerability count.
  3. Assemble one outcome table covering both dataset repos (reusing their
     already-collected merged_repos.json data) and eligible-union control
     repos.
"""

from __future__ import annotations

import logging
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Any

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
for _p in (str(_PROJECT_ROOT), str(_THIS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pipeline import config
from pipeline.models import RepoEntry
from pipeline.scorecard_runner import run_scorecard_batch
from pipeline import exploit as pipeline_exploit

logger = logging.getLogger("control_search.collect_outcomes")

RAW_SCORECARD_DIR = _THIS_DIR / "raw" / "scorecard"


@contextmanager
def _redirect_scorecard_cache():
    original = config.RAW_SCORECARD_DIR
    config.RAW_SCORECARD_DIR = RAW_SCORECARD_DIR
    try:
        yield
    finally:
        config.RAW_SCORECARD_DIR = original


def collect_scorecard_for_union(union_entries: list[RepoEntry]) -> dict[str, Any]:
    """Run Scorecard for the eligible-union control repos, keyed by 'owner/repo'."""
    if not union_entries:
        return {}
    with _redirect_scorecard_cache():
        results = run_scorecard_batch(union_entries)
    out: dict[str, Any] = {}
    for entry in union_entries:
        r = results.get(entry.repo_url)
        key = f"{entry.owner}/{entry.repo_name}"
        out[key] = {
            "scorecard_overall": r.overall_score if r else None,
            "scorecard_checks": r.checks if r else {},
        }
    return out


def build_kev_exploitable_counts(dep_report: dict[str, Any]) -> dict[str, int]:
    """Per-repo count of vulnerabilities that are in the CISA KEV catalog.

    Reuses pipeline.exploit's KEV catalog fetch + matching logic directly.
    """
    catalog = pipeline_exploit.fetch_kev_catalog()
    if not catalog:
        logger.warning(
            "[collect_outcomes] KEV catalog unavailable; kev_exploitable_count will be 0 for all repos"
        )
        return {}
    kev_matches = pipeline_exploit.match_vulnerabilities_to_kev(catalog, dep_report)

    counts: dict[str, int] = {}
    for row in dep_report.get("repos", []):
        owner = row.get("owner") or ""
        repo_name = row.get("repo_name") or ""
        if not owner or not repo_name:
            continue
        key = f"{owner}/{repo_name}"
        n = 0
        for vid in row.get("vulnerability_ids", []):
            match = kev_matches.get(str(vid))
            if match and match.get("is_exploitable"):
                n += 1
        counts[key] = n
    return counts


def _check_score(checks: dict, name: str) -> float | None:
    entry = checks.get(name) if isinstance(checks, dict) else None
    if not isinstance(entry, dict):
        return None
    score = entry.get("score")
    if score is None:
        return None
    s = int(score)
    return float(s) if s >= 0 else None


def _dep_vuln_outcomes(dep_row: dict[str, Any]) -> tuple[float | None, float | None]:
    """Derive (vuln_count, vuln_density) from a dependency_analysis.json row.

    A missing row or status "failed" (e.g. GitHub has no dependency graph
    for the repo) means dependencies were never actually queried -- that's
    reported as missing (None), not 0, so it doesn't get silently treated
    as "scanned and clean" downstream in the matched comparison.
    """
    if not dep_row or dep_row.get("status") == "failed":
        return None, None
    vulns_total = int(dep_row.get("vulnerabilities_total", 0))
    queryable = int(dep_row.get("packages_queryable", 0))
    density = (vulns_total / queryable) if queryable else 0.0
    return float(vulns_total), density


def build_outcome_table(
    dep_report: dict[str, Any],
    kev_counts: dict[str, int],
    control_scorecard: dict[str, Any],
    dataset_merged_repos: list[dict[str, Any]],
) -> tuple[dict[str, dict[str, float | None]], list[str]]:
    """Combine Scorecard + dependency + KEV data into one per-repo outcome
    table, keyed by 'owner/repo', for both dataset repos (from
    merged_repos.json) and eligible-union control repos (from
    control_scorecard + dep_report). Returns (outcomes, check_name_list).
    """
    dep_by_key: dict[str, dict[str, Any]] = {}
    for row in dep_report.get("repos", []):
        owner = row.get("owner") or ""
        repo_name = row.get("repo_name") or ""
        if owner and repo_name:
            dep_by_key[f"{owner}/{repo_name}"] = row

    check_names: set[str] = set()
    for row in dataset_merged_repos:
        checks = row.get("scorecard_checks") or {}
        if isinstance(checks, dict):
            check_names.update(checks.keys())
    for sc in control_scorecard.values():
        checks = sc.get("scorecard_checks") or {}
        if isinstance(checks, dict):
            check_names.update(checks.keys())
    check_name_list = sorted(check_names)

    outcomes: dict[str, dict[str, float | None]] = {}

    for row in dataset_merged_repos:
        owner = row.get("owner") or ""
        repo_name = row.get("repo_name") or ""
        key = f"{owner}/{repo_name}"
        dep_row = dep_by_key.get(key, {})
        vuln_count, vuln_density = _dep_vuln_outcomes(dep_row)
        entry: dict[str, float | None] = {
            "scorecard_overall": row.get("scorecard_overall"),
            "vuln_count": vuln_count,
            "vuln_density": vuln_density,
            "kev_exploitable_count": float(kev_counts.get(key, 0)),
        }
        checks = row.get("scorecard_checks") or {}
        for c in check_name_list:
            entry[f"check_{c}"] = _check_score(checks, c)
        outcomes[key] = entry

    for key, sc in control_scorecard.items():
        dep_row = dep_by_key.get(key, {})
        vuln_count, vuln_density = _dep_vuln_outcomes(dep_row)
        entry = {
            "scorecard_overall": sc.get("scorecard_overall"),
            "vuln_count": vuln_count,
            "vuln_density": vuln_density,
            "kev_exploitable_count": float(kev_counts.get(key, 0)),
        }
        checks = sc.get("scorecard_checks") or {}
        for c in check_name_list:
            entry[f"check_{c}"] = _check_score(checks, c)
        outcomes[key] = entry

    return outcomes, check_name_list
