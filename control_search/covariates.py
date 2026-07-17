"""Matching covariates for the AgOSS matched-comparison analysis.

Computed identically, via GitHub REST, for the 54 dataset repos and every
control-pool candidate — using one uniform measurement source for both groups
is itself a validity requirement, since mixing measurement sources between
groups would bias the matching before any outcome is even compared. (The
main pipeline's merged_repos.json now also collects its GitHub metrics the
same way, via pipeline.merger — this module's "GitHub REST for both groups"
stance is what the whole pipeline's data collection follows today.)

Dependency count is computed by running the pipeline's existing
dependency_runner batch analysis (SBOM + OSV) — the same call also produces
per-repo vulnerability data that the later outcome-comparison step reuses
directly, so this is done once here rather than twice.
"""

from __future__ import annotations

import json
import logging
import sys
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import requests

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
for _p in (str(_PROJECT_ROOT), str(_THIS_DIR)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from pipeline import config
from pipeline.merger import (
    _fetch_github_repo_data,
    _fetch_github_count,
    _fetch_github_language_breakdown,
    NON_IMPLEMENTATION_LANGUAGES,
)
from pipeline.models import RepoEntry
from pipeline.dependency_runner import run_dependency_analysis_batch

logger = logging.getLogger("control_search.covariates")

RAW_COVARIATES_DIR = _THIS_DIR / "raw" / "covariates"
RAW_DEPENDENCY_DIR = _THIS_DIR / "raw" / "dependency"
DEPENDENCY_REPORT_FILE = _THIS_DIR / "raw" / "dependency_analysis_full_pool.json"


@contextmanager
def _redirect_dependency_cache():
    """Point both the dependency runner's per-repo cache dir AND its aggregate
    report file at control_search/raw/ so control-pool data never mixes into
    the main 54-repo raw cache or overwrites outputs/processed/dependency_analysis.json
    (which pipeline/report/render.py reads directly for the main dashboard's
    Dependencies/Vulnerabilities tabs)."""
    original_dir = config.RAW_DEPENDENCY_DIR
    original_report = config.DEPENDENCY_REPORT_FILE
    config.RAW_DEPENDENCY_DIR = RAW_DEPENDENCY_DIR
    config.DEPENDENCY_REPORT_FILE = DEPENDENCY_REPORT_FILE
    try:
        yield
    finally:
        config.RAW_DEPENDENCY_DIR = original_dir
        config.DEPENDENCY_REPORT_FILE = original_report


def _github_headers() -> dict[str, str]:
    """Build GitHub API request headers, adding a bearer token when configured."""
    h = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if config.GITHUB_AUTH_TOKEN:
        h["Authorization"] = f"Bearer {config.GITHUB_AUTH_TOKEN}"
    return h


def _fetch_commit_activity_52w(owner: str, repo: str) -> int | None:
    """Sum weekly commit counts over the trailing year via GitHub's stats endpoint.

    GitHub computes these stats asynchronously; a 202 response means "still
    computing" and the caller should retry after a short delay.
    """
    url = f"{config.GITHUB_API_BASE.rstrip('/')}/repos/{owner}/{repo}/stats/commit_activity"
    for attempt in range(4):
        try:
            resp = requests.get(url, headers=_github_headers(), timeout=15)
        except Exception:
            return None
        if resp.status_code == 200:
            try:
                weeks = resp.json()
            except Exception:
                return None
            if isinstance(weeks, list):
                return sum(int(w.get("total", 0)) for w in weeks if isinstance(w, dict))
            return None
        if resp.status_code == 202:
            time.sleep(2.0 * (attempt + 1))
            continue
        return None
    return None


def _entry_cache_path(owner: str, repo: str) -> Path:
    """Return the on-disk cache path for one repo's covariates JSON."""
    return RAW_COVARIATES_DIR / f"{owner}__{repo}.json"


def fetch_covariates(owner: str, repo: str, *, force: bool = False) -> dict[str, Any]:
    """Fetch matching covariates for one repo via GitHub REST. Cached on disk."""
    cache_path = _entry_cache_path(owner, repo)
    if not force and cache_path.exists() and cache_path.stat().st_size > 0:
        try:
            cached = json.loads(cache_path.read_text(encoding="utf-8"))
            # Treat stale cache entries (written before NON_IMPLEMENTATION_LANGUAGES
            # or codebase_bytes existed) as a miss so they get reclassified/backfilled
            # below instead of silently staying wrong forever.
            if (
                cached.get("owner") == owner
                and cached.get("repo_name") == repo
                and cached.get("language") not in NON_IMPLEMENTATION_LANGUAGES
                and cached.get("codebase_bytes") is not None
            ):
                return cached
        except Exception:
            pass

    token = config.GITHUB_AUTH_TOKEN
    meta = _fetch_github_repo_data(owner, repo, token) or {}
    contributor_count = _fetch_github_count(owner, repo, "contributors", token, params="anon=true")
    release_count = _fetch_github_count(owner, repo, "releases", token)
    commit_activity_52w = _fetch_commit_activity_52w(owner, repo)

    # Fetch the full per-language byte breakdown once, used both to reclassify
    # NON_IMPLEMENTATION_LANGUAGES and as the codebase_bytes source. Unlike
    # pipeline.merger's GraphQL path (capped at the top 6 languages per repo),
    # this REST endpoint returns every language uncapped, giving a true total.
    breakdown = _fetch_github_language_breakdown(owner, repo, token) or {}
    non_notebook_bytes = {k: v for k, v in breakdown.items() if k not in NON_IMPLEMENTATION_LANGUAGES}
    codebase_bytes = sum(non_notebook_bytes.values()) if non_notebook_bytes else None

    # control-pool candidates are matched against dataset repos by language,
    # so a mistagged pool repo (observed here for borglab/gtsam) is exactly
    # as damaging to match quality as a mistagged dataset repo.
    language = meta.get("language")
    if not language or language in NON_IMPLEMENTATION_LANGUAGES:
        language = max(non_notebook_bytes, key=non_notebook_bytes.get) if non_notebook_bytes else None

    result = {
        "owner": owner,
        "repo_name": repo,
        "stars": meta.get("stargazers_count"),
        "forks": meta.get("forks_count"),
        "language": language,
        "owner_type": (meta.get("owner") or {}).get("type"),
        "created_at": meta.get("created_at"),
        "contributor_count": contributor_count,
        "release_count": release_count,
        "commit_activity_52w": commit_activity_52w,
        "codebase_bytes": codebase_bytes,
        "dependency_count": None,  # filled in by attach_dependency_counts()
        "fetch_error": "" if meta else "repo metadata fetch failed",
    }

    RAW_COVARIATES_DIR.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    return result


def fetch_covariates_batch(repos: list[tuple[str, str]], *, force: bool = False) -> dict[str, dict[str, Any]]:
    """Fetch covariates for a list of (owner, repo_name) tuples, keyed by 'owner/repo'."""
    out: dict[str, dict[str, Any]] = {}
    for i, (owner, repo) in enumerate(repos, 1):
        logger.info("[covariates] (%d/%d) %s/%s", i, len(repos), owner, repo)
        out[f"{owner}/{repo}"] = fetch_covariates(owner, repo, force=force)
    return out


def attach_dependency_counts(
    covariates: dict[str, dict[str, Any]],
    entries: list[RepoEntry],
) -> dict[str, Any]:
    """Run the pipeline's dependency analysis for *entries* (cache redirected
    to control_search/raw/) and merge packages_total into each covariate
    record. Returns the full dependency_analysis report so later stages
    (outcome vuln counts, KEV exposure) can reuse it without re-querying OSV.
    """
    with _redirect_dependency_cache():
        report = run_dependency_analysis_batch(entries)

    by_url = {row.get("repo_url"): row for row in report.get("repos", [])}
    for entry in entries:
        key = f"{entry.owner}/{entry.repo_name}"
        row = by_url.get(entry.repo_url)
        if key in covariates and row is not None:
            covariates[key]["dependency_count"] = row.get("packages_total", 0)
    return report
