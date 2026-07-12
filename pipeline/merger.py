"""Merge Scorecard results with directly-collected GitHub metrics into unified output files.

GitHub metrics (contributors, commits, issues, merged PRs, stars, forks,
language, license) are collected directly via the GitHub GraphQL and REST
APIs. This used to be a fallback layer behind a self-hosted Augur/Aveloxis
instance; Augur was removed because every field this pipeline actually
uses was already being sourced from this fallback in practice (Augur's
own REST metrics layer produced usable data for close to none of the
70-repo dataset), and Aveloxis's own advertised bulk throughput --
"40,000 repositories, fully collected, in three days" -- doesn't fit an
iterative research pipeline that needs to re-run in minutes. See
Kalliamvakou et al., "The Promises and Perils of Mining GitHub" (MSR
2014) for standard methodology on GitHub-API-based repository mining,
which this module follows (excluding forks/archived repos upstream).

Why GraphQL for issues/PRs/stars/forks/license/language, and REST for
contributor/commit counts:
  - The REST Search API (used for exact issue/PR counts, since GitHub
    models a PR as a kind of issue and both open_issues_count and the
    plain /issues endpoint conflate them) is capped at 30 requests/min
    authenticated -- far tighter than core REST's 5,000/hr. GraphQL's
    `issues(states: ...) { totalCount }` and `pullRequests(states: ...)
    { totalCount }` fields return the identical aggregate counts but are
    billed against the normal GraphQL point budget (~5,000 points/hr),
    not the Search sub-limit -- so moving these there removes the actual
    bottleneck instead of just retrying into it. GraphQL also lets many
    repos be requested in a single HTTP call via aliases, which cuts
    round-trips at control-pool scale.
  - GraphQL has no equivalent of REST's deduplicated /contributors count
    or a plain commit-count field without paginating full history (both
    expensive at scale for large repos); the REST per_page=1 + Link-header
    trick stays for those two fields specifically.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from pipeline import config
from pipeline.models import (
    MergedRepoRecord,
    OverallStatus,
    RepoEntry,
    RunSummary,
    ScorecardResult,
)

logger = logging.getLogger("pipeline.merger")

_GH_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
_GRAPHQL_URL = "https://api.github.com/graphql"

# Repos per GraphQL batch (one HTTP call fetches this many via aliases).
# 20 keeps individual query/response size modest while cutting round-trips
# by 20x relative to one-call-per-repo; the fields requested (totalCount
# summaries, no paginated node lists) are cheap enough that GitHub's
# per-query point cost stays low even at this batch size.
GRAPHQL_BATCH_SIZE = 20

# If GraphQL's own rate-limit budget drops below this many points
# remaining, pause until it resets rather than burning the rest of the
# budget and then failing mid-run.
_GRAPHQL_MIN_REMAINING = 100


def _gh_headers(token: str) -> dict[str, str]:
    h = dict(_GH_HEADERS)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _retrying_get(url: str, token: str, *, params: dict | None = None,
                  attempts: int = 3, timeout: int = 10) -> requests.Response | None:
    """GET with retry-on-403/429/5xx and Retry-After awareness.

    All REST calls in this module route through this rather than a bare
    requests.get -- silently swallowing a rate-limit/transient response
    (the old behavior) turns a recoverable hiccup into a missing-data
    result for that repo.
    """
    for attempt in range(attempts):
        try:
            resp = requests.get(url, headers=_gh_headers(token), params=params, timeout=timeout)
        except requests.RequestException as exc:
            if attempt < attempts - 1:
                time.sleep(2.0 * (attempt + 1))
                continue
            logger.debug("GET %s failed after %d attempts: %s", url, attempts, exc)
            return None
        if resp.status_code == 200:
            return resp
        if resp.status_code in (403, 429) and attempt < attempts - 1:
            retry_after = resp.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                wait = int(retry_after)
            elif resp.headers.get("X-RateLimit-Remaining") == "0":
                reset = resp.headers.get("X-RateLimit-Reset")
                wait = max(1, int(reset) - int(time.time())) if reset and reset.isdigit() else 20
            else:
                wait = 5 * (attempt + 1)
            logger.debug("GET %s rate-limited (HTTP %d); waiting %ds", url, resp.status_code, wait)
            time.sleep(wait)
            continue
        if resp.status_code >= 500 and attempt < attempts - 1:
            time.sleep(2.0 * (attempt + 1))
            continue
        return resp
    return None


def _fetch_github_repo_data(owner: str, repo_name: str, token: str) -> dict | None:
    """Fetch repo metadata from GitHub REST API (stars, forks, language, license, open_issues).

    Retained for callers outside this module (control_search/covariates.py)
    that only need this one repo's metadata rather than a batched fetch.
    """
    resp = _retrying_get(f"https://api.github.com/repos/{owner}/{repo_name}", token)
    if resp is not None and resp.status_code == 200:
        return resp.json()
    return None


# Languages whose byte count reflects saved document content rather than
# implementation code, and so should never be picked as a repo's primary
# language for matching purposes. Jupyter Notebook is the concrete case
# found in this dataset (ApsimX, and borglab/gtsam in the control pool):
# a notebook's saved outputs -- rendered plots, printed tensors -- are
# counted as bytes, and a handful of embedded images can dwarf the actual
# code. This is a well-documented GitHub Linguist quirk, not unique to
# this dataset -- see github-linguist/linguist issues #3496, #3316, #3282.
NON_IMPLEMENTATION_LANGUAGES = {"Jupyter Notebook"}


def _fetch_github_language_breakdown(owner: str, repo_name: str, token: str) -> dict[str, int] | None:
    """Return the raw {language: bytes} breakdown from GitHub's /languages endpoint.

    Used by control_search/covariates.py for both language reclassification
    (excluding NON_IMPLEMENTATION_LANGUAGES) and as the source for the
    codebase_bytes size matching covariate (see
    matching.CONTINUOUS_COVARIATES) -- one call serves both purposes there.
    This module's own batched GraphQL path gets a (top-6-capped) breakdown
    inline instead of calling this.
    """
    resp = _retrying_get(f"https://api.github.com/repos/{owner}/{repo_name}/languages", token)
    if resp is not None and resp.status_code == 200:
        data = resp.json()
        if isinstance(data, dict):
            return data
    return None


def _parse_link_last_page(link_header: str) -> int | None:
    """Extract the last page number from a GitHub Link header."""
    for part in link_header.split(","):
        if 'rel="last"' in part:
            m = re.search(r'[?&]page=(\d+)', part)
            if m:
                return int(m.group(1))
    return None


def _fetch_github_count(owner: str, repo_name: str, path: str, token: str,
                        params: str = "") -> int | None:
    """Return an item count using GitHub's per_page=1 + Link header trick.

    Used for contributor_count and commit_count -- GraphQL has no cheap
    equivalent for either (no deduplicated contributor total, and commit
    counts require paginating full history), so these stay on core REST,
    which has a 5,000/hr budget with plenty of headroom for this.
    """
    url = (
        f"https://api.github.com/repos/{owner}/{repo_name}/{path}"
        f"{'?' + params if params else ''}{'&' if params else '?'}per_page=1"
    )
    resp = _retrying_get(url, token)
    if resp is None or resp.status_code != 200:
        return None
    link = resp.headers.get("Link", "")
    if link:
        n = _parse_link_last_page(link)
        if n is not None:
            return n
    data = resp.json()
    if isinstance(data, list):
        return len(data)
    return None


# ---------------------------------------------------------------------------
# Batched GraphQL collection: stars, forks, license, language, issue/PR counts
# ---------------------------------------------------------------------------

def _graphql_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _build_batch_query(batch: list[RepoEntry]) -> str:
    parts = ["query {"]
    for i, entry in enumerate(batch):
        owner = _graphql_escape(entry.owner)
        repo = _graphql_escape(entry.repo_name)
        parts.append(f'''
  r{i}: repository(owner: "{owner}", name: "{repo}") {{
    stargazerCount
    forkCount
    licenseInfo {{ spdxId name }}
    languages(first: 6, orderBy: {{field: SIZE, direction: DESC}}) {{
      edges {{ size node {{ name }} }}
    }}
    openIssues: issues(states: OPEN) {{ totalCount }}
    closedIssues: issues(states: CLOSED) {{ totalCount }}
    mergedPRs: pullRequests(states: MERGED) {{ totalCount }}
  }}''')
    parts.append("""
  rateLimit { remaining resetAt cost }
}""")
    return "\n".join(parts)


def _graphql_request(query: str, token: str, *, attempts: int = 3) -> dict | None:
    """POST a GraphQL query with retry/backoff. Returns the parsed response body."""
    for attempt in range(attempts):
        try:
            resp = requests.post(
                _GRAPHQL_URL,
                headers=_gh_headers(token),
                json={"query": query},
                timeout=30,
            )
        except requests.RequestException as exc:
            if attempt < attempts - 1:
                time.sleep(2.0 * (attempt + 1))
                continue
            logger.debug("GraphQL request failed after %d attempts: %s", attempts, exc)
            return None
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code in (403, 429) and attempt < attempts - 1:
            retry_after = resp.headers.get("Retry-After")
            wait = int(retry_after) if retry_after and retry_after.isdigit() else 20
            logger.debug("GraphQL rate-limited (HTTP %d); waiting %ds", resp.status_code, wait)
            time.sleep(wait)
            continue
        if resp.status_code >= 500 and attempt < attempts - 1:
            time.sleep(2.0 * (attempt + 1))
            continue
        logger.debug("GraphQL request returned HTTP %d: %s", resp.status_code, resp.text[:300])
        return None
    return None


def _parse_batch_result(data: dict, batch: list[RepoEntry]) -> dict[str, dict[str, Any]]:
    """Map a GraphQL batch response back to {repo_url: metrics}."""
    out: dict[str, dict[str, Any]] = {}
    payload = (data or {}).get("data") or {}
    for i, entry in enumerate(batch):
        node = payload.get(f"r{i}")
        if not node:
            continue  # repo not found / inaccessible -- left absent, not zero-filled
        metrics: dict[str, Any] = {}
        if node.get("stargazerCount") is not None:
            metrics["stars"] = node["stargazerCount"]
        if node.get("forkCount") is not None:
            metrics["forks"] = node["forkCount"]
        lic = node.get("licenseInfo")
        if isinstance(lic, dict):
            lic_id = lic.get("spdxId") or lic.get("name") or ""
            if lic_id and lic_id != "NOASSERTION":
                metrics["license"] = lic_id

        edges = ((node.get("languages") or {}).get("edges")) or []
        by_size = [(e["size"], e["node"]["name"]) for e in edges
                   if e.get("node") and e["node"].get("name") not in NON_IMPLEMENTATION_LANGUAGES]
        if by_size:
            by_size.sort(reverse=True)
            metrics["languages"] = [by_size[0][1]]

        open_issues = (node.get("openIssues") or {}).get("totalCount")
        if open_issues is not None:
            metrics["issues_opened"] = open_issues
        closed_issues = (node.get("closedIssues") or {}).get("totalCount")
        if closed_issues is not None:
            metrics["issues_closed"] = closed_issues
        merged_prs = (node.get("mergedPRs") or {}).get("totalCount")
        if merged_prs is not None:
            metrics["prs_merged"] = merged_prs

        out[entry.repo_url] = metrics
    return out


def fetch_github_metrics_batch(entries: list[RepoEntry], token: str) -> dict[str, dict[str, Any]]:
    """Fetch stars/forks/license/language/issue/PR-merged counts for all *entries*.

    Batches GRAPHQL_BATCH_SIZE repos per HTTP call via GraphQL aliases, and
    watches the GraphQL rate-limit budget (returned inline in the same
    response) to pause before it's exhausted rather than after. This is the
    single call that replaces what used to be up to 3 Search-API requests
    per repo (open issues, closed issues, merged PRs) -- see module
    docstring for why that mattered.
    """
    results: dict[str, dict[str, Any]] = {}
    batches = [entries[i:i + GRAPHQL_BATCH_SIZE] for i in range(0, len(entries), GRAPHQL_BATCH_SIZE)]
    logger.info("[github] Fetching stars/forks/license/language/issues/PRs for %d repos "
                "in %d GraphQL batch(es) of up to %d …",
                len(entries), len(batches), GRAPHQL_BATCH_SIZE)

    for batch_num, batch in enumerate(batches, 1):
        query = _build_batch_query(batch)
        data = _graphql_request(query, token)
        if data is None:
            logger.warning("[github] GraphQL batch %d/%d failed outright; "
                           "%d repos in this batch will show missing metrics.",
                           batch_num, len(batches), len(batch))
            continue
        if data.get("errors"):
            # Partial errors (e.g. one repo renamed/deleted) still leave
            # `data.data` populated for every other alias -- only log, don't
            # abort the batch.
            logger.debug("[github] GraphQL batch %d/%d returned %d error(s) "
                        "(individual repos, not the whole batch): %s",
                        batch_num, len(batches), len(data["errors"]),
                        [e.get("message") for e in data["errors"][:3]])
        results.update(_parse_batch_result(data, batch))

        rate = ((data or {}).get("data") or {}).get("rateLimit") or {}
        remaining = rate.get("remaining")
        if isinstance(remaining, int) and remaining < _GRAPHQL_MIN_REMAINING:
            reset_at = rate.get("resetAt")
            wait = 60
            if reset_at:
                try:
                    reset_dt = datetime.fromisoformat(reset_at.replace("Z", "+00:00"))
                    wait = max(1, int((reset_dt - datetime.now(timezone.utc)).total_seconds()) + 2)
                except Exception:
                    pass
            logger.info("[github] GraphQL budget low (%d points remaining) -- "
                       "pausing %ds until reset.", remaining, wait)
            time.sleep(wait)

    return results


def collect_github_metrics_rest(entry: RepoEntry, token: str) -> dict[str, Any]:
    """Fetch the two fields that stay on REST: contributor_count, commit_count."""
    metrics: dict[str, Any] = {}

    # anon=true includes commit authors with no linked GitHub account
    # (counted by email) -- a broader definition of "contributor" than an
    # account-based count would give.
    n = _fetch_github_count(entry.owner, entry.repo_name, "contributors", token, params="anon=true")
    if n is not None:
        metrics["contributor_count"] = n

    # Default branch only, all-time (the Link-header count trick has no
    # time window).
    n = _fetch_github_count(entry.owner, entry.repo_name, "commits", token)
    if n is not None:
        metrics["commit_count"] = n

    return metrics


def _overall_status(sc: ScorecardResult, gh_metrics: dict[str, Any]) -> OverallStatus:
    sc_ok = sc.status in ("success", "partial_success")
    gh_ok = bool(gh_metrics)
    if sc_ok and gh_ok:
        return "complete"
    if sc_ok or gh_ok:
        return "partial"
    return "failed"


def merge(
    entries: list[RepoEntry],
    scorecard: dict[str, ScorecardResult],
) -> tuple[list[MergedRepoRecord], RunSummary]:
    """Combine Scorecard results with directly-collected GitHub metrics."""
    now = datetime.now(timezone.utc).isoformat()
    records: list[MergedRepoRecord] = []
    token = config.GITHUB_AUTH_TOKEN

    # One batched GraphQL pass for stars/forks/license/language/issues/PRs,
    # then a per-repo REST pass for the two fields GraphQL can't give
    # cheaply (contributor_count, commit_count).
    graphql_metrics = fetch_github_metrics_batch(entries, token)

    for entry in entries:
        sc = scorecard.get(entry.repo_url, ScorecardResult())
        gh_metrics = dict(graphql_metrics.get(entry.repo_url, {}))
        gh_metrics.update(collect_github_metrics_rest(entry, token))

        rec = MergedRepoRecord(
            display_name=entry.display_name,
            repo_url=entry.repo_url,
            owner=entry.owner,
            repo_name=entry.repo_name,
            category=entry.category,
            ag_specific=entry.ag_specific,
            collection_timestamp=now,
            # Scorecard
            scorecard_collected=sc.collected,
            scorecard_error=sc.error,
            scorecard_overall=sc.overall_score,
            scorecard_checks=sc.checks,
            scorecard_status=sc.status,
            scorecard_exit_code=sc.exit_code,
            scorecard_runtime=sc.runtime_seconds,
            # GitHub metrics
            github_metrics=gh_metrics,
            github_metrics_collected=bool(gh_metrics),
            github_metrics_error="" if gh_metrics else "GitHub metrics collection failed",
            # Pipeline
            overall_status=_overall_status(sc, gh_metrics),
        )
        rec.license = gh_metrics.get("license") or ""

        records.append(rec)

    summary = RunSummary(
        run_start=now,
        run_end=datetime.now(timezone.utc).isoformat(),
        total_repos=len(records),
        # Scorecard counts
        scorecard_success=sum(1 for r in records if r.scorecard_status == "success"),
        scorecard_partial=sum(1 for r in records if r.scorecard_status == "partial_success"),
        scorecard_fail=sum(1 for r in records if r.scorecard_status == "failed"),
        # GitHub metrics counts
        github_metrics_success=sum(1 for r in records if r.github_metrics_collected),
        github_metrics_fail=sum(1 for r in records if not r.github_metrics_collected),
        categories=sorted({e.category for e in entries}),
        ag_specific_yes=sum(1 for e in entries if e.ag_specific is True),
        ag_specific_no=sum(1 for e in entries if e.ag_specific is False),
        ag_specific_unknown=sum(1 for e in entries if e.ag_specific is None),
    )

    return records, summary


def write_outputs(records: list[MergedRepoRecord], summary: RunSummary) -> None:
    """Persist processed JSON, CSV, and summary to outputs/processed/."""
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    # JSON
    json_path = config.PROCESSED_DIR / "merged_repos.json"
    json_path.write_text(
        json.dumps([r.to_dict() for r in records], indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Wrote %s (%d records)", json_path.name, len(records))

    # CSV — flatten nested dicts into dot-notation columns
    csv_path = config.PROCESSED_DIR / "merged_repos.csv"
    flat = [_flatten(r.to_dict()) for r in records]
    if flat:
        all_keys: set[str] = set()
        for row in flat:
            all_keys.update(row.keys())
        fieldnames = sorted(all_keys)

        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in flat:
            writer.writerow(row)
        csv_path.write_text(buf.getvalue(), encoding="utf-8")
        logger.info("Wrote %s (%d records, %d columns)", csv_path.name, len(flat), len(fieldnames))

    # Summary
    summary_path = config.PROCESSED_DIR / "summary.json"
    summary_path.write_text(
        json.dumps(dataclasses.asdict(summary), indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Wrote %s", summary_path.name)


def _flatten(d: dict[str, Any], parent_key: str = "", sep: str = ".") -> dict[str, Any]:
    """Recursively flatten nested dicts. Lists are JSON-encoded."""
    items: list[tuple[str, Any]] = []
    for k, v in d.items():
        new_key = f"{parent_key}{sep}{k}" if parent_key else k
        if isinstance(v, dict):
            items.extend(_flatten(v, new_key, sep).items())
        elif isinstance(v, list):
            items.append((new_key, json.dumps(v, default=str)))
        else:
            items.append((new_key, v))
    return dict(items)
