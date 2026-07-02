"""Merge Scorecard + Augur results into unified output files."""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

from pipeline import config
from pipeline.models import (
    AugurResult,
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


def _gh_headers(token: str) -> dict[str, str]:
    h = dict(_GH_HEADERS)
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _fetch_github_repo_data(owner: str, repo_name: str, token: str) -> dict | None:
    """Fetch repo metadata from GitHub REST API (stars, forks, language, license, open_issues)."""
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo_name}",
            headers=_gh_headers(token),
            timeout=10,
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception:
        pass
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
    """Return an item count using GitHub's per_page=1 + Link header trick."""
    url = (
        f"https://api.github.com/repos/{owner}/{repo_name}/{path}"
        f"{'?' + params if params else ''}{'&' if params else '?'}per_page=1"
    )
    try:
        resp = requests.get(url, headers=_gh_headers(token), timeout=10)
        if resp.status_code == 200:
            link = resp.headers.get("Link", "")
            if link:
                n = _parse_link_last_page(link)
                if n is not None:
                    return n
            data = resp.json()
            if isinstance(data, list):
                return len(data)
    except Exception:
        pass
    return None


def _overall_status(sc: ScorecardResult, ag: AugurResult) -> OverallStatus:
    sc_ok = sc.status in ("success", "partial_success")
    ag_ok = ag.status in ("ready", "partial")
    if sc_ok and ag_ok:
        return "complete"
    if sc_ok or ag_ok:
        return "partial"
    return "failed"


def merge(
    entries: list[RepoEntry],
    scorecard: dict[str, ScorecardResult],
    augur: dict[str, AugurResult],
) -> tuple[list[MergedRepoRecord], RunSummary]:
    """Combine all results into a list of :class:`MergedRepoRecord`."""
    now = datetime.now(timezone.utc).isoformat()
    records: list[MergedRepoRecord] = []

    for entry in entries:
        sc = scorecard.get(entry.repo_url, ScorecardResult())
        ag = augur.get(entry.repo_url, AugurResult())

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
            # Augur
            augur_collected=ag.collected,
            augur_error=ag.error,
            augur_repo_id=ag.repo_id,
            augur_metrics=ag.metrics,
            augur_status=ag.status,
            augur_registered=ag.registered,
            augur_ready=ag.ready,
            # Pipeline
            overall_status=_overall_status(sc, ag),
        )

        # GitHub fallback: fill missing Augur metrics from GitHub REST API.
        metrics = rec.augur_metrics if isinstance(rec.augur_metrics, dict) else {}
        if not isinstance(rec.augur_metrics, dict):
            rec.augur_metrics = metrics

        needs_stars = not metrics.get("stars")
        needs_forks = not metrics.get("forks")
        needs_language = not metrics.get("languages")
        needs_license = not metrics.get("license")
        needs_issues_open = not metrics.get("issues_opened") and not metrics.get("issues_total")
        needs_contributors = not metrics.get("contributor_count")
        needs_commits = not metrics.get("commit_count")
        needs_issues_closed = not metrics.get("issues_closed")

        token = config.GITHUB_AUTH_TOKEN

        # Single metadata call covers stars, forks, language, license, open_issues.
        if any([needs_stars, needs_forks, needs_language, needs_license, needs_issues_open]):
            gh = _fetch_github_repo_data(entry.owner, entry.repo_name, token)
            if gh:
                if needs_stars and gh.get("stargazers_count") is not None:
                    v = gh["stargazers_count"]
                    metrics["stars"] = v
                    agg = metrics.get("aggregate_summary")
                    if isinstance(agg, list) and agg and isinstance(agg[0], dict):
                        agg[0]["stars_count"] = v
                    logger.debug("GH fallback stars %s/%s: %d", entry.owner, entry.repo_name, v)
                if needs_forks and gh.get("forks_count") is not None:
                    metrics["forks"] = gh["forks_count"]
                if needs_language and gh.get("language"):
                    metrics.setdefault("languages", [gh["language"]])
                if needs_license and isinstance(gh.get("license"), dict):
                    lic = gh["license"]
                    gh_lic = lic.get("spdx_id") or lic.get("name") or ""
                    if gh_lic:
                        metrics["license"] = gh_lic
                if needs_issues_open and gh.get("open_issues_count") is not None:
                    metrics.setdefault("issues_opened", gh["open_issues_count"])

        # Contributor count — paginated endpoint, one call.
        if needs_contributors:
            n = _fetch_github_count(entry.owner, entry.repo_name, "contributors", token,
                                    params="anon=true")
            if n is not None:
                metrics["contributor_count"] = n
                logger.debug("GH fallback contributors %s/%s: %d",
                             entry.owner, entry.repo_name, n)

        # Commit count — paginated endpoint, one call.
        if needs_commits:
            n = _fetch_github_count(entry.owner, entry.repo_name, "commits", token)
            if n is not None:
                metrics["commit_count"] = n
                logger.debug("GH fallback commits %s/%s: %d",
                             entry.owner, entry.repo_name, n)

        # Closed issues count — one call.
        if needs_issues_closed:
            n = _fetch_github_count(entry.owner, entry.repo_name, "issues", token,
                                    params="state=closed")
            if n is not None:
                metrics["issues_closed"] = n
                logger.debug("GH fallback issues_closed %s/%s: %d",
                             entry.owner, entry.repo_name, n)

        rec.license = metrics.get("license") or ""

        records.append(rec)

    summary = RunSummary(
        run_start=now,
        run_end=datetime.now(timezone.utc).isoformat(),
        total_repos=len(records),
        # Scorecard counts
        scorecard_success=sum(1 for r in records if r.scorecard_status == "success"),
        scorecard_partial=sum(1 for r in records if r.scorecard_status == "partial_success"),
        scorecard_fail=sum(1 for r in records if r.scorecard_status == "failed"),
        # Augur counts
        augur_success=sum(1 for r in records if r.augur_status == "ready"),
        augur_registered=sum(1 for r in records if r.augur_registered),
        augur_ready=sum(1 for r in records if r.augur_ready),
        augur_timed_out=sum(1 for r in records if r.augur_status == "timed_out"),
        augur_fail=sum(1 for r in records if r.augur_status in ("failed", "not_registered")),
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
