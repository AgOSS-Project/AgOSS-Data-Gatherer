"""Merge Scorecard + Augur results into unified output files."""

from __future__ import annotations

import csv
import dataclasses
import io
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

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
