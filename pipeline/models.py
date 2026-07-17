"""Data models used across the pipeline.

Defines the dataclasses that flow through each pipeline stage:
`RepoEntry` (one row parsed from the input CSV by `input_parser.py`),
`ScorecardResult` (normalized OpenSSF Scorecard output for one repo,
produced by `scorecard_runner.py`), `MergedRepoRecord` (the unified
per-repo record combining Scorecard results and directly-collected GitHub
metrics, built by `merger.py` and serialized to the processed JSON/CSV
outputs), and `RunSummary` (aggregate counts/metadata for a full pipeline
run). Also defines the `ScorecardStatus` and `OverallStatus` literal types
shared across modules for status fields. These are plain dataclasses with
no behavior beyond `MergedRepoRecord.to_dict()`; they exist purely to give
the rest of the pipeline a typed, consistent shape to pass around instead
of loose dicts.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


# Status literals -----------------------------------------------------------
ScorecardStatus = Literal["success", "partial_success", "failed", "skipped"]
OverallStatus = Literal["complete", "partial", "failed"]


@dataclass
class RepoEntry:
    """A single repository parsed from the input file."""
    display_name: str
    repo_url: str
    owner: str
    repo_name: str
    category: str
    ag_specific: bool | None
    line_number: int  # original line in the input file (1-based)


@dataclass
class ScorecardResult:
    """Normalised Scorecard output for one repo."""
    collected: bool = False
    error: str = ""
    overall_score: float | None = None
    checks: dict[str, Any] = field(default_factory=dict)
    raw_file: str = ""

    # Extended fields
    status: ScorecardStatus = "failed"
    exit_code: int | None = None
    stderr: str = ""
    runtime_seconds: float = 0.0
    json_parsed: bool = False
    scorecard_version: str = ""
    scorecard_commit: str = ""


@dataclass
class MergedRepoRecord:
    """Unified record written to the processed output files."""
    display_name: str
    repo_url: str
    owner: str
    repo_name: str
    category: str
    ag_specific: bool | None = None
    collection_timestamp: str = ""

    # Scorecard
    scorecard_collected: bool = False
    scorecard_error: str = ""
    scorecard_overall: float | None = None
    scorecard_checks: dict[str, Any] = field(default_factory=dict)
    scorecard_status: ScorecardStatus = "failed"
    scorecard_exit_code: int | None = None
    scorecard_runtime: float = 0.0

    # GitHub metrics (contributors, commits, issues, PRs, stars, forks,
    # language, license) -- collected directly via GitHub REST/Search API.
    # This replaces what used to be Augur-backed collection; see README's
    # "Why not Augur" note for why that was dropped.
    github_metrics: dict[str, Any] = field(default_factory=dict)
    github_metrics_collected: bool = False
    github_metrics_error: str = ""

    # License (SPDX ID or display name; empty if not detected)
    license: str = ""

    # Pipeline
    overall_status: OverallStatus = "failed"

    def to_dict(self) -> dict[str, Any]:
        """Return this record as a plain dict, suitable for JSON serialization."""
        d = dataclasses.asdict(self)
        return d


@dataclass
class RunSummary:
    """Metadata about a pipeline run."""
    run_start: str = ""
    run_end: str = ""
    total_repos: int = 0

    scorecard_success: int = 0
    scorecard_partial: int = 0
    scorecard_fail: int = 0

    github_metrics_success: int = 0
    github_metrics_fail: int = 0

    categories: list[str] = field(default_factory=list)
    ag_specific_yes: int = 0
    ag_specific_no: int = 0
    ag_specific_unknown: int = 0
    notes: list[str] = field(default_factory=list)
