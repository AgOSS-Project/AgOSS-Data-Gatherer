"""Data models used across the pipeline."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal


# Status literals -----------------------------------------------------------
ScorecardStatus = Literal["success", "partial_success", "failed", "skipped"]
AugurStatus = Literal[
    "ready", "partial", "registered", "collecting",
    "timed_out", "failed", "not_registered", "skipped",
]
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
class AugurResult:
    """Normalised Augur output for one repo."""
    collected: bool = False
    error: str = ""
    repo_id: int | None = None
    metrics: dict[str, Any] = field(default_factory=dict)
    raw_file: str = ""

    # Extended fields
    status: AugurStatus = "failed"
    registered: bool = False
    wait_mode: str = ""
    ready: bool = False
    timed_out: bool = False


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

    # Augur
    augur_collected: bool = False
    augur_error: str = ""
    augur_repo_id: int | None = None
    augur_metrics: dict[str, Any] = field(default_factory=dict)
    augur_status: AugurStatus = "failed"
    augur_registered: bool = False
    augur_ready: bool = False

    # Pipeline
    overall_status: OverallStatus = "failed"

    def to_dict(self) -> dict[str, Any]:
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

    augur_success: int = 0
    augur_registered: int = 0
    augur_ready: int = 0
    augur_timed_out: int = 0
    augur_fail: int = 0

    categories: list[str] = field(default_factory=list)
    ag_specific_yes: int = 0
    ag_specific_no: int = 0
    ag_specific_unknown: int = 0
    notes: list[str] = field(default_factory=list)
