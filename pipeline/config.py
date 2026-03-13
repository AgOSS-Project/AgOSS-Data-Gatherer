"""Centralized configuration for the pipeline."""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Path layout — all paths are relative to the project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent

TOOLS_DIR = PROJECT_ROOT / "tools"
SCORECARD_EXE = TOOLS_DIR / "scorecard.exe"
AUGUR_DIR = TOOLS_DIR / "augur"

INPUT_FILE = PROJECT_ROOT / "pipeline" / "input.txt"

OUTPUTS_DIR = PROJECT_ROOT / "outputs"
RAW_SCORECARD_DIR = OUTPUTS_DIR / "raw" / "scorecard"
RAW_AUGUR_DIR = OUTPUTS_DIR / "raw" / "augur"
PROCESSED_DIR = OUTPUTS_DIR / "processed"
DASHBOARD_DIR = OUTPUTS_DIR / "dashboard"
LOG_DIR = OUTPUTS_DIR / "logs"

# ---------------------------------------------------------------------------
# Scorecard configuration
# ---------------------------------------------------------------------------
SCORECARD_TIMEOUT_SECONDS = int(os.getenv("SCORECARD_TIMEOUT", "120"))
SCORECARD_RETRY_COUNT = int(os.getenv("SCORECARD_RETRY_COUNT", "1"))
GITHUB_AUTH_TOKEN = os.getenv("GITHUB_AUTH_TOKEN") or os.getenv("GITHUB_TOKEN", "")

# ---------------------------------------------------------------------------
# Augur configuration  (docker-compose maps container 5000 → host 5002)
# ---------------------------------------------------------------------------
AUGUR_API_BASE = os.getenv("AUGUR_API_BASE", "http://localhost:5002")
AUGUR_API_PREFIX = "/api/unstable"
AUGUR_API_KEY = os.getenv("AUGUR_API_KEY", "")
AUGUR_TIMEOUT_SECONDS = int(os.getenv("AUGUR_TIMEOUT", "30"))

# Repo group for pipeline-managed repos
AUGUR_REPO_GROUP = os.getenv("AUGUR_REPO_GROUP", "ag-oss-pipeline")

# Docker container name for direct DB access (used by register_repos)
AUGUR_DB_CONTAINER = os.getenv("AUGUR_DB_CONTAINER", "augur-augur-db-1")
AUGUR_DB_USER = os.getenv("AUGUR_DB_USER", "augur")
AUGUR_DB_NAME = os.getenv("AUGUR_DB_NAME", "augur")

# Wait-mode controls how long the pipeline waits for Augur to finish
# ingesting data after registration.
#   "none"     – do not wait at all (just register & collect what's there)
#   "minimal"  – confirm registration only
#   "standard" – wait until basic metrics (contributors) appear
#   "full"     – wait until all configured endpoints return data
AUGUR_WAIT_MODE = os.getenv("AUGUR_WAIT_MODE", "none")
AUGUR_POLL_INTERVAL = int(os.getenv("AUGUR_POLL_INTERVAL", "30"))
AUGUR_WAIT_TIMEOUT = int(os.getenv("AUGUR_WAIT_TIMEOUT", "600"))

# Endpoints used to probe readiness during wait modes
AUGUR_READINESS_ENDPOINTS: list[str] = [
    "contributors",
    "issues-new",
]

# Augur metric endpoints to collect (easily adjustable).
# Each entry is (endpoint_suffix, friendly_name).
AUGUR_METRIC_ENDPOINTS: list[tuple[str, str]] = [
    ("contributors",                    "contributors"),
    ("contributors-new",                "contributors_new"),
    ("committers",                      "committers"),
    ("top-committers",                  "top_committers"),
    ("commits",                         "commits"),
    ("commits-new",                     "commits_new"),
    ("commits-weekly",                  "commits_weekly"),
    ("commits-daily",                   "commits_daily"),
    ("code-changes",                    "code_changes"),
    ("code-changes-lines",              "code_changes_lines"),
    ("issues-new",                      "issues_new"),
    ("issues",                          "issues"),
    ("issues-closed",                   "issues_closed"),
    ("issues-active",                   "issues_active"),
    ("issue-events",                    "issue_events"),
    ("issue-comments",                  "issue_comments"),
    ("issue-open-age",                  "issue_open_age"),
    ("issue-backlog",                   "issue_backlog"),
    ("average-issue-resolution-time",   "avg_issue_resolution_time"),
    ("pull-requests-new",               "pull_requests_new"),
    ("pull-requests",                   "pull_requests"),
    ("pull-requests-active",            "pull_requests_active"),
    ("pull-requests-closed",            "pull_requests_closed"),
    ("pull-requests-merged",            "pull_requests_merged"),
    ("pull-request-comments",           "pull_request_comments"),
    ("pull-request-events",             "pull_request_events"),
    ("pull-request-reviewers",          "pull_request_reviewers"),
    ("pull-requests-merge-contributor-new", "pr_merge_contributor_new"),
    ("pull-request-acceptance-rate",    "pr_acceptance_rate"),
    ("releases",                        "releases"),
    ("tags",                            "tags"),
    ("files",                           "files"),
    ("commits-files",                   "commits_files"),
    ("stars-count",                     "stars_count"),
    ("fork-count",                      "fork_count"),
    ("watchers-count",                  "watchers_count"),
    ("languages",                       "languages"),
    ("average-weekly-commits",          "avg_weekly_commits"),
    ("license-declared",                "license_declared"),
    ("aggregate-summary",               "aggregate_summary"),
]

# ---------------------------------------------------------------------------
# Pipeline behaviour
# ---------------------------------------------------------------------------
FORCE_REFRESH = False  # overridden via CLI --force flag
