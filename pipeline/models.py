"""
models.py – Dataclasses and types for the repo-risk pipeline.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Input parsing
# ---------------------------------------------------------------------------

_RE_GH_HTTP = re.compile(
    r"^https?://github\.com/([^/]+)/([^/#?\s]+)"
)
_RE_GH_SSH = re.compile(
    r"^git@github\.com:([^/]+)/([^/#?\s]+)"
)
_RE_OWNER_REPO = re.compile(r"^([^/\s]+)/([^/\s]+)$")


@dataclass(frozen=True)
class RepoTarget:
    """One line from input.txt after parsing."""
    original: str
    owner: str
    repo: str
    repo_type: str  # e.g. "Field-Deployed Sensor"

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_input_line(line: str) -> Optional[RepoTarget]:
    """Parse ``<github_url>, <type>`` and return a *RepoTarget* or *None*."""
    raw = line.strip()
    if not raw or raw.startswith("#"):
        return None

    # Split on the FIRST comma only
    parts = raw.split(",", 1)
    url_part = parts[0].strip()
    repo_type = parts[1].strip() if len(parts) > 1 else ""

    # Strip trailing slash, .git suffix, /tree/... suffixes
    url_part = url_part.rstrip("/")
    url_part = re.sub(r"/tree/.*$", "", url_part)
    url_part = url_part.removesuffix(".git")

    owner, repo = "", ""
    m = _RE_GH_HTTP.match(url_part)
    if m:
        owner, repo = m.group(1), m.group(2)
    else:
        m = _RE_GH_SSH.match(url_part)
        if m:
            owner, repo = m.group(1), m.group(2)
        else:
            m = _RE_OWNER_REPO.match(url_part)
            if m:
                owner, repo = m.group(1), m.group(2)

    # Clean up repo name
    repo = repo.rstrip("/").removesuffix(".git")

    return RepoTarget(
        original=raw,
        owner=owner,
        repo=repo,
        repo_type=repo_type,
    )


# ---------------------------------------------------------------------------
# Per-dependency result
# ---------------------------------------------------------------------------

@dataclass
class DepResult:
    """One dependency extracted from a repo's SBOM."""
    purl: str
    vulnerable: bool = False
    vuln_ids: List[str] = field(default_factory=list)

    @property
    def vuln_count(self) -> int:
        return len(self.vuln_ids)


# ---------------------------------------------------------------------------
# Per-repo result
# ---------------------------------------------------------------------------

@dataclass
class RepoResult:
    """Full result for a single repo."""
    # Identity
    owner: str = ""
    repo: str = ""
    slug: str = ""
    repo_type: str = ""
    original_input: str = ""

    # Status: "ok" | "partial" | "failed"
    status: str = "ok"
    errors: List[str] = field(default_factory=list)

    # GitHub metadata (subset)
    gh_description: str = ""
    gh_language: str = ""
    gh_stars: int = 0
    gh_forks: int = 0
    gh_open_issues: int = 0
    gh_pushed_at: str = ""
    gh_license: str = ""
    gh_archived: bool = False
    gh_full_meta: Dict[str, Any] = field(default_factory=dict)

    # RepoReaper-lite
    reporeaper_lite: Dict[str, Any] = field(default_factory=dict)

    # OpenSSF Scorecard (optional)
    scorecard: Dict[str, Any] = field(default_factory=dict)

    # Dependencies
    dep_count: int = 0
    dependencies: List[DepResult] = field(default_factory=list)

    # Vulnerability summary
    vulnerable_dep_count: int = 0
    vuln_id_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner": self.owner,
            "repo": self.repo,
            "slug": self.slug,
            "repo_type": self.repo_type,
            "original_input": self.original_input,
            "status": self.status,
            "errors": self.errors,
            "github": {
                "description": self.gh_description,
                "language": self.gh_language,
                "stars": self.gh_stars,
                "forks": self.gh_forks,
                "open_issues": self.gh_open_issues,
                "pushed_at": self.gh_pushed_at,
                "license": self.gh_license,
                "archived": self.gh_archived,
            },
            "reporeaper_lite": self.reporeaper_lite,
            "scorecard": self.scorecard,
            "dep_count": self.dep_count,
            "vulnerable_dep_count": self.vulnerable_dep_count,
            "vuln_id_count": self.vuln_id_count,
            "dependencies": [
                {
                    "purl": d.purl,
                    "vulnerable": d.vulnerable,
                    "vuln_ids": d.vuln_ids,
                    "vuln_count": d.vuln_count,
                }
                for d in self.dependencies
            ],
        }
