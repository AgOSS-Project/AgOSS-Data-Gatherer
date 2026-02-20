"""
github_client.py – GitHub REST API helpers.

Handles repo metadata, SBOM export, file-existence checks, and
RepoReaper-lite hygiene scoring.  All calls go through a single
``requests.Session`` with rate-limit backoff.
"""
from __future__ import annotations

import datetime as dt
import math
import time
from typing import Any, Dict, List, Optional, Tuple

import requests


class GitHubClient:
    """Thin wrapper around the GitHub REST API."""

    def __init__(self, token: Optional[str] = None) -> None:
        self.session = requests.Session()
        self.token = token
        self.headers: Dict[str, str] = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repo-risk-pipeline/1.0",
        }
        if token:
            self.headers["Authorization"] = f"Bearer {token}"

    # ------------------------------------------------------------------
    # Low-level helpers
    # ------------------------------------------------------------------

    def _sleep_for_rate_limit(self, resp: requests.Response) -> None:
        remaining = resp.headers.get("X-RateLimit-Remaining")
        reset = resp.headers.get("X-RateLimit-Reset")
        if remaining == "0" and reset and reset.isdigit():
            wait = max(0, int(reset) - int(time.time())) + 1
            time.sleep(min(wait, 60))

    def get_json(
        self,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        retries: int = 3,
    ) -> Tuple[Optional[Any], Optional[int], Optional[str]]:
        """GET *url* and return ``(json_body, status, error_msg)``."""
        hdrs = headers or self.headers
        last_err: Optional[str] = None
        for attempt in range(retries):
            try:
                resp = self.session.get(
                    url, headers=hdrs, params=params,
                    timeout=timeout, allow_redirects=True,
                )
                self._sleep_for_rate_limit(resp)
                if 200 <= resp.status_code < 300:
                    return resp.json(), resp.status_code, None
                if resp.status_code in (400, 401, 403, 404):
                    return None, resp.status_code, resp.text[:500]
                last_err = f"HTTP {resp.status_code}: {resp.text[:500]}"
            except Exception as exc:
                last_err = repr(exc)
            time.sleep(1.0 * (attempt + 1))
        return None, None, last_err

    # ------------------------------------------------------------------
    # Public API calls
    # ------------------------------------------------------------------

    def repo_metadata(self, owner: str, repo: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        errors: List[str] = []
        url = f"https://api.github.com/repos/{owner}/{repo}"
        data, status, err = self.get_json(url)
        if data is None:
            errors.append(f"github_repo_metadata_failed status={status} err={err}")
        return data, errors

    def path_exists(self, owner: str, repo: str, path: str) -> bool:
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        _, status, _ = self.get_json(url)
        return status == 200

    def has_readme(self, owner: str, repo: str) -> bool:
        url = f"https://api.github.com/repos/{owner}/{repo}/readme"
        _, status, _ = self.get_json(url)
        return status == 200

    def has_license(self, owner: str, repo: str) -> bool:
        url = f"https://api.github.com/repos/{owner}/{repo}/license"
        _, status, _ = self.get_json(url)
        return status == 200

    def has_latest_release(self, owner: str, repo: str) -> bool:
        url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
        _, status, _ = self.get_json(url)
        return status == 200

    def export_sbom(self, owner: str, repo: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
        """GET /repos/{owner}/{repo}/dependency-graph/sbom → SPDX JSON."""
        errors: List[str] = []
        url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
        data, status, err = self.get_json(url, timeout=60)
        if data is None:
            errors.append(f"github_sbom_failed status={status} err={err}")
        return data, errors

    # ------------------------------------------------------------------
    # RepoReaper-lite heuristic
    # ------------------------------------------------------------------

    def reporeaper_lite(self, owner: str, repo: str, meta: Dict[str, Any]) -> Dict[str, Any]:
        """Lightweight engineering-hygiene score (0-100)."""
        signals: Dict[str, bool] = {}

        signals["readme"] = self.has_readme(owner, repo)
        signals["license"] = self.has_license(owner, repo)
        signals["contributing_md"] = self.path_exists(owner, repo, "CONTRIBUTING.md")
        signals["code_of_conduct_md"] = self.path_exists(owner, repo, "CODE_OF_CONDUCT.md")
        signals["security_md"] = self.path_exists(owner, repo, "SECURITY.md")
        signals["docs_dir"] = self.path_exists(owner, repo, "docs")
        signals["github_actions"] = self.path_exists(owner, repo, ".github/workflows")
        signals["travis"] = self.path_exists(owner, repo, ".travis.yml")
        signals["circleci"] = self.path_exists(owner, repo, ".circleci")
        signals["ci_detected"] = signals["github_actions"] or signals["travis"] or signals["circleci"]
        signals["tests_dir"] = (
            self.path_exists(owner, repo, "tests")
            or self.path_exists(owner, repo, "test")
        )
        signals["__tests__"] = self.path_exists(owner, repo, "__tests__")
        signals["unit_tests_detected"] = signals["tests_dir"] or signals["__tests__"]
        signals["has_release"] = self.has_latest_release(owner, repo)

        pushed_at = meta.get("pushed_at")
        recent = False
        if pushed_at:
            try:
                pushed = dt.datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
                recent = (dt.datetime.now(dt.timezone.utc) - pushed).days <= 180
            except Exception:
                pass
        signals["recent_push_180d"] = recent

        score = 0.0
        if signals["readme"]:             score += 10
        if signals["license"]:            score += 10
        if signals["contributing_md"]:    score += 5
        if signals["code_of_conduct_md"]: score += 5
        if signals["security_md"]:        score += 10
        if signals["docs_dir"]:           score += 5
        if signals["ci_detected"]:        score += 15
        if signals["unit_tests_detected"]:score += 15
        if signals["has_release"]:        score += 10
        if signals["recent_push_180d"]:   score += 10
        stars = int(meta.get("stargazers_count") or 0)
        score += min(15.0, math.log10(stars + 1) * 5.0)
        score = max(0.0, min(100.0, score))

        return {
            "score_0_100": round(score, 2),
            "signals": signals,
            "stars": stars,
        }


# ------------------------------------------------------------------
# SBOM purl extraction
# ------------------------------------------------------------------

def extract_purls_from_spdx(sbom: Dict[str, Any]) -> List[str]:
    """Return deduplicated purls from a GitHub SPDX SBOM response."""
    purls: List[str] = []
    doc = (sbom or {}).get("sbom") or {}
    for pkg in doc.get("packages") or []:
        for ref in pkg.get("externalRefs") or []:
            if (ref.get("referenceType") or "").lower() == "purl":
                loc = ref.get("referenceLocator")
                if isinstance(loc, str) and loc.startswith("pkg:"):
                    purls.append(loc)
    seen: set[str] = set()
    out: List[str] = []
    for p in purls:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out
