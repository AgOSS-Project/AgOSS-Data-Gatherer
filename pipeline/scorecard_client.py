"""
scorecard_client.py – OpenSSF Scorecard REST API wrapper.

The scorecard lookup is *optional*.  If the API returns 404 or any
non-200 response the pipeline records ``"not_available"`` without
failing the run.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional, Tuple

import requests


def fetch_scorecard(
    owner: str,
    repo: str,
    api_bases: Optional[List[str]] = None,
    timeout: int = 45,
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Try the Scorecard REST API and return ``(payload, error_msg)``."""
    if api_bases is None:
        custom = os.getenv("SCORECARD_API_BASE")
        api_bases = [
            custom if custom else "https://api.securityscorecards.dev",
            "https://api.scorecard.dev",
        ]

    last_err: Optional[str] = None
    for base in api_bases:
        url = f"{base}/projects/github.com/{owner}/{repo}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "repo-risk-pipeline/1.0"},
            )
            if resp.status_code == 200:
                return resp.json(), None
            if resp.status_code in (400, 404):
                return None, "scorecard_not_available"
        except Exception as exc:
            last_err = repr(exc)

    return None, last_err or "scorecard_failed_all_bases"


def summarize_scorecard(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Return a compact scorecard dict for storage in *RepoResult*."""
    if raw is None:
        return {"available": False}
    return {
        "available": True,
        "score": raw.get("score"),
        "date": raw.get("date"),
        "repo_commit": (raw.get("repo") or {}).get("commit", ""),
        "checks": [
            {
                "name": c.get("name"),
                "score": c.get("score"),
                "reason": c.get("reason"),
            }
            for c in (raw.get("checks") or [])
        ],
    }
