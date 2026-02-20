"""
scan_repos.py

Reads a list of GitHub repositories from input.txt and produces results.json with:
- GitHub repo metadata
- OpenSSF Scorecard (public REST API)
- "RepoReaper-lite" engineering hygiene heuristic (simple signals)
- SBOM export via GitHub Dependency Graph (SPDX JSON)
- OSV.dev vulnerability lookup using SBOM purls (querybatch)

Notes:
- This "RepoReaper-lite" is NOT the original RepoReapers reaper (which depends on GHTorrent/MySQL).
  It's a lightweight approximation based on easily-checkable repo signals.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import os
import re
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

from dotenv import load_dotenv
load_dotenv()  # reads .env into environment variables

# ----------------------------
# Parsing repo identifiers
# ----------------------------

RE_GH_HTTP = re.compile(r"^https?://github\.com/([^/]+)/([^/#\s]+)")
RE_GH_SSH = re.compile(r"^git@github\.com:([^/]+)/([^/#\s]+)")
RE_OWNER_REPO = re.compile(r"^([^/\s]+)/([^/\s]+)$")


@dataclass(frozen=True)
class RepoTarget:
    original: str
    owner: str
    repo: str

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repo}"


def parse_repo_line(line: str) -> Optional[RepoTarget]:
    s = line.strip()
    if not s or s.startswith("#"):
        return None

    s = s.removesuffix(".git")

    m = RE_GH_HTTP.match(s)
    if m:
        return RepoTarget(original=line.strip(), owner=m.group(1), repo=m.group(2))

    m = RE_GH_SSH.match(s)
    if m:
        return RepoTarget(original=line.strip(), owner=m.group(1), repo=m.group(2))

    m = RE_OWNER_REPO.match(s)
    if m:
        return RepoTarget(original=line.strip(), owner=m.group(1), repo=m.group(2))

    # If it's something else, skip but record later
    return RepoTarget(original=line.strip(), owner="", repo="")


# ----------------------------
# HTTP helpers
# ----------------------------

class Http:
    def __init__(self, github_token: Optional[str]) -> None:
        self.s = requests.Session()
        self.github_token = github_token

        self.github_headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "repo-risk-scan/1.0",
        }
        if github_token:
            self.github_headers["Authorization"] = f"Bearer {github_token}"

    def _sleep_for_rate_limit(self, resp: requests.Response) -> None:
        # GitHub signals rate-limit reset in epoch seconds
        reset = resp.headers.get("X-RateLimit-Reset")
        remaining = resp.headers.get("X-RateLimit-Remaining")
        if remaining == "0" and reset and reset.isdigit():
            reset_ts = int(reset)
            now = int(time.time())
            wait = max(0, reset_ts - now) + 1
            time.sleep(min(wait, 60))  # cap sleep for sanity

    def get_json(
        self,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        timeout: int = 30,
        retries: int = 3,
    ) -> Tuple[Optional[Any], Optional[int], Optional[str], Dict[str, str]]:
        last_err = None
        for attempt in range(retries):
            try:
                resp = self.s.get(
                    url,
                    headers=headers,
                    params=params,
                    timeout=timeout,
                    allow_redirects=True,
                )
                self._sleep_for_rate_limit(resp)

                if resp.status_code >= 200 and resp.status_code < 300:
                    return resp.json(), resp.status_code, None, dict(resp.headers)

                # treat 404/403 as normal "no data"
                if resp.status_code in (400, 401, 403, 404):
                    return None, resp.status_code, resp.text[:500], dict(resp.headers)

                last_err = f"HTTP {resp.status_code}: {resp.text[:500]}"
            except Exception as e:
                last_err = repr(e)

            # basic backoff
            time.sleep(1.0 * (attempt + 1))

        return None, None, last_err, {}

    def post_json(
        self,
        url: str,
        payload: Any,
        headers: Optional[Dict[str, str]] = None,
        timeout: int = 60,
        retries: int = 3,
    ) -> Tuple[Optional[Any], Optional[int], Optional[str]]:
        last_err = None
        for attempt in range(retries):
            try:
                resp = self.s.post(
                    url,
                    headers=headers,
                    json=payload,
                    timeout=timeout,
                )
                if resp.status_code >= 200 and resp.status_code < 300:
                    return resp.json(), resp.status_code, None

                if resp.status_code in (400, 401, 403, 404):
                    return None, resp.status_code, resp.text[:500]

                last_err = f"HTTP {resp.status_code}: {resp.text[:500]}"
            except Exception as e:
                last_err = repr(e)

            time.sleep(1.0 * (attempt + 1))

        return None, None, last_err


# ----------------------------
# GitHub: metadata + content checks
# ----------------------------

def gh_repo_metadata(http: Http, owner: str, repo: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    url = f"https://api.github.com/repos/{owner}/{repo}"
    data, status, err, _hdrs = http.get_json(url, headers=http.github_headers)
    if data is None:
        errors.append(f"github_repo_metadata_failed status={status} err={err}")
        return None, errors
    return data, errors


def gh_exists_path(http: Http, owner: str, repo: str, path: str) -> Tuple[bool, Optional[int]]:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    _data, status, _err, _hdrs = http.get_json(url, headers=http.github_headers)
    if status == 200:
        return True, status
    return False, status


def gh_has_readme(http: Http, owner: str, repo: str) -> bool:
    url = f"https://api.github.com/repos/{owner}/{repo}/readme"
    _data, status, _err, _hdrs = http.get_json(url, headers=http.github_headers)
    return status == 200


def gh_has_license(http: Http, owner: str, repo: str) -> bool:
    url = f"https://api.github.com/repos/{owner}/{repo}/license"
    _data, status, _err, _hdrs = http.get_json(url, headers=http.github_headers)
    return status == 200


def gh_has_latest_release(http: Http, owner: str, repo: str) -> bool:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases/latest"
    _data, status, _err, _hdrs = http.get_json(url, headers=http.github_headers)
    return status == 200


def reporeaper_lite(http: Http, owner: str, repo: str, meta: Dict[str, Any]) -> Dict[str, Any]:
    """
    Lightweight "engineered project" scoring based on repo signals.
    Output: score_0_100 + which signals were detected.
    """
    signals: Dict[str, bool] = {}

    signals["readme"] = gh_has_readme(http, owner, repo)
    signals["license"] = gh_has_license(http, owner, repo)

    # Common hygiene files/dirs
    signals["contributing_md"] = gh_exists_path(http, owner, repo, "CONTRIBUTING.md")[0]
    signals["code_of_conduct_md"] = gh_exists_path(http, owner, repo, "CODE_OF_CONDUCT.md")[0]
    signals["security_md"] = gh_exists_path(http, owner, repo, "SECURITY.md")[0]
    signals["docs_dir"] = gh_exists_path(http, owner, repo, "docs")[0]

    # CI heuristics
    signals["github_actions"] = gh_exists_path(http, owner, repo, ".github/workflows")[0]
    signals["travis"] = gh_exists_path(http, owner, repo, ".travis.yml")[0]
    signals["circleci"] = gh_exists_path(http, owner, repo, ".circleci")[0]
    signals["ci_detected"] = signals["github_actions"] or signals["travis"] or signals["circleci"]

    # Tests heuristics
    signals["tests_dir"] = gh_exists_path(http, owner, repo, "tests")[0] or gh_exists_path(http, owner, repo, "test")[0]
    signals["__tests__"] = gh_exists_path(http, owner, repo, "__tests__")[0]
    signals["unit_tests_detected"] = signals["tests_dir"] or signals["__tests__"]

    # Releases heuristic
    signals["has_release"] = gh_has_latest_release(http, owner, repo)

    # Recent activity heuristic
    pushed_at = meta.get("pushed_at")
    recent = False
    if pushed_at:
        try:
            pushed = dt.datetime.fromisoformat(pushed_at.replace("Z", "+00:00"))
            recent = (dt.datetime.now(dt.timezone.utc) - pushed).days <= 180
        except Exception:
            recent = False
    signals["recent_push_180d"] = recent

    # Score composition (simple, explainable)
    score = 0.0
    if signals["readme"]: score += 10
    if signals["license"]: score += 10
    if signals["contributing_md"]: score += 5
    if signals["code_of_conduct_md"]: score += 5
    if signals["security_md"]: score += 10
    if signals["docs_dir"]: score += 5
    if signals["ci_detected"]: score += 15
    if signals["unit_tests_detected"]: score += 15
    if signals["has_release"]: score += 10
    if signals["recent_push_180d"]: score += 10

    # Small popularity bump (log-scaled)
    stars = int(meta.get("stargazers_count") or 0)
    score += min(15.0, math.log10(stars + 1) * 5.0)

    # Clamp
    score = max(0.0, min(100.0, score))

    return {
        "score_0_100": round(score, 2),
        "signals": signals,
        "stars": stars,
        "note": "This is a lightweight heuristic (RepoReaper-like), not the original GHTorrent-backed reaper.",
    }


# ----------------------------
# OpenSSF Scorecard
# ----------------------------

def openssf_scorecard(owner: str, repo: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    Uses OpenSSF Scorecard REST API:
      GET /projects/{platform}/{org}/{repo}
    Swagger describes the endpoint and response schema. :contentReference[oaicite:4]{index=4}

    Note: OpenSSF has mentioned migration from securityscorecards.dev to scorecard.dev. :contentReference[oaicite:5]{index=5}
    """
    bases = [
        os.getenv("SCORECARD_API_BASE", "https://api.securityscorecards.dev"),
        "https://api.scorecard.dev",
    ]

    for base in bases:
        url = f"{base}/projects/github.com/{owner}/{repo}"
        try:
            r = requests.get(url, timeout=45, allow_redirects=True, headers={"User-Agent": "repo-risk-scan/1.0"})
            if r.status_code == 200:
                return r.json(), None
            if r.status_code in (404, 400):
                return None, f"scorecard_not_found status={r.status_code}"
        except Exception as e:
            # try next base
            last = repr(e)
            continue

    return None, "scorecard_failed_all_bases"


# ----------------------------
# SBOM + OSV
# ----------------------------

def gh_export_sbom(http: Http, owner: str, repo: str) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """
    GitHub Dependency Graph SBOM export:
      GET /repos/{owner}/{repo}/dependency-graph/sbom
    Returns SPDX JSON. :contentReference[oaicite:6]{index=6}
    """
    errors: List[str] = []
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    data, status, err, _hdrs = http.get_json(url, headers=http.github_headers, timeout=60)
    if data is None:
        errors.append(f"github_sbom_failed status={status} err={err}")
        return None, errors
    return data, errors


def extract_purls_from_spdx(sbom: Dict[str, Any]) -> List[str]:
    """
    GitHub returns: { "sbom": { ... "packages": [ ... ] } }
    We extract purls from packages[*].externalRefs where referenceType == "purl".
    """
    purls: List[str] = []
    doc = (sbom or {}).get("sbom") or {}
    packages = doc.get("packages") or []

    for pkg in packages:
        external_refs = pkg.get("externalRefs") or []
        for ref in external_refs:
            if (ref.get("referenceType") or "").lower() == "purl":
                loc = ref.get("referenceLocator")
                if isinstance(loc, str) and loc.startswith("pkg:"):
                    purls.append(loc)

    # de-dupe, stable order
    seen = set()
    out = []
    for p in purls:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


def osv_querybatch(purls: List[str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """
    OSV querybatch API supports querying by purl only. :contentReference[oaicite:7]{index=7}
    """
    if not purls:
        return {"results": []}, None

    # Chunk to avoid huge single requests
    CHUNK = 500
    all_results: List[Dict[str, Any]] = []

    for i in range(0, len(purls), CHUNK):
        chunk = purls[i : i + CHUNK]
        payload = {"queries": [{"package": {"purl": p}} for p in chunk]}
        data, status, err = Http(github_token=None).post_json(
            "https://api.osv.dev/v1/querybatch",
            payload=payload,
            headers={"User-Agent": "repo-risk-scan/1.0"},
            timeout=90,
            retries=3,
        )
        if data is None:
            return None, f"osv_querybatch_failed status={status} err={err}"
        all_results.extend(data.get("results", []))

    return {"results": all_results}, None


def summarize_osv(purls: List[str], osv_resp: Dict[str, Any], max_items: int = 200) -> Dict[str, Any]:
    """
    Summarize OSV results aligned with input ordering (querybatch guarantees ordering). :contentReference[oaicite:8]{index=8}
    """
    results = (osv_resp or {}).get("results") or []

    by_dep: List[Dict[str, Any]] = []
    total_vuln_ids = 0
    vulnerable_deps = 0

    for idx, p in enumerate(purls[: len(results)]):
        vulns = (results[idx] or {}).get("vulns") or []
        ids = [v.get("id") for v in vulns if isinstance(v, dict) and v.get("id")]
        if ids:
            vulnerable_deps += 1
            total_vuln_ids += len(ids)
        by_dep.append({"purl": p, "vuln_ids": ids})

    # cap for file size sanity
    capped = by_dep[:max_items]
    truncated = len(by_dep) > max_items

    return {
        "dependency_count": len(purls),
        "vulnerable_dependency_count": vulnerable_deps,
        "vulnerability_id_count": total_vuln_ids,
        "by_dependency": capped,
        "truncated": truncated,
        "max_items": max_items,
    }


# ----------------------------
# Per-repo runner
# ----------------------------

def scan_one(target: RepoTarget, http: Http, max_osv_items: int) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "input": target.original,
        "owner": target.owner,
        "repo": target.repo,
        "errors": [],
    }

    if not target.owner or not target.repo:
        out["errors"].append("parse_failed: expected owner/repo or github url")
        return out

    meta, errs = gh_repo_metadata(http, target.owner, target.repo)
    out["github"] = meta or {}
    out["errors"].extend(errs)

    if not meta:
        return out

    # OpenSSF Scorecard
    sc, sc_err = openssf_scorecard(target.owner, target.repo)
    if sc is None:
        out["openssf_scorecard"] = {}
        if sc_err:
            out["errors"].append(sc_err)
    else:
        out["openssf_scorecard"] = {
            "score": sc.get("score"),
            "date": sc.get("date"),
            "repo": (sc.get("repo") or {}),
            "checks": [
                {
                    "name": c.get("name"),
                    "score": c.get("score"),
                    "reason": c.get("reason"),
                }
                for c in (sc.get("checks") or [])
            ],
            "raw": None,  # set to sc if you want full payload
        }

    # RepoReaper-lite heuristic
    out["reporeaper_lite"] = reporeaper_lite(http, target.owner, target.repo, meta)

    # SBOM
    sbom, sbom_errs = gh_export_sbom(http, target.owner, target.repo)
    out["errors"].extend(sbom_errs)

    if sbom is None:
        out["sbom"] = {}
        out["osv"] = {}
        return out

    purls = extract_purls_from_spdx(sbom)
    out["sbom"] = {
        "format": "spdx-json",
        "purl_dependency_count": len(purls),
    }

    # OSV querybatch
    osv_resp, osv_err = osv_querybatch(purls)
    if osv_resp is None:
        out["osv"] = {}
        if osv_err:
            out["errors"].append(osv_err)
    else:
        out["osv"] = summarize_osv(purls, osv_resp, max_items=max_osv_items)

    return out


# ----------------------------
# Main
# ----------------------------

def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", default="input.txt", help="Input file with repos (one per line)")
    ap.add_argument("--output", default="results.json", help="Output JSON file")
    ap.add_argument("--workers", type=int, default=4, help="Parallel workers (threaded)")
    ap.add_argument("--max-osv-items", type=int, default=200, help="Cap OSV by_dependency items per repo")
    args = ap.parse_args()

    token = os.getenv("GITHUB_TOKEN")
    http = Http(github_token=token)

    targets: List[RepoTarget] = []
    with open(args.input, "r", encoding="utf-8") as f:
        for line in f:
            t = parse_repo_line(line)
            if t is not None:
                targets.append(t)

    started = dt.datetime.now(dt.timezone.utc)

    results: List[Dict[str, Any]] = []
    if args.workers <= 1:
        for t in targets:
            results.append(scan_one(t, http, args.max_osv_items))
    else:
        from concurrent.futures import ThreadPoolExecutor, as_completed

        with ThreadPoolExecutor(max_workers=args.workers) as ex:
            futs = [ex.submit(scan_one, t, http, args.max_osv_items) for t in targets]
            for fut in as_completed(futs):
                results.append(fut.result())

        # keep stable output ordering by input
        order = {t.original: i for i, t in enumerate(targets)}
        results.sort(key=lambda r: order.get(r.get("input", ""), 10**9))

    ended = dt.datetime.now(dt.timezone.utc)

    final = {
        "generated_at": ended.isoformat(),
        "duration_seconds": int((ended - started).total_seconds()),
        "input_file": args.input,
        "repo_count": len(targets),
        "results": results,
        "notes": {
            "scorecard_api": "Uses OpenSSF Scorecard REST API (/projects/github.com/{org}/{repo}).",
            "sbom_api": "Uses GitHub dependency-graph SBOM export endpoint.",
            "osv_api": "Uses OSV.dev querybatch with purls extracted from SPDX SBOM.",
        },
    }

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(final, f, indent=2)

    print(f"Wrote {args.output} for {len(targets)} repos.")


if __name__ == "__main__":
    main()
