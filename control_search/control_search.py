"""Search GitHub for candidate non-agricultural control repositories.

Searches operationally-similar non-ag domains (IoT, embedded systems, robotics
middleware, sensor frameworks, environmental monitoring, small cloud
dashboards, cyber-physical software) via a mix of GitHub topic qualifiers and
free-text queries, filters out anything already in the 54-repo AgOSS dataset
and anything agriculture-adjacent, and writes a frozen candidate pool to
control_candidates.json for later triage (triage.py) + human review
(review.html).

Usage:
    python control_search/control_search.py
    python control_search/control_search.py --sort stars -n 100
    python control_search/control_search.py --output path/to/output.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _THIS_DIR.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from pipeline import config
from pipeline.input_parser import parse_input

# Mix of GitHub topic qualifiers (structured, high-precision) and free-text
# queries (broader recall) covering the 7 non-ag domains named in the study
# design: IoT, embedded systems, sensor frameworks, robotics middleware,
# environmental monitoring, small cloud dashboards, cyber-physical software.
KEYWORDS = [
    "topic:iot", "topic:embedded-systems", "topic:robotics", "topic:sensor",
    "topic:environmental-monitoring", "topic:scada", "topic:firmware",
    "topic:cyber-physical-systems", "topic:home-automation", "topic:plc",
    "iot platform", "embedded systems", "robotics middleware",
    "sensor framework", "environmental monitoring", "small cloud dashboard",
]

# Wave 2 -- added after matching revealed near-zero control-pool coverage for
# the "business/community-management SaaS" niche (LiteFarm, csa-admin,
# ekylibre). Targets that domain, not a language, so Ruby/JS repos surface
# naturally rather than via a broad language-based search.
EXPANSION_KEYWORDS = [
    "topic:saas", "topic:admin-dashboard", "topic:crm", "topic:erp",
    "topic:inventory-management", "topic:scheduling",
    "business management software", "subscription management",
    "admin dashboard",
]

# Wave 3 -- 3 of 6 pool-starvation cases (bety, csa-admin, ekylibre) are
# Rails-shaped community/membership platforms neither wave 1 nor wave 2
# targeted, and only 2 Ruby repos existed pool-wide. Targets that niche
# directly, not "Ruby" as a language. Free-text + language:ruby phrases
# returned 0 live results, so topic-based forms are used instead.
RUBY_KEYWORDS = [
    "topic:ruby-on-rails", "topic:rails",
    "\"membership management\" language:ruby",
    "topic:membership-management",
    "topic:cooperative",
    "\"subscription management\" language:ruby",
]

# Mirrors ag_oss_search's own KEYWORDS: a candidate tagged with one of these
# topics was likely directly discoverable by that tool too, so it's excluded
# by exact topic match (in addition to the substring check below).
AG_OSS_SEARCH_TOPICS = {"agriculture", "agtech", "farming"}

# Candidates whose name/description/topics mention these terms are excluded —
# the control pool must be genuinely non-ag-critical, since it's the
# counterfactual baseline for the matched comparison.
AG_EXCLUSION_TERMS = [
    "agriculture", "agricultural", "agtech", "ag-tech", "farm", "farming",
    "crop", "livestock", "precision-ag", "precision agriculture", "irrigation",
    "agri", "horticulture", "viticulture", "aquaculture",
]

DEFAULT_N = 100
DEFAULT_OUTPUT = _THIS_DIR / "control_candidates.json"
EXPANSION_OUTPUT = _THIS_DIR / "control_candidates_expansion.json"
RUBY_OUTPUT = _THIS_DIR / "control_candidates_ruby.json"
GITHUB_API_BASE = "https://api.github.com"
PER_PAGE = 100
REQUEST_DELAY = 2.0  # seconds between paginated requests to stay within rate limits


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _token() -> str:
    """Return the GitHub auth token from env vars or config, or an empty string."""
    return os.getenv("GITHUB_AUTH_TOKEN") or os.getenv("GITHUB_TOKEN", "") or config.GITHUB_AUTH_TOKEN


def _headers() -> dict[str, str]:
    """Build GitHub API request headers, adding a bearer token when available."""
    hdrs: dict[str, str] = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    tok = _token()
    if tok:
        hdrs["Authorization"] = f"Bearer {tok}"
    return hdrs


def _search_page(keyword: str, sort: str, page: int) -> dict:
    """Fetch one page of GitHub repository search results."""
    q = f"{keyword} archived:false fork:false stars:>=1"
    params: dict[str, str] = {
        "q": q,
        "per_page": str(PER_PAGE),
        "page": str(page),
    }
    if sort == "stars":
        params["sort"] = "stars"
        params["order"] = "desc"

    url = f"{GITHUB_API_BASE}/search/repositories?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=_headers())

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                retry_after = int(exc.headers.get("Retry-After", "60"))
                print(f"  Rate-limited. Waiting {retry_after}s …", file=sys.stderr)
                time.sleep(retry_after)
                continue
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"GitHub API HTTP {exc.code} on page {page} for '{keyword}': {body}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt == 2:
                raise RuntimeError(
                    f"Network error fetching page {page} for '{keyword}': {exc}"
                ) from exc
            time.sleep(REQUEST_DELAY * (attempt + 1))

    raise RuntimeError(f"Failed to fetch page {page} for '{keyword}' after 3 attempts")


def _is_ag_adjacent(item: dict) -> bool:
    """Return True if item's topics match AG_OSS_SEARCH_TOPICS or its name/description/topics contain an ag exclusion term."""
    topics = {str(t).strip().lower() for t in (item.get("topics") or [])}
    if topics & AG_OSS_SEARCH_TOPICS:
        return True
    haystack = " ".join([
        str(item.get("full_name") or ""),
        str(item.get("description") or ""),
        " ".join(item.get("topics") or []),
    ]).lower()
    return any(term in haystack for term in AG_EXCLUSION_TERMS)


def _repo_short_name(item: dict) -> str:
    """Return the repo-name portion of a GitHub 'owner/repo' full_name string."""
    full = str(item.get("full_name") or "")
    return full.split("/", 1)[1] if "/" in full else full


def _is_curated_list(item: dict) -> bool:
    """"awesome-*" style curated-list repos are not software and aren't a
    useful control candidate — exclude them regardless of which keyword
    surfaced them (e.g. "phodal/awesome-iot" matches topic:iot legitimately
    but isn't itself an IoT project)."""
    name = _repo_short_name(item).lower()
    if name == "awesome" or name.startswith("awesome-") or name.startswith("awesome_"):
        return True
    topics = {str(t).strip().lower() for t in (item.get("topics") or [])}
    if "awesome-list" in topics or "awesome" in topics:
        return True
    return False


def _to_record(item: dict) -> dict:
    """Convert a raw GitHub search API item into the flat record dict stored in the pool."""
    owner = item.get("owner") or {}
    return {
        "name": item["full_name"],
        "url": item["html_url"],
        "stars": item.get("stargazers_count", 0),
        "forks": item.get("forks_count", 0),
        "archived": item.get("archived", False),
        "pushed_at": item.get("pushed_at", ""),
        "language": item.get("language"),
        "owner_type": owner.get("type"),
        "description": item.get("description") or "",
        "topics": item.get("topics") or [],
    }


# ---------------------------------------------------------------------------
# Per-keyword collection
# ---------------------------------------------------------------------------

def fetch_candidates(
    keyword: str, n: int, sort: str, excluded_names: set[str]
) -> tuple[list[dict], int, int, int, int, int]:
    """Fetch up to *n* repos for *keyword*, filtering archived repos, forks,
    repos already in the 54-repo AgOSS dataset, ag-adjacent repos, and
    "awesome-*" curated-list repos.

    Returns (repos, n_archived_filtered, n_fork_filtered, n_already_in_dataset,
    n_ag_filtered, n_curated_filtered). Cross-keyword deduplication is handled
    separately in main().
    """
    results: list[dict] = []
    n_archived = 0
    n_forks = 0
    n_already_in_dataset = 0
    n_ag = 0
    n_curated = 0
    page = 1

    while len(results) < n:
        print(f"  [{keyword}] fetching page {page} …", file=sys.stderr)
        data = _search_page(keyword, sort, page)

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            if item.get("archived"):
                n_archived += 1
                continue
            if item.get("fork"):
                n_forks += 1
                continue
            if str(item.get("full_name") or "").lower() in excluded_names:
                n_already_in_dataset += 1
                continue
            if _is_ag_adjacent(item):
                n_ag += 1
                continue
            if _is_curated_list(item):
                n_curated += 1
                continue
            results.append(_to_record(item))
            if len(results) >= n:
                break

        # GitHub Search API caps at 1 000 results; detect last page by item count.
        if len(items) < PER_PAGE:
            break

        page += 1
        time.sleep(REQUEST_DELAY)

    return results[:n], n_archived, n_forks, n_already_in_dataset, n_ag, n_curated


def _load_excluded_names(*, also_exclude_file: Path | list[Path] | None = None) -> set[str]:
    """Return owner/repo (lowercase) for every repo already in the AgOSS
    dataset, plus any repos from earlier search waves' output files, so
    later waves don't re-triage the same repo twice."""
    excluded: set[str] = set()
    if config.INPUT_FILE.exists():
        entries = parse_input(config.INPUT_FILE)
        excluded |= {f"{e.owner}/{e.repo_name}".lower() for e in entries}
    exclude_files = (
        [also_exclude_file] if isinstance(also_exclude_file, Path)
        else list(also_exclude_file or [])
    )
    for f in exclude_files:
        if not f.exists():
            continue
        try:
            prior = json.loads(f.read_text(encoding="utf-8"))
            excluded |= {str(r["name"]).lower() for r in prior.get("merged", [])}
        except Exception as exc:
            print(f"Warning: could not read {f} for dedup: {exc}", file=sys.stderr)
    return excluded


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments for sort order, candidates-per-keyword, and output path."""
    p = argparse.ArgumentParser(
        description="Search GitHub for candidate non-ag control repositories.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument(
        "--sort",
        choices=["best-match", "stars"],
        default="best-match",
        help="Sort order for search results (default: best-match).",
    )
    p.add_argument(
        "-n", "--top-n",
        type=int,
        default=DEFAULT_N,
        metavar="N",
        help=f"Candidates to retrieve per keyword (default: {DEFAULT_N}).",
    )
    p.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help=f"Output JSON file path (default: {DEFAULT_OUTPUT}).",
    )
    return p.parse_args()


def run(
    *,
    sort: str = "best-match",
    top_n: int = DEFAULT_N,
    output_path: Path = DEFAULT_OUTPUT,
    keywords: list[str] = KEYWORDS,
    wave: str = "original",
    js_global: str = "CANDIDATES",
    exclude_prior_wave_file: Path | list[Path] | None = None,
    max_total: int | None = None,
) -> Path:
    """Run the full search + dedup + write, callable directly so other
    scripts (e.g. prepare_expansion_pool.py, prepare_ruby_pool.py) can
    invoke additional search waves in-process, each writing its own
    output_path and excluding prior waves via exclude_prior_wave_file.
    max_total optionally caps the final deduplicated candidate count."""
    if not _token():
        print(
            "Warning: GITHUB_AUTH_TOKEN not set — unauthenticated rate limits apply.",
            file=sys.stderr,
        )

    excluded_names = _load_excluded_names(also_exclude_file=exclude_prior_wave_file)
    print(
        f"Control-pool search  wave={wave}  sort={sort}  n={top_n}  keywords={len(keywords)}  "
        f"excluding {len(excluded_names)} already-known repos",
        file=sys.stderr,
    )

    by_keyword: dict[str, list[dict]] = {}
    raw_counts: dict[str, dict] = {}

    # ── Fetch each keyword independently ──────────────────────────────────────
    for keyword in keywords:
        print(f"\nKeyword: '{keyword}'", file=sys.stderr)
        repos, n_archived, n_forks, n_already, n_ag, n_curated = fetch_candidates(keyword, top_n, sort, excluded_names)
        by_keyword[keyword] = repos
        raw_counts[keyword] = {
            "fetched": len(repos),
            "archived_filtered": n_archived,
            "fork_filtered": n_forks,
            "already_in_dataset_filtered": n_already,
            "ag_adjacent_filtered": n_ag,
            "curated_list_filtered": n_curated,
        }
        print(
            f"  → {len(repos)} fetched  "
            f"(archived filtered: {n_archived}, fork filtered: {n_forks}, "
            f"already-in-dataset filtered: {n_already}, "
            f"ag-adjacent filtered: {n_ag}, curated-list filtered: {n_curated})",
            file=sys.stderr,
        )

    # ── Deduplicate across keywords, preserving first-occurrence order ─────────
    seen: set[str] = set()
    merged: list[dict] = []
    stats: dict[str, dict] = {}

    for keyword in keywords:
        n_dupes = 0
        for i, repo in enumerate(by_keyword[keyword]):
            if repo["name"] in seen:
                n_dupes += 1
            else:
                seen.add(repo["name"])
                merged.append({**repo, "keyword": keyword, "rank": i + 1, "wave": wave})

        stats[keyword] = {
            **raw_counts[keyword],
            "duplicates": n_dupes,
            "final": raw_counts[keyword]["fetched"] - n_dupes,
        }
        print(
            f"  [{keyword}] {stats[keyword]['fetched']} fetched, "
            f"{n_dupes} cross-keyword duplicates → {stats[keyword]['final']} unique",
            file=sys.stderr,
        )

    print(f"\nTotal unique repos: {len(merged)}", file=sys.stderr)

    n_capped = 0
    if max_total is not None and len(merged) > max_total:
        n_capped = len(merged) - max_total
        merged = merged[:max_total]
        print(
            f"Capped to max_total={max_total} (dropped {n_capped} of the "
            f"lowest-priority candidates, same first-occurrence order as dedup)",
            file=sys.stderr,
        )

    output_payload = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "wave": wave,
            "sort": sort,
            "n_per_keyword": top_n,
            "max_total": max_total,
            "n_capped": n_capped,
            "keywords": keywords,
            "total_unique": len(merged),
            "excluded_repos": len(excluded_names),
        },
        "stats": stats,
        "by_keyword": by_keyword,
        "merged": merged,
    }

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output_payload, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # JS sidecar consumed by control_search/review.html (works on file:// without
    # a server) -- named after output_path's own stem so the expansion wave gets
    # its own sidecar (control_candidates_expansion_data.js) instead of
    # overwriting the original wave's (control_candidates_data.js).
    js_path = output_path.with_name(output_path.stem + "_data.js")
    js_path.write_text(
        f"const {js_global} = " + json.dumps(output_payload, ensure_ascii=False) + ";\n",
        encoding="utf-8",
    )

    print(f"\nDone. {len(merged)} unique repos saved to {output_path}", file=sys.stderr)
    print(f"Dashboard data : {js_path}", file=sys.stderr)
    return output_path


def main() -> None:
    """CLI entry point: parse arguments and run the original-wave control search."""
    args = parse_args()
    run(sort=args.sort, top_n=args.top_n, output_path=args.output)


if __name__ == "__main__":
    main()
