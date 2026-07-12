"""Search GitHub for candidate agricultural open-source repositories.

Fetches the top-N results for each keyword using the GitHub Search API,
discards archived repos and forks, and writes a frozen dataset to
candidates.json for use in the AgOSS MSR study.

Usage:
    python ag_oss_search/agoss_search.py
    python ag_oss_search/agoss_search.py --sort stars -n 100
    python ag_oss_search/agoss_search.py --output path/to/output.json
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

KEYWORDS = ["agriculture", "agtech", "farming"]
DEFAULT_N = 500
DEFAULT_OUTPUT = Path(__file__).parent / "candidates.json"
GITHUB_API_BASE = "https://api.github.com"
PER_PAGE = 100
REQUEST_DELAY = 2.0  # seconds between paginated requests to stay within rate limits


# ---------------------------------------------------------------------------
# GitHub API helpers
# ---------------------------------------------------------------------------

def _token() -> str:
    return os.getenv("GITHUB_AUTH_TOKEN") or os.getenv("GITHUB_TOKEN", "")


def _headers() -> dict[str, str]:
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
    q = f"{keyword} archived:false fork:false"
    params: dict[str, str] = {
        "q": q,
        "per_page": str(PER_PAGE),
        "page": str(page),
    }
    if sort == "stars":
        params["sort"] = "stars"
        params["order"] = "desc"
    # best-match is GitHub's default; omitting sort= uses relevance ranking

    url = f"{GITHUB_API_BASE}/search/repositories?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers=_headers())

    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code == 403:
                retry_after = int(exc.headers.get("Retry-After", "60"))
                print(
                    f"  Rate-limited. Waiting {retry_after}s …",
                    file=sys.stderr,
                )
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

    raise RuntimeError(
        f"Failed to fetch page {page} for '{keyword}' after 3 attempts"
    )


def _to_record(item: dict) -> dict:
    return {
        "name": item["full_name"],
        "url": item["html_url"],
        "stars": item.get("stargazers_count", 0),
        "forks": item.get("forks_count", 0),
        "archived": item.get("archived", False),
        "pushed_at": item.get("pushed_at", ""),
    }


# ---------------------------------------------------------------------------
# Per-keyword collection
# ---------------------------------------------------------------------------

def fetch_candidates(
    keyword: str, n: int, sort: str
) -> tuple[list[dict], int, int]:
    """Fetch up to *n* repos for *keyword*, filtering archived repos and forks.

    Returns (repos, n_archived_filtered, n_fork_filtered).
    Cross-keyword deduplication is handled separately in main().
    """
    results: list[dict] = []
    n_archived = 0
    n_forks = 0
    page = 1

    while len(results) < n:
        print(f"  [{keyword}] fetching page {page} …", file=sys.stderr)
        data = _search_page(keyword, sort, page)

        items = data.get("items", [])
        if not items:
            break

        for item in items:
            # Query includes archived:false fork:false; client-side check catches any inconsistency.
            if item.get("archived"):
                n_archived += 1
                continue
            if item.get("fork"):
                n_forks += 1
                continue
            results.append(_to_record(item))
            if len(results) >= n:
                break

        # GitHub Search API caps at 1 000 results; detect last page by item count.
        if len(items) < PER_PAGE:
            break

        page += 1
        time.sleep(REQUEST_DELAY)

    return results[:n], n_archived, n_forks


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Search GitHub for candidate agricultural OSS repositories.",
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


def main() -> None:
    args = parse_args()

    if not _token():
        print(
            "Warning: GITHUB_AUTH_TOKEN not set — unauthenticated rate limits apply.",
            file=sys.stderr,
        )

    print(
        f"AgOSS repo search  sort={args.sort}  n={args.top_n}  keywords={KEYWORDS}",
        file=sys.stderr,
    )

    by_keyword: dict[str, list[dict]] = {}
    raw_counts: dict[str, dict] = {}

    # ── Fetch each keyword independently ──────────────────────────────────────
    for keyword in KEYWORDS:
        print(f"\nKeyword: '{keyword}'", file=sys.stderr)
        repos, n_archived, n_forks = fetch_candidates(keyword, args.top_n, args.sort)
        by_keyword[keyword] = repos
        raw_counts[keyword] = {
            "fetched": len(repos),
            "archived_filtered": n_archived,
            "fork_filtered": n_forks,
        }
        print(
            f"  → {len(repos)} fetched  "
            f"(archived filtered: {n_archived}, fork filtered: {n_forks})",
            file=sys.stderr,
        )

    # ── Deduplicate across keywords, preserving first-occurrence order ─────────
    seen: set[str] = set()
    merged: list[dict] = []
    stats: dict[str, dict] = {}

    for keyword in KEYWORDS:
        n_dupes = 0
        for i, repo in enumerate(by_keyword[keyword]):
            if repo["name"] in seen:
                n_dupes += 1
            else:
                seen.add(repo["name"])
                merged.append({**repo, "keyword": keyword, "rank": i + 1})

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

    output = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "sort": args.sort,
            "n_per_keyword": args.top_n,
            "keywords": KEYWORDS,
            "total_unique": len(merged),
        },
        "stats": stats,
        "by_keyword": by_keyword,
        "merged": merged,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    # JS sidecar consumed by ag_oss_search/index.html (works on file:// without a server)
    js_path = args.output.with_name("candidates_data.js")
    js_path.write_text(
        "const CANDIDATES = " + json.dumps(output, ensure_ascii=False) + ";\n",
        encoding="utf-8",
    )

    summary = " + ".join(f"{stats[kw]['final']} {kw}" for kw in KEYWORDS)
    print(
        f"\nDone. {summary} = {len(merged)} unique repos saved to {args.output}",
        file=sys.stderr,
    )
    print(f"Dashboard data : {js_path}", file=sys.stderr)


if __name__ == "__main__":
    main()
