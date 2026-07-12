"""One-command convenience wrapper for a second (expansion) control-pool search wave.

Mirrors prepare_pool.py's steps 1-2, but targets
control_search.EXPANSION_KEYWORDS instead of the original 7-domain
KEYWORDS, and writes to a completely separate set of files:

    control_candidates_expansion.json / _data.js
    control_candidates_triaged_expansion.json / _data.js

The original wave's files (control_candidates.json,
control_candidates_triaged.json, and control_pool_reviewed.json) are never
read for writing and never touched by this script -- only read, for
deduplication (a repo already in the original wave's candidate list, or
already in a prior review, is excluded here so it isn't triaged/reviewed
twice). review.html loads both waves' sidecars together and shows the
expansion candidates appended after the original ones, not interleaved.

Like prepare_pool.py, this does NOT do the review step itself or write
control_pool_reviewed.json -- that still only happens via a human exporting
from review.html.

Usage:
    python control_search/prepare_expansion_pool.py
    python control_search/prepare_expansion_pool.py --sort stars -n 150
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

_THIS_DIR = Path(__file__).resolve().parent
if str(_THIS_DIR) not in sys.path:
    sys.path.insert(0, str(_THIS_DIR))

import build_control_pool
import control_search
import triage

logger = logging.getLogger("control_search.prepare_expansion_pool")

EXPANSION_TRIAGED_FILE = _THIS_DIR / "control_candidates_triaged_expansion.json"
EXPANSION_TRIAGED_JS_FILE = _THIS_DIR / "control_candidates_triaged_expansion_data.js"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Search GitHub for a second control-pool wave (business/community-"
                    "management SaaS domain) and auto-triage the results, without touching "
                    "the original wave's files.",
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
        default=control_search.DEFAULT_N,
        metavar="N",
        help=f"Candidates to retrieve per keyword (default: {control_search.DEFAULT_N}).",
    )
    return p.parse_args()


def run(*, sort: str = "best-match", top_n: int = control_search.DEFAULT_N) -> None:
    logger.info("[prepare_expansion_pool] Step 1/2 — searching GitHub for expansion candidates …")
    control_search.run(
        sort=sort,
        top_n=top_n,
        keywords=control_search.EXPANSION_KEYWORDS,
        output_path=control_search.EXPANSION_OUTPUT,
        wave="expansion",
        js_global="CANDIDATES_EXPANSION",
        exclude_prior_wave_file=control_search.DEFAULT_OUTPUT,
    )

    logger.info("[prepare_expansion_pool] Step 2/2 — auto-triaging expansion candidates …")
    triage.main(
        candidates_file=control_search.EXPANSION_OUTPUT,
        triaged_file=EXPANSION_TRIAGED_FILE,
        triaged_js_file=EXPANSION_TRIAGED_JS_FILE,
        js_global="TRIAGED_EXPANSION",
    )

    # Refresh the reviewed-pool sidecar so review.html pre-selects repos
    # already accepted in a prior review pass (no-op if
    # control_pool_reviewed.json doesn't exist yet).
    build_control_pool.write_reviewed_sidecar()

    logger.info(
        "[prepare_expansion_pool] Done. Open control_search/review.html in a browser -- "
        "it will show the original wave's candidates first, then the expansion candidates "
        "appended after, with anything already in control_pool_reviewed.json pre-checked. "
        "Review, then click 'Export reviewed pool ↓' and save the download as "
        "control_search/control_pool_reviewed.json (same filename as before -- this "
        "supersedes it with your prior decisions preserved plus the new ones)."
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(message)s")
    args = parse_args()
    run(sort=args.sort, top_n=args.top_n)


if __name__ == "__main__":
    main()
