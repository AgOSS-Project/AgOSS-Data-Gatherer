"""One-command convenience wrapper for a third (ruby) control-pool search wave.

Mirrors prepare_expansion_pool.py's steps, but targets
control_search.RUBY_KEYWORDS (Rails-shaped community/cooperative/membership
management platforms -- see RUBY_KEYWORDS's own docstring for why this wave
exists) instead of the original or expansion waves' keywords, and writes to a
completely separate set of files:

    control_candidates_ruby.json / _data.js
    control_candidates_triaged_ruby.json / _data.js

Neither the original wave's files (control_candidates.json,
control_candidates_triaged.json) nor the expansion wave's
(control_candidates_expansion.json, control_candidates_triaged_expansion.json)
nor control_pool_reviewed.json are ever read for writing or touched by this
script -- only read, for deduplication against both prior waves at once (a
repo already surfaced by the original or expansion wave, or already in a
prior review, is excluded here so it isn't triaged/reviewed a third time).
review.html loads all three waves' sidecars together and shows the ruby
candidates appended after original + expansion, not interleaved.

The result is capped at RUBY_MAX_TOTAL unique candidates (see that
constant's own comment) -- this wave's keyword set is narrow enough that the
review burden should stay small regardless of how much overlap GitHub's
search results happen to have.

Like prepare_pool.py and prepare_expansion_pool.py, this does NOT do the
review step itself or write control_pool_reviewed.json -- that still only
happens via a human exporting from review.html.

Usage:
    python control-search/prepare_ruby_pool.py
    python control-search/prepare_ruby_pool.py --sort stars -n 30
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

logger = logging.getLogger("control_search.prepare_ruby_pool")

RUBY_TRIAGED_FILE = _THIS_DIR / "control_candidates_triaged_ruby.json"
RUBY_TRIAGED_JS_FILE = _THIS_DIR / "control_candidates_triaged_ruby_data.js"

# Hard cap on the final deduplicated candidate count (see control_search.run's
# max_total docstring). 200 keeps the review set within the ~150-200 range
# requested for this wave regardless of how much cross-keyword overlap
# GitHub's search results turn out to have -- a guarantee, not an estimate.
RUBY_MAX_TOTAL = 200

# Per-keyword fetch target. 6 keywords x 40 = 240 raw-fetch ceiling before
# dedup/filtering/the max_total cap -- comfortably lands the post-dedup count
# in the 150-200 range in the typical case, and RUBY_MAX_TOTAL guarantees it
# never exceeds 200 even if this wave's keywords (more narrowly-scoped than
# wave 2's) turn out to have unexpectedly low mutual overlap.
RUBY_DEFAULT_N = 40


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Search GitHub for a third control-pool wave (Rails-shaped "
                    "community/cooperative/membership-management platforms) and "
                    "auto-triage the results, without touching the original or "
                    "expansion waves' files.",
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
        default=RUBY_DEFAULT_N,
        metavar="N",
        help=f"Candidates to retrieve per keyword (default: {RUBY_DEFAULT_N}).",
    )
    return p.parse_args()


def run(*, sort: str = "best-match", top_n: int = RUBY_DEFAULT_N) -> None:
    logger.info("[prepare_ruby_pool] Step 1/2 — searching GitHub for ruby-wave candidates …")
    control_search.run(
        sort=sort,
        top_n=top_n,
        keywords=control_search.RUBY_KEYWORDS,
        output_path=control_search.RUBY_OUTPUT,
        wave="ruby",
        js_global="CANDIDATES_RUBY",
        exclude_prior_wave_file=[control_search.DEFAULT_OUTPUT, control_search.EXPANSION_OUTPUT],
        max_total=RUBY_MAX_TOTAL,
    )

    logger.info("[prepare_ruby_pool] Step 2/2 — auto-triaging ruby-wave candidates …")
    triage.main(
        candidates_file=control_search.RUBY_OUTPUT,
        triaged_file=RUBY_TRIAGED_FILE,
        triaged_js_file=RUBY_TRIAGED_JS_FILE,
        js_global="TRIAGED_RUBY",
    )

    # Refresh the reviewed-pool sidecar so review.html pre-selects repos
    # already accepted in a prior review pass (no-op if
    # control_pool_reviewed.json doesn't exist yet).
    build_control_pool.write_reviewed_sidecar()

    logger.info(
        "[prepare_ruby_pool] Done. Open control-search/review.html in a browser -- "
        "it will show the original wave's candidates first, then expansion, then "
        "ruby, appended in that order, with anything already in "
        "control_pool_reviewed.json pre-checked. Review, then click 'Export "
        "reviewed pool ↓' and save the download as "
        "control-search/control_pool_reviewed.json (same filename as before -- this "
        "supersedes it with your prior decisions preserved plus the new ones)."
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(message)s")
    args = parse_args()
    run(sort=args.sort, top_n=args.top_n)


if __name__ == "__main__":
    main()
