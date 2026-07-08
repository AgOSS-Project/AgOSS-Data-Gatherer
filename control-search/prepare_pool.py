"""One-command convenience wrapper for control-pool steps 1-2 (search + triage).

Runs control_search.py then triage.py in sequence, so refreshing the
candidate list ready for human review is a single command instead of two.
This does NOT do the review step itself, and it never writes
control_pool_reviewed.json — that file can only be produced by a human
exporting from review.html, since it is what gates the matched-comparison
analysis (see run_matched_comparison.py). This script exists purely for
ease of use and reproducibility of steps 1-2, not to bypass step 3.

Usage:
    python control-search/prepare_pool.py
    python control-search/prepare_pool.py --sort stars -n 150
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

logger = logging.getLogger("control_search.prepare_pool")


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Search GitHub for control-pool candidates and auto-triage them in one step.",
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
    logger.info("[prepare_pool] Step 1/2 — searching GitHub for candidates …")
    control_search.run(sort=sort, top_n=top_n)

    logger.info("[prepare_pool] Step 2/2 — auto-triaging candidates …")
    triage.main()

    # Refresh the reviewed-pool sidecar so review.html pre-selects repos from
    # any prior review pass (no-op if control_pool_reviewed.json doesn't
    # exist yet -- the normal first-time state).
    build_control_pool.write_reviewed_sidecar()

    logger.info(
        "[prepare_pool] Done. Open control-search/review.html in a browser to review "
        "candidates (every row is editable, including auto-suggested-accepts), then "
        "click 'Export reviewed pool ↓' and save the download as "
        "control-search/control_pool_reviewed.json. That file is what enables the "
        "matched-comparison analysis in `python main.py`."
    )


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(message)s")
    args = parse_args()
    run(sort=args.sort, top_n=args.top_n)


if __name__ == "__main__":
    main()
