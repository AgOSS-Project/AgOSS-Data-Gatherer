"""Resolve the final control pool.

Priority order:
  1. control_pool_reviewed.json — exported from review.html by a human. Used
     as-is (this is the human-finalized pool; every row was independently
     editable in the review dashboard, so this reflects deliberate decisions).
  2. Fallback (only when allow_unreviewed=True): the suggested_decision ==
     "accept" subset of control_candidates_triaged.json, with a clearly
     logged warning that unreviewed defaults are in use.

When invoked from the automatic pipeline (control_search/run_matched_comparison.py,
which main.py calls), allow_unreviewed defaults to False there — the matched-
comparison analysis is gated on an explicit human review and will not run
against an unreviewed pool. Running this script directly on the command line
still uses the fallback by default, since that's a deliberate manual action
useful for local testing.

Usage:
    python control_search/build_control_pool.py
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("control_search.build_control_pool")

_THIS_DIR = Path(__file__).resolve().parent
TRIAGED_FILE = _THIS_DIR / "control_candidates_triaged.json"
REVIEWED_FILE = _THIS_DIR / "control_pool_reviewed.json"
REVIEWED_JS_FILE = _THIS_DIR / "control_pool_reviewed_data.js"
OUTPUT_FILE = _THIS_DIR / "control_pool.json"


def write_reviewed_sidecar() -> Path | None:
    """Mirror control_pool_reviewed.json into a JS sidecar (const REVIEWED = ...)
    so review.html -- a static file:// page, which can't fetch() local JSON --
    can pre-select repos already accepted in a prior review pass. Returns None
    (and writes nothing) if no reviewed pool has been exported yet; that's the
    normal first-time state, not an error.

    Call this before opening review.html for a new round (both prepare_pool.py
    and prepare_expansion_pool.py do), so it reflects whatever was most
    recently exported.
    """
    if not REVIEWED_FILE.exists():
        return None
    payload = json.loads(REVIEWED_FILE.read_text(encoding="utf-8"))
    REVIEWED_JS_FILE.write_text(
        "const REVIEWED = " + json.dumps(payload, ensure_ascii=False) + ";\n",
        encoding="utf-8",
    )
    logger.info("[build_control_pool] Wrote %s (%d previously-reviewed repos, for review.html pre-selection)",
                REVIEWED_JS_FILE.name, len(payload.get("repos", [])))
    return REVIEWED_JS_FILE


def main(*, allow_unreviewed: bool = True) -> Path:
    if REVIEWED_FILE.exists():
        payload = json.loads(REVIEWED_FILE.read_text(encoding="utf-8"))
        repos = payload.get("repos", [])
        review_status = "human_reviewed"
        logger.info("[build_control_pool] Using human-reviewed pool: %d repos", len(repos))
    else:
        if not allow_unreviewed:
            raise FileNotFoundError(
                f"{REVIEWED_FILE} not found. Open control_search/review.html, review the "
                "candidates, and export the reviewed pool to that path before building the "
                "control pool for the automatic pipeline."
            )
        if not TRIAGED_FILE.exists():
            raise FileNotFoundError(
                f"{TRIAGED_FILE} not found — run control_search.py then triage.py first."
            )
        payload = json.loads(TRIAGED_FILE.read_text(encoding="utf-8"))
        candidates = payload.get("candidates", [])
        repos = [c for c in candidates if c.get("suggested_decision") == "accept"]
        review_status = "auto_suggested_fallback"
        logger.warning(
            "[build_control_pool] No control_pool_reviewed.json found — using %d "
            "unreviewed auto-suggested-accept candidates. Open control_search/review.html "
            "and export to get a human-reviewed pool instead.",
            len(repos),
        )

    output = {"count": len(repos), "review_status": review_status, "repos": repos}
    OUTPUT_FILE.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    logger.info(
        "[build_control_pool] Wrote %s (%d repos, review_status=%s)",
        OUTPUT_FILE, len(repos), review_status,
    )
    return OUTPUT_FILE


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(message)s")
    main()
