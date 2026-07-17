"""Suggest accept/review decisions for control-pool candidates.

A candidate is suggested-accept only if its own GitHub topics confirm it
belongs to one of the target non-ag domains (a maintainer-asserted signal,
much higher precision than a free-text keyword hit) and it doesn't match a
student/toy-project blocklist. Everything else is suggested-review.

These are *suggestions* only — every candidate (including suggested-accepts)
stays visible and independently editable in review.html, so a human can catch
and correct any triage mistake before the pool is finalized.

Usage:
    python control_search/triage.py
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger("control_search.triage")

_THIS_DIR = Path(__file__).resolve().parent
CANDIDATES_FILE = _THIS_DIR / "control_candidates.json"
TRIAGED_FILE = _THIS_DIR / "control_candidates_triaged.json"
TRIAGED_JS_FILE = _THIS_DIR / "control_candidates_triaged_data.js"

# Same domain-topic vocabulary used to build the "topic:" search queries in
# control_search.py, plus a few close synonyms GitHub maintainers commonly use.
# Safe to extend in place (unlike the search KEYWORDS/EXPANSION_KEYWORDS
# lists) -- this is matching vocabulary applied fresh to whatever candidates
# exist, not a frozen historical record of what was searched for.
TARGET_TOPICS = {
    "iot", "internet-of-things", "iot-platform",
    "embedded", "embedded-systems", "embedded-linux", "embedded-software",
    "robotics", "ros", "ros2", "robot",
    "sensor", "sensors", "sensor-network", "sensor-fusion",
    "environmental-monitoring", "environment-monitoring", "air-quality-monitoring",
    "scada", "plc", "industrial-automation",
    "firmware",
    "cyber-physical-systems", "cyber-physical",
    "home-automation", "smart-home",
    "drone", "uav",
    # Wave 2 (business/community-management SaaS) -- see
    # control_search.EXPANSION_KEYWORDS for why this domain was added.
    "saas", "admin-dashboard", "admin-panel", "crm", "erp",
    "inventory-management", "scheduling", "business-management",
    "subscription-management",
    # Wave 3 (Rails-shaped community/cooperative/membership platforms) --
    # see control_search.RUBY_KEYWORDS for why this domain was added.
    "ruby-on-rails", "rails", "membership-management",
    "association-management", "cooperative", "cooperative-software",
}

STUDENT_BLOCKLIST = [
    "homework", "assignment", "coursework", "class-project", "classproject",
    "tutorial", "my-first", "myfirst", "test-repo", "testrepo", "learning-",
    "cs101", "cs50", "school-project", "university-project", "capstone-project",
    "final-project", "hw1", "hw2", "hw3",
]


def _is_student_project(candidate: dict) -> bool:
    """Return True if candidate's name/description/topics match a student/toy-project blocklist term."""
    haystack = " ".join([
        str(candidate.get("name") or ""),
        str(candidate.get("description") or ""),
        " ".join(candidate.get("topics") or []),
    ]).lower()
    return any(term in haystack for term in STUDENT_BLOCKLIST)


def _topic_confirmed(candidate: dict) -> bool:
    """Return True if any of candidate's GitHub topics is in TARGET_TOPICS."""
    topics = {str(t).strip().lower() for t in (candidate.get("topics") or [])}
    return bool(topics & TARGET_TOPICS)


def triage_candidate(candidate: dict) -> dict:
    """Suggest an accept/review decision for one candidate, based on the
    student-project blocklist and target-topic confirmation checks."""
    blocked = _is_student_project(candidate)
    confirmed = _topic_confirmed(candidate)
    if blocked:
        decision, confidence = "review", "low"
        reason = "matched student/toy-project blocklist term"
    elif confirmed:
        decision, confidence = "accept", "high"
        reason = "GitHub topics confirm target domain"
    else:
        decision, confidence = "review", "low"
        reason = "no confirming topic; only matched via free-text search"
    return {
        **candidate,
        "suggested_decision": decision,
        "confidence": confidence,
        "suggestion_reason": reason,
    }


def main(
    *,
    candidates_file: Path = CANDIDATES_FILE,
    triaged_file: Path = TRIAGED_FILE,
    triaged_js_file: Path = TRIAGED_JS_FILE,
    js_global: str = "TRIAGED",
) -> Path:
    """Auto-triage *candidates_file*, writing *triaged_file* + JS sidecar.

    Defaults triage the original wave (backward compatible); the expansion
    prep script calls this a second time pointed at the expansion wave's
    files, which are separate from and never overwrite the original wave's.
    """
    if not candidates_file.exists():
        raise FileNotFoundError(f"{candidates_file} not found — run control_search.py first.")

    payload = json.loads(candidates_file.read_text(encoding="utf-8"))
    candidates = payload.get("merged", [])

    triaged = [triage_candidate(c) for c in candidates]
    n_accept = sum(1 for c in triaged if c["suggested_decision"] == "accept")
    logger.info("[triage] %d/%d candidates suggested-accept (topic-confirmed)", n_accept, len(triaged))

    # Sort so low-confidence (needs-review) rows surface first for human attention.
    triaged.sort(key=lambda c: (c["confidence"] != "low", c.get("name", "")))

    output = {
        "generated_at": payload.get("meta", {}).get("generated_at", ""),
        "wave": payload.get("meta", {}).get("wave", "original"),
        "total": len(triaged),
        "suggested_accept": n_accept,
        "suggested_review": len(triaged) - n_accept,
        "candidates": triaged,
    }

    triaged_file.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    triaged_js_file.write_text(
        f"const {js_global} = " + json.dumps(output, ensure_ascii=False) + ";\n",
        encoding="utf-8",
    )
    logger.info("[triage] Wrote %s and %s", triaged_file.name, triaged_js_file.name)
    return triaged_file


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(message)s")
    main()
