"""Render the static HTML dashboard from processed data."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pipeline import config

logger = logging.getLogger("pipeline.report")

_TEMPLATE_DIR = Path(__file__).resolve().parent


def _empty_dependency_payload() -> dict:
    return {
        "generated_at": "",
        "status": "missing",
        "notes": ["Dependency artifact not found."],
        "totals": {
            "repos_total": 0,
            "repos_analyzed": 0,
            "repos_failed": 0,
            "repos_with_vulnerabilities": 0,
            "packages_total": 0,
            "packages_queryable": 0,
            "packages_unqueryable": 0,
            "vulnerabilities_total": 0,
            "unique_vulnerability_ids": 0,
            "severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "unknown": 0,
            },
        },
        "vulnerabilities": [],
        "repos": [],
    }


def _empty_kev_payload() -> dict:
    """Empty KEV analysis payload when file is not available."""
    return {
        "generated_at": "",
        "summary": {
            "total_vulnerabilities_analyzed": 0,
            "exploitable_vulnerabilities": 0,
            "exploitability_rate_percent": 0,
            "exploitable_by_severity": {},
            "top_priority_vulnerabilities": [],
        },
        "notes": ["KEV analysis not available."],
    }


def build_dashboard() -> Path:
    """Read processed data and emit a self-contained dashboard HTML.

    Returns the path to the generated index.html.
    """
    config.DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)

    # Load processed data
    merged_path = config.PROCESSED_DIR / "merged_repos.json"
    summary_path = config.PROCESSED_DIR / "summary.json"
    dependency_path = config.DEPENDENCY_REPORT_FILE
    kev_summary_path = config.PROCESSED_DIR / "kev_summary.json"

    if not merged_path.exists():
        raise FileNotFoundError(f"Processed data not found: {merged_path}")
    if not summary_path.exists():
        raise FileNotFoundError(f"Summary not found: {summary_path}")

    merged_data = json.loads(merged_path.read_text(encoding="utf-8"))
    summary_data = json.loads(summary_path.read_text(encoding="utf-8"))
    if dependency_path.exists():
        try:
            dependency_data = json.loads(dependency_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("Dependency artifact unreadable (%s): %s", dependency_path.name, exc)
            dependency_data = _empty_dependency_payload()
            dependency_data["status"] = "invalid"
            dependency_data["notes"] = [f"Dependency artifact unreadable: {exc}"]
    else:
        dependency_data = _empty_dependency_payload()

    # Load KEV summary data
    if kev_summary_path.exists():
        try:
            kev_data = json.loads(kev_summary_path.read_text(encoding="utf-8"))
        except Exception as exc:
            logger.warning("KEV summary artifact unreadable (%s): %s", kev_summary_path.name, exc)
            kev_data = _empty_kev_payload()
    else:
        kev_data = _empty_kev_payload()

    # Read the HTML template
    template_html = (_TEMPLATE_DIR / "template.html").read_text(encoding="utf-8")
    styles_css = (_TEMPLATE_DIR / "styles.css").read_text(encoding="utf-8")

    # Inject data and styles into template
    html = template_html.replace("/* @@STYLES@@ */", styles_css)
    html = html.replace("/* @@REPO_DATA@@ */ []", json.dumps(merged_data, default=str))
    html = html.replace("/* @@SUMMARY_DATA@@ */ {}", json.dumps(summary_data, default=str))
    html = html.replace("/* @@DEPENDENCY_DATA@@ */ {}", json.dumps(dependency_data, default=str))
    html = html.replace("/* @@KEV_DATA@@ */ {}", json.dumps(kev_data, default=str))

    out_path = config.DASHBOARD_DIR / "index.html"
    out_path.write_text(html, encoding="utf-8")
    logger.info("Dashboard written to %s", out_path)
    return out_path
