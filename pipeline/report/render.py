"""Render the static HTML dashboard from processed data."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from pipeline import config

logger = logging.getLogger("pipeline.report")

_TEMPLATE_DIR = Path(__file__).resolve().parent


def build_dashboard() -> Path:
    """Read processed data and emit a self-contained dashboard HTML.

    Returns the path to the generated index.html.
    """
    config.DASHBOARD_DIR.mkdir(parents=True, exist_ok=True)

    # Load processed data
    merged_path = config.PROCESSED_DIR / "merged_repos.json"
    summary_path = config.PROCESSED_DIR / "summary.json"

    if not merged_path.exists():
        raise FileNotFoundError(f"Processed data not found: {merged_path}")
    if not summary_path.exists():
        raise FileNotFoundError(f"Summary not found: {summary_path}")

    merged_data = json.loads(merged_path.read_text(encoding="utf-8"))
    summary_data = json.loads(summary_path.read_text(encoding="utf-8"))

    # Read the HTML template
    template_html = (_TEMPLATE_DIR / "template.html").read_text(encoding="utf-8")
    styles_css = (_TEMPLATE_DIR / "styles.css").read_text(encoding="utf-8")

    # Inject data and styles into template
    html = template_html.replace("/* @@STYLES@@ */", styles_css)
    html = html.replace("/* @@REPO_DATA@@ */ []", json.dumps(merged_data, default=str))
    html = html.replace("/* @@SUMMARY_DATA@@ */ {}", json.dumps(summary_data, default=str))

    out_path = config.DASHBOARD_DIR / "index.html"
    out_path.write_text(html, encoding="utf-8")
    logger.info("Dashboard written to %s", out_path)
    return out_path
