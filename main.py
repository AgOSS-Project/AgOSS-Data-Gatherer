"""AgOSS top-level entry point.

Run the full pipeline, start Docker services, and open the dashboard:

    python main.py

Skip stages selectively:

    python main.py --skip-scorecard --skip-augur   # only dependency analysis
    python main.py --skip-pipeline                 # just start services + open dashboard
    python main.py --skip-docker --no-browser      # pipeline only, no services
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from pipeline import config
from pipeline.logger_setup import setup_logging

PROJECT_ROOT = Path(__file__).resolve().parent
_AUGUR_DIR = PROJECT_ROOT / "tools" / "augur"


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Run the AgOSS pipeline, start Docker services, and open the dashboard.\n"
            "By default all three stages run in sequence."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Pipeline stage ──────────────────────────────────────────────────────
    pl = p.add_argument_group("Pipeline")
    pl.add_argument(
        "--skip-pipeline", action="store_true",
        help="Skip data collection entirely and use existing outputs.",
    )
    pl.add_argument(
        "--regenerate", action="store_true",
        help="Skip all data collection and re-run stats + saturation + dashboard only.",
    )
    pl.add_argument(
        "--force", "--force-refresh", action="store_true",
        help="Re-collect data even if cached results exist.",
    )
    pl.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug-level console output.",
    )
    pl.add_argument(
        "--skip-scorecard", action="store_true",
        help="Skip Scorecard collection (load from cache).",
    )
    pl.add_argument(
        "--skip-augur", action="store_true",
        help="Skip Augur collection (load from cache).",
    )
    pl.add_argument(
        "--skip-dependencies", action="store_true",
        help="Skip dependency vulnerability analysis.",
    )
    pl.add_argument(
        "--skip-kev", action="store_true",
        help="Skip KEV (Known Exploited Vulnerabilities) analysis.",
    )
    pl.add_argument(
        "--input", type=str, default=None,
        help="Path to input file (CSV or legacy text; default: inputs\\Open Source Agricultural Software(Input).csv).",
    )

    # ── Augur orchestration ─────────────────────────────────────────────────
    ag = p.add_argument_group("Augur orchestration")
    ag.add_argument("--wait-for-augur", action="store_true",
                    help="Poll Augur until repos have data.")
    ag.add_argument("--augur-wait-mode", type=str, default=None,
                    choices=["none", "minimal", "standard", "full"],
                    help="Readiness level to wait for (default: from AUGUR_WAIT_MODE env).")
    ag.add_argument("--augur-timeout", type=int, default=None,
                    help="Max seconds to wait for Augur data (default: 600).")

    # ── Services + dashboard ────────────────────────────────────────────────
    svc = p.add_argument_group("Services & dashboard")
    svc.add_argument(
        "--skip-docker", action="store_true",
        help="Skip starting Docker services.",
    )
    svc.add_argument(
        "--no-browser", action="store_true",
        help="Do not open the dashboard in the browser.",
    )

    return p.parse_args()


# ---------------------------------------------------------------------------
# Stage 1 — pipeline
# ---------------------------------------------------------------------------

def run_pipeline(args: argparse.Namespace, logger) -> bool:
    """Run the data-collection pipeline. Returns True on success."""

    t0 = time.monotonic()
    logger.info("=" * 60)
    logger.info("AgOSS Repo Analysis Pipeline — starting")
    logger.info("=" * 60)

    config.FORCE_REFRESH = args.force
    if args.augur_wait_mode:
        config.AUGUR_WAIT_MODE = args.augur_wait_mode
    if args.augur_timeout is not None:
        config.AUGUR_WAIT_TIMEOUT = args.augur_timeout

    # ── Validate environment ──────────────────────────────────────────────
    logger.info("Step 1/8: Validating environment …")
    if not config.SCORECARD_EXE.exists():
        logger.warning("scorecard.exe not found at %s — Scorecard collection will fail.",
                       config.SCORECARD_EXE)
    if not config.GITHUB_AUTH_TOKEN:
        logger.warning("GITHUB_AUTH_TOKEN not set — Scorecard requires it to avoid rate limits.")

    input_path = config.INPUT_FILE
    if args.input:
        input_path = Path(args.input)
    if not input_path.exists():
        logger.error("Input file not found: %s", input_path)
        return False

    # ── Parse input ───────────────────────────────────────────────────────
    logger.info("Step 2/8: Parsing input …")
    from pipeline.input_parser import parse_input
    entries = parse_input(input_path)
    if not entries:
        logger.error("No valid repo entries found in %s — aborting.", input_path)
        return False

    # ── Scorecard ─────────────────────────────────────────────────────────
    from pipeline.models import ScorecardResult
    scorecard_results: dict[str, ScorecardResult] = {}

    if args.skip_scorecard:
        logger.info("Step 3/8: Scorecard collection SKIPPED (--skip-scorecard)")
        from pipeline.scorecard_runner import load_scorecard_batch_from_cache
        scorecard_results = load_scorecard_batch_from_cache(entries)
        sc_ok   = sum(1 for r in scorecard_results.values() if r.status == "success")
        sc_fail = sum(1 for r in scorecard_results.values() if r.status == "failed")
        logger.info("Scorecard cache: %d loaded, %d missing/failed (of %d)",
                    sc_ok, sc_fail, len(entries))
    else:
        logger.info("Step 3/8: Running Scorecard collection for %d repos …", len(entries))
        from pipeline.scorecard_runner import run_scorecard_batch
        scorecard_results = run_scorecard_batch(entries)
        sc_ok      = sum(1 for r in scorecard_results.values() if r.status == "success")
        sc_partial = sum(1 for r in scorecard_results.values() if r.status == "partial_success")
        sc_fail    = sum(1 for r in scorecard_results.values() if r.status == "failed")
        logger.info("Scorecard: %d success, %d partial, %d failed (of %d)",
                    sc_ok, sc_partial, sc_fail, len(entries))

    # ── Augur ─────────────────────────────────────────────────────────────
    from pipeline.models import AugurResult
    augur_results: dict[str, AugurResult] = {}

    if args.skip_augur:
        logger.info("Step 4/8: Augur collection SKIPPED (--skip-augur)")
        from pipeline.augur_runner import load_augur_batch_from_cache
        augur_results = load_augur_batch_from_cache(entries)
        ag_ok   = sum(1 for r in augur_results.values()
                      if r.status in ("ready", "partial", "collecting", "registered"))
        ag_fail = sum(1 for r in augur_results.values()
                      if r.status in ("failed", "not_registered"))
        logger.info("Augur cache: %d loaded, %d missing/failed (of %d)",
                    ag_ok, ag_fail, len(entries))
    else:
        logger.info("Step 4/8: Running Augur collection for %d repos …", len(entries))
        from pipeline.augur_runner import check_augur_health, run_augur_batch, load_augur_batch_from_cache
        if not check_augur_health():
            logger.warning("Augur API unreachable at %s — loading cached results.",
                           config.AUGUR_API_BASE)
            augur_results = load_augur_batch_from_cache(entries)
        else:
            augur_results = run_augur_batch(
                entries,
                do_sync=True,
                do_register=True,
                do_wait=args.wait_for_augur,
                wait_mode=args.augur_wait_mode,
            )
            ag_ok   = sum(1 for r in augur_results.values() if r.status in ("ready", "partial"))
            ag_fail = sum(1 for r in augur_results.values() if r.status in ("failed", "not_registered"))
            logger.info("Augur: %d collected, %d failed (of %d)", ag_ok, ag_fail, len(entries))

    # ── Dependency analysis ───────────────────────────────────────────────
    dependency_report: dict[str, object] = {}

    if args.skip_dependencies:
        logger.info("Step 5/8: Dependency analysis SKIPPED (--skip-dependencies)")
        from pipeline.dependency_runner import write_empty_dependency_report
        dependency_report = write_empty_dependency_report(entries, reason="Skipped by --skip-dependencies")
    else:
        logger.info("Step 5/8: Running dependency vulnerability analysis for %d repos …", len(entries))
        from pipeline.dependency_runner import run_dependency_analysis_batch, write_empty_dependency_report
        try:
            dependency_report = run_dependency_analysis_batch(entries)
        except Exception as exc:
            logger.error("Dependency analysis failed: %s", exc)
            dependency_report = write_empty_dependency_report(
                entries, reason=f"Dependency analysis failed: {exc}")

        dep_totals = dependency_report.get("totals") if isinstance(dependency_report, dict) else {}
        if isinstance(dep_totals, dict):
            logger.info("Dependencies: %d analyzed, %d failed, %d vulnerabilities",
                        dep_totals.get("repos_analyzed", 0),
                        dep_totals.get("repos_failed", 0),
                        dep_totals.get("vulnerabilities_total", 0))

    # ── Merge ─────────────────────────────────────────────────────────────
    logger.info("Step 6/8: Merging results …")
    from pipeline.merger import merge, write_outputs
    records, summary = merge(entries, scorecard_results, augur_results)
    summary.run_start = datetime.now(timezone.utc).isoformat()
    write_outputs(records, summary)

    # ── KEV analysis ──────────────────────────────────────────────────────
    if args.skip_kev:
        logger.info("Step 7/8: KEV analysis SKIPPED (--skip-kev)")
    else:
        logger.info("Step 7/8: Running KEV analysis …")
        try:
            from pipeline import exploit as _exploit
            if not _exploit.main():
                logger.warning("KEV analysis did not complete — dashboard will show empty KEV section.")
        except Exception as exc:
            logger.warning("KEV analysis failed (%s) — dashboard will show empty KEV section.", exc)

    # ── Statistical analysis ──────────────────────────────────────────────
    logger.info("Step 7.5/8: Running statistical analysis …")
    try:
        from pipeline.stats import run_all as run_stats
        run_stats(config.PROCESSED_DIR / "merged_repos.json", config.DEPENDENCY_REPORT_FILE)
    except Exception:
        import traceback as _tb
        logger.warning("Statistical analysis failed — dashboard will show no stats:\n%s",
                       _tb.format_exc())

    # ── Saturation analysis ───────────────────────────────────────────────
    logger.info("Step 7.6/8: Running saturation analysis …")
    try:
        from pipeline.saturation import run_saturation
        run_saturation(config.PROCESSED_DIR / "merged_repos.json", config.DEPENDENCY_REPORT_FILE)
    except Exception as exc:
        logger.warning("Saturation analysis failed (%s) — dashboard will have no saturation data.", exc)

    # ── Dashboard ─────────────────────────────────────────────────────────
    logger.info("Step 8/8: Building dashboard …")
    from pipeline.report.render import build_dashboard
    try:
        dash_path = build_dashboard()
        logger.info("Dashboard ready: %s", dash_path)
    except Exception as exc:
        logger.error("Dashboard generation failed: %s", exc)

    # ── Summary ───────────────────────────────────────────────────────────
    elapsed = time.monotonic() - t0
    summary.run_end = datetime.now(timezone.utc).isoformat()
    write_outputs(records, summary)

    # ── Collection date stamp ─────────────────────────────────────────────
    try:
        (PROJECT_ROOT / "COLLECTION_DATE.txt").write_text(
            datetime.now(timezone.utc).strftime("%Y-%m-%d"), encoding="utf-8"
        )
    except Exception as exc:
        logger.warning("Could not write COLLECTION_DATE.txt: %s", exc)

    logger.info("=" * 60)
    logger.info("Pipeline complete in %.1fs", elapsed)
    logger.info("  Repos analysed     : %d", len(entries))
    logger.info("  Scorecard success  : %d", summary.scorecard_success)
    logger.info("  Scorecard partial  : %d", summary.scorecard_partial)
    logger.info("  Scorecard fail     : %d", summary.scorecard_fail)
    logger.info("  Augur ready        : %d", summary.augur_success)
    logger.info("  Augur registered   : %d", summary.augur_registered)
    logger.info("  Augur timed-out    : %d", summary.augur_timed_out)
    logger.info("  Augur fail         : %d", summary.augur_fail)
    dep_totals = dependency_report.get("totals") if isinstance(dependency_report, dict) else {}
    if isinstance(dep_totals, dict):
        logger.info("  Dependency analyzed: %d", dep_totals.get("repos_analyzed", 0))
        logger.info("  Dependency failed  : %d", dep_totals.get("repos_failed", 0))
        logger.info("  Dependency vulns   : %d", dep_totals.get("vulnerabilities_total", 0))
    logger.info("  Outputs            : %s", config.OUTPUTS_DIR)
    logger.info("=" * 60)
    return True


# ---------------------------------------------------------------------------
# Stage 2 — Docker services
# ---------------------------------------------------------------------------

def start_docker(logger) -> bool:
    """Start the Augur/Aveloxis Docker stack. Returns True on success."""
    if not _AUGUR_DIR.exists():
        logger.error("Docker compose directory not found: %s", _AUGUR_DIR)
        return False

    logger.info("Starting Docker services (%s) …", _AUGUR_DIR)
    result = subprocess.run(
        ["docker", "compose", "up", "-d"],
        cwd=_AUGUR_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.error("docker compose up failed (exit %d):\n%s",
                     result.returncode, result.stderr.strip())
        return False

    logger.info("Docker services started.")
    return True


# ---------------------------------------------------------------------------
# Stage 3 — open dashboard
# ---------------------------------------------------------------------------

def open_dashboard(logger) -> None:
    dash_path = config.DASHBOARD_DIR / "index.html"
    if not dash_path.exists():
        logger.error("Dashboard not found at %s — skipping browser open.", dash_path)
        return
    url = dash_path.as_uri()
    logger.info("Opening dashboard in browser: %s", url)
    webbrowser.open(url)


def stop_docker(logger) -> None:
    """Shut down the Docker stack."""
    logger.info("Stopping Docker services …")
    result = subprocess.run(
        ["docker", "compose", "down"],
        cwd=_AUGUR_DIR,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        logger.warning("docker compose down exited %d:\n%s",
                       result.returncode, result.stderr.strip())
    else:
        logger.info("Docker services stopped.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    logger = setup_logging(verbose=args.verbose)

    # ── Stage 1: Docker (must be up before Augur collection) ────────────
    if args.skip_docker:
        logger.info("Docker services skipped (--skip-docker).")
    else:
        if not start_docker(logger):
            logger.warning("Docker services could not be started — Augur will fall back to cache.")

    # ── Stage 2: pipeline ────────────────────────────────────────────────
    if args.regenerate:
        logger.info("--regenerate: skipping data collection; re-running stats + saturation + dashboard.")
        merged_path = config.PROCESSED_DIR / "merged_repos.json"
        if not merged_path.exists():
            logger.error("No merged_repos.json found — run the full pipeline first.")
            sys.exit(1)
        try:
            from pipeline.stats import run_all as run_stats
            run_stats(merged_path, config.DEPENDENCY_REPORT_FILE)
        except Exception as exc:
            logger.warning("Statistical analysis failed (%s)", exc)
        try:
            from pipeline.saturation import run_saturation
            run_saturation(merged_path, config.DEPENDENCY_REPORT_FILE)
        except Exception as exc:
            logger.warning("Saturation analysis failed (%s)", exc)
        from pipeline.report.render import build_dashboard
        try:
            dash_path = build_dashboard()
            logger.info("Dashboard ready: %s", dash_path)
        except Exception as exc:
            logger.error("Dashboard generation failed: %s", exc)
            sys.exit(1)
    elif args.skip_pipeline:
        logger.info("Pipeline skipped (--skip-pipeline).")
    else:
        if not run_pipeline(args, logger):
            sys.exit(1)

    # ── Stage 3: dashboard ───────────────────────────────────────────────
    if args.no_browser:
        logger.info("Dashboard: %s", config.DASHBOARD_DIR / "index.html")
    else:
        open_dashboard(logger)
        if not args.skip_docker:
            stop_docker(logger)


if __name__ == "__main__":
    main()
