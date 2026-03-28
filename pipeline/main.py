"""AgOSS Repository Analysis Pipeline — CLI entry point.

Usage:
    python -m pipeline.main [--force] [--verbose] [--skip-scorecard] [--skip-augur]
                            [--skip-dependencies]
                            [--sync-augur] [--register-augur] [--wait-for-augur]
                            [--augur-wait-mode MODE] [--augur-timeout N]
"""

from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone

from pipeline import config
from pipeline.logger_setup import setup_logging


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Run the AgOSS repo analysis pipeline.",
    )
    p.add_argument(
        "--force", "--force-refresh", action="store_true",
        help="Re-collect data even if cached results exist.",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable debug-level console output.",
    )
    p.add_argument(
        "--skip-scorecard", action="store_true",
        help="Skip Scorecard collection (use cached or empty).",
    )
    p.add_argument(
        "--skip-augur", action="store_true",
        help="Skip Augur collection (use cached or empty).",
    )
    p.add_argument(
        "--skip-dependencies", action="store_true",
        help="Skip dependency vulnerability analysis (write empty dependency artifact).",
    )
    p.add_argument(
        "--input", type=str, default=None,
        help="Path to input file (CSV or legacy text; default: pipeline/input.txt).",
    )

    # Augur orchestration flags
    augur_grp = p.add_argument_group("Augur orchestration")
    augur_grp.add_argument(
        "--sync-augur", action="store_true",
        help="Compare input repos vs Augur-registered repos and log the diff.",
    )
    augur_grp.add_argument(
        "--register-augur", action="store_true",
        help="Register missing repos in Augur before collection.",
    )
    augur_grp.add_argument(
        "--wait-for-augur", action="store_true",
        help="Poll Augur until repos have data (respects --augur-wait-mode).",
    )
    augur_grp.add_argument(
        "--augur-wait-mode", type=str, default=None,
        choices=["none", "minimal", "standard", "full"],
        help="Readiness level to wait for (default: from AUGUR_WAIT_MODE env).",
    )
    augur_grp.add_argument(
        "--augur-timeout", type=int, default=None,
        help="Max seconds to wait for Augur data (default: 600).",
    )

    return p.parse_args()


def main() -> None:
    args = parse_args()
    logger = setup_logging(verbose=args.verbose)

    t0 = time.monotonic()
    logger.info("=" * 60)
    logger.info("AgOSS Repo Analysis Pipeline — starting")
    logger.info("=" * 60)

    # ── Apply CLI flags ──
    config.FORCE_REFRESH = args.force
    if args.augur_wait_mode:
        config.AUGUR_WAIT_MODE = args.augur_wait_mode
    if args.augur_timeout is not None:
        config.AUGUR_WAIT_TIMEOUT = args.augur_timeout

    # ── 1. Validate environment ──
    logger.info("Step 1/7: Validating environment …")

    if not config.SCORECARD_EXE.exists():
        logger.warning("scorecard.exe not found at %s — Scorecard collection will fail.", config.SCORECARD_EXE)
    if not config.GITHUB_AUTH_TOKEN:
        logger.warning("GITHUB_AUTH_TOKEN not set — Scorecard requires it to avoid rate limits.")

    input_path = config.INPUT_FILE
    if args.input:
        from pathlib import Path
        input_path = Path(args.input)
    if not input_path.exists():
        logger.error("Input file not found: %s", input_path)
        sys.exit(1)

    # ── 2. Parse input ──
    logger.info("Step 2/7: Parsing input …")
    from pipeline.input_parser import parse_input
    entries = parse_input(input_path)

    if not entries:
        logger.error("No valid repo entries found in %s — aborting.", input_path)
        sys.exit(1)

    # ── 3. Scorecard collection ──
    from pipeline.models import ScorecardResult
    scorecard_results: dict[str, ScorecardResult] = {}

    if args.skip_scorecard:
        logger.info("Step 3/7: Scorecard collection SKIPPED (--skip-scorecard)")
        from pipeline.scorecard_runner import load_scorecard_batch_from_cache
        scorecard_results = load_scorecard_batch_from_cache(entries)
        sc_ok = sum(1 for r in scorecard_results.values() if r.status == "success")
        sc_fail = sum(1 for r in scorecard_results.values() if r.status == "failed")
        logger.info("Scorecard cache: %d loaded, %d missing/failed (of %d)",
                    sc_ok, sc_fail, len(entries))
    else:
        logger.info("Step 3/7: Running Scorecard collection for %d repos …", len(entries))
        from pipeline.scorecard_runner import run_scorecard_batch
        scorecard_results = run_scorecard_batch(entries)

        sc_ok = sum(1 for r in scorecard_results.values() if r.status == "success")
        sc_partial = sum(1 for r in scorecard_results.values() if r.status == "partial_success")
        sc_fail = sum(1 for r in scorecard_results.values() if r.status == "failed")
        logger.info("Scorecard: %d success, %d partial, %d failed (of %d)",
                     sc_ok, sc_partial, sc_fail, len(entries))

    # ── 4. Augur collection ──
    from pipeline.models import AugurResult
    augur_results: dict[str, AugurResult] = {}

    if args.skip_augur:
        logger.info("Step 4/7: Augur collection SKIPPED (--skip-augur)")
        from pipeline.augur_runner import load_augur_batch_from_cache
        augur_results = load_augur_batch_from_cache(entries)
        ag_ok = sum(1 for r in augur_results.values() if r.status in ("ready", "partial", "collecting", "registered"))
        ag_fail = sum(1 for r in augur_results.values() if r.status in ("failed", "not_registered"))
        logger.info("Augur cache: %d loaded, %d missing/failed (of %d)",
                    ag_ok, ag_fail, len(entries))
    else:
        logger.info("Step 4/7: Running Augur collection for %d repos …", len(entries))
        from pipeline.augur_runner import check_augur_health, run_augur_batch, load_augur_batch_from_cache

        if not check_augur_health():
            logger.error("Augur API is not reachable at %s — loading cached Augur results.", config.AUGUR_API_BASE)
            augur_results = load_augur_batch_from_cache(entries)
        else:
            augur_results = run_augur_batch(
                entries,
                do_sync=args.sync_augur or args.register_augur or args.wait_for_augur,
                do_register=args.register_augur,
                do_wait=args.wait_for_augur,
                wait_mode=args.augur_wait_mode,
            )
            ag_ok = sum(1 for r in augur_results.values() if r.status in ("ready", "partial"))
            ag_fail = sum(1 for r in augur_results.values() if r.status in ("failed", "not_registered"))
            logger.info("Augur: %d collected, %d failed (of %d)", ag_ok, ag_fail, len(entries))

    # ── 5. Dependency vulnerability analysis ──
    dependency_report: dict[str, object] = {}
    if args.skip_dependencies:
        logger.info("Step 5/7: Dependency analysis SKIPPED (--skip-dependencies)")
        from pipeline.dependency_runner import write_empty_dependency_report
        dependency_report = write_empty_dependency_report(entries, reason="Skipped by --skip-dependencies")
    else:
        logger.info("Step 5/7: Running dependency vulnerability analysis for %d repos …", len(entries))
        from pipeline.dependency_runner import run_dependency_analysis_batch, write_empty_dependency_report

        try:
            dependency_report = run_dependency_analysis_batch(entries)
        except Exception as exc:
            logger.error("Dependency analysis failed: %s", exc)
            dependency_report = write_empty_dependency_report(
                entries,
                reason=f"Dependency analysis failed: {exc}",
            )

        dep_totals = dependency_report.get("totals") if isinstance(dependency_report, dict) else {}
        if isinstance(dep_totals, dict):
            logger.info(
                "Dependencies: %d analyzed, %d failed, %d vulnerabilities",
                dep_totals.get("repos_analyzed", 0),
                dep_totals.get("repos_failed", 0),
                dep_totals.get("vulnerabilities_total", 0),
            )

    # ── 6. Merge results ──
    logger.info("Step 6/7: Merging results …")
    from pipeline.merger import merge, write_outputs
    records, summary = merge(entries, scorecard_results, augur_results)
    summary.run_start = datetime.now(timezone.utc).isoformat()
    write_outputs(records, summary)

    # ── 7. Build dashboard ──
    logger.info("Step 7/7: Building dashboard …")
    from pipeline.report.render import build_dashboard
    try:
        dash_path = build_dashboard()
        logger.info("Dashboard ready: %s", dash_path)
    except Exception as exc:
        logger.error("Dashboard generation failed: %s", exc)

    # ── Done ──
    elapsed = time.monotonic() - t0
    summary.run_end = datetime.now(timezone.utc).isoformat()
    write_outputs(records, summary)

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
    logger.info("  Dashboard          : %s", config.DASHBOARD_DIR / "index.html")
    logger.info("=" * 60)


if __name__ == "__main__":
    main()
