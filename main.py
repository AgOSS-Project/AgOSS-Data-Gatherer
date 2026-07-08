"""AgOSS top-level entry point.

Run the full pipeline and open the dashboard:

    python main.py

Skip stages selectively:

    python main.py --skip-scorecard                # only dependency analysis
    python main.py --skip-pipeline                  # just open the dashboard
    python main.py --no-browser                     # pipeline only, don't open a browser
"""

from __future__ import annotations

import argparse
import sys
import time
import webbrowser
from datetime import datetime, timezone
from pathlib import Path

from pipeline import config
from pipeline.logger_setup import setup_logging

PROJECT_ROOT = Path(__file__).resolve().parent


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description=(
            "Run the AgOSS pipeline and open the dashboard.\n"
            "By default both stages run in sequence."
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
        "--skip-dependencies", action="store_true",
        help="Skip dependency vulnerability analysis.",
    )
    pl.add_argument(
        "--skip-kev", action="store_true",
        help="Skip KEV (Known Exploited Vulnerabilities) analysis.",
    )
    pl.add_argument(
        "--skip-matched-comparison", action="store_true",
        help="Skip the matched-comparison analysis (control-search/) after the main pipeline.",
    )
    pl.add_argument(
        "--input", type=str, default=None,
        help="Path to input file (CSV or legacy text; default: inputs\\Open Source Agricultural Software(Input).csv).",
    )

    # ── Dashboard ────────────────────────────────────────────────────────────
    svc = p.add_argument_group("Dashboard")
    svc.add_argument(
        "--no-browser", action="store_true",
        help="Do not open the dashboard in the browser.",
    )

    return p.parse_args()


def _run_matched_comparison(logger, *, force: bool = False) -> None:
    """Run control-search/run_matched_comparison.py's run().

    control-search/ has a hyphen and isn't a valid Python package name, so it
    is loaded via sys.path insertion rather than a normal dotted import.

    force must be passed through explicitly: run()'s own force parameter
    defaults to False and unconditionally overwrites config.FORCE_REFRESH
    (see run_matched_comparison.py), so calling run() with no arguments here
    would silently reset FORCE_REFRESH to False for the covariates/dependency
    fetches this stage does, even after main.py --force set it True earlier
    in the same run.
    """
    control_search_dir = PROJECT_ROOT / "control-search"
    if str(control_search_dir) not in sys.path:
        sys.path.insert(0, str(control_search_dir))
    import run_matched_comparison as _matched
    _matched.run(force=force)


def _clear_caches(logger) -> None:
    """Delete every per-repo raw cache file so --force is a hard guarantee,
    not just a hint that individual call sites are trusted to honor.

    FORCE_REFRESH-gated cache checks are scattered across scorecard_runner,
    dependency_runner, and control-search/covariates.py; a mistake in any one
    of them can leave stale data readable indefinitely (this happened for
    real: 13 covariate cache entries kept returning "Jupyter Notebook" as a
    repo's language long after the reclassification fix landed, because nothing
    ever invalidated the cache file itself). Deleting the files outright removes
    that whole class of bug for a --force run, regardless of whether every
    caller's FORCE_REFRESH check is correct.
    """
    cache_dirs = [
        config.RAW_SCORECARD_DIR,
        config.RAW_DEPENDENCY_DIR,
        PROJECT_ROOT / "control-search" / "raw" / "covariates",
        PROJECT_ROOT / "control-search" / "raw" / "dependency",
    ]
    n_files = 0
    for d in cache_dirs:
        if not d.exists():
            continue
        for f in d.glob("*.json"):
            f.unlink()
            n_files += 1
    logger.info("--force: cleared %d cached per-repo file(s)", n_files)


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
    if args.force:
        _clear_caches(logger)

    # ── Validate environment ──────────────────────────────────────────────
    logger.info("Step 1/7: Validating environment …")
    if not config.SCORECARD_EXE.exists():
        logger.warning("scorecard.exe not found at %s — Scorecard collection will fail.",
                       config.SCORECARD_EXE)
    if not config.GITHUB_AUTH_TOKEN:
        logger.warning("GITHUB_AUTH_TOKEN not set — Scorecard and GitHub metrics collection "
                       "require it to avoid rate limits.")

    input_path = config.INPUT_FILE
    if args.input:
        input_path = Path(args.input)
    if not input_path.exists():
        logger.error("Input file not found: %s", input_path)
        return False

    # ── Parse input ───────────────────────────────────────────────────────
    logger.info("Step 2/7: Parsing input …")
    from pipeline.input_parser import parse_input
    entries = parse_input(input_path)
    if not entries:
        logger.error("No valid repo entries found in %s — aborting.", input_path)
        return False

    # ── Scorecard ─────────────────────────────────────────────────────────
    from pipeline.models import ScorecardResult
    scorecard_results: dict[str, ScorecardResult] = {}

    if args.skip_scorecard:
        logger.info("Step 3/7: Scorecard collection SKIPPED (--skip-scorecard)")
        from pipeline.scorecard_runner import load_scorecard_batch_from_cache
        scorecard_results = load_scorecard_batch_from_cache(entries)
        sc_ok   = sum(1 for r in scorecard_results.values() if r.status == "success")
        sc_fail = sum(1 for r in scorecard_results.values() if r.status == "failed")
        logger.info("Scorecard cache: %d loaded, %d missing/failed (of %d)",
                    sc_ok, sc_fail, len(entries))
    else:
        logger.info("Step 3/7: Running Scorecard collection for %d repos …", len(entries))
        from pipeline.scorecard_runner import run_scorecard_batch
        scorecard_results = run_scorecard_batch(entries)
        sc_ok      = sum(1 for r in scorecard_results.values() if r.status == "success")
        sc_partial = sum(1 for r in scorecard_results.values() if r.status == "partial_success")
        sc_fail    = sum(1 for r in scorecard_results.values() if r.status == "failed")
        logger.info("Scorecard: %d success, %d partial, %d failed (of %d)",
                    sc_ok, sc_partial, sc_fail, len(entries))

    # ── Dependency analysis ───────────────────────────────────────────────
    dependency_report: dict[str, object] = {}

    if args.skip_dependencies:
        logger.info("Step 4/7: Dependency analysis SKIPPED (--skip-dependencies)")
        from pipeline.dependency_runner import write_empty_dependency_report
        dependency_report = write_empty_dependency_report(entries, reason="Skipped by --skip-dependencies")
    else:
        logger.info("Step 4/7: Running dependency vulnerability analysis for %d repos …", len(entries))
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

    # ── Merge (includes GitHub metrics collection) ──────────────────────────
    logger.info("Step 5/7: Collecting GitHub metrics and merging results …")
    from pipeline.merger import merge, write_outputs
    records, summary = merge(entries, scorecard_results)
    summary.run_start = datetime.now(timezone.utc).isoformat()
    write_outputs(records, summary)

    # ── KEV analysis ──────────────────────────────────────────────────────
    if args.skip_kev:
        logger.info("Step 6/7: KEV analysis SKIPPED (--skip-kev)")
    else:
        logger.info("Step 6/7: Running KEV analysis …")
        try:
            from pipeline import exploit as _exploit
            if not _exploit.main():
                logger.warning("KEV analysis did not complete — dashboard will show empty KEV section.")
        except Exception as exc:
            logger.warning("KEV analysis failed (%s) — dashboard will show empty KEV section.", exc)

    # ── Statistical analysis ──────────────────────────────────────────────
    logger.info("Step 6.5/7: Running statistical analysis …")
    try:
        from pipeline.stats import run_all as run_stats
        run_stats(config.PROCESSED_DIR / "merged_repos.json", config.DEPENDENCY_REPORT_FILE)
    except Exception:
        import traceback as _tb
        logger.warning("Statistical analysis failed — dashboard will show no stats:\n%s",
                       _tb.format_exc())

    # ── Saturation analysis ───────────────────────────────────────────────
    logger.info("Step 6.6/7: Running saturation analysis …")
    try:
        from pipeline.saturation import run_saturation
        run_saturation(config.PROCESSED_DIR / "merged_repos.json", config.DEPENDENCY_REPORT_FILE)
    except Exception as exc:
        logger.warning("Saturation analysis failed (%s) — dashboard will have no saturation data.", exc)

    # ── Matched-comparison analysis (control-search/) ──────────────────────
    if args.skip_matched_comparison:
        logger.info("Step 6.7/7: Matched-comparison analysis SKIPPED (--skip-matched-comparison)")
    else:
        logger.info("Step 6.7/7: Running matched-comparison analysis …")
        try:
            _run_matched_comparison(logger, force=args.force)
        except Exception:
            import traceback as _tb
            logger.warning(
                "Matched-comparison analysis failed — dashboard will show no matched-comparison "
                "data:\n%s", _tb.format_exc(),
            )

    # ── Dashboard ─────────────────────────────────────────────────────────
    logger.info("Step 7/7: Building dashboard …")
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
    logger.info("  Repos analysed        : %d", len(entries))
    logger.info("  Scorecard success     : %d", summary.scorecard_success)
    logger.info("  Scorecard partial     : %d", summary.scorecard_partial)
    logger.info("  Scorecard fail        : %d", summary.scorecard_fail)
    logger.info("  GitHub metrics success: %d", summary.github_metrics_success)
    logger.info("  GitHub metrics fail   : %d", summary.github_metrics_fail)
    dep_totals = dependency_report.get("totals") if isinstance(dependency_report, dict) else {}
    if isinstance(dep_totals, dict):
        logger.info("  Dependency analyzed: %d", dep_totals.get("repos_analyzed", 0))
        logger.info("  Dependency failed  : %d", dep_totals.get("repos_failed", 0))
        logger.info("  Dependency vulns   : %d", dep_totals.get("vulnerabilities_total", 0))
    logger.info("  Outputs            : %s", config.OUTPUTS_DIR)
    logger.info("=" * 60)
    return True


# ---------------------------------------------------------------------------
# Stage 2 — open dashboard
# ---------------------------------------------------------------------------

def open_dashboard(logger) -> None:
    dash_path = config.DASHBOARD_DIR / "index.html"
    if not dash_path.exists():
        logger.error("Dashboard not found at %s — skipping browser open.", dash_path)
        return
    url = dash_path.as_uri()
    logger.info("Opening dashboard in browser: %s", url)
    webbrowser.open(url)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    args = parse_args()
    logger = setup_logging(verbose=args.verbose)

    # ── Stage 1: pipeline ────────────────────────────────────────────────
    if args.regenerate:
        logger.info("--regenerate: skipping data collection; re-running stats + saturation + dashboard.")
        config.FORCE_REFRESH = args.force
        if args.force:
            _clear_caches(logger)
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
        if args.skip_matched_comparison:
            logger.info("Matched-comparison analysis skipped (--skip-matched-comparison).")
        else:
            try:
                _run_matched_comparison(logger, force=args.force)
            except Exception as exc:
                logger.warning("Matched-comparison analysis failed (%s)", exc)
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

    # ── Stage 2: dashboard ───────────────────────────────────────────────
    if args.no_browser:
        logger.info("Dashboard: %s", config.DASHBOARD_DIR / "index.html")
    else:
        open_dashboard(logger)


if __name__ == "__main__":
    main()
