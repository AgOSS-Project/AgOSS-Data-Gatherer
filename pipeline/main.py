"""
main.py – Single entrypoint for the repo-risk pipeline.

Usage:
    python -m pipeline.main --input input.txt --output output

    or

    python pipeline/main.py --input input.txt --output output

Environment variables (read from .env via python-dotenv):
    GITHUB_TOKEN          – GitHub PAT (recommended; needed for SBOM export
                            and higher rate limits)
    SCORECARD_API_BASE    – Override the OpenSSF Scorecard API base URL
                            (optional)

Config knobs are in the CONFIG dict below.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import logging
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List

# Load .env *before* any imports that read env vars
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # python-dotenv not installed; rely on real env vars

from .models import RepoTarget, RepoResult, DepResult, parse_input_line
from .github_client import GitHubClient, extract_purls_from_spdx
from .osv_client import osv_querybatch, build_dep_results
from .scorecard_client import fetch_scorecard, summarize_scorecard
from .aggregate import build_dep_aggregate, build_vuln_aggregate, build_report_data
from .report.render import render_report

# -------------------------------------------------------------------
# Configuration
# -------------------------------------------------------------------

CONFIG: Dict[str, Any] = {
    "max_workers": 4,
    "http_timeout": 30,
    "osv_chunk_size": 500,
    "max_osv_items_html": 200,
    "top_deps_n": 15,
    "top_vuln_deps_n": 15,
    "top_vulns_n": 20,
}

# -------------------------------------------------------------------
# Logging
# -------------------------------------------------------------------

logger = logging.getLogger("pipeline")


def _setup_logging(output_dir: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")

    sh = logging.StreamHandler(sys.stdout)
    sh.setLevel(logging.INFO)
    sh.setFormatter(fmt)
    logger.addHandler(sh)

    fh = logging.FileHandler(os.path.join(output_dir, "errors.log"), mode="w", encoding="utf-8")
    fh.setLevel(logging.WARNING)
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    logger.setLevel(logging.DEBUG)


# -------------------------------------------------------------------
# Per-repo scanning
# -------------------------------------------------------------------

def scan_one(target: RepoTarget, gh: GitHubClient) -> RepoResult:
    """Run all checks for a single repo and return a :class:`RepoResult`."""
    r = RepoResult(
        owner=target.owner,
        repo=target.repo,
        slug=target.slug,
        repo_type=target.repo_type,
        original_input=target.original,
    )

    if not target.owner or not target.repo:
        r.status = "failed"
        r.errors.append("parse_failed: could not extract owner/repo")
        return r

    # 1) GitHub metadata
    meta, meta_errs = gh.repo_metadata(target.owner, target.repo)
    r.errors.extend(meta_errs)
    if meta is None:
        r.status = "failed"
        return r

    r.gh_description = meta.get("description") or ""
    r.gh_language = meta.get("language") or ""
    r.gh_stars = int(meta.get("stargazers_count") or 0)
    r.gh_forks = int(meta.get("forks_count") or 0)
    r.gh_open_issues = int(meta.get("open_issues_count") or 0)
    r.gh_pushed_at = meta.get("pushed_at") or ""
    lic = meta.get("license")
    r.gh_license = (lic.get("spdx_id") or lic.get("name") or "") if isinstance(lic, dict) else ""
    r.gh_archived = bool(meta.get("archived"))
    r.gh_full_meta = meta

    # 2) RepoReaper-lite
    r.reporeaper_lite = gh.reporeaper_lite(target.owner, target.repo, meta)

    # 3) Scorecard (optional – never fails the run)
    sc_raw, sc_err = fetch_scorecard(target.owner, target.repo)
    if sc_err:
        logger.info("Scorecard not available for %s: %s", target.slug, sc_err)
    r.scorecard = summarize_scorecard(sc_raw)

    # 4) SBOM export
    sbom, sbom_errs = gh.export_sbom(target.owner, target.repo)
    r.errors.extend(sbom_errs)
    if sbom is None:
        r.status = "partial"
        return r

    purls = extract_purls_from_spdx(sbom)
    r.dep_count = len(purls)

    # 5) OSV querybatch
    osv_results, osv_err = osv_querybatch(purls, chunk_size=CONFIG["osv_chunk_size"])
    if osv_results is None:
        r.status = "partial"
        if osv_err:
            r.errors.append(osv_err)
        # Still store deps without vuln info
        r.dependencies = [DepResult(purl=p) for p in purls]
        return r

    r.dependencies = build_dep_results(purls, osv_results)
    r.vulnerable_dep_count = sum(1 for d in r.dependencies if d.vulnerable)
    r.vuln_id_count = sum(d.vuln_count for d in r.dependencies)

    return r


# -------------------------------------------------------------------
# Main orchestrator
# -------------------------------------------------------------------

def run_pipeline(input_path: str, output_dir: str, workers: int) -> None:
    _setup_logging(output_dir)
    logger.info("Pipeline started  input=%s  output=%s  workers=%d", input_path, output_dir, workers)

    # 0) Parse input
    targets: List[RepoTarget] = []
    with open(input_path, "r", encoding="utf-8") as fh:
        for line in fh:
            t = parse_input_line(line)
            if t is not None:
                targets.append(t)
    logger.info("Parsed %d repo targets from %s", len(targets), input_path)

    # GitHub client
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        logger.warning("GITHUB_TOKEN not set – rate limits will be strict and SBOM may fail")
    gh = GitHubClient(token=token)

    # Scan repos (threaded)
    started = dt.datetime.now(dt.timezone.utc)
    results: List[RepoResult] = []

    if workers <= 1:
        for i, t in enumerate(targets, 1):
            logger.info("[%d/%d] Scanning %s", i, len(targets), t.slug)
            results.append(scan_one(t, gh))
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            future_to_target = {pool.submit(scan_one, t, gh): t for t in targets}
            done_count = 0
            for fut in as_completed(future_to_target):
                done_count += 1
                tgt = future_to_target[fut]
                try:
                    results.append(fut.result())
                    logger.info("[%d/%d] Done %s", done_count, len(targets), tgt.slug)
                except Exception as exc:
                    logger.error("Unhandled error for %s: %s", tgt.slug, exc)
                    rr = RepoResult(
                        owner=tgt.owner, repo=tgt.repo, slug=tgt.slug,
                        repo_type=tgt.repo_type, original_input=tgt.original,
                        status="failed", errors=[repr(exc)],
                    )
                    results.append(rr)

    # Stable ordering by input position
    order = {t.original: i for i, t in enumerate(targets)}
    results.sort(key=lambda r: order.get(r.original_input, 10**9))

    ended = dt.datetime.now(dt.timezone.utc)
    duration = int((ended - started).total_seconds())
    logger.info("Scanning complete – %d repos in %ds", len(results), duration)

    # Log per-repo errors
    for r in results:
        for e in r.errors:
            logger.warning("[%s] %s", r.slug, e)

    # ---- Write outputs ----
    os.makedirs(output_dir, exist_ok=True)

    # results.raw.json
    raw_payload = {
        "generated_at": ended.isoformat(),
        "duration_seconds": duration,
        "input_file": input_path,
        "repo_count": len(results),
        "results": [r.to_dict() for r in results],
    }
    _write_json(os.path.join(output_dir, "results.raw.json"), raw_payload)

    # deps.aggregate.json
    dep_agg = build_dep_aggregate(results)
    _write_json(os.path.join(output_dir, "deps.aggregate.json"), dep_agg)

    # vulns.aggregate.json
    vuln_agg = build_vuln_aggregate(results)
    _write_json(os.path.join(output_dir, "vulns.aggregate.json"), vuln_agg)

    # report.data.json
    report_data = build_report_data(
        results, dep_agg, vuln_agg,
        top_deps_n=CONFIG["top_deps_n"],
        top_vuln_deps_n=CONFIG["top_vuln_deps_n"],
        top_vulns_n=CONFIG["top_vulns_n"],
    )
    _write_json(os.path.join(output_dir, "report.data.json"), report_data)

    # report.html + styles.css
    html_path = render_report(report_data, output_dir)
    logger.info("Report written to %s", html_path)

    print(f"\nPipeline complete – {len(results)} repos scanned in {duration}s")
    print(f"Outputs in: {output_dir}/")


def _write_json(path: str, data: Any) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)
    logger.info("Wrote %s", path)


# -------------------------------------------------------------------
# CLI
# -------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Repo-risk pipeline: SBOM + OSV + Scorecard scanning",
    )
    ap.add_argument("--input", default="input.txt", help="Input file (default: input.txt)")
    ap.add_argument("--output", default="output", help="Output directory (default: output)")
    ap.add_argument("--workers", type=int, default=CONFIG["max_workers"],
                    help=f"Thread-pool size (default: {CONFIG['max_workers']})")
    args = ap.parse_args()
    run_pipeline(args.input, args.output, args.workers)


if __name__ == "__main__":
    main()
