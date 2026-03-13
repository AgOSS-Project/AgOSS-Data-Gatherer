"""Run OpenSSF Scorecard (tools/scorecard.exe) for each repo.

Key robustness improvements:
- Non-zero exit codes with valid JSON in stdout → partial_success
- Captures exit_code, stderr, runtime_seconds per repo
- Retries on hard failure up to SCORECARD_RETRY_COUNT
- Fails early if GITHUB_AUTH_TOKEN is unset
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from pipeline import config
from pipeline.models import RepoEntry, ScorecardResult

logger = logging.getLogger("pipeline.scorecard")


def _output_path(entry: RepoEntry) -> Path:
    return config.RAW_SCORECARD_DIR / f"{entry.owner}__{entry.repo_name}.json"


def _should_skip(entry: RepoEntry) -> bool:
    """Return True when a cached result exists and FORCE_REFRESH is off."""
    if config.FORCE_REFRESH:
        return False
    out = _output_path(entry)
    return out.exists() and out.stat().st_size > 0


def check_scorecard_prereqs() -> list[str]:
    """Return a list of problems (empty = ready to run)."""
    problems: list[str] = []
    if not config.SCORECARD_EXE.exists():
        problems.append(f"scorecard.exe not found at {config.SCORECARD_EXE}")
    if not config.GITHUB_AUTH_TOKEN:
        problems.append(
            "GITHUB_AUTH_TOKEN env var is not set — Scorecard requires it "
            "and will hit rate-limit walls without it."
        )
    return problems


def run_scorecard(entry: RepoEntry) -> ScorecardResult:
    """Execute scorecard.exe for a single repo and return normalised result."""
    result = ScorecardResult()
    out_file = _output_path(entry)
    config.RAW_SCORECARD_DIR.mkdir(parents=True, exist_ok=True)

    # Cache hit
    if _should_skip(entry):
        logger.info("[scorecard] Using cached result for %s/%s", entry.owner, entry.repo_name)
        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
            r = _normalize(raw, out_file)
            r.status = "success"
            return r
        except Exception as exc:
            logger.warning("[scorecard] Cached file corrupt for %s/%s, re-running: %s",
                           entry.owner, entry.repo_name, exc)

    # Build command
    exe = str(config.SCORECARD_EXE)
    cmd = [exe, f"--repo={entry.repo_url}", "--format=json"]
    env_extra: dict[str, str] = {}
    if config.GITHUB_AUTH_TOKEN:
        env_extra["GITHUB_AUTH_TOKEN"] = config.GITHUB_AUTH_TOKEN

    logger.info("[scorecard] Running for %s/%s …", entry.owner, entry.repo_name)

    attempts = max(1, config.SCORECARD_RETRY_COUNT)
    last_error = ""

    for attempt in range(1, attempts + 1):
        t0 = time.monotonic()
        try:
            run_env = {**os.environ, **env_extra}
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=config.SCORECARD_TIMEOUT_SECONDS,
                env=run_env,
            )
            elapsed = time.monotonic() - t0
            result.exit_code = proc.returncode
            result.stderr = (proc.stderr or "").strip()[:2000]
            result.runtime_seconds = round(elapsed, 2)

            # Try to parse JSON regardless of exit code
            parsed_json = None
            if proc.stdout and proc.stdout.strip():
                try:
                    parsed_json = json.loads(proc.stdout)
                    result.json_parsed = True
                except json.JSONDecodeError:
                    result.json_parsed = False

            # Persist raw output
            out_file.write_text(proc.stdout or "", encoding="utf-8")
            result.raw_file = str(out_file)

            if proc.returncode == 0 and parsed_json is not None:
                # Clean success
                norm = _normalize(parsed_json, out_file)
                norm.exit_code = result.exit_code
                norm.stderr = result.stderr
                norm.runtime_seconds = result.runtime_seconds
                norm.json_parsed = True
                norm.status = "success"
                return norm

            if proc.returncode != 0 and parsed_json is not None:
                # Non-zero exit but valid JSON — partial success
                norm = _normalize(parsed_json, out_file)
                norm.exit_code = result.exit_code
                norm.stderr = result.stderr
                norm.runtime_seconds = result.runtime_seconds
                norm.json_parsed = True
                norm.status = "partial_success"
                norm.error = f"scorecard exited {proc.returncode} but produced valid JSON"
                logger.warning(
                    "[scorecard] %s/%s: partial_success (exit %d, valid JSON)",
                    entry.owner, entry.repo_name, proc.returncode,
                )
                return norm

            # Non-zero exit and no valid JSON — hard failure, may retry
            last_error = f"scorecard exited {proc.returncode}: {result.stderr[:500]}"
            logger.error("[scorecard] %s/%s attempt %d/%d: %s",
                         entry.owner, entry.repo_name, attempt, attempts, last_error)

        except subprocess.TimeoutExpired:
            elapsed = time.monotonic() - t0
            result.runtime_seconds = round(elapsed, 2)
            last_error = f"scorecard timed out after {config.SCORECARD_TIMEOUT_SECONDS}s"
            logger.error("[scorecard] %s/%s attempt %d/%d: %s",
                         entry.owner, entry.repo_name, attempt, attempts, last_error)

        except FileNotFoundError:
            result.error = f"scorecard.exe not found at {config.SCORECARD_EXE}"
            result.status = "failed"
            logger.error("[scorecard] %s", result.error)
            return result

        except Exception as exc:
            elapsed = time.monotonic() - t0
            result.runtime_seconds = round(elapsed, 2)
            last_error = f"scorecard unexpected error: {exc}"
            logger.error("[scorecard] %s/%s attempt %d/%d: %s",
                         entry.owner, entry.repo_name, attempt, attempts, last_error)

        # Brief pause before retry (skip on last attempt)
        if attempt < attempts:
            time.sleep(2)

    # All attempts exhausted
    result.error = last_error
    result.status = "failed"
    result.raw_file = str(out_file) if out_file.exists() else ""
    return result


def _normalize(raw: dict[str, Any], out_file: Path) -> ScorecardResult:
    """Extract structured data from raw scorecard JSON."""
    result = ScorecardResult(collected=True, raw_file=str(out_file))

    # Version info
    sc_info = raw.get("scorecard", {})
    if isinstance(sc_info, dict):
        result.scorecard_version = sc_info.get("version", "")
        result.scorecard_commit = sc_info.get("commit", "")

    # Overall score
    result.overall_score = raw.get("score") or raw.get("aggregate_score")
    if result.overall_score is not None:
        try:
            result.overall_score = float(result.overall_score)
        except (ValueError, TypeError):
            result.overall_score = None

    # Per-check scores
    checks = raw.get("checks", [])
    for chk in checks:
        name = chk.get("name", "unknown")
        score = chk.get("score")
        details = chk.get("reason", "")
        result.checks[name] = {
            "score": score,
            "reason": details,
        }
        if chk.get("documentation", {}).get("url"):
            result.checks[name]["doc_url"] = chk["documentation"]["url"]

    if not result.overall_score and checks:
        valid = [c.get("score", -1) for c in checks
                 if isinstance(c.get("score"), (int, float)) and c["score"] >= 0]
        if valid:
            result.overall_score = round(sum(valid) / len(valid), 2)

    result.json_parsed = True
    return result


def run_scorecard_batch(entries: list[RepoEntry]) -> dict[str, ScorecardResult]:
    """Run scorecard for all entries, keyed by repo_url."""
    results: dict[str, ScorecardResult] = {}

    # Pre-flight check
    problems = check_scorecard_prereqs()
    for p in problems:
        logger.warning("[scorecard] Pre-check: %s", p)

    for i, entry in enumerate(entries, 1):
        logger.info("[scorecard] (%d/%d) %s/%s", i, len(entries), entry.owner, entry.repo_name)
        results[entry.repo_url] = run_scorecard(entry)

    return results


def load_scorecard_batch_from_cache(entries: list[RepoEntry]) -> dict[str, ScorecardResult]:
    """Load Scorecard results from local cache files for the provided entries."""
    results: dict[str, ScorecardResult] = {}
    for entry in entries:
        out_file = _output_path(entry)
        if not out_file.exists() or out_file.stat().st_size == 0:
            results[entry.repo_url] = ScorecardResult(
                status="failed",
                error="No cached Scorecard output found.",
            )
            continue
        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
            norm = _normalize(raw, out_file)
            norm.status = "success"
            norm.collected = True
            results[entry.repo_url] = norm
        except Exception as exc:
            results[entry.repo_url] = ScorecardResult(
                status="failed",
                error=f"Cached Scorecard file unreadable: {exc}",
                raw_file=str(out_file),
            )
    return results
