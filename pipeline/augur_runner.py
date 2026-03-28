"""Interact with a locally-running Augur instance to collect repo metrics.

Extended with:
- sync_repos()      – compare input vs Augur-registered repos
- register_repos()  – POST missing repos to Augur
- wait_for_repos()  – poll until data is ready (configurable wait mode)
- Per-repo status tracking (registered / collecting / ready / partial / timed_out / failed)
"""

from __future__ import annotations

import json
import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

from pipeline import config
from pipeline.models import RepoEntry, AugurResult

logger = logging.getLogger("pipeline.augur")


# ── helpers ──────────────────────────────────────────────────────────────────

def _api_url(path: str) -> str:
    base = config.AUGUR_API_BASE.rstrip("/")
    prefix = config.AUGUR_API_PREFIX.rstrip("/")
    return f"{base}{prefix}/{path.lstrip('/')}"


def _get(path: str, params: dict | None = None) -> requests.Response:
    url = _api_url(path)
    headers: dict[str, str] = {}
    if config.AUGUR_API_KEY:
        headers["Authorization"] = f"Client {config.AUGUR_API_KEY}"
    return requests.get(url, params=params, headers=headers,
                        timeout=config.AUGUR_TIMEOUT_SECONDS)


def _post(path: str, payload: Any = None) -> requests.Response:
    url = _api_url(path)
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if config.AUGUR_API_KEY:
        headers["Authorization"] = f"Client {config.AUGUR_API_KEY}"
    return requests.post(url, json=payload, headers=headers,
                         timeout=config.AUGUR_TIMEOUT_SECONDS)


def _output_path(entry: RepoEntry) -> Path:
    return config.RAW_AUGUR_DIR / f"{entry.owner}__{entry.repo_name}.json"


def _should_skip(entry: RepoEntry) -> bool:
    if config.FORCE_REFRESH:
        return False
    out = _output_path(entry)
    if not out.exists() or out.stat().st_size == 0:
        return False
    # Don't treat cached errors or transient states as valid cache hits
    try:
        raw = json.loads(out.read_text(encoding="utf-8"))
        if raw.get("error"):
            return False
        # "collecting" is transient — always re-check
        if raw.get("status") in ("collecting", "registered"):
            return False
    except Exception:
        return False
    return True


# ── health-check ─────────────────────────────────────────────────────────────

def check_augur_health() -> bool:
    """Return True if the Augur API is reachable."""
    try:
        r = requests.get(
            f"{config.AUGUR_API_BASE.rstrip('/')}/api/unstable/",
            timeout=5,
        )
        return r.status_code == 200
    except Exception:
        return False


# ── sync / registration ─────────────────────────────────────────────────────

@dataclass
class SyncReport:
    """Result of comparing input repos vs what Augur currently has."""
    overlap: list[RepoEntry] = field(default_factory=list)
    missing: list[RepoEntry] = field(default_factory=list)
    augur_repo_ids: dict[str, int] = field(default_factory=dict)  # repo_url → repo_id


def sync_repos(entries: list[RepoEntry]) -> SyncReport:
    """Compare *entries* against repos registered in Augur.

    Returns a :class:`SyncReport` classifying each repo as overlap or missing.
    """
    report = SyncReport()

    for entry in entries:
        repo_id = _resolve_repo_id(entry)
        if repo_id is not None:
            report.overlap.append(entry)
            report.augur_repo_ids[entry.repo_url] = repo_id
        else:
            report.missing.append(entry)

    logger.info(
        "[augur-sync] %d overlap, %d missing out of %d input repos",
        len(report.overlap), len(report.missing), len(entries),
    )
    return report


def _ensure_repo_group(group_name: str) -> int | None:
    """Ensure the repo group exists in Augur, creating it if needed.

    Returns the repo_group_id, or None on failure.
    """
    # Check if group already exists
    try:
        r = _get("repo-groups")
        if r.status_code == 200:
            for rg in r.json():
                if rg.get("rg_name") == group_name:
                    return rg["repo_group_id"]
    except Exception:
        pass

    # Create via direct SQL
    sql = (
        "INSERT INTO augur_data.repo_groups (rg_name, rg_description, tool_source) "
        f"VALUES ('{group_name}', 'Created by ag-oss pipeline', 'pipeline') "
        "ON CONFLICT DO NOTHING "
        "RETURNING repo_group_id;"
    )
    try:
        result = subprocess.run(
            ["docker", "exec", config.AUGUR_DB_CONTAINER,
             "psql", "-U", config.AUGUR_DB_USER, "-d", config.AUGUR_DB_NAME,
             "-tAc", sql],
            capture_output=True, text=True, timeout=15,
        )
        rid = result.stdout.strip().split('\n')[0].strip()
        if rid and rid.isdigit():
            logger.info("[augur-register] Created repo group '%s' (id=%s)", group_name, rid)
            return int(rid)
        # ON CONFLICT means it exists but RETURNING gave nothing — re-query
        r2 = _get("repo-groups")
        if r2.status_code == 200:
            for rg in r2.json():
                if rg.get("rg_name") == group_name:
                    return rg["repo_group_id"]
    except Exception as exc:
        logger.warning("[augur-register] Could not create repo group '%s': %s", group_name, exc)
    return None


def register_repos(entries: list[RepoEntry]) -> dict[str, bool]:
    """Register repos in Augur that are not already present.

    Uses direct SQL insertion via ``docker exec psql`` because the Augur
    HTTP API requires SSL for write endpoints (returns 426).  Falls back
    to the HTTP API if the DB container is not reachable.

    Returns a mapping of repo_url → success boolean.
    """
    outcomes: dict[str, bool] = {}

    # Resolve or create the target repo group
    group_name = config.AUGUR_REPO_GROUP or "Default Repo Group"
    repo_group_id = _ensure_repo_group(group_name)
    if repo_group_id is None:
        # Fall back to Default Repo Group (id=1)
        logger.warning("[augur-register] Could not resolve repo group '%s'; using id=1", group_name)
        repo_group_id = 1

    for entry in entries:
        url = entry.repo_url.rstrip("/")
        # Sanitise for SQL (only allow URL-safe chars)
        safe_url = url.replace("'", "''")
        safe_name = entry.repo_name.replace("'", "''")
        # Augur API expects url as "github.com/owner/repo" and repo_path as "github.com-owner-repo"
        short_url = url.replace("https://", "").replace("http://", "")
        repo_path = short_url.replace("/", "-")
        safe_short_url = short_url.replace("'", "''")
        safe_repo_path = repo_path.replace("'", "''")

        sql = (
            "INSERT INTO augur_data.repo "
            "(repo_group_id, repo_git, repo_name, repo_type, tool_source, data_source, url, repo_path) "
            f"VALUES ({repo_group_id}, '{safe_url}', '{safe_name}', '', 'pipeline', 'pipeline', '{safe_short_url}', '{safe_repo_path}') "
            "ON CONFLICT (repo_git) DO NOTHING "
            "RETURNING repo_id;"
        )
        try:
            result = subprocess.run(
                ["docker", "exec", config.AUGUR_DB_CONTAINER,
                 "psql", "-U", config.AUGUR_DB_USER, "-d", config.AUGUR_DB_NAME,
                 "-tAc", sql],
                capture_output=True, text=True, timeout=15,
            )
            new_id = result.stdout.strip().split('\n')[0].strip()
            if result.returncode != 0:
                logger.warning("[augur-register] psql error for %s: %s",
                               url, result.stderr.strip())
                outcomes[url] = False
                continue

            if new_id and new_id.isdigit():
                logger.info("[augur-register] Inserted %s (repo_id=%s)", url, new_id)
                # Also insert a collection_status row so Augur knows to collect
                cs_sql = (
                    "INSERT INTO augur_operations.collection_status (repo_id) "
                    f"VALUES ({new_id}) ON CONFLICT DO NOTHING;"
                )
                subprocess.run(
                    ["docker", "exec", config.AUGUR_DB_CONTAINER,
                     "psql", "-U", config.AUGUR_DB_USER, "-d", config.AUGUR_DB_NAME,
                     "-tAc", cs_sql],
                    capture_output=True, text=True, timeout=10,
                )
                outcomes[url] = True
            else:
                # ON CONFLICT — repo already exists (race with another process)
                logger.info("[augur-register] %s already in DB (no insert needed)", url)
                outcomes[url] = True
        except FileNotFoundError:
            logger.error("[augur-register] 'docker' command not found — cannot register repos")
            outcomes[url] = False
            break
        except Exception as exc:
            logger.error("[augur-register] Error registering %s: %s", url, exc)
            outcomes[url] = False

    ok = sum(1 for v in outcomes.values() if v)
    logger.info("[augur-register] %d/%d repos registered successfully", ok, len(entries))
    return outcomes


# ── wait / readiness ─────────────────────────────────────────────────────────

def _check_readiness(repo_id: int, mode: str) -> bool:
    """Return True if *repo_id* has data according to *mode*.

    - "minimal"  → repo resolves (always true if we got a repo_id)
    - "standard" → at least one readiness endpoint returns non-empty data
    - "full"     → all readiness endpoints return non-empty data
    """
    if mode == "minimal":
        return True

    endpoints = config.AUGUR_READINESS_ENDPOINTS
    results: list[bool] = []

    for ep in endpoints:
        try:
            r = _get(f"repos/{repo_id}/{ep}")
            has_data = r.status_code == 200 and bool(r.json())
        except Exception:
            has_data = False
        results.append(has_data)

    if mode == "full":
        return all(results)

    # "standard": accept readiness if any configured endpoint has data.
    if any(results):
        return True

    # Fallback for repos that have little/no issue activity but still have
    # meaningful collected data in other endpoints.
    fallback_endpoints = (
        "committers",
        "commits",
        "pull-requests-new",
        "releases",
    )
    fallback_results: list[bool] = []
    for ep in fallback_endpoints:
        try:
            r = _get(f"repos/{repo_id}/{ep}")
            has_data = r.status_code == 200 and bool(r.json())
        except Exception:
            has_data = False
        fallback_results.append(has_data)

    return any(fallback_results)


def wait_for_repos(
    entries: list[RepoEntry],
    repo_ids: dict[str, int],
    mode: str | None = None,
) -> dict[str, str]:
    """Poll Augur until repos are ready (or timeout).

    Returns a mapping of repo_url → final status string
    ("ready" / "timed_out" / "not_registered").
    """
    mode = mode or config.AUGUR_WAIT_MODE
    if mode == "none":
        return {e.repo_url: "ready" if e.repo_url in repo_ids else "not_registered"
                for e in entries}

    poll = config.AUGUR_POLL_INTERVAL
    timeout = config.AUGUR_WAIT_TIMEOUT

    pending = {e.repo_url for e in entries if e.repo_url in repo_ids}
    statuses: dict[str, str] = {}

    # Mark repos without IDs immediately
    for e in entries:
        if e.repo_url not in repo_ids:
            statuses[e.repo_url] = "not_registered"

    t0 = time.monotonic()
    while pending and (time.monotonic() - t0) < timeout:
        for url in list(pending):
            rid = repo_ids[url]
            if _check_readiness(rid, mode):
                statuses[url] = "ready"
                pending.discard(url)
                logger.info("[augur-wait] %s is ready (mode=%s)", url, mode)

        if not pending:
            break

        elapsed = time.monotonic() - t0
        logger.info(
            "[augur-wait] %d repos still pending (%.0f/%.0fs elapsed) …",
            len(pending), elapsed, timeout,
        )
        time.sleep(poll)

    # Anything still pending is timed out
    for url in pending:
        statuses[url] = "timed_out"
        logger.warning("[augur-wait] %s timed out after %ds", url, timeout)

    return statuses


# ── repo-id resolution ───────────────────────────────────────────────────────

def _resolve_repo_id(entry: RepoEntry) -> int | None:
    """Look up the Augur repo_id for a given owner/repo."""
    try:
        r = _get(f"owner/{quote(entry.owner, safe='')}/repo/{quote(entry.repo_name, safe='')}")
        if r.status_code == 200:
            data = r.json()
            if isinstance(data, list) and data:
                return data[0].get("repo_id")
            elif isinstance(data, dict):
                return data.get("repo_id")
    except Exception as exc:
        logger.debug("[augur] Could not resolve repo_id for %s/%s: %s",
                     entry.owner, entry.repo_name, exc)
    return None


# ── metric collection ────────────────────────────────────────────────────────

def _collect_metric(repo_id: int, endpoint: str, friendly: str) -> Any:
    """Fetch a single metric endpoint for a repo_id."""
    try:
        r = _get(f"repos/{repo_id}/{endpoint}")
        if r.status_code == 200:
            return r.json()
        logger.debug("[augur] %s returned status %d for repo %d",
                     endpoint, r.status_code, repo_id)
    except Exception as exc:
        logger.debug("[augur] Error fetching %s for repo %d: %s", endpoint, repo_id, exc)
    return None


def _collect_db_counts(repo_id: int) -> dict[str, int]:
    """Collect additional per-repo counts directly from Augur DB tables.

    This captures richer data even when some API endpoints are unavailable
    or still sparse for a repo.
    """
    tables: list[tuple[str, str]] = [
        ("augur_data.commits", "db_commit_rows"),
        ("augur_data.issues", "db_issue_rows"),
        ("augur_data.pull_requests", "db_pull_request_rows"),
        ("augur_data.pull_request_events", "db_pull_request_event_rows"),
        ("augur_data.pull_request_files", "db_pull_request_file_rows"),
        ("augur_data.issue_events", "db_issue_event_rows"),
        ("augur_data.issue_labels", "db_issue_label_rows"),
        ("augur_data.pull_request_labels", "db_pull_request_label_rows"),
        ("augur_data.releases", "db_release_rows"),
        ("augur_data.repo_stats", "db_repo_stat_rows"),
    ]

    counts: dict[str, int] = {}
    for table, key in tables:
        sql = f"SELECT COUNT(*) FROM {table} WHERE repo_id={repo_id};"
        try:
            p = subprocess.run(
                [
                    "docker", "exec", config.AUGUR_DB_CONTAINER,
                    "psql", "-U", config.AUGUR_DB_USER, "-d", config.AUGUR_DB_NAME,
                    "-tAc", sql,
                ],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if p.returncode == 0:
                raw = p.stdout.strip()
                if raw.isdigit():
                    counts[key] = int(raw)
        except Exception:
            # Keep graceful behavior: DB enrichment is best-effort.
            continue
    return counts


def run_augur(
    entry: RepoEntry,
    *,
    known_repo_id: int | None = None,
    wait_status: str = "",
    use_cache: bool = True,
) -> AugurResult:
    """Collect Augur metrics for a single repo."""
    result = AugurResult()
    out_file = _output_path(entry)
    config.RAW_AUGUR_DIR.mkdir(parents=True, exist_ok=True)

    # Cache hit (optionally bypassed by orchestration)
    if use_cache and _should_skip(entry):
        logger.info("[augur] Using cached result for %s/%s", entry.owner, entry.repo_name)
        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
            return _from_cache(raw, out_file)
        except Exception as exc:
            logger.warning("[augur] Cached file corrupt for %s/%s, re-fetching: %s",
                           entry.owner, entry.repo_name, exc)

    # Resolve repo in Augur
    repo_id = known_repo_id or _resolve_repo_id(entry)
    if repo_id is None:
        result.error = "Repo not found in Augur — may not be registered yet."
        result.status = "not_registered"
        logger.warning("[augur] %s/%s: %s", entry.owner, entry.repo_name, result.error)
        _persist(out_file, {"error": result.error, "metrics": {}})
        result.raw_file = str(out_file)
        return result

    result.repo_id = repo_id
    result.registered = True

    # Apply wait_status if provided by orchestrator
    if wait_status == "timed_out":
        result.timed_out = True
        result.wait_mode = config.AUGUR_WAIT_MODE

    # Collect each configured metric
    raw_metrics: dict[str, Any] = {}
    responded_count = 0   # endpoints that returned any 200
    nonempty_count = 0    # endpoints that returned actual data
    for endpoint, friendly in config.AUGUR_METRIC_ENDPOINTS:
        value = _collect_metric(repo_id, endpoint, friendly)
        if value is not None:
            raw_metrics[friendly] = value
            responded_count += 1
            # Only count as meaningful if there's real data (not [] or {})
            if value:
                nonempty_count += 1

    # Enrich with DB-backed counts for broader coverage.
    db_counts = _collect_db_counts(repo_id)
    if db_counts:
        raw_metrics["db_counts"] = db_counts

    result.metrics = _summarize_metrics(raw_metrics)
    if db_counts:
        result.metrics.update(db_counts)
    result.raw_file = str(out_file)
    result.wait_mode = config.AUGUR_WAIT_MODE

    # Check if the summary contains any meaningful (non-zero, non-empty) values
    has_data = any(
        (isinstance(v, (int, float)) and v > 0)
        or (isinstance(v, str) and v != "")
        or (isinstance(v, list) and len(v) > 0)
        for k, v in result.metrics.items()
        if k not in ("aggregate_summary", "languages")
    )
    # Languages alone don't indicate collection is complete
    if not has_data and result.metrics.get("languages"):
        has_data = False

    # Classify final status based on wait outcome + collected data.
    total_endpoints = len(config.AUGUR_METRIC_ENDPOINTS)
    ready_threshold = max(1, total_endpoints // 2)

    # If the wait phase already confirmed readiness, trust it.
    if wait_status == "ready":
        result.status = "ready"
        result.collected = True
        result.ready = True
    elif wait_status == "timed_out" and not has_data:
        result.status = "timed_out"
        result.collected = False
        result.ready = False
    elif has_data and nonempty_count >= ready_threshold:
        result.status = "ready"
        result.collected = True
        result.ready = True
    elif has_data:
        result.status = "partial"
        result.collected = True
        result.ready = False
    elif responded_count > 0:
        # API is reachable but no meaningful data yet — still collecting
        result.status = "collecting"
        result.collected = False
    else:
        result.status = "registered" if result.registered else "failed"
        result.collected = False

    _persist(out_file, {
        "repo_id": repo_id,
        "status": result.status,
        "metrics_raw": raw_metrics,
        "metrics_summary": result.metrics,
    })

    return result


def _persist(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _from_cache(raw: dict, out_file: Path) -> AugurResult:
    """Rebuild an AugurResult from a previously-persisted file."""
    result = AugurResult(collected=True, raw_file=str(out_file))
    result.repo_id = raw.get("repo_id")
    result.metrics = raw.get("metrics_summary", {})
    result.error = raw.get("error", "")
    cached_status = raw.get("status", "")
    if result.error:
        result.collected = False
        result.status = "failed"
    elif cached_status:
        result.status = cached_status  # type: ignore[assignment]
        result.collected = cached_status in ("ready", "partial")
        result.ready = cached_status == "ready"
        result.registered = cached_status not in ("not_registered", "failed")
    return result


def load_augur_batch_from_cache(entries: list[RepoEntry]) -> dict[str, AugurResult]:
    """Load Augur results from local cache files for the provided entries."""
    results: dict[str, AugurResult] = {}
    for entry in entries:
        out_file = _output_path(entry)
        if not out_file.exists() or out_file.stat().st_size == 0:
            results[entry.repo_url] = AugurResult(
                status="failed",
                error="No cached Augur output found.",
            )
            continue
        try:
            raw = json.loads(out_file.read_text(encoding="utf-8"))
            results[entry.repo_url] = _from_cache(raw, out_file)
        except Exception as exc:
            results[entry.repo_url] = AugurResult(
                status="failed",
                error=f"Cached Augur file unreadable: {exc}",
                raw_file=str(out_file),
            )
    return results


# ── orchestrated batch ───────────────────────────────────────────────────────

def run_augur_batch(
    entries: list[RepoEntry],
    *,
    do_sync: bool = False,
    do_register: bool = False,
    do_wait: bool = False,
    wait_mode: str | None = None,
) -> dict[str, AugurResult]:
    """Orchestrate sync → register → wait → collect for all entries."""
    results: dict[str, AugurResult] = {}
    repo_ids: dict[str, int] = {}
    wait_statuses: dict[str, str] = {}

    # ── Phase 1: Sync ──
    if do_sync or do_register or do_wait:
        logger.info("[augur] Phase 1: Syncing repo list with Augur …")
        report = sync_repos(entries)
        repo_ids = dict(report.augur_repo_ids)

        if do_register and report.missing:
            logger.info("[augur] Phase 1b: Registering %d missing repos …", len(report.missing))
            register_outcomes = register_repos(report.missing)
            # Re-resolve IDs for newly registered repos
            for entry in report.missing:
                if register_outcomes.get(entry.repo_url):
                    # Give Augur a moment, then resolve
                    time.sleep(1)
                    rid = _resolve_repo_id(entry)
                    if rid is not None:
                        repo_ids[entry.repo_url] = rid

        if do_wait:
            logger.info("[augur] Phase 2: Waiting for repo data (mode=%s) …",
                        wait_mode or config.AUGUR_WAIT_MODE)
            wait_statuses = wait_for_repos(entries, repo_ids, mode=wait_mode)

    # ── Phase 3: Collect ──
    logger.info("[augur] Phase 3: Collecting metrics for %d repos …", len(entries))
    # During registration/wait orchestration, force fresh metric reads so
    # stale cached "partial" files do not mask newly-ready repos.
    use_cache = not (do_register or do_wait)
    for i, entry in enumerate(entries, 1):
        logger.info("[augur] (%d/%d) %s/%s", i, len(entries), entry.owner, entry.repo_name)
        results[entry.repo_url] = run_augur(
            entry,
            known_repo_id=repo_ids.get(entry.repo_url),
            wait_status=wait_statuses.get(entry.repo_url, ""),
            use_cache=use_cache,
        )

    return results


# ── metric summarisation ─────────────────────────────────────────────────────

def _summarize_metrics(raw: dict[str, Any]) -> dict[str, Any]:
    """Distil raw Augur API responses into simple summary values."""
    summary: dict[str, Any] = {}

    def _count(key: str) -> int | None:
        data = raw.get(key)
        if isinstance(data, list):
            return len(data)
        return None

    def _scalar(key: str, field: str) -> Any:
        data = raw.get(key)
        if isinstance(data, list) and data:
            return data[0].get(field)
        if isinstance(data, dict):
            return data.get(field)
        return None

    # Contributors
    c = _count("contributors")
    if c is not None:
        summary["contributor_count"] = c

    c = _count("contributors_new")
    if c is not None:
        summary["new_contributor_count"] = c

    # Committers
    c = _count("committers")
    if c is not None:
        summary["committer_count"] = c

    # Commits
    c = _count("commits")
    if c is not None:
        summary["commit_count"] = c

    c = _count("commits_new")
    if c is not None:
        summary["new_commit_count"] = c

    c = _count("commits_files")
    if c is not None:
        summary["commit_files_count"] = c

    c = _count("files")
    if c is not None:
        summary["files_touched_count"] = c

    c = _count("tags")
    if c is not None:
        summary["tag_count"] = c

    c = _count("commits_weekly")
    if c is not None:
        summary["weekly_commit_windows"] = c

    c = _count("commits_daily")
    if c is not None:
        summary["daily_commit_windows"] = c

    v = _scalar("code_changes", "commit_count")
    if v is None:
        v = _scalar("code_changes", "commits")
    if v is not None:
        summary["code_change_commits"] = v

    v = _scalar("code_changes_lines", "added")
    if v is None:
        v = _scalar("code_changes_lines", "lines_added")
    if v is not None:
        summary["lines_added"] = v

    v = _scalar("code_changes_lines", "removed")
    if v is None:
        v = _scalar("code_changes_lines", "lines_removed")
    if v is not None:
        summary["lines_removed"] = v

    # Issues
    c = _count("issues_new")
    if c is not None:
        summary["issues_opened"] = c

    c = _count("issues")
    if c is not None:
        summary["issues_total"] = c

    c = _count("issues_closed")
    if c is not None:
        summary["issues_closed"] = c
    c = _count("issues_active")
    if c is not None:
        summary["issues_active"] = c

    c = _count("issue_events")
    if c is not None:
        summary["issue_event_count"] = c

    c = _count("issue_comments")
    if c is not None:
        summary["issue_comment_count"] = c

    v = _scalar("issue_open_age", "average_days_open")
    if v is None:
        v = _scalar("issue_open_age", "mean_days_open")
    if v is not None:
        summary["avg_issue_open_age_days"] = v

    v = _scalar("issue_backlog", "issue_backlog")
    if v is not None:
        summary["issue_backlog"] = v

    v = _scalar("avg_issue_resolution_time", "average_issue_resolution_time")
    if v is not None:
        summary["avg_issue_resolution_time"] = v

    # Pull Requests
    c = _count("pull_requests_new")
    if c is not None:
        summary["prs_opened"] = c

    c = _count("pull_requests")
    if c is not None:
        summary["prs_total"] = c

    c = _count("pull_requests_active")
    if c is not None:
        summary["prs_active"] = c

    c = _count("pull_requests_closed")
    if c is not None:
        summary["prs_closed"] = c

    c = _count("pull_requests_merged")
    if c is not None:
        summary["prs_merged"] = c

    c = _count("pull_request_comments")
    if c is not None:
        summary["pr_comment_count"] = c

    c = _count("pull_request_events")
    if c is not None:
        summary["pr_event_count"] = c

    c = _count("pull_request_reviewers")
    if c is not None:
        summary["pr_reviewer_count"] = c

    v = _scalar("pr_acceptance_rate", "pull_request_acceptance_rate")
    if v is None:
        v = _scalar("pr_acceptance_rate", "rate")
    if v is not None:
        summary["pr_acceptance_rate"] = v

    # Releases
    c = _count("releases")
    if c is not None:
        summary["release_count"] = c

    # Stars / Forks / Watchers
    v = _scalar("stars_count", "stars_count")
    if v is not None:
        summary["stars"] = v
    v = _scalar("fork_count", "fork_count")
    if v is not None:
        summary["forks"] = v
    v = _scalar("watchers_count", "watchers_count")
    if v is not None:
        summary["watchers"] = v

    # Languages
    langs = raw.get("languages")
    if isinstance(langs, list):
        lang_names = [
            l.get("programming_language")
            for l in langs
            if isinstance(l, dict) and l.get("programming_language")
        ]
        if lang_names:
            summary["languages"] = lang_names

    # Avg weekly commits
    v = _scalar("avg_weekly_commits", "average_weekly_commits")
    if v is None:
        v = _scalar("avg_weekly_commits", "avg")
    if v is not None:
        summary["avg_weekly_commits"] = v

    # License
    v = _scalar("license_declared", "license")
    if v is None:
        v = _scalar("license_declared", "short_name")
    if v is not None:
        summary["license"] = v

    # Aggregate summary (catch-all)
    agg = raw.get("aggregate_summary")
    if isinstance(agg, (dict, list)):
        summary["aggregate_summary"] = agg
        first = agg[0] if isinstance(agg, list) and agg else (agg if isinstance(agg, dict) else None)
        if isinstance(first, dict):
            if "commit_count" in first and first.get("commit_count") is not None:
                summary.setdefault("commit_count", first.get("commit_count"))
            if "stars_count" in first and first.get("stars_count") is not None:
                summary.setdefault("stars", first.get("stars_count"))
            if "fork_count" in first and first.get("fork_count") is not None:
                summary.setdefault("forks", first.get("fork_count"))
            if "watcher_count" in first and first.get("watcher_count") is not None:
                summary.setdefault("watchers", first.get("watcher_count"))
            if "merged_count" in first and first.get("merged_count") is not None:
                summary.setdefault("prs_merged", first.get("merged_count"))

    # Include endpoint-level collection coverage for transparency
    summary["augur_endpoint_count"] = len(raw)
    summary["augur_nonempty_endpoint_count"] = sum(1 for v in raw.values() if v)

    return summary
