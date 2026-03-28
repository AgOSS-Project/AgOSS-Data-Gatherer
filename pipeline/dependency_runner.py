"""Dependency vulnerability analysis using GitHub SBOM + OSV.

This module is intentionally isolated from Scorecard/Augur scoring so the
existing pipeline behavior remains unchanged.
"""

from __future__ import annotations

import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote

import requests

from pipeline import config
from pipeline.models import RepoEntry

logger = logging.getLogger("pipeline.dependency")

# purl type -> OSV ecosystem
_PURL_TO_OSV_ECOSYSTEM = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "nuget": "NuGet",
    "golang": "Go",
    "go": "Go",
    "cargo": "crates.io",
    "gem": "RubyGems",
    "composer": "Packagist",
    "pub": "Pub",
    "hex": "Hex",
}

_RETRIABLE_HTTP_CODES = {429, 500, 502, 503, 504}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _repo_output_path(entry: RepoEntry) -> Path:
    return config.RAW_DEPENDENCY_DIR / f"{entry.owner}__{entry.repo_name}.json"


def _should_skip(entry: RepoEntry) -> bool:
    if config.FORCE_REFRESH:
        return False
    path = _repo_output_path(entry)
    return path.exists() and path.stat().st_size > 0


def _persist(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if config.GITHUB_AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {config.GITHUB_AUTH_TOKEN}"
    return headers


def _retry_delay(response: requests.Response | None, attempt: int) -> float:
    if response is not None:
        retry_after = response.headers.get("Retry-After", "").strip()
        if retry_after.isdigit():
            return min(float(retry_after), 30.0)
    base = max(0.1, config.DEPENDENCY_RETRY_BACKOFF_SECONDS)
    return min(30.0, base * (2**attempt))


def _http_error_message(response: requests.Response) -> str:
    body = ""
    try:
        payload = response.json()
        if isinstance(payload, dict):
            body = str(payload.get("message") or payload.get("error") or "")
            if not body:
                body = json.dumps(payload)[:300]
        else:
            body = str(payload)[:300]
    except Exception:
        body = (response.text or "").strip()[:300]

    if body:
        return f"HTTP {response.status_code}: {body}"
    return f"HTTP {response.status_code}"


def _request_json(
    session: requests.Session,
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | None = None,
    expected_statuses: set[int] | None = None,
) -> tuple[dict[str, Any] | list[Any] | None, str]:
    """Request JSON with bounded retries and timeout."""
    expected = expected_statuses or {200}
    attempts = max(1, config.DEPENDENCY_RETRY_COUNT + 1)
    timeout = max(1, config.DEPENDENCY_HTTP_TIMEOUT_SECONDS)

    last_error = ""
    for attempt in range(attempts):
        response: requests.Response | None = None
        try:
            response = session.request(
                method,
                url,
                headers=headers,
                json=payload,
                timeout=timeout,
            )

            if response.status_code in expected:
                try:
                    return response.json(), ""
                except Exception as exc:
                    return None, f"Invalid JSON response: {exc}"

            should_retry = response.status_code in _RETRIABLE_HTTP_CODES and attempt < (attempts - 1)
            last_error = _http_error_message(response)
            if should_retry:
                time.sleep(_retry_delay(response, attempt))
                continue
            return None, last_error

        except requests.RequestException as exc:
            last_error = f"Request failed: {exc}"
            if attempt < (attempts - 1):
                time.sleep(_retry_delay(response, attempt))
                continue
            return None, last_error

    return None, (last_error or "Request failed")


def _fetch_github_sbom(entry: RepoEntry) -> tuple[dict[str, Any] | None, str]:
    """Fetch SBOM from GitHub dependency graph API for a repository."""
    url = (
        f"{config.GITHUB_API_BASE.rstrip('/')}/repos/"
        f"{quote(entry.owner, safe='')}/{quote(entry.repo_name, safe='')}/dependency-graph/sbom"
    )
    with requests.Session() as session:
        payload, err = _request_json(session, "GET", url, headers=_github_headers())
    if err:
        return None, err
    if not isinstance(payload, dict):
        return None, "Unexpected SBOM payload type"
    return payload, ""


def _extract_purl(pkg: dict[str, Any]) -> str:
    refs = pkg.get("externalRefs")
    if not isinstance(refs, list):
        return ""

    for ref in refs:
        if not isinstance(ref, dict):
            continue
        locator = str(ref.get("referenceLocator") or "").strip()
        if not locator:
            continue
        ref_type = str(ref.get("referenceType") or "").strip().lower()
        if ref_type == "purl" or locator.startswith("pkg:"):
            return locator

    return ""


def parse_purl_to_osv(purl: str) -> tuple[str | None, str | None, str | None]:
    """Map a package URL (purl) to OSV ecosystem/name/version when possible."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None, None, None

    body = purl[4:]
    body = body.split("#", 1)[0]
    body = body.split("?", 1)[0]
    if "/" not in body:
        return None, None, None

    purl_type, remainder = body.split("/", 1)
    purl_type = purl_type.strip().lower()
    path, _, version = remainder.partition("@")
    decoded_path = unquote(path.strip("/"))
    version = version.strip() or None

    if not decoded_path:
        return None, None, version

    ecosystem = _PURL_TO_OSV_ECOSYSTEM.get(purl_type)
    name: str | None = None

    if purl_type == "maven":
        # purl: pkg:maven/group/artifact@version
        segments = [s for s in decoded_path.split("/") if s]
        if len(segments) >= 2:
            group = ".".join(segments[:-1])
            name = f"{group}:{segments[-1]}"
        else:
            name = decoded_path.replace("/", ":")
    elif purl_type == "npm":
        # Supports scoped and unscoped package names.
        segments = [s for s in decoded_path.split("/") if s]
        if len(segments) >= 2 and segments[0].startswith("@"):
            name = f"{segments[0]}/{segments[-1]}"
        elif segments:
            name = segments[-1]
    elif purl_type == "composer":
        name = decoded_path
    elif purl_type in {"go", "golang"}:
        name = decoded_path
    else:
        segments = [s for s in decoded_path.split("/") if s]
        if segments:
            name = segments[-1]

    return ecosystem, name, version


def classify_package_for_osv(
    package_name: str,
    purl: str,
    version: str,
) -> dict[str, Any]:
    """Decide if a package is queryable against OSV and normalize query fields."""
    fallback_name = (package_name or "").strip()
    normalized_version = (version or "").strip() or None

    ecosystem = None
    query_name = fallback_name

    if purl:
        purl_ecosystem, purl_name, purl_version = parse_purl_to_osv(purl)
        ecosystem = purl_ecosystem
        if purl_name:
            query_name = purl_name
        if purl_version and not normalized_version:
            normalized_version = purl_version

    if not query_name:
        return {
            "queryable": False,
            "query_reason": "missing package name",
            "ecosystem": None,
            "query_name": "",
            "version": normalized_version,
        }

    if not ecosystem:
        return {
            "queryable": False,
            "query_reason": "missing ecosystem mapping from purl",
            "ecosystem": None,
            "query_name": query_name,
            "version": normalized_version,
        }

    return {
        "queryable": True,
        "query_reason": "",
        "ecosystem": ecosystem,
        "query_name": query_name,
        "version": normalized_version,
    }


def parse_sbom_packages(sbom_payload: dict[str, Any]) -> tuple[list[dict[str, Any]], int, int]:
    """Extract and normalize dependency package records from a GitHub SBOM payload.

    Returns:
      (normalized_packages, raw_package_count, filtered_self_package_count)
    """
    sbom_doc = sbom_payload.get("sbom") if isinstance(sbom_payload, dict) else None
    if not isinstance(sbom_doc, dict):
        sbom_doc = sbom_payload if isinstance(sbom_payload, dict) else {}

    raw_packages = sbom_doc.get("packages")
    relationships = sbom_doc.get("relationships")
    if not isinstance(raw_packages, list):
        raw_packages = []
    if not isinstance(relationships, list):
        relationships = []

    described_ids: set[str] = set()
    for rel in relationships:
        if not isinstance(rel, dict):
            continue
        if str(rel.get("relationshipType") or "").upper() != "DESCRIBES":
            continue
        src = str(rel.get("spdxElementId") or "")
        dst = str(rel.get("relatedSpdxElement") or "")
        if dst and (src.endswith("DOCUMENT") or src == "SPDXRef-DOCUMENT"):
            described_ids.add(dst)

    filtered_self = 0
    deduped: dict[tuple[str, str, str, str], dict[str, Any]] = {}

    for pkg in raw_packages:
        if not isinstance(pkg, dict):
            continue

        spdx_id = str(pkg.get("SPDXID") or "")
        if spdx_id and spdx_id in described_ids:
            filtered_self += 1
            continue

        name = str(pkg.get("name") or "").strip()
        if not name:
            continue

        version = str(pkg.get("versionInfo") or "").strip()
        purl = _extract_purl(pkg)
        query_meta = classify_package_for_osv(name, purl, version)

        record = {
            "name": name,
            "version": query_meta.get("version"),
            "purl": purl or "",
            "ecosystem": query_meta.get("ecosystem"),
            "query_name": query_meta.get("query_name", name),
            "queryable": bool(query_meta.get("queryable")),
            "query_reason": str(query_meta.get("query_reason") or ""),
            "vulnerability_ids": [],
            "vulnerability_count": 0,
        }

        key = (
            str(record["ecosystem"] or ""),
            str(record["query_name"] or "").lower(),
            str(record["version"] or ""),
            str(record["purl"] or ""),
        )

        existing = deduped.get(key)
        if existing is None:
            deduped[key] = record
            continue

        # Prefer the most queryable/complete variant for duplicate package rows.
        if not existing["queryable"] and record["queryable"]:
            deduped[key] = record
            continue
        if not existing.get("purl") and record.get("purl"):
            deduped[key] = record

    packages = list(deduped.values())
    packages.sort(key=lambda p: ((p.get("ecosystem") or "zzzz"), (p.get("query_name") or ""), (p.get("version") or "")))
    return packages, len(raw_packages), filtered_self


def _chunked(items: list[dict[str, Any]], size: int) -> list[list[dict[str, Any]]]:
    if size <= 0:
        size = 100
    return [items[i:i + size] for i in range(0, len(items), size)]


def _query_osv_for_packages(packages: list[dict[str, Any]]) -> list[str]:
    """Query OSV in batches and annotate package records in-place."""
    errors: list[str] = []
    queryable = [pkg for pkg in packages if pkg.get("queryable")]
    if not queryable:
        return errors

    batch_size = max(1, config.OSV_QUERY_BATCH_SIZE)
    url = f"{config.OSV_API_BASE.rstrip('/')}/v1/querybatch"

    with requests.Session() as session:
        for batch in _chunked(queryable, batch_size):
            queries: list[dict[str, Any]] = []
            for pkg in batch:
                query: dict[str, Any] = {
                    "package": {
                        "name": pkg["query_name"],
                        "ecosystem": pkg["ecosystem"],
                    }
                }
                if pkg.get("version"):
                    query["version"] = pkg["version"]
                queries.append(query)

            payload, err = _request_json(
                session,
                "POST",
                url,
                headers={"Content-Type": "application/json"},
                payload={"queries": queries},
            )
            if err:
                errors.append(err)
                for pkg in batch:
                    if not pkg.get("query_reason"):
                        pkg["query_reason"] = err
                continue

            if not isinstance(payload, dict) or not isinstance(payload.get("results"), list):
                malformed = "OSV querybatch returned malformed payload"
                errors.append(malformed)
                for pkg in batch:
                    if not pkg.get("query_reason"):
                        pkg["query_reason"] = malformed
                continue

            results = payload["results"]
            for idx, pkg in enumerate(batch):
                result_item = results[idx] if idx < len(results) and isinstance(results[idx], dict) else {}
                vulns = result_item.get("vulns") if isinstance(result_item.get("vulns"), list) else []
                vuln_ids = sorted({str(v.get("id")) for v in vulns if isinstance(v, dict) and v.get("id")})
                pkg["vulnerability_ids"] = vuln_ids
                pkg["vulnerability_count"] = len(vuln_ids)

    return errors


def _empty_severity_counts() -> dict[str, int]:
    return {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0,
    }


def _severity_from_score(score: str) -> str:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return "UNKNOWN"

    if value >= 9.0:
        return "CRITICAL"
    if value >= 7.0:
        return "HIGH"
    if value >= 4.0:
        return "MEDIUM"
    if value > 0:
        return "LOW"
    return "UNKNOWN"


def _normalize_severity(vuln_payload: dict[str, Any]) -> str:
    db_specific = vuln_payload.get("database_specific")
    if isinstance(db_specific, dict):
        db_sev = str(db_specific.get("severity") or "").strip().upper()
        if db_sev == "MODERATE":
            return "MEDIUM"
        if db_sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
            return db_sev

    severity_items = vuln_payload.get("severity")
    if isinstance(severity_items, list):
        for item in severity_items:
            if not isinstance(item, dict):
                continue
            maybe = _severity_from_score(str(item.get("score") or "").strip())
            if maybe != "UNKNOWN":
                return maybe

    return "UNKNOWN"


def _severity_rank(level: str) -> int:
    order = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
        "UNKNOWN": 0,
    }
    return order.get(str(level or "UNKNOWN").upper(), 0)


def _bump_severity(counts: dict[str, int], severity: str) -> None:
    key = str(severity or "UNKNOWN").strip().lower()
    if key not in counts:
        key = "unknown"
    counts[key] += 1


def _normalize_vulnerability_detail(vuln_id: str, payload: dict[str, Any] | None, error: str = "") -> dict[str, Any]:
    data = payload if isinstance(payload, dict) else {}
    aliases = data.get("aliases") if isinstance(data.get("aliases"), list) else []
    summary = str(data.get("summary") or data.get("details") or "").strip()
    severity = _normalize_severity(data)
    return {
        "id": vuln_id,
        "summary": summary,
        "aliases": [str(a) for a in aliases],
        "severity": severity,
        "published": str(data.get("published") or ""),
        "modified": str(data.get("modified") or ""),
        "error": error,
    }


def _fetch_vulnerability_details(vulnerability_ids: list[str]) -> dict[str, dict[str, Any]]:
    """Fetch OSV vulnerability documents, keyed by vulnerability id."""
    unique_ids = sorted({vid for vid in vulnerability_ids if vid})
    if not unique_ids:
        return {}

    url_base = f"{config.OSV_API_BASE.rstrip('/')}/v1/vulns"
    max_workers = max(1, min(config.DEPENDENCY_MAX_WORKERS, 8))

    def fetch_one(vuln_id: str) -> tuple[str, dict[str, Any]]:
        url = f"{url_base}/{quote(vuln_id, safe='')}"
        with requests.Session() as session:
            payload, err = _request_json(session, "GET", url)
        if err:
            return vuln_id, _normalize_vulnerability_detail(vuln_id, None, error=err)
        return vuln_id, _normalize_vulnerability_detail(vuln_id, payload if isinstance(payload, dict) else None)

    results: dict[str, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(fetch_one, vid): vid for vid in unique_ids}
        for fut in as_completed(future_map):
            vid = future_map[fut]
            try:
                key, detail = fut.result()
                results[key] = detail
            except Exception as exc:
                results[vid] = _normalize_vulnerability_detail(vid, None, error=f"detail fetch failed: {exc}")

    return results


def analyze_repo_dependencies(entry: RepoEntry) -> dict[str, Any]:
    """Analyze one repository's dependency vulnerabilities."""
    out_path = _repo_output_path(entry)

    if _should_skip(entry):
        try:
            cached = json.loads(out_path.read_text(encoding="utf-8"))
            if isinstance(cached, dict) and cached.get("repo_url") == entry.repo_url:
                logger.info("[dependency] Using cached result for %s/%s", entry.owner, entry.repo_name)
                return cached
        except Exception as exc:
            logger.warning(
                "[dependency] Cached file unreadable for %s/%s, re-running: %s",
                entry.owner,
                entry.repo_name,
                exc,
            )

    sbom_payload, sbom_error = _fetch_github_sbom(entry)
    if sbom_error:
        result = {
            "repo_url": entry.repo_url,
            "owner": entry.owner,
            "repo_name": entry.repo_name,
            "status": "failed",
            "error": sbom_error,
            "sbom_package_count": 0,
            "filtered_self_packages": 0,
            "packages_total": 0,
            "packages_queryable": 0,
            "packages_unqueryable": 0,
            "vulnerability_ids": [],
            "vulnerabilities_total": 0,
            "severity": _empty_severity_counts(),
            "packages": [],
            "vulnerabilities": [],
        }
        _persist(out_path, result)
        return result

    packages, raw_package_count, filtered_self = parse_sbom_packages(sbom_payload or {})
    osv_errors = _query_osv_for_packages(packages)

    vulnerability_ids: set[str] = set()
    for pkg in packages:
        for vid in pkg.get("vulnerability_ids", []):
            vulnerability_ids.add(str(vid))

    status = "success"
    error = ""
    if osv_errors:
        status = "partial"
        error = "; ".join(sorted(set(osv_errors)))[:1200]

    result = {
        "repo_url": entry.repo_url,
        "owner": entry.owner,
        "repo_name": entry.repo_name,
        "status": status,
        "error": error,
        "sbom_package_count": raw_package_count,
        "filtered_self_packages": filtered_self,
        "packages_total": len(packages),
        "packages_queryable": sum(1 for p in packages if p.get("queryable")),
        "packages_unqueryable": sum(1 for p in packages if not p.get("queryable")),
        "vulnerability_ids": sorted(vulnerability_ids),
        "vulnerabilities_total": len(vulnerability_ids),
        "severity": _empty_severity_counts(),
        "packages": packages,
        "vulnerabilities": [],
    }
    _persist(out_path, result)
    return result


def build_dependency_report(
    entries: list[RepoEntry],
    repo_results: list[dict[str, Any]],
    vulnerability_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Build final dependency artifact from per-repo analysis + vulnerability docs."""
    by_url = {str(r.get("repo_url") or ""): r for r in repo_results}
    ordered_repos: list[dict[str, Any]] = []

    for entry in entries:
        row = by_url.get(entry.repo_url)
        if row is None:
            row = {
                "repo_url": entry.repo_url,
                "owner": entry.owner,
                "repo_name": entry.repo_name,
                "status": "failed",
                "error": "missing dependency analysis result",
                "sbom_package_count": 0,
                "filtered_self_packages": 0,
                "packages_total": 0,
                "packages_queryable": 0,
                "packages_unqueryable": 0,
                "vulnerability_ids": [],
                "vulnerabilities_total": 0,
                "severity": _empty_severity_counts(),
                "packages": [],
                "vulnerabilities": [],
            }

        sev = _empty_severity_counts()
        repo_vulns: list[dict[str, Any]] = []
        for vuln_id in row.get("vulnerability_ids", []):
            detail = vulnerability_index.get(vuln_id) or _normalize_vulnerability_detail(vuln_id, None, error="missing detail")
            repo_vulns.append(detail)
            _bump_severity(sev, detail.get("severity", "UNKNOWN"))

        row["vulnerabilities"] = sorted(
            repo_vulns,
            key=lambda v: (-_severity_rank(v.get("severity", "UNKNOWN")), str(v.get("id") or "")),
        )
        row["vulnerabilities_total"] = len(row["vulnerabilities"])
        row["severity"] = sev
        ordered_repos.append(row)

    # Global vulnerability rollup
    vulnerability_rollup: list[dict[str, Any]] = []
    for vuln_id, detail in vulnerability_index.items():
        affected_repos = [
            repo for repo in ordered_repos
            if vuln_id in set(str(x) for x in repo.get("vulnerability_ids", []))
        ]
        if not affected_repos:
            continue

        affected_package_count = 0
        for repo in affected_repos:
            for pkg in repo.get("packages", []):
                if vuln_id in set(str(x) for x in pkg.get("vulnerability_ids", [])):
                    affected_package_count += 1

        vulnerability_rollup.append({
            "id": vuln_id,
            "summary": detail.get("summary", ""),
            "aliases": detail.get("aliases", []),
            "severity": detail.get("severity", "UNKNOWN"),
            "affected_repo_count": len(affected_repos),
            "affected_package_count": affected_package_count,
        })

    vulnerability_rollup.sort(
        key=lambda r: (
            -_severity_rank(str(r.get("severity") or "UNKNOWN")),
            -int(r.get("affected_repo_count") or 0),
            str(r.get("id") or ""),
        )
    )

    totals_severity = _empty_severity_counts()
    for repo in ordered_repos:
        sev = repo.get("severity") if isinstance(repo.get("severity"), dict) else {}
        for key in totals_severity:
            totals_severity[key] += int(sev.get(key, 0) if isinstance(sev, dict) else 0)

    repos_failed = sum(1 for r in ordered_repos if r.get("status") == "failed")
    repos_partial = sum(1 for r in ordered_repos if r.get("status") == "partial")
    repos_analyzed = sum(1 for r in ordered_repos if r.get("status") in {"success", "partial"})

    report_status = "success"
    if repos_failed == len(ordered_repos) and ordered_repos:
        report_status = "failed"
    elif repos_failed > 0 or repos_partial > 0:
        report_status = "partial"

    totals = {
        "repos_total": len(entries),
        "repos_analyzed": repos_analyzed,
        "repos_failed": repos_failed,
        "repos_with_vulnerabilities": sum(1 for r in ordered_repos if int(r.get("vulnerabilities_total", 0)) > 0),
        "packages_total": sum(int(r.get("packages_total", 0)) for r in ordered_repos),
        "packages_queryable": sum(int(r.get("packages_queryable", 0)) for r in ordered_repos),
        "packages_unqueryable": sum(int(r.get("packages_unqueryable", 0)) for r in ordered_repos),
        "vulnerabilities_total": sum(int(r.get("vulnerabilities_total", 0)) for r in ordered_repos),
        "unique_vulnerability_ids": len(vulnerability_rollup),
        "severity": totals_severity,
    }

    return {
        "generated_at": _now_iso(),
        "status": report_status,
        "notes": [],
        "totals": totals,
        "vulnerabilities": vulnerability_rollup,
        "repos": ordered_repos,
    }


def run_dependency_analysis_batch(entries: list[RepoEntry]) -> dict[str, Any]:
    """Run dependency vulnerability analysis for all repositories and persist output."""
    config.RAW_DEPENDENCY_DIR.mkdir(parents=True, exist_ok=True)
    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)

    if not config.GITHUB_AUTH_TOKEN:
        logger.warning(
            "[dependency] GITHUB_AUTH_TOKEN is not set. Public rate limits may reduce SBOM coverage."
        )

    max_workers = max(1, config.DEPENDENCY_MAX_WORKERS)
    repo_results: list[dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {
            executor.submit(analyze_repo_dependencies, entry): entry
            for entry in entries
        }
        for fut in as_completed(future_map):
            entry = future_map[fut]
            try:
                repo_results.append(fut.result())
            except Exception as exc:
                logger.error(
                    "[dependency] %s/%s analysis failed: %s",
                    entry.owner,
                    entry.repo_name,
                    exc,
                )
                repo_results.append({
                    "repo_url": entry.repo_url,
                    "owner": entry.owner,
                    "repo_name": entry.repo_name,
                    "status": "failed",
                    "error": f"unexpected analysis error: {exc}",
                    "sbom_package_count": 0,
                    "filtered_self_packages": 0,
                    "packages_total": 0,
                    "packages_queryable": 0,
                    "packages_unqueryable": 0,
                    "vulnerability_ids": [],
                    "vulnerabilities_total": 0,
                    "severity": _empty_severity_counts(),
                    "packages": [],
                    "vulnerabilities": [],
                })

    all_vulnerability_ids: list[str] = []
    for repo in repo_results:
        all_vulnerability_ids.extend([str(v) for v in repo.get("vulnerability_ids", [])])

    vulnerability_index = _fetch_vulnerability_details(all_vulnerability_ids)
    report = build_dependency_report(entries, repo_results, vulnerability_index)

    config.DEPENDENCY_REPORT_FILE.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Wrote %s", config.DEPENDENCY_REPORT_FILE.name)
    return report


def write_empty_dependency_report(entries: list[RepoEntry], reason: str) -> dict[str, Any]:
    """Write an empty dependency analysis artifact (used when stage is skipped)."""
    report = {
        "generated_at": _now_iso(),
        "status": "skipped",
        "notes": [reason] if reason else [],
        "totals": {
            "repos_total": len(entries),
            "repos_analyzed": 0,
            "repos_failed": 0,
            "repos_with_vulnerabilities": 0,
            "packages_total": 0,
            "packages_queryable": 0,
            "packages_unqueryable": 0,
            "vulnerabilities_total": 0,
            "unique_vulnerability_ids": 0,
            "severity": _empty_severity_counts(),
        },
        "vulnerabilities": [],
        "repos": [
            {
                "repo_url": e.repo_url,
                "owner": e.owner,
                "repo_name": e.repo_name,
                "status": "skipped",
                "error": reason,
                "sbom_package_count": 0,
                "filtered_self_packages": 0,
                "packages_total": 0,
                "packages_queryable": 0,
                "packages_unqueryable": 0,
                "vulnerability_ids": [],
                "vulnerabilities_total": 0,
                "severity": _empty_severity_counts(),
                "packages": [],
                "vulnerabilities": [],
            }
            for e in entries
        ],
    }

    config.PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    config.DEPENDENCY_REPORT_FILE.write_text(
        json.dumps(report, indent=2, default=str),
        encoding="utf-8",
    )
    logger.info("Wrote %s", config.DEPENDENCY_REPORT_FILE.name)
    return report
