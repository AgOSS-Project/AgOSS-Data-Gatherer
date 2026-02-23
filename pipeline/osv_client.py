"""
osv_client.py – OSV.dev querybatch logic.

Queries the OSV /v1/querybatch endpoint using purls extracted from
each repo's SBOM.  Results are aligned 1-to-1 with input ordering.
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional, Tuple

import requests

from .models import DepResult


def _post_json(
    url: str,
    payload: Any,
    timeout: int = 90,
    retries: int = 3,
) -> Tuple[Optional[Any], Optional[int], Optional[str]]:
    last_err: Optional[str] = None
    for attempt in range(retries):
        try:
            resp = requests.post(
                url,
                json=payload,
                headers={"User-Agent": "repo-risk-pipeline/1.0"},
                timeout=timeout,
            )
            if 200 <= resp.status_code < 300:
                return resp.json(), resp.status_code, None
            if resp.status_code in (400, 401, 403, 404):
                return None, resp.status_code, resp.text[:500]
            last_err = f"HTTP {resp.status_code}: {resp.text[:500]}"
        except Exception as exc:
            last_err = repr(exc)
        time.sleep(1.0 * (attempt + 1))
    return None, None, last_err


def osv_querybatch(
    purls: List[str],
    chunk_size: int = 500,
) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
    """Query OSV for all *purls* and return the ordered results list."""
    if not purls:
        return [], None

    all_results: List[Dict[str, Any]] = []
    for i in range(0, len(purls), chunk_size):
        chunk = purls[i : i + chunk_size]
        payload = {"queries": [{"package": {"purl": p}} for p in chunk]}
        data, status, err = _post_json(
            "https://api.osv.dev/v1/querybatch",
            payload=payload,
        )
        if data is None:
            return None, f"osv_querybatch_failed status={status} err={err}"
        all_results.extend(data.get("results", []))

    return all_results, None


def build_dep_results(
    purls: List[str],
    osv_results: List[Dict[str, Any]],
) -> List[DepResult]:
    """Zip purls with OSV results into a list of :class:`DepResult`."""
    deps: List[DepResult] = []
    for idx, purl in enumerate(purls):
        vulns_raw = (osv_results[idx] if idx < len(osv_results) else {}) or {}
        vuln_entries = vulns_raw.get("vulns") or []
        ids = sorted(
            {v.get("id") for v in vuln_entries if isinstance(v, dict) and v.get("id")}
        )
        deps.append(DepResult(
            purl=purl,
            vulnerable=bool(ids),
            vuln_ids=ids,
        ))
    return deps
