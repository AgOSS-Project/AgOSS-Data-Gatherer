"""
aggregate.py – Build global and by-type rollups from per-repo results.

Produces:
  * deps.aggregate.json  – dependency rollup (global + by_type)
  * vulns.aggregate.json – vulnerability rollup
  * report.data.json     – data blob consumed by the HTML report
"""
from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List

from .models import RepoResult


# -----------------------------------------------------------------------
# Dependency aggregation
# -----------------------------------------------------------------------

def _empty_dep_entry() -> Dict[str, Any]:
    return {
        "occurrences": 0,
        "vulnerable": False,
        "vuln_ids": set(),
        "repos": set(),
        "types": set(),
    }


def _finalise_dep_map(dep_map: Dict[str, Dict[str, Any]], cap_repos: int = 50) -> Dict[str, Any]:
    """Convert sets → sorted lists and apply repo-list cap."""
    out: Dict[str, Any] = {}
    for key in sorted(dep_map):
        e = dep_map[key]
        out[key] = {
            "occurrences": e["occurrences"],
            "vulnerable": e["vulnerable"],
            "vuln_ids": sorted(e["vuln_ids"]),
            "repos": sorted(e["repos"])[:cap_repos],
            "types": sorted(e["types"]),
        }
    return out


def build_dep_aggregate(results: List[RepoResult]) -> Dict[str, Any]:
    """Return the full deps.aggregate.json payload."""
    global_map: Dict[str, Dict[str, Any]] = {}
    type_maps: Dict[str, Dict[str, Dict[str, Any]]] = {}

    for r in results:
        t = r.repo_type or "Unknown"
        if t not in type_maps:
            type_maps[t] = {}

        for dep in r.dependencies:
            key = dep.purl

            # --- global ---
            if key not in global_map:
                global_map[key] = _empty_dep_entry()
            g = global_map[key]
            g["occurrences"] += 1
            if dep.vulnerable:
                g["vulnerable"] = True
            g["vuln_ids"].update(dep.vuln_ids)
            g["repos"].add(r.slug)
            g["types"].add(t)

            # --- per type ---
            tm = type_maps[t]
            if key not in tm:
                tm[key] = _empty_dep_entry()
            te = tm[key]
            te["occurrences"] += 1
            if dep.vulnerable:
                te["vulnerable"] = True
            te["vuln_ids"].update(dep.vuln_ids)
            te["repos"].add(r.slug)
            te["types"].add(t)

    # Summarise global
    final_global = _finalise_dep_map(global_map)
    vuln_unique = sum(1 for v in final_global.values() if v["vulnerable"])
    vuln_occ = sum(v["occurrences"] for v in final_global.values() if v["vulnerable"])

    global_section = {
        "unique_dependency_count": len(final_global),
        "dependency_occurrence_count": sum(v["occurrences"] for v in final_global.values()),
        "vulnerable_unique_dependency_count": vuln_unique,
        "vulnerable_dependency_occurrence_count": vuln_occ,
        "dependencies": final_global,
    }

    # Summarise by_type
    by_type: Dict[str, Any] = {}
    for t, tm in sorted(type_maps.items()):
        ftm = _finalise_dep_map(tm)
        v_u = sum(1 for v in ftm.values() if v["vulnerable"])
        v_o = sum(v["occurrences"] for v in ftm.values() if v["vulnerable"])
        by_type[t] = {
            "unique_dependency_count": len(ftm),
            "dependency_occurrence_count": sum(v["occurrences"] for v in ftm.values()),
            "vulnerable_unique_dependency_count": v_u,
            "vulnerable_dependency_occurrence_count": v_o,
            "dependencies": ftm,
        }

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        **global_section,
        "by_type": by_type,
    }


# -----------------------------------------------------------------------
# Vulnerability aggregation
# -----------------------------------------------------------------------

def build_vuln_aggregate(results: List[RepoResult]) -> Dict[str, Any]:
    """Return the full vulns.aggregate.json payload."""
    vuln_map: Dict[str, Dict[str, Any]] = {}

    for r in results:
        t = r.repo_type or "Unknown"
        for dep in r.dependencies:
            for vid in dep.vuln_ids:
                if vid not in vuln_map:
                    vuln_map[vid] = {
                        "affected_dependency_count": 0,
                        "affected_repo_count": 0,
                        "dependencies": set(),
                        "repos": set(),
                        "types": set(),
                    }
                entry = vuln_map[vid]
                entry["dependencies"].add(dep.purl)
                entry["repos"].add(r.slug)
                entry["types"].add(t)

    # Finalise
    final: Dict[str, Any] = {}
    for vid in sorted(vuln_map):
        e = vuln_map[vid]
        final[vid] = {
            "affected_dependency_count": len(e["dependencies"]),
            "affected_repo_count": len(e["repos"]),
            "dependencies": sorted(e["dependencies"]),
            "repos": sorted(e["repos"]),
            "types": sorted(e["types"]),
        }

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "unique_vulnerability_count": len(final),
        "vulnerabilities": final,
    }


# -----------------------------------------------------------------------
# Report data blob
# -----------------------------------------------------------------------

def build_report_data(
    results: List[RepoResult],
    dep_agg: Dict[str, Any],
    vuln_agg: Dict[str, Any],
    *,
    top_deps_n: int = 15,
    top_vuln_deps_n: int = 15,
    top_vulns_n: int = 20,
) -> Dict[str, Any]:
    """Build the JSON blob consumed by the HTML template."""

    # --- repo table rows (sorted by vulnerable_dep_count desc) ---
    repo_rows = sorted(
        [
            {
                "slug": r.slug,
                "repo_type": r.repo_type,
                "language": r.gh_language,
                "stars": r.gh_stars,
                "pushed_at": r.gh_pushed_at,
                "dep_count": r.dep_count,
                "vulnerable_dep_count": r.vulnerable_dep_count,
                "vuln_id_count": r.vuln_id_count,
                "status": r.status,
                "scorecard_score": (r.scorecard.get("score") if r.scorecard.get("available") else None),
                "reporeaper_score": r.reporeaper_lite.get("score_0_100"),
            }
            for r in results
        ],
        key=lambda x: (-x["vulnerable_dep_count"], -x["vuln_id_count"], x["slug"]),
    )

    # --- top deps by occurrences ---
    all_deps = dep_agg.get("dependencies", {})
    top_deps = sorted(
        all_deps.items(),
        key=lambda kv: (-kv[1]["occurrences"], kv[0]),
    )[:top_deps_n]

    # --- top vulnerable deps ---
    vuln_deps_items = [(k, v) for k, v in all_deps.items() if v["vulnerable"]]
    top_vuln_deps = sorted(
        vuln_deps_items,
        key=lambda kv: (-len(kv[1]["vuln_ids"]), -kv[1]["occurrences"], kv[0]),
    )[:top_vuln_deps_n]

    # --- by-type summary ---
    by_type_rows = []
    for t, td in sorted(dep_agg.get("by_type", {}).items()):
        # count unique vulns in this type
        vuln_ids_in_type: set[str] = set()
        for dv in td.get("dependencies", {}).values():
            vuln_ids_in_type.update(dv.get("vuln_ids", []))
        type_repo_count = len({
            r.slug for r in results if (r.repo_type or "Unknown") == t
        })
        by_type_rows.append({
            "type": t,
            "repo_count": type_repo_count,
            "unique_dep_count": td["unique_dependency_count"],
            "vulnerable_unique_dep_count": td["vulnerable_unique_dependency_count"],
            "unique_vuln_count": len(vuln_ids_in_type),
        })

    # --- top vulns by affected_repo_count ---
    all_vulns = vuln_agg.get("vulnerabilities", {})
    top_vulns = sorted(
        all_vulns.items(),
        key=lambda kv: (-kv[1]["affected_repo_count"], -kv[1]["affected_dependency_count"], kv[0]),
    )[:top_vulns_n]

    # --- big numbers ---
    repos_with_vulns = sum(1 for r in results if r.vulnerable_dep_count > 0)
    unique_deps = dep_agg.get("unique_dependency_count", 0)
    vuln_unique_deps = dep_agg.get("vulnerable_unique_dependency_count", 0)
    unique_vulns = vuln_agg.get("unique_vulnerability_count", 0)

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "repo_count": len(results),
        "repos_with_vulnerabilities": repos_with_vulns,
        "unique_dependency_count": unique_deps,
        "vulnerable_unique_dependency_count": vuln_unique_deps,
        "unique_vulnerability_count": unique_vulns,
        "repo_table": repo_rows,
        "top_dependencies": [
            {"purl": k, **v} for k, v in top_deps
        ],
        "top_vulnerable_dependencies": [
            {"purl": k, **v} for k, v in top_vuln_deps
        ],
        "by_type": by_type_rows,
        "top_vulnerabilities": [
            {"id": k, **v} for k, v in top_vulns
        ],
    }
