"""
render.py – Generate output/report.html from report.data.json.

Can be called standalone:
    python -m pipeline.report.render output/report.data.json output/report.html

Or via the ``render_report()`` function from `main.py`.
"""
from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict

_HERE = Path(__file__).resolve().parent
_TEMPLATE = _HERE / "template.html"
_STYLES = _HERE / "styles.css"


def _esc(val: Any) -> str:
    """Minimal HTML escaping."""
    return str(val).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _fmt_list(items: list, cap: int = 5) -> str:
    """Render a list as comma-separated string, capped."""
    if not items:
        return ""
    shown = items[:cap]
    suffix = f" (+{len(items) - cap} more)" if len(items) > cap else ""
    return ", ".join(_esc(str(i)) for i in shown) + suffix


def _render_repo_table(rows: list) -> str:
    lines = []
    for r in rows:
        sc = r.get("scorecard_score")
        sc_str = f'{sc}' if sc is not None else "N/A"
        rr = r.get("reporeaper_score")
        rr_str = f'{rr}' if rr is not None else "N/A"
        status_cls = "status-ok" if r["status"] == "ok" else (
            "status-partial" if r["status"] == "partial" else "status-failed"
        )
        vuln_cls = "vuln-highlight" if r["vulnerable_dep_count"] > 0 else ""
        lines.append(
            f'<tr class="{vuln_cls}">'
            f'<td><a href="https://github.com/{_esc(r["slug"])}" target="_blank">{_esc(r["slug"])}</a></td>'
            f'<td>{_esc(r["repo_type"])}</td>'
            f'<td>{_esc(r["language"] or "—")}</td>'
            f'<td class="num">{r["stars"]:,}</td>'
            f'<td>{_esc(r["pushed_at"][:10] if r["pushed_at"] else "—")}</td>'
            f'<td class="num">{r["dep_count"]}</td>'
            f'<td class="num">{r["vulnerable_dep_count"]}</td>'
            f'<td class="num">{r["vuln_id_count"]}</td>'
            f'<td>{sc_str}</td>'
            f'<td>{rr_str}</td>'
            f'<td class="{status_cls}">{_esc(r["status"])}</td>'
            f'</tr>'
        )
    return "\n".join(lines)


def _render_top_deps(items: list) -> str:
    lines = []
    for i, d in enumerate(items, 1):
        vuln_str = ", ".join(_esc(v) for v in d.get("vuln_ids", [])[:10])
        if len(d.get("vuln_ids", [])) > 10:
            vuln_str += f' (+{len(d["vuln_ids"]) - 10} more)'
        lines.append(
            f'<tr>'
            f'<td class="num">{i}</td>'
            f'<td class="purl">{_esc(d["purl"])}</td>'
            f'<td class="num">{d["occurrences"]}</td>'
            f'<td>{"Yes" if d.get("vulnerable") else "No"}</td>'
            f'<td class="num">{len(d.get("vuln_ids", []))}</td>'
            f'<td>{vuln_str or "—"}</td>'
            f'</tr>'
        )
    return "\n".join(lines)


def _render_by_type(rows: list) -> str:
    lines = []
    for r in rows:
        lines.append(
            f'<tr>'
            f'<td>{_esc(r["type"])}</td>'
            f'<td class="num">{r["repo_count"]}</td>'
            f'<td class="num">{r["unique_dep_count"]}</td>'
            f'<td class="num">{r["vulnerable_unique_dep_count"]}</td>'
            f'<td class="num">{r["unique_vuln_count"]}</td>'
            f'</tr>'
        )
    return "\n".join(lines)


def _render_top_vulns(items: list) -> str:
    lines = []
    for v in items:
        repos_str = _fmt_list(v.get("repos", []), cap=5)
        types_str = ", ".join(_esc(t) for t in v.get("types", []))
        lines.append(
            f'<tr>'
            f'<td class="vuln-id">{_esc(v["id"])}</td>'
            f'<td class="num">{v["affected_repo_count"]}</td>'
            f'<td class="num">{v["affected_dependency_count"]}</td>'
            f'<td>{types_str or "—"}</td>'
            f'<td>{repos_str or "—"}</td>'
            f'</tr>'
        )
    return "\n".join(lines)


def render_report(data: Dict[str, Any], output_dir: str) -> str:
    """Write report.html + styles.css to *output_dir* and return the HTML path."""
    os.makedirs(output_dir, exist_ok=True)

    # Read template
    template = _TEMPLATE.read_text(encoding="utf-8")

    # Build replacement map
    replacements = {
        "{{GENERATED_AT}}": _esc(data.get("generated_at", "")),
        "{{REPO_COUNT}}": str(data.get("repo_count", 0)),
        "{{REPOS_WITH_VULNS}}": str(data.get("repos_with_vulnerabilities", 0)),
        "{{UNIQUE_DEP_COUNT}}": f'{data.get("unique_dependency_count", 0):,}',
        "{{VULN_UNIQUE_DEP_COUNT}}": f'{data.get("vulnerable_unique_dependency_count", 0):,}',
        "{{UNIQUE_VULN_COUNT}}": f'{data.get("unique_vulnerability_count", 0):,}',
        "{{REPO_TABLE_ROWS}}": _render_repo_table(data.get("repo_table", [])),
        "{{TOP_DEPS_ROWS}}": _render_top_deps(data.get("top_dependencies", [])),
        "{{TOP_VULN_DEPS_ROWS}}": _render_top_deps(data.get("top_vulnerable_dependencies", [])),
        "{{BY_TYPE_ROWS}}": _render_by_type(data.get("by_type", [])),
        "{{TOP_VULNS_ROWS}}": _render_top_vulns(data.get("top_vulnerabilities", [])),
    }

    html = template
    for placeholder, value in replacements.items():
        html = html.replace(placeholder, value)

    # Write outputs
    html_path = os.path.join(output_dir, "report.html")
    css_path = os.path.join(output_dir, "styles.css")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)
    shutil.copy2(str(_STYLES), css_path)

    return html_path


# Allow direct invocation for debugging
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python -m pipeline.report.render <report.data.json> [output_dir]")
        sys.exit(1)
    data_path = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) > 2 else "output"
    with open(data_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    path = render_report(data, out_dir)
    print(f"Wrote {path}")
