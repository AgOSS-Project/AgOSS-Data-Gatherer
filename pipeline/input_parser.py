"""Parse input files into a list of RepoEntry objects."""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path

from pipeline.models import RepoEntry

logger = logging.getLogger("pipeline.input_parser")

_GITHUB_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/,\s]+?)/?$"
)

_TRUE_VALUES = {"yes", "y", "true", "t", "1"}
_FALSE_VALUES = {"no", "n", "false", "f", "0"}


def parse_input(input_path: Path) -> list[RepoEntry]:
    """Read *input_path* and return a list of validated :class:`RepoEntry`.

    Supported formats:
      1) Legacy 2-column: ``url, category``
      2) CSV 4-column: ``name, url, category, ag_specific``

    Blank/comment rows are skipped; malformed rows are logged and skipped.
    """
    entries: list[RepoEntry] = []
    with input_path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.reader(fh)
        for lineno, row in enumerate(reader, start=1):
            normalized = [cell.strip() for cell in row]
            if not normalized:
                continue
            if len(normalized) == 1 and not normalized[0]:
                continue
            if normalized[0].startswith("#"):
                continue
            if _is_header_row(normalized):
                logger.debug("Line %d: header row detected; skipping", lineno)
                continue

            entry = _parse_row(normalized, lineno)
            if not entry:
                continue

            entries.append(entry)
            logger.debug(
                "Parsed: %s/%s  [%s] ag_specific=%s",
                entry.owner,
                entry.repo_name,
                entry.category,
                entry.ag_specific,
            )

    logger.info("Parsed %d valid repo entries from %s", len(entries), input_path.name)
    return entries


def _parse_row(row: list[str], lineno: int) -> RepoEntry | None:
    if len(row) >= 4:
        display_name = row[0]
        url_part = row[1].rstrip("/")
        category = row[2]
        ag_specific = _parse_ag_specific(row[3], lineno)
    elif len(row) == 2:
        display_name = ""
        url_part = row[0].rstrip("/")
        category = row[1]
        ag_specific = None
    else:
        logger.warning(
            "Line %d: expected either 2 columns (url, category) or 4 columns "
            "(name, url, category, ag_specific) — skipping: %s",
            lineno,
            row,
        )
        return None

    m = _GITHUB_RE.match(url_part + "/")  # add trailing slash for regex
    if not m:
        logger.warning("Line %d: could not parse GitHub URL — skipping: %s", lineno, url_part)
        return None

    owner = m.group("owner")
    repo_name = m.group("repo")
    resolved_display_name = display_name or repo_name

    return RepoEntry(
        display_name=resolved_display_name,
        repo_url=url_part,
        owner=owner,
        repo_name=repo_name,
        category=category,
        ag_specific=ag_specific,
        line_number=lineno,
    )


def _parse_ag_specific(raw_value: str, lineno: int) -> bool | None:
    value = (raw_value or "").strip().lower()
    if not value:
        return None
    if value in _TRUE_VALUES:
        return True
    if value in _FALSE_VALUES:
        return False

    logger.warning(
        "Line %d: could not parse ag_specific value '%s' (expected yes/no, true/false, 1/0); storing null",
        lineno,
        raw_value,
    )
    return None


def _is_header_row(row: list[str]) -> bool:
    lower = [c.strip().lower() for c in row]
    joined = " ".join(lower)
    has_name = any(c in {"name", "repo", "repository", "repo_name"} for c in lower)
    has_url = any("url" in c or "link" in c for c in lower)
    has_category = any("category" in c for c in lower)

    # Detect explicit header columns like "ag-specific" or variants such as
    # "ag specific" / "ag_specific" but avoid matching occurrences where
    # words like "agricultural" and "domain-specific" appear separately in
    # the category text (which would be a valid data row).
    import re
    has_ag = bool(re.search(r"\bag(?:-|_)?specific\b", joined)) or "ag-specific" in joined

    return (has_name and has_url and has_category) or has_ag
