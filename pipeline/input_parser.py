"""Parse pipeline/input.txt into a list of RepoEntry objects."""

from __future__ import annotations

import logging
import re
from pathlib import Path

from pipeline.models import RepoEntry

logger = logging.getLogger("pipeline.input_parser")

_GITHUB_RE = re.compile(
    r"^https?://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/,\s]+?)/?$"
)


def parse_input(input_path: Path) -> list[RepoEntry]:
    """Read *input_path* and return a list of validated :class:`RepoEntry`.

    - Blank lines and lines starting with ``#`` are skipped.
    - Malformed lines are logged and skipped.
    - Original order is preserved.
    """
    entries: list[RepoEntry] = []
    text = input_path.read_text(encoding="utf-8")

    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split(",", maxsplit=1)
        if len(parts) != 2:
            logger.warning("Line %d: expected 'url, category' — skipping: %s", lineno, line)
            continue

        url_part = parts[0].strip().rstrip("/")
        category = parts[1].strip()

        m = _GITHUB_RE.match(url_part + "/")  # add trailing slash for regex
        if not m:
            logger.warning("Line %d: could not parse GitHub URL — skipping: %s", lineno, url_part)
            continue

        entry = RepoEntry(
            repo_url=url_part,
            owner=m.group("owner"),
            repo_name=m.group("repo"),
            category=category,
            line_number=lineno,
        )
        entries.append(entry)
        logger.debug("Parsed: %s/%s  [%s]", entry.owner, entry.repo_name, entry.category)

    logger.info("Parsed %d valid repo entries from %s", len(entries), input_path.name)
    return entries
