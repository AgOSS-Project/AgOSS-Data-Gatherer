"""Tests for pipeline/dependency_runner.py.

Covers the pure parsing/classification helpers -- purl-to-OSV-query
translation (parse_purl_to_osv, classify_package_for_osv), SBOM package
extraction with self-package filtering and dedup (parse_sbom_packages) --
plus report aggregation (build_dependency_report) and the higher-level
analyze_repo_dependencies flow, including cache reuse/retry behavior.

analyze_repo_dependencies tests use unittest.mock.patch to stub out
_fetch_github_sbom (no real network calls) and patch.object to override
config.RAW_DEPENDENCY_DIR / config.FORCE_REFRESH per-test, with
tempfile.TemporaryDirectory providing an isolated cache directory so tests
don't touch the real cache on disk.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pipeline import config
from pipeline.dependency_runner import (
    analyze_repo_dependencies,
    build_dependency_report,
    classify_package_for_osv,
    parse_purl_to_osv,
    parse_sbom_packages,
)
from pipeline.models import RepoEntry


def make_entry(owner: str = "octocat", repo: str = "demo") -> RepoEntry:
    """Build a minimal RepoEntry fixture for tests that don't care about its other fields."""
    return RepoEntry(
        display_name=repo,
        repo_url=f"https://github.com/{owner}/{repo}",
        owner=owner,
        repo_name=repo,
        category="Test",
        ag_specific=None,
        line_number=1,
    )


class DependencyRunnerParsingTests(unittest.TestCase):
    def test_parse_purl_to_osv_handles_common_ecosystems(self) -> None:
        """Verify purl strings for Maven and scoped npm packages translate to the (ecosystem, name, version) OSV expects."""
        eco, name, ver = parse_purl_to_osv("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
        self.assertEqual("Maven", eco)
        self.assertEqual("org.apache.commons:commons-lang3", name)
        self.assertEqual("3.12.0", ver)

        # %40 is the URL-encoded "@" that prefixes npm scoped package names.
        eco, name, ver = parse_purl_to_osv("pkg:npm/%40types/node@20.0.0")
        self.assertEqual("npm", eco)
        self.assertEqual("@types/node", name)
        self.assertEqual("20.0.0", ver)

    def test_parse_sbom_filters_self_package_and_dedupes(self) -> None:
        """Verify parse_sbom_packages drops the SBOM's own root package, dedupes repeated packages, and flags unqueryable packages."""
        payload = {
            "sbom": {
                "packages": [
                    {
                        # This is the repo's own package (see DESCRIBES relationship below);
                        # parse_sbom_packages should filter it out of the result.
                        "SPDXID": "SPDXRef-root",
                        "name": "demo",
                        "versionInfo": "1.0.0",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/demo@1.0.0",
                            }
                        ],
                    },
                    {
                        "SPDXID": "SPDXRef-requests",
                        "name": "requests",
                        "versionInfo": "2.31.0",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/requests@2.31.0",
                            }
                        ],
                    },
                    {
                        # Duplicate SPDX entry for the same package+version, to exercise dedup.
                        "SPDXID": "SPDXRef-requests-dup",
                        "name": "requests",
                        "versionInfo": "2.31.0",
                        "externalRefs": [
                            {
                                "referenceType": "purl",
                                "referenceLocator": "pkg:pypi/requests@2.31.0",
                            }
                        ],
                    },
                    {
                        # No externalRefs/purl -> ecosystem can't be determined -> unqueryable.
                        "SPDXID": "SPDXRef-custom",
                        "name": "custom-lib",
                        "versionInfo": "0.1.0",
                    },
                ],
                "relationships": [
                    {
                        "spdxElementId": "SPDXRef-DOCUMENT",
                        "relationshipType": "DESCRIBES",
                        "relatedSpdxElement": "SPDXRef-root",
                    }
                ],
            }
        }

        packages, raw_count, filtered_self = parse_sbom_packages(payload)
        self.assertEqual(4, raw_count)
        self.assertEqual(1, filtered_self)
        self.assertEqual(2, len(packages))

        requests_pkg = next(p for p in packages if p["query_name"] == "requests")
        self.assertTrue(requests_pkg["queryable"])
        self.assertEqual("PyPI", requests_pkg["ecosystem"])

        custom_pkg = next(p for p in packages if p["name"] == "custom-lib")
        self.assertFalse(custom_pkg["queryable"])
        self.assertIn("missing ecosystem", custom_pkg["query_reason"])

    def test_classify_package_for_osv_marks_unqueryable_without_ecosystem(self) -> None:
        """Verify a package with an empty ecosystem string is marked unqueryable with an explanatory reason."""
        classified = classify_package_for_osv("flask", "", "2.2.0")
        self.assertFalse(classified["queryable"])
        self.assertIn("missing ecosystem", classified["query_reason"])


class DependencyRunnerReportTests(unittest.TestCase):
    def test_build_dependency_report_aggregates_totals_and_severity(self) -> None:
        """Verify build_dependency_report aggregates per-repo results into totals, including a mix of success and failure statuses."""
        entries = [make_entry("a", "one"), make_entry("b", "two")]

        repo_results = [
            {
                "repo_url": entries[0].repo_url,
                "owner": entries[0].owner,
                "repo_name": entries[0].repo_name,
                "status": "success",
                "error": "",
                "sbom_package_count": 3,
                "filtered_self_packages": 1,
                "packages_total": 2,
                "packages_queryable": 2,
                "packages_unqueryable": 0,
                "vulnerability_ids": ["CVE-2024-0001", "GHSA-aaaa-bbbb-cccc"],
                "vulnerabilities_total": 2,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                "packages": [
                    {
                        "name": "pkg-a",
                        "query_name": "pkg-a",
                        "ecosystem": "PyPI",
                        "version": "1.0.0",
                        "queryable": True,
                        "query_reason": "",
                        "vulnerability_ids": ["CVE-2024-0001"],
                        "vulnerability_count": 1,
                    },
                    {
                        "name": "pkg-b",
                        "query_name": "pkg-b",
                        "ecosystem": "PyPI",
                        "version": "2.0.0",
                        "queryable": True,
                        "query_reason": "",
                        "vulnerability_ids": ["GHSA-aaaa-bbbb-cccc"],
                        "vulnerability_count": 1,
                    },
                ],
                "vulnerabilities": [],
            },
            {
                "repo_url": entries[1].repo_url,
                "owner": entries[1].owner,
                "repo_name": entries[1].repo_name,
                "status": "failed",
                "error": "sbom unavailable",
                "sbom_package_count": 0,
                "filtered_self_packages": 0,
                "packages_total": 0,
                "packages_queryable": 0,
                "packages_unqueryable": 0,
                "vulnerability_ids": [],
                "vulnerabilities_total": 0,
                "severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0},
                "packages": [],
                "vulnerabilities": [],
            },
        ]

        vulnerability_index = {
            "CVE-2024-0001": {
                "id": "CVE-2024-0001",
                "summary": "critical issue",
                "aliases": [],
                "severity": "CRITICAL",
                "published": "",
                "modified": "",
                "error": "",
            },
            "GHSA-aaaa-bbbb-cccc": {
                "id": "GHSA-aaaa-bbbb-cccc",
                "summary": "medium issue",
                "aliases": [],
                "severity": "MEDIUM",
                "published": "",
                "modified": "",
                "error": "",
            },
        }

        report = build_dependency_report(entries, repo_results, vulnerability_index)
        totals = report["totals"]

        self.assertEqual("partial", report["status"])
        self.assertEqual(2, totals["repos_total"])
        self.assertEqual(1, totals["repos_analyzed"])
        self.assertEqual(1, totals["repos_failed"])
        self.assertEqual(1, totals["repos_with_vulnerabilities"])
        self.assertEqual(2, totals["vulnerabilities_total"])
        self.assertEqual(2, totals["unique_vulnerability_ids"])
        self.assertEqual(1, totals["severity"]["critical"])
        self.assertEqual(1, totals["severity"]["medium"])

    def test_analyze_repo_dependencies_handles_sbom_error_gracefully(self) -> None:
        """Verify a failed SBOM fetch produces a "failed" status result with the error message and empty package/vuln lists, not an exception."""
        entry = make_entry("c", "three")

        # Isolated cache dir + forced refresh so this run doesn't read/write real cache state.
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(config, "RAW_DEPENDENCY_DIR", Path(tmpdir)):
                with patch.object(config, "FORCE_REFRESH", True):
                    with patch("pipeline.dependency_runner._fetch_github_sbom", return_value=(None, "sbom unavailable")):
                        result = analyze_repo_dependencies(entry)

        self.assertEqual("failed", result["status"])
        self.assertIn("sbom unavailable", result["error"])
        self.assertEqual(0, result["packages_total"])
        self.assertEqual([], result["vulnerability_ids"])

    def test_analyze_repo_dependencies_retries_failed_cache(self) -> None:
        """Verify a previously-failed cached result triggers a quick retry: one fetch attempt, no extra retries, and a capped short timeout."""
        entry = make_entry("retry", "me")

        with tempfile.TemporaryDirectory() as tmpdir:
            cache_dir = Path(tmpdir)
            cache_file = cache_dir / "retry__me.json"
            # Pre-seed a cache file with a "failed" prior result so FORCE_REFRESH=False
            # still exercises the quick-retry path instead of returning the cache as-is.
            cache_file.write_text(
                """{
  "repo_url": "https://github.com/retry/me",
  "owner": "retry",
  "repo_name": "me",
  "status": "failed",
  "error": "old failure"
}""",
                encoding="utf-8",
            )

            with patch.object(config, "RAW_DEPENDENCY_DIR", cache_dir):
                with patch.object(config, "FORCE_REFRESH", False):
                    with patch(
                        "pipeline.dependency_runner._fetch_github_sbom",
                        return_value=(None, "sbom unavailable"),
                    ) as mock_fetch:
                        result = analyze_repo_dependencies(entry)

        self.assertEqual(1, mock_fetch.call_count)
        self.assertEqual(0, mock_fetch.call_args.kwargs.get("retry_count"))
        # Retry-after-failed-cache uses a short capped timeout to fail fast, not the full configured timeout.
        self.assertEqual(
            min(10, config.DEPENDENCY_HTTP_TIMEOUT_SECONDS),
            mock_fetch.call_args.kwargs.get("timeout_seconds"),
        )
        self.assertEqual("failed", result["status"])
        self.assertIn("sbom unavailable", result["error"])


if __name__ == "__main__":
    unittest.main()
