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
        eco, name, ver = parse_purl_to_osv("pkg:maven/org.apache.commons/commons-lang3@3.12.0")
        self.assertEqual("Maven", eco)
        self.assertEqual("org.apache.commons:commons-lang3", name)
        self.assertEqual("3.12.0", ver)

        eco, name, ver = parse_purl_to_osv("pkg:npm/%40types/node@20.0.0")
        self.assertEqual("npm", eco)
        self.assertEqual("@types/node", name)
        self.assertEqual("20.0.0", ver)

    def test_parse_sbom_filters_self_package_and_dedupes(self) -> None:
        payload = {
            "sbom": {
                "packages": [
                    {
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
        classified = classify_package_for_osv("flask", "", "2.2.0")
        self.assertFalse(classified["queryable"])
        self.assertIn("missing ecosystem", classified["query_reason"])


class DependencyRunnerReportTests(unittest.TestCase):
    def test_build_dependency_report_aggregates_totals_and_severity(self) -> None:
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
        entry = make_entry("c", "three")

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(config, "RAW_DEPENDENCY_DIR", Path(tmpdir)):
                with patch.object(config, "FORCE_REFRESH", True):
                    with patch("pipeline.dependency_runner._fetch_github_sbom", return_value=(None, "sbom unavailable")):
                        result = analyze_repo_dependencies(entry)

        self.assertEqual("failed", result["status"])
        self.assertIn("sbom unavailable", result["error"])
        self.assertEqual(0, result["packages_total"])
        self.assertEqual([], result["vulnerability_ids"])


if __name__ == "__main__":
    unittest.main()
