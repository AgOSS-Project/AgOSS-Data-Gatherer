# AgOSS Data Gatherer

> **Paper:** AgOSS: An Empirical Dataset and Multi-Layer Characterization of Open-Source Agricultural Software
> _[Citation to be filled in]_

A research pipeline for collecting, analysing, and visualising security and
ecosystem-health metrics across open-source agricultural software (AgOSS)
repositories. The pipeline orchestrates four independent data sources —
**OpenSSF Scorecard**, **Aveloxis (Augur)**, **GitHub SBOM + OSV**, and the
**CISA Known Exploited Vulnerabilities (KEV) catalogue** — merges them into a
unified dataset, runs a battery of statistical tests, and produces a fully
self-contained interactive HTML dashboard.

---

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Repository Discovery (Supplementary)](#repository-discovery-supplementary)
4. [Installation & Setup](#installation--setup)
5. [Input File Format](#input-file-format)
6. [Running the Pipeline](#running-the-pipeline)
7. [Pipeline Stages in Detail](#pipeline-stages-in-detail)
8. [Statistical Methodology](#statistical-methodology)
9. [Outputs](#outputs)
10. [Dashboard Guide](#dashboard-guide)
11. [Reproducibility](#reproducibility)
12. [Troubleshooting](#troubleshooting)
13. [Extending the Pipeline](#extending-the-pipeline)

---

## Overview

The pipeline was designed to answer the following research questions:

- **RQ1:** How can open-source agricultural software repositories be
  systematically identified, filtered, and organized into an empirically
  analyzable ecosystem?
- **RQ2:** How do agricultural OSS repositories differ across stack layers and
  ag-specificity in security hygiene, maintenance activity, and dependency
  exposure?

The pipeline processes a user-curated list of GitHub repositories through eight
sequential stages:

```
Input CSV (user-provided)
        │
        ▼
  [1] Parse & Validate Input
        │
        ├──► [2] OpenSSF Scorecard  (security checks per repo)
        │
        ├──► [3] Aveloxis / Augur   (ecosystem metrics per repo)
        │
        └──► [4] GitHub SBOM + OSV  (dependency vulnerability scan)
                        │
        ┌───────────────┘
        ▼
  [5] Merge & Enrich  (unified JSON + CSV)
        │
        ├──► [6] KEV Analysis  (CISA exploitability cross-reference)
        │
        ├──► [7] Statistical Analysis  (tests, correlations, CIs)
        │
        └──► [7.5] Saturation Analysis  (sample-size adequacy)
                        │
        ┌───────────────┘
        ▼
  [8] Dashboard Generation  →  outputs/dashboard/index.html
```

> **Platform note:** The pipeline has been developed and tested exclusively on
> **Windows 11**. It should work on macOS and Linux — path separators are
> handled by Python's `pathlib` throughout — but those platforms have not been
> validated. Windows-specific notes are included in the steps below where
> relevant.

---

## Prerequisites

### Required

| Requirement | Version | Notes |
|---|---|---|
| Python | 3.10 or later | Tested with CPython 3.11 on Windows 11 |
| pip | any recent | Bundled with Python 3.10+ |
| GitHub Personal Access Token (PAT) | — | `public_repo` scope is sufficient |
| OpenSSF Scorecard binary | v5.4.0+ | See [Installation & Setup](#installation--setup) |

### For Aveloxis (Augur) Metrics

| Requirement | Version | Notes |
|---|---|---|
| Docker Desktop | 4.x | Must be running before the pipeline starts |
| Docker Compose | v2 | Bundled with Docker Desktop |

Aveloxis is the current deployment name of the CHAOSS Augur analytics platform.
The pipeline registers each input repository with a locally-running Aveloxis
instance and then collects ecosystem metrics (commits, contributors, issues,
pull requests, stars, etc.) through its REST API. If you are running without
Docker, use `--skip-docker` and `--skip-augur`; the merger will fall back to
the GitHub REST API for the subset of metrics it supports (stars, fork count,
open issues, languages, licence).

### Optional (for full analysis)

| Requirement | Purpose |
|---|---|
| Internet access to `api.osv.dev` | Dependency vulnerability analysis (Stage 4) |
| Internet access to CISA KEV feed | Exploitability cross-reference (Stage 6) |

---

## Repository Discovery (Supplementary)

> This step is **not** part of the primary pipeline. It is a separate,
> one-time activity used to identify candidate repositories before the main
> analysis begins.

The `repo-search/` directory contains a utility (`agoss_search.py`) that
queries the GitHub Search API and produces a browsable web interface for
reviewing candidates. In practice, repository selection for this study
combined three methods:

1. **Automated GitHub search** — keyword queries (`agriculture`, `agtech`,
   `farming`) returning up to 250 results per keyword, filtered for
   non-archived, non-forked repos.
2. **Manual snowball sampling** — following references in academic papers,
   blog posts, and project documentation.
3. **Curated community lists** — `awesome-*` lists of agricultural software
   found on GitHub and the broader internet.

The result of this discovery process is encoded in the input CSV (see
[Input File Format](#input-file-format)), which is the true entry point to the
pipeline.

### Running the search tool (optional)

```bash
# Requires GITHUB_AUTH_TOKEN in environment or .env
python repo-search/agoss_search.py

# Customise: sort by stars, fetch top 500 per keyword
python repo-search/agoss_search.py --sort stars -n 500

# Write results to a custom file
python repo-search/agoss_search.py --output my_candidates.json
```

After running, open `repo-search/index.html` in a browser to browse and
shortlist candidates interactively. The frozen candidate dataset used for this
study is committed as `repo-search/candidates.json`.

---

## Installation & Setup

### 1. Clone the Repository

```bash
git clone https://github.com/<org>/AgOSS-Data-Gatherer.git
cd AgOSS-Data-Gatherer
```

### 2. Create a Python Virtual Environment

```powershell
# Windows (PowerShell)
python -m venv venv
venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

```bash
# macOS / Linux
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Python dependencies** (`requirements.txt`):

| Package | Purpose |
|---|---|
| `requests` | GitHub REST API, OSV API, CISA KEV feed |
| `numpy` | Bootstrap resampling in statistical and saturation analysis |
| `scipy` | Mann-Whitney U, Kruskal-Wallis, Spearman correlation |

### 3. Install the OpenSSF Scorecard Binary

The Scorecard binary is **not** bundled in this repository. Download the
correct build for your platform from the
[OpenSSF Scorecard releases page](https://github.com/ossf/scorecard/releases)
and place it at `tools/scorecard` (Linux / macOS) or `tools/scorecard.exe`
(Windows). The pipeline auto-detects the `.exe` extension on Windows.

```
AgOSS-Data-Gatherer/
└── tools/
    └── scorecard.exe   ← Windows
    # OR
    └── scorecard       ← Linux / macOS  (chmod +x required)
```

Verify the binary is working:

```powershell
.\tools\scorecard.exe version
```

### 4. Set Up Aveloxis (Augur) with Docker

> **Skip this section** if you are not collecting Aveloxis metrics. Pass
> `--skip-augur --skip-docker` when running the pipeline.

Aveloxis is a containerised deployment of the CHAOSS Augur platform. The
Docker Compose configuration and runtime files are not included in this
repository (they are gitignored as they contain credentials). Obtain the
Aveloxis Docker setup from the official Aveloxis / CHAOSS Augur documentation
and place it in a `tools/augur/` directory of your own.

**4a.** Create your Aveloxis config file and set the `github_api_key` field to
a GitHub PAT (the same token used for Scorecard works).

**4b.** Start the Aveloxis stack. The pipeline can start Docker automatically
on each run, or you can do it manually:

```powershell
docker compose up -d
```

The stack brings up five containers:

| Container | Role |
|---|---|
| `augur-postgres-1` | PostgreSQL database |
| `augur-migrate-1` | One-shot schema migration (exits after completion) |
| `augur-serve-1` | Augur backend worker |
| `augur-web-1` | Augur web UI (optional) |
| `augur-api-1` | REST API (port 8383) |

Allow approximately 60 seconds for the stack to initialise before running
the pipeline.

**4c.** Registration happens automatically.

When you run `python main.py` with Augur enabled, the pipeline compares the
input repo list against what is already registered in Aveloxis and registers
any missing repos automatically before collecting metrics. Registration is
idempotent — repos already present in Aveloxis are not re-inserted.

> **⚠️ User input required:** Registration inserts records directly into the
> Aveloxis PostgreSQL database via `psql` inside the `augur-postgres-1`
> container. Ensure Docker Desktop is running and that the container name in
> `AUGUR_DB_CONTAINER` (default: `augur-postgres-1`) matches your actual
> container name shown by `docker ps`.

After the pipeline registers repos, Aveloxis begins collecting data
asynchronously in the background. Full collection for ~54 repositories
typically takes **15–60 minutes** depending on GitHub API rate limits and
server load. Run the pipeline again after that window to pick up the
collected metrics from cache.

### 5. Configure Environment Variables

Copy the provided template and fill in your values:

```powershell
cp .env.example .env
```

Then edit `.env` and set at minimum `GITHUB_AUTH_TOKEN`. A `.env.example` file
at the project root documents every available variable with its default value
and a short description.

> **Security:** `.env` is listed in `.gitignore` and must **never** be
> committed to version control. It contains credentials.

---

## Input File Format

> **⚠️ User input required:** You must create and maintain this file before
> running the pipeline. It is the sole definition of which repositories are
> analysed. There is no automated mechanism to populate it.

**Default path:**
`inputs/Open Source Agricultural Software(Input).csv`
(override with `--input <path>`)

The file uses a **4-column, comma-separated** format with **no header row**:

```
Display Name, https://github.com/owner/repo, Category, Ag-Specific
```

| Column | Description | Example |
|---|---|---|
| Display Name | Human-readable label shown in the dashboard | `FarmOS` |
| URL | Full GitHub repository URL | `https://github.com/farmOS/farmOS` |
| Category | Software layer / domain label | `Domain-specific agricultural platform` |
| Ag-Specific | Whether the repo is purpose-built for agriculture | `Yes` or `No` |

**Category values used in this study:**

| Category | Description |
|---|---|
| `Embedded OS substrate` | Operating systems and runtime environments for embedded devices |
| `Field-Deployed Sensor` | Firmware and software for physical sensing hardware |
| `Edge and Gateway software` | Protocol adapters, data bridges, and gateway logic |
| `Cloud-hosted backends and dashboard` | REST services, web apps, and cloud dashboards |
| `Domain-specific agricultural platform` | Integrated farm management platforms |
| `Messaging and data transport layers` | MQTT brokers and data transport middleware |

**Accepted values for Ag-Specific:** `Yes`, `No`, `yes`, `no`, `true`,
`false`, `1`, `0`

**Example rows:**

```csv
FarmOS,https://github.com/farmOS/farmOS,Domain-specific agricultural platform,Yes
ArduPilot,https://github.com/ArduPilot/ardupilot,Field-Deployed Sensor,No
Grafana,https://github.com/grafana/grafana,Cloud-hosted backends and dashboard,No
```

**Parser behaviour:**

- Blank lines and lines beginning with `#` are silently ignored.
- A header row is auto-detected and skipped.
- A legacy 2-column format (`url, category`) is accepted for backward
  compatibility; `ag_specific` defaults to `unknown`.
- Invalid or non-GitHub URLs are rejected with a warning; the offending row
  is skipped rather than aborting the run.
- Duplicate URLs are deduplicated with a warning.

---

## Running the Pipeline

### Full pipeline (recommended first run)

```powershell
python main.py
```

Starts the Aveloxis Docker stack first (so Augur is reachable during
collection), runs all eight pipeline stages in sequence, then opens the
dashboard in the default browser. Pass `--skip-docker` if the stack is already
running or if you are not using Aveloxis.

### Skip slow stages using cached outputs

Individual stages can be skipped when their raw outputs already exist from a
previous run. This is the normal workflow after initial data collection:

```powershell
# Re-run only stats + dashboard (~5 seconds, no network calls)
python main.py --regenerate

# Skip Scorecard collection; use cached JSONs, re-run everything else
python main.py --skip-scorecard

# Skip both collection stages
python main.py --skip-scorecard --skip-augur

# Skip dependency and KEV analysis (no external calls for those stages)
python main.py --skip-dependencies --skip-kev
```

### Force a full re-collection (ignore all caches)

```powershell
python main.py --force
```

### Suppress the browser launch

```powershell
python main.py --no-browser
```

### Use a custom input file

```powershell
python main.py --input "inputs/my_repos.csv"
```

### All CLI flags

| Flag | Description |
|---|---|
| `--skip-pipeline` | Skip all data collection; only run merger → stats → dashboard |
| `--regenerate` | Skip collection and merge; only re-run stats, saturation, and dashboard |
| `--force` / `--force-refresh` | Ignore all cache; re-collect from scratch |
| `--verbose` / `-v` | Print DEBUG-level messages to the console |
| `--skip-scorecard` | Load Scorecard from cache (`outputs/raw/scorecard/`) |
| `--skip-augur` | Load Augur metrics from cache (`outputs/raw/augur/`) |
| `--skip-dependencies` | Skip GitHub SBOM + OSV dependency vulnerability analysis |
| `--skip-kev` | Skip CISA KEV exploitability cross-reference |
| `--skip-docker` | Do not attempt to start or stop Docker services |
| `--no-browser` | Do not open the dashboard on completion |
| `--input PATH` | Path to the input CSV (default: `inputs/Open Source Agricultural Software(Input).csv`) |
| `--wait-for-augur` | Poll Aveloxis after the run until repos report data |
| `--augur-wait-mode MODE` | Readiness level to wait for: `none` / `minimal` / `standard` / `full` |
| `--augur-timeout N` | Maximum seconds to wait for Aveloxis readiness (default: 600) |

---

## Pipeline Stages in Detail

### Stage 1 — Environment Validation

Verifies that:
- The Scorecard binary exists at `tools/scorecard[.exe]` and is executable.
- `GITHUB_AUTH_TOKEN` is set and non-empty.
- The input CSV exists and is parseable (at least one valid row).

Fails immediately with a descriptive error message if any check fails.

### Stage 2 — Input Parsing

Reads the input CSV, validates each GitHub URL, and constructs an in-memory
`RepoEntry` object for each repository row. This object carries
`display_name`, `owner`, `repo_name`, `category`, and `ag_specific` through
all subsequent stages.

> **User input required:** The CSV must be created manually. See
> [Input File Format](#input-file-format).

### Stage 3 — OpenSSF Scorecard Collection

Invokes the `scorecard` binary once per repository, authenticating via
`GITHUB_AUTH_TOKEN`. Raw JSON output is written to
`outputs/raw/scorecard/owner__repo.json`.

**Status model:**

| Status | Meaning |
|---|---|
| `success` | Binary exited 0; complete JSON produced |
| `partial_success` | Binary exited non-zero but produced valid JSON (common for repos lacking admin-level checks such as Branch-Protection) |
| `failed` | Binary produced no valid JSON |
| `skipped` | Stage skipped via `--skip-scorecard` |

**Security dimensions evaluated** (17 checks):
`Binary-Artifacts`, `Branch-Protection`, `CI-Tests`, `CII-Best-Practices`,
`Code-Review`, `Contributors`, `Dangerous-Workflow`, `Dependency-Update-Tool`,
`Fuzzing`, `License`, `Maintained`, `Packaging`, `Pinned-Dependencies`,
`SAST`, `Security-Policy`, `Signed-Releases`, `Token-Permissions`,
`Vulnerabilities`

Each check is scored 0–10; the overall Scorecard score is a weighted aggregate
in the same range.

### Stage 4 — Aveloxis (Augur) Metrics Collection

Queries the Aveloxis REST API (`http://localhost:8383/api/v1`) for each
registered repository and writes results to `outputs/raw/augur/owner__repo.json`.

**Metrics collected** (up to 38 endpoints), including:
contributor count, commit count, issues opened/closed/backlog, pull requests
merged, release count, fork count, star count, language breakdown, declared
licence (SPDX ID), average issue resolution time.

**Status model:**

| Status | Meaning |
|---|---|
| `ready` | All expected metric endpoints returned data |
| `partial` | Some endpoints returned data; others are still processing |
| `registered` | Repository inserted in DB; collection not yet started |
| `collecting` | Data collection actively in progress |
| `timed_out` | Collection did not complete within `--augur-timeout` |
| `not_registered` | Repository not found in the Aveloxis database |
| `failed` | API returned an unrecoverable error |
| `skipped` | Stage skipped via `--skip-augur` |

> **On `partial` status:** Aveloxis populates metrics asynchronously.
> A `partial` result does not mean data is absent — it means at least one
> metric endpoint has responded. The merger uses all available data.
> For metrics not yet returned by Aveloxis, the merger falls back to the
> **GitHub REST API** (stars, fork count, open issues, languages, licence).
> In this study, all 54 repositories reached `partial` status with core metrics
> (commits, contributors, stars) fully populated.

### Stage 5 — Dependency Vulnerability Analysis

Fetches the **Software Bill of Materials (SBOM)** from the GitHub Dependency
Graph API for each repository, then queries the
[Open Source Vulnerabilities (OSV)](https://osv.dev) database to identify
known CVEs, GHSAs, and ecosystem advisories affecting each dependency.

**Process:**

1. `GET /repos/{owner}/{repo}/dependency-graph/sbom` → list of packages with
   PURL identifiers.
2. Each PURL is resolved to an OSV query payload (`PURL` or
   `name + ecosystem + version`).
3. OSV batch endpoint (`/v1/querybatch`, up to 100 packages per request) is
   queried.
4. Responses are normalised, deduplicated, and classified by severity
   (Critical / High / Medium / Low / Unknown).

Parallel processing uses a `ThreadPoolExecutor` (default: 4 workers).
HTTP 429 and 5xx responses are retried with exponential backoff.

Output: `outputs/processed/dependency_analysis.json`

### Stage 6 — KEV Exploitability Analysis

Downloads the CISA
[Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and cross-references each CVE found in Stage 5 against it. Vulnerabilities
present in the KEV catalogue have **confirmed public exploits** and an active
CISA remediation deadline.

This stage is **non-fatal**: if the CISA feed is unreachable, a warning is
logged and the pipeline continues without KEV enrichment.

Outputs:
- `outputs/processed/kev_analysis.json` — per-vulnerability KEV match details.
- `outputs/processed/kev_summary.json` — exploitability statistics and
  severity breakdown (embedded into the main dashboard).

### Stage 5b — Merge & Enrich

Reads all Scorecard and Augur raw caches, merges them into a unified
per-repository record, and supplements with live data from the GitHub REST API
where Aveloxis metrics are missing (stars, forks, contributor count, commit
count, closed-issue count, and SPDX license identifier). The detected license
is promoted to a top-level `license` field on each record so the dashboard can
display and filter by it without parsing nested Augur metrics. Writes:

- `outputs/processed/merged_repos.json` — array of unified records (one per input repo).
- `outputs/processed/merged_repos.csv` — flat CSV equivalent for spreadsheet use.
- `outputs/processed/summary.json` — run metadata and aggregate counts.

### Stage 7 — Statistical Analysis

Runs the full test battery described in
[Statistical Methodology](#statistical-methodology) and writes
`outputs/processed/statistical_analysis.json`.

### Stage 7.5 — Saturation Analysis

Computes **rarefaction curves** to assess whether the sample of N repositories
is large enough to stabilise the key outcome metrics. At each sample size
(from 5 to N, stepping by 5), 500 bootstrap resamples are drawn and four
metrics are computed:

- Mean Scorecard score across sampled repos
- Percentage of repos with at least one detected vulnerability
- Mean vulnerability count
- Number of unique software-layer categories represented

95% percentile bootstrap CI bands are computed at each step. Convergence of
the bands as N → 54 is evidence that the sample is sufficient for the observed
patterns.

Output: `outputs/processed/saturation_analysis.json`

### Stage 8 — Dashboard Generation

Combines all processed outputs into a **single self-contained HTML file**
(`outputs/dashboard/index.html`). All data is embedded as JSON literals and
all chart rendering uses a bundled copy of Chart.js. No web server, internet
connection, or external assets are required to view the dashboard.

---

## Statistical Methodology

All statistical analyses are implemented in `pipeline/stats.py`.

### Bootstrap Confidence Intervals

95% confidence intervals for group means and medians are computed using the
**percentile bootstrap** with **2 000 iterations**. For each group × metric
combination, the statistic is recomputed on 2 000 resamples drawn with
replacement from the observed values; the 2.5th and 97.5th percentiles of the
resulting distribution form the CI bounds. A fixed random seed (42) ensures
reproducibility.

### Mann-Whitney U Test — Ag-Specific vs Non-Ag-Specific

A **two-sided Mann-Whitney U test** (`scipy.stats.mannwhitneyu`) compares each
metric between:

- **Group A** — Ag-specific repositories (`ag_specific = Yes`)
- **Group B** — Non-ag-specific repositories (`ag_specific = No`)

This non-parametric rank-based test makes no assumption of normality, which is
appropriate given the small and skewed sample sizes involved.

**Effect size — rank-biserial r**

The rank-biserial correlation r is derived from U₁, the U statistic returned
by scipy for the first (ag) group:

```
r = (2 · U₁) / (n_A · n_B) − 1
```

| r value | Interpretation |
|---|---|
| +1 | Group A (ag-specific) always ranks higher |
| 0 | No systematic difference |
| −1 | Group B (non-ag-specific) always ranks higher |

Magnitude labels: `|r| < 0.1` = negligible · `0.1–0.3` = small ·
`0.3–0.5` = medium · `≥ 0.5` = large.

A 95% bootstrap CI for r is also reported (2 000 iterations, same seed).

**Multiple comparison correction**

After all Mann-Whitney tests are run simultaneously across all metrics (nine
core metrics plus all Scorecard check dimensions), p-values are adjusted using
**Benjamini-Hochberg FDR correction**. Both the raw p-value and the
FDR-adjusted p-value appear in `statistical_analysis.json`. The dashboard
significance markers use the raw α = 0.05 threshold.

### Kruskal-Wallis Test — Across Software-Layer Categories

A **Kruskal-Wallis H test** (`scipy.stats.kruskal`) tests for differences in
metric distributions across all software-layer categories simultaneously, for:
`scorecard_overall`, `vuln_count`, `vuln_density`.

Where the Kruskal-Wallis test is significant (p < 0.05), **Dunn's post-hoc
pairwise test** is applied with **Bonferroni correction** to identify which
specific category pairs drive the difference. All pairwise Z-scores and
corrected p-values are reported in the dashboard and in
`statistical_analysis.json`.

### Spearman Rank Correlations

Pairwise **Spearman rank correlations** (`scipy.stats.spearmanr`) are computed
for the following pre-defined pairs:

| Pair | Research question |
|---|---|
| Scorecard vs Contributors | Does a larger contributor base predict better security? |
| Scorecard vs Stars | Does popularity correlate with security posture? |
| Scorecard vs Vulnerability count | Does a higher score mean fewer dependency vulns? |
| Scorecard vs Commit count | Does active development predict security? |
| Contributors vs Vulnerability count | Does maintainer count reduce vuln exposure? |
| Issues opened vs Issues closed | How efficiently are issues resolved? |
| Scorecard vs Vulnerability density | Does score predict vuln rate per queryable package? |

A **full correlation matrix** across all nine core metrics is also computed and
displayed as a colour-coded heatmap in the dashboard (upper triangle only).
Cells are marked `*` for p < 0.05 and `**` for p < 0.01. Metrics whose values
are constant across all repositories (e.g., all zeros) are automatically
excluded from the matrix with an explanatory note.

---

## Outputs

### Directory structure

```
outputs/
├── raw/
│   ├── scorecard/
│   │   └── owner__repo.json        ← one file per repo (raw Scorecard output)
│   ├── augur/
│   │   └── owner__repo.json        ← one file per repo (Aveloxis API response)
│   └── dependency/
│       └── owner__repo.json        ← one file per repo (SBOM + OSV results)
├── processed/
│   ├── merged_repos.json           ← unified dataset (one record per input repo)
│   ├── merged_repos.csv            ← flat CSV version of merged_repos.json
│   ├── summary.json                ← run metadata and aggregate counts
│   ├── dependency_analysis.json    ← aggregated vulnerability data
│   ├── kev_analysis.json           ← per-vulnerability KEV match details
│   ├── kev_summary.json            ← exploitability statistics (embedded in dashboard)
│   ├── statistical_analysis.json   ← all statistical test results
│   └── saturation_analysis.json    ← rarefaction curve data
├── dashboard/
│   └── index.html                  ← self-contained interactive dashboard
└── logs/
    └── pipeline.log                ← full DEBUG log for the most recent run
```

### Key output files

#### `merged_repos.json`

Array of per-repository records. Each record includes:

```json
{
  "display_name": "FarmOS",
  "repo_url": "https://github.com/farmOS/farmOS",
  "owner": "farmOS",
  "repo_name": "farmOS",
  "category": "Domain-specific agricultural platform",
  "ag_specific": true,
  "scorecard_overall": 4.3,
  "scorecard_status": "success",
  "scorecard_checks": {
    "Code-Review": { "score": 7, "reason": "..." },
    "Maintained":  { "score": 10, "reason": "..." }
  },
  "augur_status": "partial",
  "augur_metrics": {
    "contributor_count": 54,
    "commit_count": 9349,
    "stars": 1305
  },
  "overall_status": "partial"
}
```

#### `statistical_analysis.json`

Structured results of all statistical tests, keyed by group and metric:

```json
{
  "by_category": {
    "Domain-specific agricultural platform": {
      "scorecard_overall": {
        "n": 6, "mean": 4.3,
        "mean_ci_lo": 3.8, "mean_ci_hi": 4.9
      }
    }
  },
  "comparisons": {
    "ag_vs_nonag": {
      "scorecard_overall": {
        "n_a": 43, "n_b": 10,
        "mw_statistic": 52.5,
        "p_value": 0.000100,
        "effect_size_r": -0.856,
        "effect_label": "large",
        "significant": true
      }
    }
  },
  "correlations": { "scorecard_vs_contributors": { "spearman_r": 0.42, "p_value": 0.001, "n": 54 } },
  "correlation_matrix": { ... },
  "kruskal_wallis": { ... }
}
```

---

## Dashboard Guide

Open `outputs/dashboard/index.html` in any modern browser. No server or
internet connection is required.

### Tabs

| Tab | Contents |
|---|---|
| **Overview** | Summary cards · score histogram · category counts · license distribution · ag-specific breakdown · Spearman correlation heatmap |
| **Repo Table** | Sortable, filterable table of all repositories with Scorecard scores, Augur metrics, vulnerability counts, and detected license |
| **Categories** | Scorecard boxplots by software layer · dependency vulnerability boxplot · category comparison bar charts with 95% CI error bars · per-repo security check heatmap · Kruskal-Wallis + Dunn results |
| **Ag-Specific** | Ag vs non-ag metric comparisons · Mann-Whitney effect size chart with CI · radar chart of Scorecard check averages · full Mann-Whitney table |
| **Vulnerabilities** | Dependency vulnerability breakdown · CISA KEV exploitability panel with remediation deadlines |
| **Dependencies** | Full dependency scan results per repository · severity breakdown · vulnerability density chart |
| **Comparisons** | Repo rankings by score / stars / commits · scatter plots with Spearman subtitles · Scorecard check averages with 95% CI error bars |
| **Pipeline Health** | Per-repository Scorecard and Augur status badges · runtime statistics |

### Chart interactions

- **Enlarge** — click any chart or the "Enlarge" button to open a full-screen
  modal with pan and scroll-wheel zoom.
- **Download** — the "Download" button on any chart card saves a
  high-resolution PNG (3× canvas resolution, white background).
- **Correlation matrix download** — a dedicated button renders the HTML table
  to a PNG via the Canvas 2D API.
- **95% CI error bars** — all mean-based bar charts display bootstrap CI error
  bars. Hover a bar to see the exact bounds in the tooltip.

---

## Reproducibility

### Tool versions

| Tool | Version used in this study |
|---|---|
| OpenSSF Scorecard | v5.4.0 |
| Aveloxis / Augur | Docker image as of collection date (see `COLLECTION_DATE.txt`) |
| Python | 3.11 |
| scipy | 1.11+ |
| numpy | 1.24+ |

The collection date is recorded in `COLLECTION_DATE.txt` and in
`outputs/processed/summary.json` (`run_start`, `run_end` fields).

### Reproducing analysis from committed cache

The `outputs/raw/` directory is committed to version control so that
statistical analysis and dashboard generation can be reproduced without
re-running data collection or requiring any API access:

```powershell
# Reproduce all downstream results from committed raw outputs (~5 seconds)
python main.py --regenerate
```

### Random seed

Bootstrap resampling in `pipeline/stats.py` and `pipeline/saturation.py` uses
a fixed NumPy seed (`seed=42`). All bootstrap CI results are therefore
**deterministic** given the same input data.

### Aveloxis collection timing

Aveloxis collects data asynchronously. Metric values improve over time as the
worker processes each repository's git history and issue tracker. Exact values
depend on when repositories were first registered and how long the Docker
stack has been running. The committed `outputs/raw/augur/` cache represents the state at
the recorded collection date.

---

## Troubleshooting

### `GITHUB_AUTH_TOKEN` not found

Ensure `.env` exists in the project root and contains:

```
GITHUB_AUTH_TOKEN=github_pat_...
```

The pipeline strips leading/trailing whitespace around the `=` sign.

### Scorecard returns `partial_success` for most repos

This is expected behaviour. The `Branch-Protection`, `Signed-Releases`, and
`Token-Permissions` checks require admin-level access to the repository and
routinely exit non-zero for public repos analysed by a non-admin token.
The overall score and most check scores are still valid and usable.

### Aveloxis not reachable (`Connection refused` on port 8383)

1. Confirm Docker Desktop is running.
2. Check all five containers are healthy:
   ```powershell
   docker ps --filter name=augur
   ```
3. Allow ~60 seconds after `docker compose up -d` before running the pipeline.
4. If port 8383 conflicts with another service, change `AUGUR_API_BASE` in
   `.env` and update the `docker-compose.yml` port mapping accordingly.

### All Augur metrics are zero / status is `not_registered`

Registration is now automatic — the pipeline registers any unregistered repos
before collecting metrics. If all repos still show `not_registered`:

1. Confirm Docker Desktop is running and `docker ps` shows all Aveloxis containers.
2. Run an Augur-only pass to trigger registration and wait for collection:
   ```powershell
   python main.py --skip-scorecard --skip-dependencies --skip-kev
   ```
3. Allow 15–60 minutes for Aveloxis to collect data, then re-run the full pipeline.

### Dependency analysis returns no results for a repository

- Verify `GITHUB_AUTH_TOKEN` has `public_repo` scope (required for the GitHub
  Dependency Graph API).
- Some repositories have the Dependency Graph disabled or do not publish an
  SBOM. These repos are marked `skipped` in `dependency_analysis.json` and
  excluded from vulnerability statistics.

### Dashboard shows no correlation matrix

The matrix is suppressed when every pair of metrics has at least one member
with constant values across all repositories (e.g., all vulnerability counts
= 0 because dependency analysis has not run). Running Stage 5
(`--skip-scorecard --skip-augur`) populates the dependency data.

### Windows: `scorecard binary not found`

Check that `tools\scorecard.exe` exists (note the backslash). The parent
`tools\` directory must not be renamed.

---

## Extending the Pipeline

### Adding new repositories

Edit the input CSV and add rows following the 4-column format, then run:

```powershell
# Full re-collection; new repos are auto-registered with Aveloxis
# (cache is used for repos whose raw JSON already exists)
python main.py
```

### Changing the repository list

Remove rows from the input CSV and delete the corresponding files from
`outputs/raw/scorecard/`, `outputs/raw/augur/`, and `outputs/raw/dependency/`
before re-running. Stale cache files for removed repositories will otherwise
be included in the merge step.

### Adding new statistical tests

Add test logic to `pipeline/stats.py` and include the results in the `output`
dict. The dashboard template receives the full `statistical_analysis.json` as
the `STATS` JavaScript variable and can access any new keys immediately.

### Adding new dashboard visualisations

1. Add a `<canvas id="chartMyNew">` element to the appropriate tab in
   `pipeline/report/template.html`.
2. Create the chart in the corresponding `(function() { ... })()` block using
   Chart.js v4.
3. Regenerate the dashboard:
   ```powershell
   python -c "from pipeline.report.render import build_dashboard; build_dashboard()"
   ```
   This bypasses the full pipeline and completes in under a second.

### Regenerating only the dashboard (template edits)

```powershell
python -c "from pipeline.report.render import build_dashboard; build_dashboard()"
```
