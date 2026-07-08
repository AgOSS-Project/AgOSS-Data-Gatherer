# AgOSS Data Gatherer

> **Paper:** AgOSS: An Empirical Dataset and Multi-Layer Characterization of Open-Source Agricultural Software
> _[Citation to be filled in]_

A research pipeline for collecting, analysing, and visualising security and
ecosystem-health metrics across open-source agricultural software (AgOSS)
repositories. The pipeline orchestrates four independent data sources —
**OpenSSF Scorecard**, **GitHub GraphQL/REST API**, **GitHub SBOM + OSV**, and the
**CISA Known Exploited Vulnerabilities (KEV) catalogue** — merges them into a
unified dataset, runs a battery of statistical tests, and produces a fully
self-contained interactive HTML dashboard.

> **Why not Augur/Aveloxis?** Earlier versions of this pipeline used a
> self-hosted [CHAOSS Augur](https://chaoss.github.io/augur/) instance
> (deployed as Aveloxis, Augur's high-throughput Go rewrite) for
> commit/contributor/PR/issue metrics. It was dropped: every metric this
> pipeline actually uses (contributors, commits, issues, merged PRs, stars,
> forks, language, license) is collectable directly and reliably via GitHub's
> own APIs — which is itself standard MSR methodology (see Kalliamvakou et
> al., ["The Promises and Perils of Mining
> GitHub"](https://dl.acm.org/doi/10.1145/2597073.2597074), MSR 2014) — and
> Aveloxis's own advertised bulk throughput, "40,000 repositories fully
> collected in three days," doesn't fit a pipeline that needs to re-run in
> minutes during iterative analysis. Collection is now Scorecard + a single
> GitHub metrics pass (`pipeline/merger.py`) + dependency/OSV + KEV — no
> Docker stack required.
>
> **REST vs. GraphQL:** stars, forks, license, primary language, and
> issue/merged-PR counts are fetched via a single **batched GraphQL** call
> per ~20 repos (using aliases), because GitHub's REST **Search API** —
> needed for exact issue/PR counts, since a plain `/issues` call or
> `open_issues_count` both silently fold pull requests into "issues" — is
> capped at 30 requests/min authenticated, far tighter than core REST's
> 5,000/hr. GraphQL's `issues(states:...){ totalCount }` /
> `pullRequests(states:...){ totalCount }` return the same exact aggregate
> counts but bill against the normal ~5,000-point/hr GraphQL budget instead,
> and batching many repos per call cuts round-trips further. Contributor
> count and commit count stay on core REST (the `per_page=1` + `Link`-header
> trick) since GraphQL has no cheap equivalent for either. Every request —
> REST and GraphQL — retries with backoff on 403/429/5xx rather than
> silently dropping data, and the GraphQL path watches its own rate-limit
> budget (returned inline in each response) to pause before it runs out
> rather than after.

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
9. [Matched-Comparison Analysis](#matched-comparison-analysis)
10. [Outputs](#outputs)
11. [Dashboard Guide](#dashboard-guide)
12. [Reproducibility](#reproducibility)
13. [Troubleshooting](#troubleshooting)
14. [Extending the Pipeline](#extending-the-pipeline)

---

## Overview

The pipeline was designed to answer the following research questions:

- **RQ1:** How can open-source agricultural software repositories be
  systematically identified, filtered, and organized into an empirically
  analyzable ecosystem?
- **RQ2:** How do agricultural OSS repositories differ across stack layers and
  ag-specificity in security hygiene, maintenance activity, and dependency
  exposure?

The pipeline processes a user-curated list of GitHub repositories through seven
sequential stages:

```
Input CSV (user-provided)
        │
        ▼
  [1] Parse & Validate Input
        │
        ├──► [2] OpenSSF Scorecard  (security checks per repo)
        │
        └──► [3] GitHub SBOM + OSV  (dependency vulnerability scan)
                        │
        ┌───────────────┘
        ▼
  [4] Merge & Enrich  (GitHub metrics collection + unified JSON/CSV)
        │
        ├──► [5] KEV Analysis  (CISA exploitability cross-reference)
        │
        ├──► [6] Statistical Analysis  (tests, correlations, CIs)
        │
        ├──► [6.5] Saturation Analysis  (sample-size adequacy)
        │
        └──► [6.6] Matched-Comparison Analysis  (control-search/, see below)
                        │
        ┌───────────────┘
        ▼
  [7] Dashboard Generation  →  outputs/dashboard/index.html
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

The `ag-oss-search/` directory (renamed from `repo-search/` — see
[Matched-Comparison Analysis](#matched-comparison-analysis) for the sibling
`control-search/` tool used to build the *non-ag* comparison pool) contains a
utility (`agoss_search.py`) that queries the GitHub Search API and produces a
browsable web interface for reviewing candidates. In practice, repository
selection for this study combined three methods:

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
python ag-oss-search/agoss_search.py

# Customise: sort by stars, fetch top 500 per keyword
python ag-oss-search/agoss_search.py --sort stars -n 500

# Write results to a custom file
python ag-oss-search/agoss_search.py --output my_candidates.json
```

After running, open `ag-oss-search/index.html` in a browser to browse and
shortlist candidates interactively. `candidates.json`/`shortlist.json` are
local, regenerable discovery artifacts and are not committed — the actual
result of this discovery process (the study's data of record) is the input
CSV (see [Input File Format](#input-file-format)).

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

### 4. Configure Environment Variables

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

Runs all seven pipeline stages in sequence, then opens the dashboard in the
default browser.

### Skip slow stages using cached outputs

Individual stages can be skipped when their raw outputs already exist from a
previous run. This is the normal workflow after initial data collection:

```powershell
# Re-run only stats + dashboard (~5 seconds, no network calls)
python main.py --regenerate

# Skip Scorecard collection; use cached JSONs, re-run everything else
python main.py --skip-scorecard

# Skip Scorecard and dependency collection both
python main.py --skip-scorecard --skip-dependencies

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
| `--skip-dependencies` | Skip GitHub SBOM + OSV dependency vulnerability analysis |
| `--skip-kev` | Skip CISA KEV exploitability cross-reference |
| `--skip-matched-comparison` | Skip the matched-comparison analysis (`control-search/`) described below |
| `--no-browser` | Do not open the dashboard on completion |
| `--input PATH` | Path to the input CSV (default: `inputs/Open Source Agricultural Software(Input).csv`) |

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

### Stage 4 — Dependency Vulnerability Analysis

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

### Stage 5 — Merge & Enrich (includes GitHub Metrics Collection)

Collects repo metrics directly via GitHub's GraphQL and REST APIs
(`pipeline/merger.py`) — contributor count, commit count, issues
opened/closed, merged pull requests, stars, forks, primary language, and
declared license (SPDX ID). This comfortably fits GitHub's rate limits even
at control-pool scale and completes in minutes, not the hours-to-days a
self-hosted Augur/Aveloxis crawl would need for PR-heavy repositories (see the
"Why not Augur/Aveloxis?" note near the top of this document).

**Stars, forks, license, primary language, and issue/merged-PR counts** are
fetched via one **batched GraphQL query per ~20 repos**
(`fetch_github_metrics_batch`, using GraphQL aliases to request many repos in
a single HTTP call). Issue and PR counts specifically use GraphQL's
`issues(states:...){ totalCount }` / `pullRequests(states:...){ totalCount }`
rather than the plain REST `/issues` endpoint or `open_issues_count` (both of
which silently fold pull requests into "issues" — GitHub models a PR as a
special kind of issue) or the REST Search API (`type:issue`/`type:pr`
qualifiers), which returns the same exact counts but is capped at 30
requests/min authenticated — GraphQL's equivalent fields bill against the
much larger ~5,000-point/hr budget instead. Every GraphQL response also
returns `rateLimit { remaining resetAt }` inline, so the pipeline can pause
before that budget runs out rather than after.

**Contributor count and commit count** stay on core REST (`per_page=1` +
`Link`-header trick) since GraphQL has no cheap equivalent for either — no
deduplicated contributor total, and a commit count requires paginating full
history. Both retry with backoff on 403/429/5xx.

Primary language detection excludes `NON_IMPLEMENTATION_LANGUAGES` (currently
just `Jupyter Notebook`) from consideration — GitHub Linguist counts a
notebook's saved outputs (rendered plots, printed tensors) as bytes, which can
dwarf the actual code and make a repo appear to be "written in" Jupyter
Notebook. When the top-level `language` field is null or falls in this set,
the next-largest language in the full byte-count breakdown
(`/repos/{owner}/{repo}/languages`) is used instead.

Merges Scorecard results with the above into a unified per-repository record.
The detected license is promoted to a top-level `license` field on each
record so the dashboard can display and filter by it without parsing nested
GitHub metrics. Writes:

- `outputs/processed/merged_repos.json` — array of unified records (one per input repo), each carrying a `github_metrics` object plus a `github_metrics_collected` flag and `github_metrics_error` if collection failed.
- `outputs/processed/merged_repos.csv` — flat CSV equivalent for spreadsheet use.
- `outputs/processed/summary.json` — run metadata and aggregate counts.

### Stage 6 — KEV Exploitability Analysis

Downloads the CISA
[Known Exploited Vulnerabilities catalogue](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
and cross-references each CVE found in Stage 4 against it. Vulnerabilities
present in the KEV catalogue have **confirmed public exploits** and an active
CISA remediation deadline.

This stage is **non-fatal**: if the CISA feed is unreachable, a warning is
logged and the pipeline continues without KEV enrichment.

Outputs:
- `outputs/processed/kev_analysis.json` — per-vulnerability KEV match details.
- `outputs/processed/kev_summary.json` — exploitability statistics and
  severity breakdown (embedded into the main dashboard).

### Stage 6.5 — Statistical Analysis

Runs the full test battery described in
[Statistical Methodology](#statistical-methodology) and writes
`outputs/processed/statistical_analysis.json`.

### Stage 6.6 — Saturation Analysis

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

### Stage 6.7 — Matched-Comparison Analysis

Runs the matched-comparison analysis described in full in
[Matched-Comparison Analysis](#matched-comparison-analysis) below. This stage
lives in `control-search/` (outside `pipeline/`) and is invoked by `main.py`
as a post-pipeline step; it is non-fatal (a failure here logs a warning and
the dashboard simply shows no matched-comparison data) and can be skipped
with `--skip-matched-comparison`.

Output: `outputs/processed/matched_comparison.json`

### Stage 7 — Dashboard Generation

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

## Matched-Comparison Analysis

> Code for this analysis lives entirely in `control-search/`, separate from
> `pipeline/`. It is invoked automatically by `main.py` after the main
> pipeline (Stage 7.6) but can also be run and inspected standalone.

### Why this analysis exists

The main pipeline's `ag_vs_nonag` comparison (see
[Statistical Methodology](#statistical-methodology)) compares the 43
`ag_specific=Yes` repos against the 11 `ag_specific=No` repos already in the
dataset. Those 11 are themselves **ag-critical infrastructure** (ArduPilot,
ROS 2, Zephyr, FreeRTOS, WebODM, etc.) — software actually used in
agricultural contexts, just not purpose-built for agriculture — and they also
skew toward large, mature projects. A "weaker" result for the ag-specific
group in that comparison could simply reflect project maturity rather than
anything agriculture-specific.

The matched-comparison analysis addresses this by treating **all 54 dataset
repos** (both `ag_specific=Yes` and `ag_specific=No`) as the group of
interest, and comparing each of them against `k=3` statistically **matched
controls** drawn from a much larger pool of genuinely **non-ag-critical but
operationally similar** repositories — IoT platforms, embedded systems,
robotics middleware, sensor frameworks, environmental monitoring tools, small
cloud dashboards, and other cyber-physical software with no agricultural
connection at all. This tests whether the AgOSS maturity/security gap
persists once compared against software with similar observable size, age,
activity, and ecosystem — a more defensible baseline than "the whole rest of
the dataset."

**This analysis does not establish causality.** It cannot show that
agriculture *causes* weaker security posture; it can only show whether the
observed gap survives controlling for observable confounders.

### Building the control pool

Candidates are filtered at search time (`control_search.py`) before triage
ever sees them: already-archived repos, forks, repos already in the 54-repo
dataset, repos whose name/description/topics are agriculture-adjacent, and
`awesome-*`-style curated list repos (e.g. `phodal/awesome-iot` — these
surface legitimately from topic searches like `topic:iot` but aren't software
themselves, so they're excluded regardless of which keyword found them).

Steps 1–2 (search + triage) are combined into a single command,
`prepare_pool.py`, for ease of use and reproducibility of the *procedure* —
the keyword list, exclusion rules, and triage heuristic are all fixed in
code, so re-running it applies the exact same method every time (GitHub's
live search results themselves can still drift over time as repos are
created, starred, or archived — that part is inherently not fully
reproducible, same as the original `ag-oss-search/` tool). Step 3 (review) is
the one part that's inherently manual — it requires a human judgment call —
and cannot be automated away.

```powershell
# 1-2. Search GitHub for non-ag candidates across the target domains, then
#      auto-suggest accept/review decisions (topic-confirmed vs needs-review)
python control-search/prepare_pool.py

# Customise: sort by stars, fetch top 150 per keyword
python control-search/prepare_pool.py --sort stars -n 150

# 3. Open control-search/review.html in a browser to review every candidate
#    — including auto-suggested-accepts, which stay fully editable in case
#    the heuristic is wrong — then click "Export reviewed pool ↓" and save
#    the download as control-search/control_pool_reviewed.json
#
#    The table supports sorting (click any of the Confidence/Repository/
#    Stars/Forks column headers to sort, click again to reverse), a language
#    filter dropdown, a confidence filter (All/Topic-confirmed/Needs review),
#    a text search box, and a "Selected only" toggle — useful for quickly
#    scanning a large candidate pool.

# 4. (Optional — run_matched_comparison.py does this automatically) Resolve
#    the final pool from the reviewed export
python control-search/build_control_pool.py
```

`control_search.py` and `triage.py` remain runnable individually (e.g. to
re-triage without re-searching) — `prepare_pool.py` is a thin wrapper that
calls both in sequence and prints the next-step reminder to open
`review.html`.

#### Later search waves: expansion and ruby

The control pool isn't necessarily built in one pass. After an initial
matching run, the post-matching diagnostics (`unmatched_dataset_repos`,
`unmatched_characterization` in `matched_comparison.json`, and the "why
didn't this repo match" detail per repo) can reveal that specific dataset
repos have no viable control because the pool itself has a coverage gap —
not because the matching protocol is broken. Rather than loosen the hard
exact-language gate or the caliper to paper over that (which would
reintroduce the confound matching exists to remove), the fix is to run an
additional, narrowly-targeted search wave and append its accepted repos to
the same reviewed pool. Two such waves exist so far, both following the same
pattern as the original wave — search, auto-triage, human review in
`review.html`, export — via their own `control_search.run(..., wave=...)`
call and their own output files, so neither wave ever reads-for-writing or
overwrites an earlier wave's files (only reads them, for deduplication):

- **Expansion wave** (`prepare_expansion_pool.py`, `EXPANSION_KEYWORDS`) —
  added after the initial pool showed near-zero coverage for the
  "business/community-management SaaS" niche that repos like `LiteFarm`,
  `csa-admin`, and `ekylibre` occupy: a full-stack CRUD business-management
  web app. Targets that *domain* (SaaS/CRM/ERP/admin-dashboard/scheduling
  topics), not a language.
- **Ruby wave** (`prepare_ruby_pool.py`, `RUBY_KEYWORDS`) — added after the
  expansion wave still left a specific gap: 3 of the dataset's unmatched
  repos (`PecanProject/bety`, `csa-admin-org/csa-admin`, `ekylibre/ekylibre`)
  are all Ruby, and specifically the same archetype — a long-running,
  Rails-shaped community/cooperative/membership-management platform — while
  the whole reviewed pool had only 2 Ruby repos total. Targets that niche
  directly (`topic:ruby-on-rails`, `topic:rails`, and Rails-adjacent
  membership/cooperative/association-management terms), not "Ruby" as a
  language — a broad `language:ruby` search would be a much less principled
  net than the rest of the pool was built with, and would mostly resurface
  generic gems/CLI tools rather than the community-platform archetype that
  motivated the wave. Capped at 200 unique candidates
  (`prepare_ruby_pool.RUBY_MAX_TOTAL`) via `control_search.run`'s
  `max_total` parameter — this wave's keyword set is narrow enough that the
  review burden should stay small (~150–200 candidates) regardless of how
  much overlap GitHub's search results happen to have between keywords.

```powershell
# Run an additional wave (after an initial matching pass has already
# identified a coverage gap) — same pattern for either:
python control-search/prepare_expansion_pool.py
python control-search/prepare_ruby_pool.py

# review.html then shows all waves present, appended in
# original -> expansion -> ruby order (never interleaved), with a wave
# filter and a per-repo "Expansion"/"Ruby" chip once more than one wave
# exists. Export still writes a single control_pool_reviewed.json covering
# every wave's accepted repos.
```

Every candidate carries a `"wave"` field through to the final exported pool,
so the two waves' contributions can be reported and audited separately in
the paper (e.g. "N repos added via a follow-up wave targeting the Ruby/Rails
community-platform niche") rather than blending invisibly into "the control
pool." Unlike the original wave's search, later waves' *unreviewed*
intermediate files (`control_candidates_expansion*.json`,
`control_candidates_ruby*.json`, and their triaged/JS-sidecar counterparts)
are gitignored the same way the original wave's are — only the final
`control_pool_reviewed.json` is committed.

**Step 3 is required, not optional, for `python main.py`.** The matched-
comparison analysis is gated on an explicit human-reviewed pool: `main.py`
checks for `control-search/control_pool_reviewed.json` before running Stage
7.6, and skips it entirely (logging a clear message, and leaving the
dashboard's Matched Comparison tab in its "not available yet" state) if that
file doesn't exist. This is deliberate — an unreviewed, auto-suggested
control pool should never silently reach the published dashboard. Once you've
exported the reviewed pool, every subsequent `python main.py` run uses it
automatically; you don't need to re-review unless you want to change the pool.

For local testing only, `python control-search/run_matched_comparison.py
--allow-unreviewed` bypasses the gate and uses the auto-suggested-accept set
(marked `"review_status": "auto_suggested_fallback"` in the output JSON).
`main.py` never passes this flag.

### Methodology summary

1. **Matching covariates** — `log(stars+1)`, `log(forks+1)`, repository age,
   `log(contributor count+1)`, `log(recent 52-week commit activity+1)`, and
   `log(codebase size in bytes+1)` (total non-notebook language bytes from
   GitHub's `/languages` breakdown — added because two repos with similar
   stars/forks/activity can still differ substantially in actual codebase
   scale, a dimension the other five don't capture), plus a hard gate on
   primary language (see Eligibility below). All count-type covariates are
   log-transformed for the same reason: Mahalanobis distance assumes roughly
   elliptical covariate distributions, and raw GitHub activity counts are
   heavily right-skewed (commit activity here is more skewed than stars).
   Release count, dependency count (SBOM package count), and
   organization-vs-individual ownership were considered and deliberately
   excluded — the first two are plausible mediators (downstream of
   ag-specific status rather than a nuisance confound of it), and ownership
   type was the noisiest of the candidate covariates without being the main
   driver of caliper failures. Computed via the **GitHub REST API uniformly
   for every repo in the analysis** (both the dataset repos and every control
   candidate), since mixing measurement sources between groups would bias
   the matching itself.
2. **Eligibility** — a hard exact primary-language gate (no ecosystem-bucket
   fallback: a dataset repo with zero same-language candidates in the control
   pool is dropped into the unmatched cohort rather than matched against a
   different-language proxy), then a **Mahalanobis-distance caliper** over
   the standardized continuous
   covariates plus the ownership indicator. Mahalanobis distance (rather than
   raw Euclidean distance) accounts for correlation between covariates and is
   the standard choice in the matching literature for a covariate set this
   size with a modest treated sample (Rosenbaum & Rubin; King & Nielsen 2019).
   The caliper threshold is set via the chi-squared distribution (df = number
   of covariates), since squared Mahalanobis distances are asymptotically
   chi-squared distributed.
3. **Covariate balance diagnostics** — standardized mean difference (SMD) per
   covariate, dataset group vs. control pool (before) and vs. each repo's
   top-k nearest-eligible controls at the dashboard's selected k (after),
   following the Rosenbaum/Rubin/Austin convention (`|SMD| < 0.1` well
   balanced, `0.1–0.25` acceptable, `> 0.25` imbalanced). Computed per k in
   `k_options`, not against the full caliper-eligible union, so "after"
   always reflects the same matched sample the effect estimates use.
4. **Repeated random matching, at multiple k** — for each of many random
   seeds (default 1,000), `k` controls are drawn from the *full eligible
   pool* per dataset repo (without replacement within a seed where possible,
   with replacement only if the eligible pool is too small). This — rather
   than a single fixed assignment — represents matching-*assignment*
   uncertainty in addition to ordinary sampling uncertainty. This step is run
   once per value in `--k-options` (default `1,3,5`), not just once at a
   single k: the dashboard's **k selector** lets you switch between fully
   precomputed results at each k instantly, for every group and every
   metric — not only a headline-metrics robustness footnote. `--k` picks
   which of those values is pre-selected by default. `k_guidance` in the
   output JSON reports the average and minimum eligible-control pool size
   across matched repos, to help judge how much higher k values would force
   reusing the same control.
5. **Effect estimation** — per seed, the matched-pair difference (dataset
   repo's outcome − mean of its k matched controls' outcome) is computed per
   metric, and a Wilcoxon signed-rank test gives a matched-pairs rank-biserial
   effect size. Across seeds, the **median effect and [2.5th, 97.5th]
   percentile interval** are reported, with **Benjamini-Hochberg FDR
   correction** applied across metrics within each grouping (reusing the same
   `_bh_fdr_correct` helper the `ag_vs_nonag` comparison already uses).
   Results are reported for **all 54 repos**, separately for the
   `ag_specific=Yes` and `ag_specific=No` subgroups (the latter has limited
   statistical power at n=11 and should be read as suggestive, not
   conclusive, on its own), and separately per repo category.
6. **Outcome metrics** — `scorecard_overall` and all Scorecard per-check
   scores (including `Dependency-Update-Tool` and `Signed-Releases`),
   dependency vulnerability count/density, and CISA KEV-exploitable
   vulnerability count — computed with the exact same
   `pipeline/scorecard_runner.py`, `pipeline/dependency_runner.py`, and
   `pipeline/exploit.py` logic used for the original 54 repos, so outcome
   measurement is identical across groups.

Full limitations and interpretation framing are included verbatim in the
`data_notes` field of `outputs/processed/matched_comparison.json`.

### Running standalone

```powershell
# Full run (builds the control pool if needed, fetches covariates, collects
# Scorecard for the eligible union, runs 1000 seeds)
python control-search/run_matched_comparison.py

# Re-fetch everything, ignoring caches
python control-search/run_matched_comparison.py --force

# Fewer seeds for a quick check
python control-search/run_matched_comparison.py --n-seeds 100

# Change which k values get precomputed for the dashboard's k selector, and
# which one is pre-selected by default (both default to 1,3,5 / 3)
python control-search/run_matched_comparison.py --k-options 1,2,3,5,8 --k 3
```

Results appear in the dashboard's **Matched Comparison** tab (see
[Dashboard Guide](#dashboard-guide)). Per-repo raw API responses are cached
under `control-search/raw/` (covariates, scorecard, dependency), separate from
`outputs/raw/`, so reruns are fast unless `--force` is passed.

---

## Outputs

### Directory structure

```
outputs/
├── raw/
│   ├── scorecard/
│   │   └── owner__repo.json        ← one file per repo (raw Scorecard output)
│   └── dependency/
│       └── owner__repo.json        ← one file per repo (SBOM + OSV results)
│   # GitHub metrics (contributors, commits, issues, merged PRs, stars,
│   # forks, language, license) have no separate raw/ cache — collection is
│   # 1 batched GraphQL call per ~20 repos plus 2 REST calls per repo
│   # (minutes for the whole dataset), so unlike Scorecard/dependency
│   # there's no slow step worth caching separately. Results live directly
│   # in merged_repos.json's `github_metrics` field.
├── processed/
│   ├── merged_repos.json           ← unified dataset (one record per input repo)
│   ├── merged_repos.csv            ← flat CSV version of merged_repos.json
│   ├── summary.json                ← run metadata and aggregate counts
│   ├── dependency_analysis.json    ← aggregated vulnerability data
│   ├── kev_analysis.json           ← per-vulnerability KEV match details
│   ├── kev_summary.json            ← exploitability statistics (embedded in dashboard)
│   ├── statistical_analysis.json   ← all statistical test results
│   ├── saturation_analysis.json    ← rarefaction curve data
│   └── matched_comparison.json     ← matched-comparison results (see below)
├── dashboard/
│   └── index.html                  ← self-contained interactive dashboard
└── logs/
    └── pipeline.log                ← full DEBUG log for the most recent run

control-search/
├── control_candidates.json         ← raw non-ag candidate search results
├── control_candidates_triaged.json ← candidates + auto-triage suggestions
├── control_pool_reviewed.json      ← human-exported reviewed pool (from review.html)
├── control_pool.json               ← final resolved control pool
└── raw/
    ├── covariates/owner__repo.json ← cached GitHub REST covariate fetches
    ├── scorecard/owner__repo.json  ← cached Scorecard runs (eligible union only)
    └── dependency/owner__repo.json ← cached SBOM + OSV results (full control pool)
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
  "github_metrics_collected": true,
  "github_metrics": {
    "contributor_count": 54,
    "commit_count": 9349,
    "issues_opened": 7,
    "issues_closed": 41,
    "prs_merged": 312,
    "stars": 1305,
    "forks": 356,
    "languages": ["PHP"],
    "license": "GPL-2.0"
  },
  "overall_status": "complete"
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
| **Repo Table** | Sortable, filterable table of all repositories with Scorecard scores, GitHub metrics, vulnerability counts, and detected license |
| **Categories** | Scorecard boxplots by software layer · dependency vulnerability boxplot · category comparison bar charts with 95% CI error bars · per-repo security check heatmap · Kruskal-Wallis + Dunn results |
| **Ag-Specific** | Ag vs non-ag metric comparisons · Mann-Whitney effect size chart with CI · radar chart of Scorecard check averages · full Mann-Whitney table |
| **Vulnerabilities** | Dependency vulnerability breakdown · CISA KEV exploitability panel with remediation deadlines |
| **Dependencies** | Full dependency scan results per repository · severity breakdown · vulnerability density chart |
| **Comparisons** | Repo rankings by score / stars / commits · scatter plots with Spearman subtitles · Scorecard check averages with 95% CI error bars |
| **Matched Comparison** | All-54-vs-matched-controls results: covariate balance table, per-metric effect table (all / ag-specific / non-ag-specific / per category), a k selector that instantly switches every section between precomputed k values, per-repo eligible-control coverage — see [Matched-Comparison Analysis](#matched-comparison-analysis) |
| **Pipeline Health** | Per-repository Scorecard and GitHub metrics status badges · runtime statistics |

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
| Python | 3.11 |
| scipy | 1.11+ |
| numpy | 1.24+ |

The collection date is recorded in `COLLECTION_DATE.txt` and in
`outputs/processed/summary.json` (`run_start`, `run_end` fields).

### Reproducing analysis from committed cache

`outputs/processed/` (the actual analysis results and merged dataset) and
`outputs/dashboard/` are committed to version control, so statistical
analysis and dashboard generation can be reproduced without re-running data
collection or requiring any API access. `outputs/raw/` (per-repo Scorecard
and dependency API caches) is gitignored — it's large and fully reproducible
from `inputs/` via a pipeline re-run, not needed for `--regenerate`:

```powershell
# Reproduce all downstream results from committed processed outputs (~5 seconds)
python main.py --regenerate
```

### Random seed

Bootstrap resampling in `pipeline/stats.py` and `pipeline/saturation.py` uses
a fixed NumPy seed (`seed=42`). All bootstrap CI results are therefore
**deterministic** given the same input data.

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

### GitHub metrics collection failed for a repository

Check `github_metrics_error` on that repo's record in `merged_repos.json`.
The most common cause is a transient GitHub API error or rate limiting —
re-run the pipeline (or just `--force` for that stage) once the rate limit
window resets. `GET /rate_limit` (authenticated) shows your current quota.

### Dependency analysis returns no results for a repository

- Verify `GITHUB_AUTH_TOKEN` has `public_repo` scope (required for the GitHub
  Dependency Graph API).
- Some repositories have the Dependency Graph disabled or do not publish an
  SBOM. These repos are marked `skipped` in `dependency_analysis.json` and
  excluded from vulnerability statistics.

### Dashboard shows no correlation matrix

The matrix is suppressed when every pair of metrics has at least one member
with constant values across all repositories (e.g., all vulnerability counts
= 0 because dependency analysis has not run). Running Stage 4
(`python main.py --skip-scorecard`) populates the dependency data.

### Windows: `scorecard binary not found`

Check that `tools\scorecard.exe` exists (note the backslash). The parent
`tools\` directory must not be renamed.

---

## Extending the Pipeline

### Adding new repositories

Edit the input CSV and add rows following the 4-column format, then run:

```powershell
# Full re-collection; Scorecard and dependency caches are reused for repos
# whose raw JSON already exists, GitHub metrics are re-collected fresh
# (cheap enough not to need caching -- see Stage 5)
python main.py
```

### Changing the repository list

Remove rows from the input CSV and delete the corresponding files from
`outputs/raw/scorecard/` and `outputs/raw/dependency/` before re-running.
Stale cache files for removed repositories will otherwise be included in the
merge step.

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
