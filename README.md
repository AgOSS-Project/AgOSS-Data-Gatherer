# AgOSS Repository Analysis Pipeline

A local-first pipeline that analyses open-source agricultural software repositories using [OpenSSF Scorecard](https://github.com/ossf/scorecard) and a locally-running [Augur](https://github.com/chaoss/augur) instance, then produces a unified dataset and an interactive browser dashboard.

---

## Quick Start

```powershell
# 1. Clone the repo
git clone https://github.com/AgOSS-Project/AgOSS-Data-Gatherer.git
cd AgOSS-Data-Gatherer

# 2. Install Python dependencies
pip install -r requirements.txt          # only `requests` is needed

# 3. Set your GitHub token  (required by Scorecard)
$env:GITHUB_AUTH_TOKEN = "ghp_YOUR_TOKEN_HERE"

# 4. Set up Augur  (Docker required — see "Setting Up Augur" below)
cd tools/augur
docker compose up -d                     # pulls images on first run
cd ../..

# 5. Run the full pipeline
python -m pipeline.main --register-augur --wait-for-augur --augur-wait-mode minimal

# 6. Open the dashboard
start outputs\dashboard\index.html       # or open in any browser
```

> **Scorecard only (no Augur)?** Skip steps 4 and the `--register-augur` / `--wait-for-augur` flags:
> ```powershell
> python -m pipeline.main --skip-augur
> ```

---

## Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Setting Up Augur](#setting-up-augur)
- [Environment / Secrets Setup](#environment--secrets-setup)
- [Formatting the Input File](#formatting-the-input-file)
- [Running the Pipeline](#running-the-pipeline)
- [Scorecard Status Model](#scorecard-status-model)
- [Augur Orchestration](#augur-orchestration)
- [Known Exploited Vulnerabilities (KEV) Analysis](#known-exploited-vulnerabilities-kev-analysis)
- [Where Outputs Are Written](#where-outputs-are-written)
- [Merged Output Schema](#merged-output-schema)
- [Using the Dashboard](#using-the-dashboard)
- [Troubleshooting](#troubleshooting)
- [Extending the Pipeline](#extending-the-pipeline)
- [Folder Structure](#folder-structure)
- [License](#license)

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.10+** | Standard library + `requests` |
| **GitHub PAT** | **Required** by Scorecard — set `GITHUB_AUTH_TOKEN`. Create a [classic token](https://github.com/settings/tokens) with `public_repo` scope |
| **Docker & Docker Compose** | Required only for Augur |

The `tools/scorecard.exe` binary is included in the repository. If you are on Linux/macOS, download the appropriate binary from the [Scorecard releases page](https://github.com/ossf/scorecard/releases) and place it at `tools/scorecard` (then update `SCORECARD_EXE` in `pipeline/config.py` if needed).

---

## Setting Up Augur

Augur is **not** included in this repository — you clone it separately into `tools/augur/`.

### First-time setup

```powershell
# From the project root
cd tools

# Clone the Augur repo
git clone https://github.com/chaoss/augur.git augur
cd augur
```

Create a `tools/augur/.env` file with your credentials:

```env
AUGUR_DB_USER=augur
AUGUR_DB_PASSWORD=augur
AUGUR_GITHUB_API_KEY=ghp_YOUR_TOKEN_HERE
AUGUR_GITHUB_USERNAME=your-github-username
```

Then start the containers:

```powershell
docker compose up -d
```

This pulls and starts five containers: `augur` (API server), `augur-db` (PostgreSQL), `augur-keyman`, `rabbitmq`, and `redis`. The first pull may take several minutes.

### Verify Augur is running

```powershell
# Wait ~30 seconds for services to start, then:
curl http://localhost:5002/api/unstable/
# Expected: {"status":"OK","version":"0.92.0"}
```

> **Port note:** The `docker-compose.yml` maps container port 5000 → **host port 5002**. Always use port 5002 from the host.

### Stopping and restarting Augur

```powershell
cd tools\augur
docker compose stop       # stop containers (preserves data)
docker compose up -d      # restart
docker compose down       # stop and remove containers (data in volumes is kept)
docker compose down -v    # stop, remove containers AND volumes (full reset)
```

If you don't want to use Augur at all, simply pass `--skip-augur` when running the pipeline.

---

## Environment / Secrets Setup

Create a `.env` file **in the project root** (this file is gitignored):

```env
# Required for Scorecard (will fail without it)
GITHUB_AUTH_TOKEN=ghp_YOUR_TOKEN_HERE

# Optional — Augur base URL (default: http://localhost:5002)
AUGUR_API_BASE=http://localhost:5002

# Optional — Augur API key if your instance requires one
AUGUR_API_KEY=

# Optional — timeouts in seconds
SCORECARD_TIMEOUT=120
SCORECARD_RETRY_COUNT=1
AUGUR_TIMEOUT=30

# Optional — Augur wait-mode controls
AUGUR_WAIT_MODE=none          # none | minimal | standard | full
AUGUR_POLL_INTERVAL=30        # seconds between readiness polls
AUGUR_WAIT_TIMEOUT=600        # max wait seconds
AUGUR_REPO_GROUP=ag-oss-pipeline

# Optional — Augur DB container (for direct registration)
AUGUR_DB_CONTAINER=augur-augur-db-1
AUGUR_DB_USER=augur
AUGUR_DB_NAME=augur
```

Load the file before running the pipeline:

```powershell
# PowerShell
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#=]+)=(.*)$') {
    [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2].Trim(), 'Process')
  }
}
```

```bash
# Bash / WSL
set -a; source .env; set +a
```

> **Security note:** Never commit `.env` to Git. It is already in `.gitignore`.

---

## Formatting the Input File

Edit your input CSV (for example `pipeline/Open Source Agricultural Software(Input).csv`) with one repository per line:

```
Display Name, https://github.com/owner/repo, Category Label, Yes|No
```

- Blank lines and lines starting with `#` are ignored.
- Optional header rows are detected and skipped.
- The URL must be a full `https://github.com/…` link.
- The category can be any free-text label (e.g. "Field-Deployed Sensor").
- The Ag-specific column accepts `Yes/No` (also supports `true/false`, `1/0`).

Legacy 2-column rows (`url, category`) are still accepted for backward compatibility.

The repo ships with 37 pre-configured ag-OSS repositories across several categories.

---

## Running the Pipeline

### Full run (Scorecard + Augur)

```powershell
python -m pipeline.main --register-augur --wait-for-augur --augur-wait-mode minimal
```

### Scorecard only (no Docker needed)

```powershell
python -m pipeline.main --skip-augur
```

### Rebuild dashboard from cached data (instant)

```powershell
python -m pipeline.main --skip-scorecard --skip-augur
```

### CLI flags

| Flag | Effect |
|---|---|
| `--force` / `--force-refresh` | Re-collect all data (ignore cached raw files) |
| `--verbose` / `-v` | Show debug-level output on the console |
| `--skip-scorecard` | Skip Scorecard collection |
| `--skip-augur` | Skip Augur collection |
| `--input path/to/file.csv` | Use a different input file |
| `--sync-augur` | Compare input repos vs Augur-registered repos and log the diff |
| `--register-augur` | Register missing repos in Augur before collection |
| `--wait-for-augur` | Poll Augur until repos have data (uses `--augur-wait-mode`) |
| `--augur-wait-mode MODE` | Readiness level: `none` / `minimal` / `standard` / `full` |
| `--augur-timeout N` | Max seconds to wait for Augur data (default: 600) |

### More examples

```powershell
# Full run with verbose output
python -m pipeline.main --verbose

# Re-collect everything from scratch
python -m pipeline.main --force

# Sync input repos with Augur, register missing ones, then collect
python -m pipeline.main --sync-augur --register-augur

# Register + wait for standard readiness (basic metrics appear)
python -m pipeline.main --register-augur --wait-for-augur --augur-wait-mode standard

# Full orchestration with 10-minute timeout
python -m pipeline.main --register-augur --wait-for-augur --augur-wait-mode full --augur-timeout 600
```

---

## Scorecard Status Model

Each repo gets a Scorecard status:

| Status | Meaning |
|---|---|
| **success** | Exit code 0 and valid JSON with scores |
| **partial_success** | Non-zero exit code but valid JSON was still produced (scores may be incomplete) |
| **failed** | No usable JSON output after all retries |
| **skipped** | `--skip-scorecard` was used |

The pipeline retries failed runs up to `SCORECARD_RETRY_COUNT` times (default 1). Partial-success results are still included in analysis.

---

## Augur Orchestration

### Sync (`--sync-augur`)

Compares your input-file repos against what Augur has registered. Logs which repos overlap and which are missing.

### Registration (`--register-augur`)

Registers missing repos directly into Augur's PostgreSQL database via `docker exec psql`. The HTTP write API requires SSL (returns 426 on local instances), so the pipeline uses direct DB insertion instead. Repos are placed in the `AUGUR_REPO_GROUP` group and a `collection_status` row is created to trigger Augur's data ingestion.

### Wait modes (`--wait-for-augur`)

After registration, data ingestion takes time. The wait system polls readiness:

| Mode | Behaviour |
|---|---|
| `none` | Don't wait — collect whatever data exists immediately |
| `minimal` | Confirm the repo is registered (resolves a repo_id) |
| `standard` | Wait until at least one readiness endpoint returns data |
| `full` | Wait until all readiness endpoints return data |

Readiness endpoints (configurable in `config.py`): `contributors`, `issues-new`.

### Per-repo Augur status

| Status | Meaning |
|---|---|
| **ready** | All configured metrics collected |
| **partial** | Some metrics collected (data available but incomplete) |
| **registered** | Repo is in Augur but no metric data yet |
| **timed_out** | Wait exceeded `--augur-timeout` |
| **not_registered** | Repo not found and registration not requested |
| **failed** | API error or Augur unreachable |

---

## Known Exploited Vulnerabilities (KEV) Analysis

The pipeline's vulnerability detection can be enriched using `exploit.py`, a standalone script that cross-references discovered vulnerabilities with CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog.

### What it does

`exploit.py` analyzes the dependency analysis output to identify which vulnerabilities have **known public exploits**. This is a critical security indicator — a vulnerability with a known exploit presents immediate risk if unpatched.

### How to run it

```powershell
# Requires: pipeline run must have completed (produces dependency_analysis.json)
python exploit.py
```

The script:
1. Loads the `outputs/processed/dependency_analysis.json` file
2. Fetches CISA's current KEV catalog via HTTPS
3. Cross-references each vulnerability's CVE ID against the catalog
4. Generates two output files with detailed findings and statistics

### Output files

| File | Contents |
|---|---|
| `outputs/processed/kev_analysis.json` | Full analysis — all vulnerabilities, KEV match status, and CISA details |
| `outputs/processed/kev_summary.json` | Executive summary — counts, exploitability rate, and top-priority vulnerabilities |

### Understanding the output

**Key metrics in `kev_summary.json`:**

```json
{
  "summary": {
    "total_vulnerabilities_analyzed": 150,
    "exploitable_vulnerabilities": 12,
    "exploitability_rate_percent": 8.0,
    "exploitable_by_severity": {
      "CRITICAL": 2,
      "HIGH": 5,
      "MEDIUM": 5
    },
    "top_priority_vulnerabilities": [...]
  }
}
```

**Each vulnerability in `kev_analysis.json` includes:**

- `id`: OSV vulnerability ID
- `summary`: Vulnerability description
- `severity`: Severity level (CRITICAL, HIGH, etc.)
- `is_exploitable`: Whether it's in the CISA KEV catalog
- `matched_cve`: The CVE ID matched to CISA's catalog (if exploitable)
- `kev_data`: Full CISA entry including vendor, product, due date, required actions

---

## Where Outputs Are Written

All outputs go to `outputs/`:

| Path | Contents |
|---|---|
| `outputs/raw/scorecard/` | One JSON file per repo with raw Scorecard output |
| `outputs/raw/augur/` | One JSON file per repo with raw Augur API responses |
| `outputs/processed/merged_repos.json` | Unified dataset — all repos, all fields |
| `outputs/processed/merged_repos.csv` | Flattened CSV version |
| `outputs/processed/summary.json` | Run metadata — counts, timestamps, categories |
| `outputs/processed/dependency_analysis.json` | Vulnerability analysis from pipeline (input for `exploit.py`) |
| `outputs/processed/kev_analysis.json` | Full KEV analysis (from `exploit.py`) — all vulnerabilities with exploitation status |
| `outputs/processed/kev_summary.json` | KEV summary (from `exploit.py`) — exploitability statistics and top findings |
| `outputs/dashboard/index.html` | Self-contained HTML dashboard |
| `outputs/logs/pipeline.log` | Detailed run log |

---

## Merged Output Schema

Each record in `merged_repos.json` has:

| Field | Description |
|---|---|
| `repo_url` | Full GitHub URL |
| `display_name` | Human-readable name from input CSV |
| `owner` / `repo_name` | Parsed from URL |
| `category` | From input file |
| `ag_specific` | `true` / `false` / `null` from input CSV |
| `collection_timestamp` | UTC ISO-8601 timestamp |
| `scorecard_collected` | Boolean — did Scorecard produce data? |
| `scorecard_status` | `success` / `partial_success` / `failed` / `skipped` |
| `scorecard_error` | Error message if failed |
| `scorecard_overall` | Aggregate Scorecard score (0–10) |
| `scorecard_checks` | Dict of check name → `{score, reason}` |
| `scorecard_exit_code` | Process exit code |
| `scorecard_runtime` | Execution time in seconds |
| `augur_collected` | Boolean — did Augur produce data? |
| `augur_status` | `ready` / `partial` / `registered` / `timed_out` / `not_registered` / `failed` |
| `augur_error` | Error message if failed |
| `augur_repo_id` | Augur internal ID |
| `augur_registered` | Boolean — is repo registered in Augur? |
| `augur_ready` | Boolean — all metrics collected? |
| `augur_metrics` | Dict with keys like `contributor_count`, `stars`, `forks`, `issues_opened`, `prs_opened`, etc. |
| `overall_status` | `complete` / `partial` / `failed` — combined pipeline status |

---

## Using the Dashboard

Open `outputs/dashboard/index.html` in any modern browser. No server required — it is fully self-contained.

### Dashboard sections

| Tab | What it shows |
|---|---|
| **Overview** | Summary cards, score distribution, category breakdown, collection status doughnut |
| **Repo Table** | Searchable / sortable / filterable table with SC status, Augur status, and overall status badges |
| **Categories** | Category-level stats, comparison charts, scatter plots |
| **Comparisons** | Repo rankings, scatter plots (security vs ecosystem), average check scores |
| **Pipeline Health** | Per-tool status breakdown (SC success/partial/failed, Augur ready/partial/registered/timed_out/failed), status doughnut charts, detailed quality table with exit codes and runtimes |

Click **View** on any repo row to open a detail modal showing the full Scorecard check breakdown, Augur metrics, and pipeline status.

---

## Troubleshooting

### Scorecard: `GITHUB_AUTH_TOKEN` not set

Scorecard **requires** a GitHub token. Without it you'll see:

```
WARNING  GITHUB_AUTH_TOKEN not set — Scorecard requires it to avoid rate limits.
```

Set the token in your environment or `.env` and reload it.

### Scorecard: partial_success

If Scorecard exits non-zero but produces valid JSON, the pipeline classifies this as `partial_success` and still extracts scores. This commonly happens with repos that have restricted GitHub API access.

### Invalid / expired GitHub token

```
scorecard exited 1: … 403 Forbidden …
```

Regenerate your PAT and update `.env`. Scorecard needs at least `public_repo` scope.

### Augur not reachable

```
ERROR    Augur API is not reachable at http://localhost:5002
```

- Make sure you've cloned Augur into `tools/augur/` and run `docker compose up -d`.
- Check containers are running: `docker ps`
- Check the port: `curl http://localhost:5002/api/unstable/`
- Remember: the host port is **5002** (not 5000).

### Augur containers won't start

- Ensure Docker Desktop is running.
- Check for port conflicts: `netstat -an | findstr 5002` / `netstat -an | findstr 5432`.
- View container logs: `docker logs augur-augur-1 --tail 50`
- If the DB is corrupt, reset with `docker compose down -v` then `docker compose up -d`.

### Repo not found in Augur

```
WARNING  owner/repo: Repo not found in Augur — may not be registered yet.
```

Use `--register-augur` to automatically register missing repos. The pipeline inserts them directly into Augur's PostgreSQL database.

### Augur timed out waiting for data

```
WARNING  https://github.com/… timed out after 600s
```

Augur data ingestion can be slow for fresh repos. Increase `--augur-timeout` or use `--augur-wait-mode minimal` to just confirm registration.

### Re-running after a partial failure

Simply re-run `python -m pipeline.main`. The pipeline uses cached raw files, so only repos without cached data will be re-collected. Use `--force` to ignore the cache entirely.

---

## Extending the Pipeline

- **Add more Augur metrics:** Edit the `AUGUR_METRIC_ENDPOINTS` list in `pipeline/config.py` and add a summarisation clause in `augur_runner.py → _summarize_metrics()`.
- **Add more readiness checks:** Edit `AUGUR_READINESS_ENDPOINTS` in `config.py`.
- **Add a new tool:** Create a new `*_runner.py` module following the same pattern as `scorecard_runner.py`, then wire it into `main.py` and `merger.py`.
- **Custom dashboard charts:** Edit `pipeline/report/template.html` — Chart.js is already loaded.

---

## Folder Structure

```
AgOSS-Data-Gatherer/
├── exploit.py              # KEV (Known Exploited Vulnerabilities) analysis tool — cross-references findings with CISA catalog
├── pipeline/               # Python pipeline package
│   ├── Open Source Agricultural Software(Input).csv  # Main input list (Name, URL, Category, Ag-specific)
│   ├── input.txt           # Optional legacy input (URL, Category)
│   ├── main.py             # CLI entry point
│   ├── config.py           # Centralised paths & settings
│   ├── logger_setup.py     # Logging configuration
│   ├── models.py           # Dataclass models
│   ├── input_parser.py     # Parse CSV / legacy input formats
│   ├── scorecard_runner.py # Scorecard integration (retries, partial_success)
│   ├── augur_runner.py     # Augur API + DB registration + wait logic
│   ├── merger.py           # Merge & write outputs
│   └── report/
│       ├── render.py       # Dashboard generator
│       ├── template.html   # HTML template (Chart.js)
│       └── styles.css      # Dashboard CSS
├── tools/
│   ├── scorecard.exe       # OpenSSF Scorecard binary (checked in)
│   └── augur/              # ← clone Augur here (gitignored)
├── outputs/                # Generated artefacts (gitignored)
│   ├── raw/
│   │   ├── scorecard/      # Per-repo raw Scorecard JSON
│   │   └── augur/          # Per-repo raw Augur JSON
│   ├── processed/
│   │   ├── merged_repos.json
│   │   ├── merged_repos.csv
│   │   ├── dependency_analysis.json
│   │   ├── kev_analysis.json          # From exploit.py
│   │   ├── kev_summary.json           # From exploit.py
│   │   └── summary.json
│   ├── dashboard/
│   │   └── index.html      # Self-contained HTML dashboard
│   └── logs/
│       └── pipeline.log
├── requirements.txt        # requests>=2.28
├── .gitignore
└── README.md
```

---

## License

See the individual tool licences (Scorecard: Apache-2.0, Augur: MIT). Pipeline code in this repo is provided for academic/research use.