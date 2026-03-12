# AgOSS Repository Analysis Pipeline

A local-first pipeline that analyses open-source agricultural software repositories using [OpenSSF Scorecard](https://github.com/ossf/scorecard) and a locally-running [Augur](https://github.com/chaoss/augur) instance, then produces a unified dataset and an interactive browser dashboard.

---

## Folder Structure

```
root/
├── pipeline/               # Python pipeline package
│   ├── input.txt           # One repo per line (URL, Category)
│   ├── main.py             # CLI entry point
│   ├── config.py           # Centralised paths & settings
│   ├── logger_setup.py     # Logging configuration
│   ├── models.py           # Dataclass models
│   ├── input_parser.py     # Parse input.txt
│   ├── scorecard_runner.py # Scorecard integration
│   ├── augur_runner.py     # Augur API integration
│   ├── merger.py           # Merge & write outputs
│   └── report/
│       ├── render.py       # Dashboard generator
│       ├── template.html   # HTML template
│       └── styles.css      # Dashboard CSS
├── tools/
│   ├── scorecard.exe       # OpenSSF Scorecard binary
│   └── augur/              # Local Augur installation
├── outputs/                # All generated artefacts (gitignored)
│   ├── raw/
│   │   ├── scorecard/      # Per-repo raw Scorecard JSON
│   │   └── augur/          # Per-repo raw Augur JSON
│   ├── processed/
│   │   ├── merged_repos.json
│   │   ├── merged_repos.csv
│   │   └── summary.json
│   ├── dashboard/
│   │   └── index.html      # Self-contained HTML dashboard
│   └── logs/
│       └── pipeline.log
├── requirements.txt
└── README.md               # ← you are here
```

---

## Prerequisites

| Requirement | Notes |
|---|---|
| **Python 3.10+** | Standard library + `requests` |
| **tools/scorecard.exe** | Must be present. [Download from GitHub Releases](https://github.com/ossf/scorecard/releases) |
| **GitHub PAT** | **Required** by Scorecard — set `GITHUB_AUTH_TOKEN`. Create a classic token with `public_repo` scope |
| **Augur (optional)** | A locally running instance at `http://localhost:5002` (or custom URL via env var) |
| **Docker & Docker Compose** | Only needed if you want to start Augur from `tools/augur/` |

---

## Environment / Secrets Setup

Create a `.env` file **in the project root** (this file is gitignored):

```env
# Required for Scorecard (will fail without it)
GITHUB_AUTH_TOKEN=ghp_YOUR_TOKEN_HERE

# Optional — Augur base URL (default: http://localhost:5002)
# Note: docker-compose maps container port 5000 → host port 5002
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

> **Security note:** Never commit `.env` to Git. Add it to `.gitignore`.

---

## Verifying the Tools

### Scorecard

```powershell
$env:GITHUB_AUTH_TOKEN = "ghp_YOUR_TOKEN_HERE"
.\tools\scorecard.exe --repo=https://github.com/ossf/scorecard --format=json
```

If you see JSON output with `"score"` and `"checks"`, the binary is working. **Without `GITHUB_AUTH_TOKEN`, Scorecard will error or hit rate limits.**

### Augur

```powershell
cd tools\augur
docker compose up -d        # start Augur (if not already running)
curl http://localhost:5002/api/unstable/   # should return {"status":"OK", ...}
```

> **Port note:** The `docker-compose.yml` maps container port 5000 → host port 5002. Always use port 5002 from the host.

If Augur is not reachable the pipeline will still run — Augur columns will show as "not collected".

---

## Formatting `pipeline/input.txt`

One repository per line, comma-separated:

```
https://github.com/owner/repo, Category Label
```

- Blank lines and lines starting with `#` are ignored.
- The URL must be a full `https://github.com/…` link.
- The category can be any free-text label.

---

## Running the Pipeline

### Install dependencies

```powershell
pip install -r requirements.txt
```

### Full run

```powershell
python -m pipeline.main
```

### CLI flags

| Flag | Effect |
|---|---|
| `--force` / `--force-refresh` | Re-collect all data (ignore cached raw files) |
| `--verbose` / `-v` | Show debug-level output on the console |
| `--skip-scorecard` | Skip Scorecard collection |
| `--skip-augur` | Skip Augur collection |
| `--input path/to/file.txt` | Use a different input file |
| `--sync-augur` | Compare input repos vs Augur-registered repos and log the diff |
| `--register-augur` | Register missing repos in Augur before collection |
| `--wait-for-augur` | Poll Augur until repos have data (uses `--augur-wait-mode`) |
| `--augur-wait-mode MODE` | Readiness level: `none` / `minimal` / `standard` / `full` |
| `--augur-timeout N` | Max seconds to wait for Augur data (default: 600) |

### Examples

```powershell
# Full run with verbose output
python -m pipeline.main --verbose

# Re-collect everything from scratch
python -m pipeline.main --force

# Only collect Scorecard data (skip Augur)
python -m pipeline.main --skip-augur

# Only build dashboard from existing cached data
python -m pipeline.main --skip-scorecard --skip-augur

# Sync input repos with Augur, register missing ones, then collect
python -m pipeline.main --sync-augur --register-augur

# Register + wait for data (standard readiness = basic metrics appear)
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

Compares your `input.txt` repos against what Augur has registered. Logs which repos overlap and which are missing.

### Registration (`--register-augur`)

Automatically POSTs missing repos to Augur's `/repos/add` endpoint. Repos are placed in the `AUGUR_REPO_GROUP` group.

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

## Where Outputs Are Written

All outputs go to `outputs/`:

| Path | Contents |
|---|---|
| `outputs/raw/scorecard/` | One JSON file per repo with raw Scorecard output |
| `outputs/raw/augur/` | One JSON file per repo with raw Augur API responses |
| `outputs/processed/merged_repos.json` | Unified dataset — all repos, all fields |
| `outputs/processed/merged_repos.csv` | Flattened CSV version |
| `outputs/processed/summary.json` | Run metadata — counts, timestamps, categories |
| `outputs/dashboard/index.html` | Self-contained HTML dashboard |
| `outputs/logs/pipeline.log` | Detailed run log |

---

## Merged Output Schema

Each record in `merged_repos.json` has:

| Field | Description |
|---|---|
| `repo_url` | Full GitHub URL |
| `owner` / `repo_name` | Parsed from URL |
| `category` | From input.txt |
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

Set the token in your `.env` and reload it.

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

- Make sure Docker containers are running: `cd tools/augur && docker compose ps`
- Check the port: `curl http://localhost:5002/api/unstable/`
- Remember: the host port is **5002** (not 5000).

### Repo not found in Augur

```
WARNING  owner/repo: Repo not found in Augur — may not be registered yet.
```

Use `--register-augur` to automatically register missing repos, or manually add them via the Augur admin UI.

### Augur timed out waiting for data

```
WARNING  https://github.com/… timed out after 600s
```

Augur data ingestion can be slow. Increase `--augur-timeout` or use `--augur-wait-mode minimal` to just confirm registration.

### Re-running after a partial failure

Simply re-run `python -m pipeline.main`. The pipeline uses cached raw files, so only repos without cached data will be re-collected. Use `--force` to ignore the cache entirely.

---

## Extending the Pipeline

- **Add more Augur metrics:** Edit the `AUGUR_METRIC_ENDPOINTS` list in `pipeline/config.py` and add a summarisation clause in `augur_runner.py → _summarize_metrics()`.
- **Add more readiness checks:** Edit `AUGUR_READINESS_ENDPOINTS` in `config.py`.
- **Add a new tool:** Create a new `*_runner.py` module following the same pattern as `scorecard_runner.py`, then wire it into `main.py` and `merger.py`.
- **Custom dashboard charts:** Edit `pipeline/report/template.html` — Chart.js is already loaded.

---

## License

See the individual tool licences (Scorecard: Apache-2.0, Augur: MIT). Pipeline code in this repo is provided for academic/research use.