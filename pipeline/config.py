"""Centralized configuration for the pipeline."""

import os
from pathlib import Path

# ---------------------------------------------------------------------------
# Path layout — all paths are relative to the project root
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def _load_dotenv_file(path: Path, *, override: bool = False) -> None:
    """Load simple KEY=VALUE lines from a .env file into os.environ."""
    if not path.exists() or not path.is_file():
        return

    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):].strip()
        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"\"", "'"}:
            value = value[1:-1]

        if override or key not in os.environ:
            os.environ[key] = value


def _load_project_env_files() -> None:
    """Load environment files used by the pipeline."""
    candidates = [
        PROJECT_ROOT / ".env",
        PROJECT_ROOT / "pipeline" / ".env",
    ]
    for env_path in candidates:
        _load_dotenv_file(env_path, override=False)


_load_project_env_files()

TOOLS_DIR = PROJECT_ROOT / "tools"


def _resolve_scorecard_executable() -> Path:
    """Pick the platform-appropriate Scorecard executable path."""
    if os.name == "nt":
        candidates = [TOOLS_DIR / "scorecard.exe", TOOLS_DIR / "scorecard"]
    else:
        candidates = [TOOLS_DIR / "scorecard", TOOLS_DIR / "scorecard.exe"]

    for candidate in candidates:
        if candidate.exists():
            return candidate

    return candidates[0]


SCORECARD_EXE = _resolve_scorecard_executable()

INPUT_FILE = PROJECT_ROOT / "inputs" / "Open Source Agricultural Software(Input).csv"

OUTPUTS_DIR = PROJECT_ROOT / "outputs"
RAW_SCORECARD_DIR = OUTPUTS_DIR / "raw" / "scorecard"
RAW_DEPENDENCY_DIR = OUTPUTS_DIR / "raw" / "dependency"
PROCESSED_DIR = OUTPUTS_DIR / "processed"
DEPENDENCY_REPORT_FILE = PROCESSED_DIR / "dependency_analysis.json"
DASHBOARD_DIR = OUTPUTS_DIR / "dashboard"
LOG_DIR = OUTPUTS_DIR / "logs"

# ---------------------------------------------------------------------------
# Scorecard configuration
# ---------------------------------------------------------------------------
SCORECARD_TIMEOUT_SECONDS = int(os.getenv("SCORECARD_TIMEOUT", "120"))
SCORECARD_RETRY_COUNT = int(os.getenv("SCORECARD_RETRY_COUNT", "1"))
GITHUB_AUTH_TOKEN = os.getenv("GITHUB_AUTH_TOKEN") or os.getenv("GITHUB_TOKEN", "")

# ---------------------------------------------------------------------------
# Dependency analysis configuration (GitHub SBOM + OSV)
# ---------------------------------------------------------------------------
DEPENDENCY_MAX_WORKERS = int(os.getenv("DEPENDENCY_MAX_WORKERS", "4"))
DEPENDENCY_HTTP_TIMEOUT_SECONDS = int(os.getenv("DEPENDENCY_HTTP_TIMEOUT", "30"))
DEPENDENCY_RETRY_COUNT = int(os.getenv("DEPENDENCY_RETRY_COUNT", "2"))
DEPENDENCY_RETRY_BACKOFF_SECONDS = float(os.getenv("DEPENDENCY_RETRY_BACKOFF", "1.5"))

GITHUB_API_BASE = os.getenv("GITHUB_API_BASE", "https://api.github.com")
OSV_API_BASE = os.getenv("OSV_API_BASE", "https://api.osv.dev")
OSV_QUERY_BATCH_SIZE = int(os.getenv("OSV_QUERY_BATCH_SIZE", "100"))

# ---------------------------------------------------------------------------
# Pipeline behaviour
# ---------------------------------------------------------------------------
FORCE_REFRESH = False  # overridden via CLI --force flag
