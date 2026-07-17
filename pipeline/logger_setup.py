"""Pipeline logging setup — file + console handlers.

Provides `setup_logging()`, called once by `main.py` at startup to
configure the shared "pipeline" logger used by every pipeline module
(`pipeline.dependency`, `pipeline.input_parser`, etc. all log through
child loggers of this root). Attaches two handlers: a file handler that
always writes DEBUG-level records to `config.LOG_DIR / "pipeline.log"`
for later troubleshooting, and a console handler whose level depends on
the `verbose` flag (DEBUG when verbose, INFO otherwise) so normal runs
stay quiet while `--verbose` surfaces detailed progress.
"""

import logging
import sys
from pathlib import Path

from pipeline.config import LOG_DIR


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure and return the root pipeline logger."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / "pipeline.log"

    logger = logging.getLogger("pipeline")
    logger.setLevel(logging.DEBUG)

    # File handler — always DEBUG
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s"
    ))

    # Console handler — INFO unless verbose
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(logging.Formatter("%(levelname)-8s  %(message)s"))

    logger.addHandler(fh)
    logger.addHandler(ch)
    return logger
