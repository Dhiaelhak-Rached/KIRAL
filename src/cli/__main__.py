"""Entry point for `python -m src.cli`."""

import logging
import sys

# Suppress noisy library loggers so the CLI stays clean.
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)

# Force UTF-8 on Windows so Rich box-drawing characters render correctly.
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

from src.cli.main import app

if __name__ == "__main__":
    app()
