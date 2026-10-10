"""Backward-compatible backend entry point. See README.md for the full-stack launch flow."""
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "backend"))

from src.core.config import settings  # noqa: E402
from src.main import app  # noqa: E402


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=settings.debug)
