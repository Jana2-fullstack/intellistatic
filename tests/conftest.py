import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
os.environ.setdefault("DATABASE_URL", f"sqlite:///{Path(tempfile.gettempdir()) / 'intellistatic-smoke-test.db'}")
# Tests exercise the API directly and may run many analyzes quickly.
os.environ["API_KEY"] = ""
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"
