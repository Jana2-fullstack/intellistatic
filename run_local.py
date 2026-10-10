"""Start the local API and dashboard together; Ctrl+C stops both processes."""
from pathlib import Path
import os
import signal
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parent


def main() -> None:
    # Propagate the server-side API key from .env so the dashboard can authenticate.
    env = os.environ.copy()
    api_key = env.get("API_KEY")
    if not api_key and (ROOT / ".env").exists():
        for line in (ROOT / ".env").read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("API_KEY=") and not line.startswith("#"):
                api_key = line.split("=", 1)[1].strip()
                env["API_KEY"] = api_key
                break
    if api_key:
        env.setdefault("INTELLISTATIC_API_KEY", api_key)

    backend = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "src.main:app", "--app-dir", "backend", "--host", "127.0.0.1", "--port", "8000"],
        cwd=ROOT,
        env=env,
    )
    frontend = None
    try:
        time.sleep(1)
        if backend.poll() is not None:
            raise RuntimeError("The API process stopped during startup.")
        frontend = subprocess.Popen(
            [sys.executable, "-m", "streamlit", "run", "frontend/app.py", "--server.address", "127.0.0.1"],
            cwd=ROOT,
            env=env,
        )
        print("API: http://127.0.0.1:8000/docs", flush=True)
        print("Dashboard URL is printed by Streamlit. Press Ctrl+C to stop both services.", flush=True)
        while backend.poll() is None and frontend.poll() is None:
            time.sleep(.5)
    except KeyboardInterrupt:
        pass
    finally:
        for process in (frontend, backend):
            if process is not None and process.poll() is None:
                process.terminate()
        for process in (frontend, backend):
            if process is not None:
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
