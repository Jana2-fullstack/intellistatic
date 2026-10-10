"""Run the reproducible synthetic model-training pipeline end to end."""
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parent
STEPS = [
    "ml_training/generate_synthetic_data.py",
    "ml_training/train_binary.py",
    "ml_training/train_multiclass.py",
    "ml_training/evaluate.py",
]


def main() -> None:
    for script in STEPS:
        print(f"\n--- Running {script} ---", flush=True)
        subprocess.run([sys.executable, str(ROOT / script)], cwd=ROOT, check=True)
    print("\nTraining complete. These artifacts were trained on synthetic data; validate on a representative dataset before operational use.")


if __name__ == "__main__":
    main()
