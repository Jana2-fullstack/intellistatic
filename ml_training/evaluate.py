"""Create evaluation plots from persisted holdout predictions."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("MPLCONFIGDIR", str(ROOT / "ml_training" / ".mplconfig"))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.metrics import ConfusionMatrixDisplay, RocCurveDisplay, confusion_matrix

EVALUATION = ROOT / "ml_training" / "evaluation"
FAMILIES = ["Benign", "Trojan", "Ransomware", "Spyware", "Worm", "Adware"]


def main() -> None:
    EVALUATION.mkdir(parents=True, exist_ok=True)
    binary_path = EVALUATION / "binary_holdout.csv"
    if binary_path.is_file():
        frame = pd.read_csv(binary_path)
        fig, axes = plt.subplots(1, 2, figsize=(10, 4))
        ConfusionMatrixDisplay.from_predictions(frame.actual, frame.prediction, display_labels=["Benign", "Malicious"], ax=axes[0], colorbar=False)
        RocCurveDisplay.from_predictions(frame.actual, frame.probability, ax=axes[1])
        fig.tight_layout()
        fig.savefig(EVALUATION / "binary_evaluation.png", dpi=160)
        plt.close(fig)
    multiclass_path = EVALUATION / "multiclass_holdout.csv"
    if multiclass_path.is_file():
        frame = pd.read_csv(multiclass_path)
        matrix = confusion_matrix(frame.actual, frame.prediction, labels=list(range(6)))
        display = ConfusionMatrixDisplay(matrix, display_labels=FAMILIES)
        fig, ax = plt.subplots(figsize=(8, 7))
        display.plot(ax=ax, xticks_rotation=35, colorbar=False)
        fig.tight_layout()
        fig.savefig(EVALUATION / "multiclass_confusion_matrix.png", dpi=160)
        plt.close(fig)
    model_path = ROOT / "ml_training" / "models" / "lgbm_binary.txt"
    if model_path.is_file():
        model = lgb.Booster(model_file=str(model_path))
        importance = pd.Series(model.feature_importance(importance_type="gain"), index=model.feature_name()).sort_values().tail(20)
        ax = importance.plot(kind="barh", figsize=(8, 7), color="#0047AB", title="Binary model feature importance (gain)")
        ax.figure.tight_layout()
        ax.figure.savefig(EVALUATION / "binary_feature_importance.png", dpi=160)
        plt.close(ax.figure)
    print("Evaluation plots saved under", EVALUATION)


if __name__ == "__main__":
    main()
