"""Train/evaluate a binary PE baseline without duplicate-vector leakage."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


ROOT = Path(__file__).resolve().parents[1]
DATA_PATH = ROOT / "data" / "MalwareDataSet.csv"
MODEL_DIR = ROOT / "ml_training" / "models"
MODEL_PATH = MODEL_DIR / "pe_rf_baseline.joblib"
METRICS_PATH = MODEL_DIR / "pe_rf_baseline_metrics.json"
SEED = 42

# These seven columns are present in both the labeled source table and the
# static PE feature extractor. ResourceSize is intentionally omitted because
# the current extractor does not calculate that exact dataset field.
DATASET_TO_FEATURE = {
    "AddressOfEntryPoint": "address_of_entry_point",
    "MajorLinkerVersion": "major_linker_version",
    "MajorImageVersion": "major_image_version",
    "MajorOperatingSystemVersion": "major_os_version",
    "DllCharacteristics": "dll_characteristics",
    "SizeOfStackReserve": "size_of_stack_reserve",
    "NumberOfSections": "number_of_sections",
}


def main() -> None:
    if not DATA_PATH.is_file():
        raise FileNotFoundError(f"Labeled source dataset not found: {DATA_PATH}")

    frame = pd.read_csv(DATA_PATH)
    required = [*DATASET_TO_FEATURE, "legitimate"]
    missing = sorted(set(required) - set(frame.columns))
    if missing:
        raise ValueError(f"Dataset is missing required columns: {', '.join(missing)}")
    frame = frame[required].dropna()
    frame["legitimate"] = pd.to_numeric(frame["legitimate"], errors="raise").astype(int)
    if not set(frame["legitimate"].unique()).issubset({0, 1}):
        raise ValueError("The legitimate target must contain only 0 (malware) and 1 (legitimate).")
    for column in DATASET_TO_FEATURE:
        frame[column] = pd.to_numeric(frame[column], errors="raise")

    features = list(DATASET_TO_FEATURE)
    grouped = frame.groupby(features, as_index=False, dropna=False).agg(
        legitimate=("legitimate", "mean"), source_rows=("legitimate", "size")
    )
    conflicting_groups = int(((grouped["legitimate"] != 0) & (grouped["legitimate"] != 1)).sum())
    unique_rows = grouped[grouped["legitimate"].isin([0, 1])].copy()
    unique_rows["legitimate"] = unique_rows["legitimate"].astype(int)

    x = unique_rows[features]
    y = unique_rows["legitimate"]
    train_indices, holdout_indices = train_test_split(
        unique_rows.index,
        test_size=0.20,
        random_state=SEED,
        stratify=y,
    )
    model = RandomForestClassifier(
        n_estimators=300,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=SEED,
    )
    model.fit(x.loc[train_indices], y.loc[train_indices])

    holdout_x = x.loc[holdout_indices]
    holdout_y = y.loc[holdout_indices]
    class_scores = model.predict_proba(holdout_x)
    malware_index = list(model.classes_).index(0)
    malware_scores = class_scores[:, malware_index]
    predicted_malware = (malware_scores >= 0.5).astype(int)
    actual_malware = (holdout_y.to_numpy() == 0).astype(int)
    matrix = confusion_matrix(actual_malware, predicted_malware, labels=[1, 0])

    dataset_sha256 = hashlib.sha256(DATA_PATH.read_bytes()).hexdigest()
    metrics = {
        "model": "RandomForestClassifier binary PE research baseline",
        "dataset": "Project-bundled MalwareDataSet.csv",
        "dataset_source_note": "Dataset README reports PE metadata and legitimacy labels; the upstream collection URL and per-file hashes are not recorded in this project.",
        "dataset_sha256": dataset_sha256,
        "seed": SEED,
        "features": list(DATASET_TO_FEATURE.values()),
        "source_rows": int(len(frame)),
        "unique_feature_groups": int(len(grouped)),
        "conflicting_feature_groups_excluded": conflicting_groups,
        "train_unique_rows": int(len(train_indices)),
        "holdout_unique_rows": int(len(holdout_indices)),
        "split_strategy": "Stratified 80/20 split after grouping identical feature vectors; conflicting-label groups excluded.",
        "threshold": 0.5,
        "accuracy": float(accuracy_score(holdout_y, (malware_scores < 0.5).astype(int))),
        "balanced_accuracy": float(balanced_accuracy_score(actual_malware, predicted_malware)),
        "malware_precision": float(precision_score(actual_malware, predicted_malware, pos_label=1, zero_division=0)),
        "malware_recall": float(recall_score(actual_malware, predicted_malware, pos_label=1, zero_division=0)),
        "malware_roc_auc": float(roc_auc_score(actual_malware, malware_scores)),
        "confusion_matrix_labels": ["malware", "legitimate"],
        "confusion_matrix": matrix.tolist(),
        "score_calibration": "Raw Random Forest class score; not calibrated as a real-world probability.",
        "validation_limitations": [
            "Evaluation is an internal holdout of unique PE metadata vectors, not a temporal, family, or source-separated malware benchmark.",
            "The dataset source URL and per-sample hashes are not recorded in this project.",
            "Only seven header fields are used; this model cannot assign malware families.",
            "These metrics do not guarantee performance on future or unseen files.",
        ],
    }

    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    metrics["model_sha256"] = hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest()
    METRICS_PATH.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "model_path": str(MODEL_PATH),
        "metrics_path": str(METRICS_PATH),
        "source_rows": metrics["source_rows"],
        "unique_feature_groups": metrics["unique_feature_groups"],
        "conflicting_feature_groups_excluded": conflicting_groups,
        "train_unique_rows": metrics["train_unique_rows"],
        "holdout_unique_rows": metrics["holdout_unique_rows"],
        "accuracy": metrics["accuracy"],
        "balanced_accuracy": metrics["balanced_accuracy"],
        "malware_precision": metrics["malware_precision"],
        "malware_recall": metrics["malware_recall"],
        "malware_roc_auc": metrics["malware_roc_auc"],
    }, indent=2))


if __name__ == "__main__":
    main()
