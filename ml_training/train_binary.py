"""Train the binary LightGBM model and fit the shared RobustScaler."""
import json
from pathlib import Path
import sys

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import RobustScaler

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from src.ml.feature_extractor import FeatureExtractor  # noqa: E402

SEED = 42
DATA = ROOT / "ml_training" / "data" / "synthetic_dataset.csv"
MODELS = ROOT / "ml_training" / "models"
EVALUATION = ROOT / "ml_training" / "evaluation"


def main() -> None:
    if not DATA.is_file():
        raise FileNotFoundError("Generate data first: python ml_training/generate_synthetic_data.py")
    MODELS.mkdir(parents=True, exist_ok=True)
    EVALUATION.mkdir(parents=True, exist_ok=True)
    names = FeatureExtractor.get_feature_names()
    frame = pd.read_csv(DATA)
    manifest_path = DATA.parent / "dataset_manifest.json"
    dataset_description = json.loads(manifest_path.read_text(encoding="utf-8"))["source"] if manifest_path.is_file() else "custom dataset; source not recorded"
    X = frame[names].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = frame["binary_label"].astype(int)
    # Use the family taxonomy for the shared split so both models share the
    # same train/test rows and the persisted scaler cannot see multiclass holdout data.
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=.2, random_state=SEED, stratify=frame["family_label"]
    )

    scaler = RobustScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    joblib.dump(scaler, MODELS / "scaler.pkl")

    train_set = lgb.Dataset(X_train_scaled, label=y_train, feature_name=names)
    valid_set = lgb.Dataset(X_test_scaled, label=y_test, reference=train_set, feature_name=names)
    model = lgb.train(
        {"objective": "binary", "metric": "binary_logloss", "learning_rate": .05,
         "num_leaves": 31, "feature_fraction": .9, "bagging_fraction": .85,
         "bagging_freq": 1, "verbosity": -1, "seed": SEED, "num_threads": -1},
        train_set, num_boost_round=1000, valid_sets=[valid_set],
        callbacks=[lgb.early_stopping(50), lgb.log_evaluation(50)],
    )
    probabilities = model.predict(X_test_scaled)
    predictions = (probabilities >= .5).astype(int)
    metrics = {
        "dataset": dataset_description,
        "seed": SEED, "features": len(names), "threshold": .5,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_test, probabilities)),
        "best_iteration": int(model.best_iteration),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, output_dict=True, zero_division=0),
    }
    model.save_model(str(MODELS / "lgbm_binary.txt"))
    (MODELS / "binary_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    pd.DataFrame({"actual": y_test, "probability": probabilities, "prediction": predictions}).to_csv(EVALUATION / "binary_holdout.csv", index=False)
    print(json.dumps({key: value for key, value in metrics.items() if key != "classification_report"}, indent=2))


if __name__ == "__main__":
    main()
