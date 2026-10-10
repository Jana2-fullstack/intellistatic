"""Train the six-family LightGBM classifier using the shared persisted scaler."""
import json
from pathlib import Path
import sys

import joblib
import lightgbm as lgb
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score, top_k_accuracy_score
from sklearn.model_selection import train_test_split

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
from src.ml.feature_extractor import FeatureExtractor  # noqa: E402

SEED = 42
FAMILIES = ["Benign", "Trojan", "Ransomware", "Spyware", "Worm", "Adware"]
DATA = ROOT / "ml_training" / "data" / "synthetic_dataset.csv"
MODELS = ROOT / "ml_training" / "models"
EVALUATION = ROOT / "ml_training" / "evaluation"


def main() -> None:
    if not DATA.is_file():
        raise FileNotFoundError("Generate data first: python ml_training/generate_synthetic_data.py")
    scaler_path = MODELS / "scaler.pkl"
    if not scaler_path.is_file():
        raise FileNotFoundError("Train the binary model first to create the shared scaler.")
    names = FeatureExtractor.get_feature_names()
    frame = pd.read_csv(DATA)
    manifest_path = DATA.parent / "dataset_manifest.json"
    dataset_description = json.loads(manifest_path.read_text(encoding="utf-8"))["source"] if manifest_path.is_file() else "custom dataset; source not recorded"
    X = frame[names].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    y = frame["family_label"].astype(int)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=.2, random_state=SEED, stratify=y)
    scaler = joblib.load(scaler_path)
    X_train_scaled, X_test_scaled = scaler.transform(X_train), scaler.transform(X_test)

    train_set = lgb.Dataset(X_train_scaled, label=y_train, feature_name=names)
    valid_set = lgb.Dataset(X_test_scaled, label=y_test, reference=train_set, feature_name=names)
    model = lgb.train(
        {"objective": "multiclass", "num_class": 6, "metric": "multi_logloss",
         "learning_rate": .05, "num_leaves": 31, "feature_fraction": .9,
         "bagging_fraction": .85, "bagging_freq": 1, "verbosity": -1, "seed": SEED, "num_threads": -1},
        train_set, num_boost_round=1000, valid_sets=[valid_set],
        callbacks=[lgb.early_stopping(50), lgb.log_evaluation(50)],
    )
    probabilities = model.predict(X_test_scaled)
    predictions = np.argmax(probabilities, axis=1)
    metrics = {
        "dataset": dataset_description,
        "seed": SEED, "features": len(names), "classes": FAMILIES,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "macro_f1": float(f1_score(y_test, predictions, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_test, predictions, average="weighted", zero_division=0)),
        "top_2_accuracy": float(top_k_accuracy_score(y_test, probabilities, k=2, labels=list(range(6)))),
        "best_iteration": int(model.best_iteration),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(y_test, predictions, target_names=FAMILIES, output_dict=True, zero_division=0),
    }
    model.save_model(str(MODELS / "lgbm_multiclass.txt"))
    (MODELS / "multiclass_metrics.json").write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    probabilities_out = pd.DataFrame(probabilities, columns=[f"prob_{name}" for name in FAMILIES])
    probabilities_out.insert(0, "actual", y_test.to_numpy())
    probabilities_out.insert(1, "prediction", predictions)
    probabilities_out.to_csv(EVALUATION / "multiclass_holdout.csv", index=False)
    print(json.dumps({key: value for key, value in metrics.items() if key != "classification_report"}, indent=2))


if __name__ == "__main__":
    main()
