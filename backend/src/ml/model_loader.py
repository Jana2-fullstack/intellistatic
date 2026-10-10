import json
import hashlib
import logging
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from src.core.config import settings

logger = logging.getLogger(__name__)

# The bundled labeled dataset only supports a binary model. Keep the names in
# the same order as the trainer and map them explicitly to extracted PE fields.
DATASET_FEATURES = [
    "AddressOfEntryPoint",
    "MajorLinkerVersion",
    "MajorImageVersion",
    "MajorOperatingSystemVersion",
    "DllCharacteristics",
    "SizeOfStackReserve",
    "NumberOfSections",
]
FEATURE_MAP = {
    "AddressOfEntryPoint": "address_of_entry_point",
    "MajorLinkerVersion": "major_linker_version",
    "MajorImageVersion": "major_image_version",
    "MajorOperatingSystemVersion": "major_os_version",
    "DllCharacteristics": "dll_characteristics",
    "SizeOfStackReserve": "size_of_stack_reserve",
    "NumberOfSections": "number_of_sections",
}


class ModelService:
    """Load the evaluated binary PE baseline and reject unverified artifacts."""

    def __init__(self) -> None:
        self.binary_model: Any = None
        self.multiclass_model: Any = None
        self.scaler: Any = None
        self.explainer: Any = None
        self.synthetic_training_data = False
        self.provenance_verified = False
        self.metrics: dict[str, Any] = {}
        self.warnings: list[str] = []
        self._load()

    def _load(self) -> None:
        model_path = settings.model_dir / "pe_rf_baseline.joblib"
        metrics_path = settings.model_dir / "pe_rf_baseline_metrics.json"
        if metrics_path.is_file():
            try:
                self.metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
                dataset_note = str(self.metrics.get("dataset", "")).strip()
                features_match = self.metrics.get("features") == list(FEATURE_MAP.values())
                self.synthetic_training_data = "synthetic" in dataset_note.lower()
                self.provenance_verified = bool(
                    dataset_note
                    and not self.synthetic_training_data
                    and self.metrics.get("dataset_sha256")
                    and self.metrics.get("model_sha256")
                    and self.metrics.get("train_unique_rows", 0) > 0
                    and self.metrics.get("holdout_unique_rows", 0) > 0
                    and features_match
                )
                if self.synthetic_training_data:
                    self.warnings.append("Synthetic demonstration models are disabled; their scores are not valid for real files.")
                elif not self.provenance_verified:
                    self.warnings.append("Model training provenance or feature schema could not be verified; predictions are disabled.")
            except Exception:
                logger.exception("Could not read binary model metrics")
                self.warnings.append("Model evaluation metadata could not be read; predictions are disabled.")
        else:
            self.warnings.append("No evaluated binary model is installed. Train the PE baseline before running classification.")

        if not model_path.is_file():
            self.warnings.append("The evaluated binary model artifact is missing.")
            logger.warning("Binary model artifact is missing: %s", model_path)
            return
        if not self.provenance_verified:
            logger.warning("Not loading model with missing or unverified evaluation metadata")
            return
        try:
            import joblib

            actual_digest = hashlib.sha256(model_path.read_bytes()).hexdigest()
            if actual_digest != self.metrics.get("model_sha256"):
                raise ValueError("Model artifact hash does not match its evaluation metadata.")
            self.binary_model = joblib.load(model_path)
            model_features = list(getattr(self.binary_model, "feature_names_in_", []))
            if model_features and model_features != DATASET_FEATURES:
                raise ValueError("Binary model feature order does not match its evaluation metadata.")
        except Exception:
            logger.exception("Unable to load evaluated binary model")
            self.binary_model = None
            self.warnings.append("The evaluated binary model could not be loaded; predictions are unavailable.")
            return

        self.warnings.append(
            f"Research baseline trained on {self.metrics.get('dataset', 'the bundled PE dataset')} using seven PE header fields; "
            f"evaluation used {int(self.metrics.get('train_unique_rows', 0)):,} training and "
            f"{int(self.metrics.get('holdout_unique_rows', 0)):,} distinct holdout vectors. Raw scores are uncalibrated; "
            "the CSV's upstream source URL and per-sample hashes are not recorded. This is triage support, not a guarantee "
            "of safety or malware detection. Malware-family classification is not available."
        )

    @property
    def binary_model_loaded(self) -> bool:
        return self.binary_model is not None

    @property
    def multiclass_model_loaded(self) -> bool:
        return False

    @property
    def scaler_loaded(self) -> bool:
        return False

    @property
    def ready(self) -> bool:
        return self.binary_model_loaded and self.provenance_verified

    def unavailable_prediction(self, reason: str | None = None) -> dict[str, Any]:
        warnings = self.warnings.copy()
        if reason:
            warnings.append(reason)
        return {
            "binary_label": "UNKNOWN",
            "malware_probability": None,
            "benign_probability": None,
            "confidence": None,
            "threat_family": "Not classified",
            "threat_family_confidence": None,
            "family_probabilities": {},
            "top_features": [],
            "warnings": warnings,
        }

    def predict(self, features: dict[str, float]) -> dict[str, Any]:
        if not self.ready:
            return self.unavailable_prediction()

        try:
            row = {
                dataset_name: float(features.get(feature_name, 0.0))
                for dataset_name, feature_name in FEATURE_MAP.items()
            }
            frame = pd.DataFrame([row], columns=DATASET_FEATURES)
            probabilities = np.asarray(self.binary_model.predict_proba(frame), dtype=float)
            classes = list(self.binary_model.classes_)
            malware_index = classes.index(0)  # The bundled dataset labels malware as legitimate=0.
            benign_index = classes.index(1)
            malware_score = float(np.clip(probabilities[0, malware_index], 0.0, 1.0))
            benign_score = float(np.clip(probabilities[0, benign_index], 0.0, 1.0))
            label = "MALICIOUS" if malware_score >= 0.5 else "BENIGN"
            return {
                "binary_label": label,
                "malware_probability": malware_score,
                "benign_probability": benign_score,
                "confidence": max(malware_score, benign_score),
                "threat_family": "Not classified",
                "threat_family_confidence": None,
                "family_probabilities": {},
                "top_features": [],
                "warnings": self.warnings.copy(),
            }
        except Exception:
            logger.exception("Binary PE baseline inference failed")
            return {
                "binary_label": "UNKNOWN",
                "malware_probability": None,
                "benign_probability": None,
                "confidence": None,
                "threat_family": "Not classified",
                "threat_family_confidence": None,
                "family_probabilities": {},
                "top_features": [],
                "warnings": self.warnings + ["Model inference failed; no verdict was produced."],
            }
