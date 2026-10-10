import numpy as np
import pytest

from src.ml.feature_extractor import FeatureExtractor
from src.ml.model_loader import ModelService


class BinaryModel:
    classes_ = np.asarray([0, 1])

    def predict_proba(self, values):
        return np.asarray([[.8, .2]])


def test_inference_uses_binary_baseline_without_inventing_family() -> None:
    service = ModelService.__new__(ModelService)
    service.binary_model = BinaryModel()
    service.multiclass_model = None
    service.scaler = None
    service.explainer = None
    service.synthetic_training_data = False
    service.provenance_verified = True
    service.warnings = []
    service.metrics = {}
    features = {name: 0.0 for name in FeatureExtractor.get_feature_names()}
    result = service.predict(features)
    assert result["binary_label"] == "MALICIOUS"
    assert result["malware_probability"] == .8
    assert result["benign_probability"] == pytest.approx(.2)
    assert result["threat_family"] == "Not classified"
    assert result["family_probabilities"] == {}
