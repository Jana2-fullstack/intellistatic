import logging
from typing import Any

import numpy as np
import pandas as pd

from src.ml.feature_extractor import FeatureExtractor

logger = logging.getLogger(__name__)


def prepare_features(features: dict[str, float], scaler: Any) -> np.ndarray:
    """Sanitize, order, and scale one sample using the persisted training scaler."""
    names = FeatureExtractor.get_feature_names()
    frame = pd.DataFrame([[features.get(name, 0.0) for name in names]], columns=names)
    frame = frame.replace([np.inf, -np.inf], np.nan).fillna(0.0)
    scaled = scaler.transform(frame)
    result = np.asarray(scaled, dtype=np.float64)
    return np.nan_to_num(result, nan=0.0, posinf=0.0, neginf=0.0)
