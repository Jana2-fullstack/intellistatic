import hashlib
import json
import logging
import re
import uuid
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any

from sqlalchemy.orm import Session

from src.db.models import AnalysisLog
from src.ml.feature_extractor import FeatureExtractor
from src.ml.model_loader import ModelService
from src.schemas.analysis_schemas import AnalysisResponse
from src.services.threat_assessment import assess_threat
from src.services.yara_service import YaraService

logger = logging.getLogger(__name__)


def sanitize_filename(name: str | None) -> str:
    normalized = (name or "upload.bin").replace("\\", "/")
    safe = PurePosixPath(normalized).name
    safe = re.sub(r"[\x00-\x1f\x7f]", "", safe).strip(" .")
    return (safe or "upload.bin")[:255]


class AnalysisService:
    def __init__(self, models: ModelService, yara: YaraService, extractor: FeatureExtractor | None = None) -> None:
        self.models = models
        self.yara = yara
        self.extractor = extractor or FeatureExtractor()

    def analyze(self, filename: str, data: bytes, db: Session | None = None) -> AnalysisResponse:
        safe_name = sanitize_filename(filename)
        extension = PurePosixPath(safe_name).suffix.lower()
        is_pe = self.extractor.is_valid_pe(data)
        file_type = "Windows PE" if is_pe else "Unknown or malformed PE"
        sha256 = hashlib.sha256(data).hexdigest()
        features = self.extractor.extract(data)
        yara_matches = self.yara.scan(data)
        prediction = (
            self.models.predict(features)
            if is_pe
            else self.models.unavailable_prediction("PE validation failed; classifier output was withheld.")
        )
        threat = assess_threat(prediction, yara_matches)
        warnings = list(prediction.get("warnings", []))
        if self.yara.warning:
            warnings.append(self.yara.warning)
        result = AnalysisResponse(
            analysis_id=str(uuid.uuid4()),
            file_info={
                "filename": safe_name, "file_type": file_type, "extension": extension.lstrip("."),
                "size_bytes": len(data), "sha256": sha256,
            },
            prediction={
                "binary_label": prediction["binary_label"],
                "malware_probability": prediction["malware_probability"],
                "benign_probability": prediction["benign_probability"],
                "confidence": prediction["confidence"],
                "threat_family": prediction["threat_family"],
                "threat_family_confidence": prediction["threat_family_confidence"],
                "family_probabilities": prediction["family_probabilities"],
            },
            threat_assessment=threat,
            top_features=prediction["top_features"],
            static_features=features,
            created_at=datetime.now(timezone.utc),
            warnings=warnings,
        )

        if db is not None:
            self._persist(db, result)
        logger.info(
            "Analysis complete: filename=%s verdict=%s threat=%s",
            safe_name, result.prediction.binary_label, result.threat_assessment.threat_level,
        )
        return result

    @staticmethod
    def _persist(db: Session, result: AnalysisResponse) -> None:
        try:
            db.add(AnalysisLog(
                id=result.analysis_id,
                filename=result.file_info.filename,
                file_size=result.file_info.size_bytes,
                sha256=result.file_info.sha256,
                binary_label=result.prediction.binary_label,
                malware_prob=result.prediction.malware_probability or 0.0,
                threat_family=result.prediction.threat_family,
                threat_level=result.threat_assessment.threat_level,
                yara_matches=json.dumps(result.threat_assessment.yara_matches),
                feature_json=json.dumps(result.static_features, separators=(",", ":")),
                result_json=result.model_dump_json(),
                created_at=result.created_at,
            ))
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("Analysis persistence failed for %s", result.analysis_id)
