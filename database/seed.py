"""Insert clearly marked sample rows for local UI previews when history is empty."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import func, select  # noqa: E402
from src.db.database import Base, SessionLocal, engine  # noqa: E402
from src.db.models import AnalysisLog  # noqa: E402
from src.ml.feature_extractor import FeatureExtractor  # noqa: E402


def _record(filename: str, marker: bytes, label: str, malware: float, family: str, threat: str, yara: list[str]) -> AnalysisLog:
    now = datetime.now(timezone.utc)
    feature_names = FeatureExtractor.get_feature_names()
    result = {
        "analysis_id": str(uuid.uuid4()),
        "file_info": {
            "filename": filename, "file_type": "Windows PE", "extension": filename.rsplit(".", 1)[-1],
            "size_bytes": 0, "sha256": hashlib.sha256(marker).hexdigest(),
        },
        "prediction": {
            "binary_label": label, "malware_probability": malware, "benign_probability": 1 - malware,
            "confidence": max(malware, 1 - malware), "threat_family": family,
            "threat_family_confidence": .82, "family_probabilities": {family: .82},
        },
        "threat_assessment": {
            "threat_level": threat, "composite_score": .72, "analysis_type": "STATIC",
            "file_executed": False, "yara_matches": yara,
            "reasoning": "Demonstration row only; no file was uploaded or analyzed.",
        },
        "top_features": [], "static_features": {name: 0.0 for name in feature_names},
        "created_at": now.isoformat(),
        "warnings": ["DEMO SAMPLE: this row is synthetic and is not an analysis result."],
    }
    return AnalysisLog(
        id=result["analysis_id"], filename=filename, file_size=0, sha256=result["file_info"]["sha256"],
        binary_label=label, malware_prob=malware, threat_family=family, threat_level=threat,
        yara_matches=json.dumps(yara), feature_json=json.dumps(result["static_features"]),
        result_json=json.dumps(result), created_at=now,
    )


def main() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        if (db.scalar(select(func.count()).select_from(AnalysisLog)) or 0) > 0:
            print("History already contains rows; no demo data was added.")
            return
        db.add_all([
            _record("demo-benign.exe", b"IntelliStatic demo benign sample", "BENIGN", .03, "Benign", "LOW", []),
            _record("demo-ransomware.exe", b"IntelliStatic demo ransomware sample", "MALICIOUS", .96, "Ransomware", "CRITICAL", ["Suspicious_Ransomware_Note"]),
            _record("demo-library.dll", b"IntelliStatic demo benign DLL", "BENIGN", .08, "Benign", "LOW", []),
        ])
        db.commit()
    print("Inserted three clearly marked demonstration rows.")


if __name__ == "__main__":
    main()
