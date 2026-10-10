from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.core.config import settings
from src.db.database import get_db
from src.ml.feature_extractor import FeatureExtractor
from src.schemas.analysis_schemas import HealthResponse, ModelInfo

router = APIRouter(tags=["status"])


@router.get("/", summary="API information")
def root() -> dict[str, str]:
    return {"name": settings.app_name, "version": settings.app_version, "docs": "/docs"}


@router.get("/api/v1/health", response_model=HealthResponse)
def health(db: Session = Depends(get_db)) -> HealthResponse:
    database = "postgresql" if settings.normalized_database_url.startswith("postgresql") else "sqlite"
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        database = "unavailable"
    return HealthResponse(status="ok" if database != "unavailable" else "degraded", version=settings.app_version, database=database)


@router.get("/api/v1/model/info", response_model=ModelInfo)
def model_info(request: Request) -> ModelInfo:
    models = request.app.state.models
    warnings = models.warnings
    return ModelInfo(
        binary_model_loaded=models.binary_model_loaded,
        multiclass_model_loaded=models.multiclass_model_loaded,
        scaler_loaded=models.scaler_loaded,
        model_usable=models.ready,
        model_name=models.metrics.get("model"),
        training_dataset=models.metrics.get("dataset"),
        model_scope="Binary classification only; malware family is not available",
        evaluation={
            key: float(models.metrics[key])
            for key in ("accuracy", "balanced_accuracy", "malware_precision", "malware_recall", "malware_roc_auc")
            if isinstance(models.metrics.get(key), (int, float))
        },
        feature_count=len(FeatureExtractor.get_feature_names()),
        max_upload_mb=settings.max_upload_mb,
        allowed_extensions=sorted(settings.extension_allowlist),
        threat_classes=["Legitimate", "Malware"],
        warning=" ".join(warnings) if warnings else None,
    )
