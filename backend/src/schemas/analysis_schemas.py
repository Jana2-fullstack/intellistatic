from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class FileInfo(BaseModel):
    filename: str
    file_type: str
    extension: str
    size_bytes: int
    sha256: str


class Prediction(BaseModel):
    binary_label: str
    malware_probability: float | None = None
    benign_probability: float | None = None
    confidence: float | None = None
    threat_family: str = "Unknown"
    threat_family_confidence: float | None = None
    family_probabilities: dict[str, float] = Field(default_factory=dict)


class ThreatAssessment(BaseModel):
    threat_level: str
    composite_score: float | None = None
    analysis_type: str = "STATIC"
    file_executed: bool = False
    yara_matches: list[str] = Field(default_factory=list)
    reasoning: str


class FeatureContribution(BaseModel):
    name: str
    value: float
    contribution: float


class AnalysisResponse(BaseModel):
    analysis_id: str
    file_info: FileInfo
    prediction: Prediction
    threat_assessment: ThreatAssessment
    top_features: list[FeatureContribution] = Field(default_factory=list)
    static_features: dict[str, float] = Field(default_factory=dict)
    created_at: datetime
    warnings: list[str] = Field(default_factory=list)


class HistoryPage(BaseModel):
    total: int
    items: list[AnalysisResponse]
    page: int
    page_size: int


class DeleteResponse(BaseModel):
    success: bool
    message: str


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str


class ModelInfo(BaseModel):
    binary_model_loaded: bool
    multiclass_model_loaded: bool
    scaler_loaded: bool
    model_usable: bool = False
    model_name: str | None = None
    training_dataset: str | None = None
    model_scope: str = "binary-only"
    evaluation: dict[str, float] = Field(default_factory=dict)
    feature_count: int
    max_upload_mb: int = 100
    allowed_extensions: list[str] = Field(default_factory=lambda: [".exe", ".dll", ".sys", ".bin"])
    threat_classes: list[str]
    warning: str | None = None


class ErrorResponse(BaseModel):
    detail: str
    errors: list[dict[str, Any]] | None = None
