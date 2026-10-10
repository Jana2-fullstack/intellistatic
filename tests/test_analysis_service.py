from src.ml.model_loader import ModelService
from src.services.analysis_service import AnalysisService
from src.services.yara_service import YaraService
from tests.test_feature_extractor import tiny_pe


def test_analysis_service_returns_report_without_model_artifacts() -> None:
    # Keep this test independent from locally generated training artifacts.
    model_service = ModelService.__new__(ModelService)
    model_service.binary_model = None
    model_service.multiclass_model = None
    model_service.scaler = None
    model_service.explainer = None
    model_service.warnings = ["Model artifacts are unavailable."]
    analysis = AnalysisService(model_service, YaraService())
    result = analysis.analyze(r"C:\temp\..\sample.exe", tiny_pe())
    assert result.file_info.filename == "sample.exe"
    assert result.prediction.binary_label == "UNKNOWN"
    assert result.threat_assessment.threat_level == "UNKNOWN"
    assert result.threat_assessment.file_executed is False
    assert len(result.static_features) == 77
