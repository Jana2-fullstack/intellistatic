import asyncio

from httpx import ASGITransport, AsyncClient

from src.main import app
from src.db import models  # noqa: F401
from src.db.database import Base, engine
from src.ml.model_loader import ModelService
from src.services.analysis_service import AnalysisService
from src.services.yara_service import YaraService
from tests.test_feature_extractor import tiny_pe


Base.metadata.create_all(bind=engine)
app.state.models = ModelService()
app.state.yara = YaraService()
app.state.analysis_service = AnalysisService(app.state.models, app.state.yara)


def api_client() -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


def test_health_and_model_info() -> None:
    async def scenario() -> None:
        async with api_client() as client:
            health = await client.get("/api/v1/health")
            assert health.status_code == 200
            assert health.json()["status"] in {"ok", "degraded"}
            info = await client.get("/api/v1/model/info")
            assert info.status_code == 200
            assert info.json()["feature_count"] == 77
    asyncio.run(scenario())


def test_fake_exe_returns_response_schema_and_persists_history() -> None:
    async def scenario() -> None:
        async with api_client() as client:
            response = await client.post("/api/v1/analyze", files={"file": ("sample.exe", tiny_pe(), "application/octet-stream")})
            assert response.status_code == 200, response.text
            item = response.json()
            assert len(item["analysis_id"]) == 36
            assert item["file_info"]["filename"] == "sample.exe"
            assert len(item["file_info"]["sha256"]) == 64
            assert item["threat_assessment"]["file_executed"] is False
            assert len(item["static_features"]) == 77
            history = await client.get("/api/v1/history")
            assert history.status_code == 200
            assert history.json()["total"] >= 1
    asyncio.run(scenario())


def test_upload_validation_errors() -> None:
    async def scenario() -> None:
        async with api_client() as client:
            unsupported = await client.post("/api/v1/analyze", files={"file": ("readme.txt", b"text")})
            empty = await client.post("/api/v1/analyze", files={"file": ("empty.exe", b"")})
            assert unsupported.status_code == 422
            assert empty.status_code == 422
    asyncio.run(scenario())
