from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from src.api.multipart import read_multipart_files
from src.core.config import settings
from src.db.database import get_db
from src.schemas.analysis_schemas import AnalysisResponse

router = APIRouter(prefix="/api/v1", tags=["analysis"])


def _validate_upload(filename: str, data: bytes) -> None:
    extension = "." + filename.replace("\\", "/").rsplit("/", 1)[-1].rsplit(".", 1)[-1].lower() if "." in filename else ""
    if extension not in settings.extension_allowlist:
        accepted = ", ".join(sorted(settings.extension_allowlist))
        raise HTTPException(status_code=422, detail=f"Unsupported file type. Allowed extensions: {accepted}.")
    if not data:
        raise HTTPException(status_code=422, detail="The uploaded file is empty.")
    max_bytes = settings.max_upload_mb * 1024 * 1024
    if len(data) > max_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds the maximum allowed size of {settings.max_upload_mb} MB.")


@router.post(
    "/analyze",
    response_model=AnalysisResponse,
    openapi_extra={"requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {
        "type": "object", "required": ["file"], "properties": {"file": {"type": "string", "format": "binary"}},
    }}}}},
)
async def analyze(request: Request, db: Session = Depends(get_db)) -> AnalysisResponse:
    uploads = await read_multipart_files(request, "file", max_files=1)
    filename, data = uploads[0]
    _validate_upload(filename, data)
    return request.app.state.analysis_service.analyze(filename, data, db)


@router.post(
    "/analyze/batch",
    response_model=list[AnalysisResponse],
    openapi_extra={"requestBody": {"required": True, "content": {"multipart/form-data": {"schema": {
        "type": "object", "required": ["files"], "properties": {"files": {
            "type": "array", "items": {"type": "string", "format": "binary"}, "maxItems": 20,
        }},
    }}}}},
)
async def analyze_batch(request: Request, db: Session = Depends(get_db)) -> list[AnalysisResponse]:
    uploads = await read_multipart_files(request, "files", max_files=20)
    for filename, data in uploads:
        _validate_upload(filename, data)
    service = request.app.state.analysis_service
    return [service.analyze(filename, data, db) for filename, data in uploads]
