import uuid

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from src.db.database import get_db
from src.db.models import AnalysisLog
from src.schemas.analysis_schemas import AnalysisResponse, DeleteResponse, HistoryPage

router = APIRouter(prefix="/api/v1/history", tags=["history"])


@router.get("", response_model=HistoryPage)
def list_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    search: str | None = None,
    verdict: str | None = None,
    threat: str | None = None,
    db: Session = Depends(get_db),
) -> HistoryPage:
    query = select(AnalysisLog)
    if search:
        query = query.where(AnalysisLog.filename.ilike(f"%{search[:120]}%"))
    if verdict:
        query = query.where(AnalysisLog.binary_label == verdict.upper())
    if threat:
        query = query.where(AnalysisLog.threat_level == threat.upper())
    total = db.scalar(select(func.count()).select_from(query.subquery())) or 0
    rows = db.scalars(query.order_by(AnalysisLog.created_at.desc()).offset((page - 1) * page_size).limit(page_size)).all()
    items = [AnalysisResponse.model_validate_json(row.result_json) for row in rows]
    return HistoryPage(total=total, items=items, page=page, page_size=page_size)


@router.get("/{analysis_id}", response_model=AnalysisResponse)
def get_history_item(analysis_id: uuid.UUID, db: Session = Depends(get_db)) -> AnalysisResponse:
    row = db.get(AnalysisLog, str(analysis_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    return AnalysisResponse.model_validate_json(row.result_json)


@router.delete("/{analysis_id}", response_model=DeleteResponse)
def delete_history_item(analysis_id: uuid.UUID, db: Session = Depends(get_db)) -> DeleteResponse:
    row = db.get(AnalysisLog, str(analysis_id))
    if row is None:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
    db.delete(row)
    db.commit()
    return DeleteResponse(success=True, message="Deleted.")
