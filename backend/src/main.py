import hmac
import logging
import time
from collections import defaultdict, deque
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from sqlalchemy.exc import SQLAlchemyError

from src.api.routes_analyze import router as analyze_router
from src.api.routes_health import router as health_router
from src.api.routes_history import router as history_router
from src.core.config import settings
from src.core.logging_config import configure_logging
from src.db.database import Base, engine
from src.db import models  # noqa: F401 - register ORM models before create_all
from src.ml.model_loader import ModelService
from src.services.analysis_service import AnalysisService
from src.services.yara_service import YaraService

configure_logging()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("Database schema initialized")
    except SQLAlchemyError:
        logger.exception("Database initialization failed; analysis can continue without persistence")
    app.state.models = ModelService()
    app.state.yara = YaraService()
    app.state.analysis_service = AnalysisService(app.state.models, app.state.yara)
    logger.info("%s %s started", settings.app_name, settings.app_version)
    yield
    logger.info("%s stopped", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Local, static-only Windows PE analysis API. Uploaded files are never executed or written to disk.",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE"],
    allow_headers=["Content-Type", "X-API-Key"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Cache-Control", "no-store")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'none'; frame-ancestors 'none'; sandbox",
    )
    return response


RATE_LIMIT_PATHS = ("/api/v1/analyze",)
_request_times: dict[str, deque[float]] = defaultdict(deque)


@app.middleware("http")
async def rate_limit(request: Request, call_next):
    limit = settings.rate_limit_per_minute
    if limit > 0 and request.method == "POST" and request.url.path.startswith(RATE_LIMIT_PATHS):
        client = request.client.host if request.client else "unknown"
        now = time.monotonic()
        window = _request_times[client]
        while window and now - window[0] >= 60:
            window.popleft()
        if len(window) >= limit:
            response = JSONResponse(
                status_code=429,
                content={"detail": "Too many analysis requests. Please wait a minute and try again."},
            )
            response.headers["Retry-After"] = str(max(1, int(60 - (now - window[0]))))
            return response
        window.append(now)
    return await call_next(request)


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    if settings.api_key and (not x_api_key or not hmac.compare_digest(x_api_key, settings.api_key)):
        raise HTTPException(status_code=401, detail="A valid API key is required.")


app.include_router(health_router, dependencies=[Depends(require_api_key)])
app.include_router(analyze_router, dependencies=[Depends(require_api_key)])
app.include_router(history_router, dependencies=[Depends(require_api_key)])


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content=jsonable_encoder({"detail": "Request validation failed.", "errors": exc.errors()}))


@app.exception_handler(Exception)
async def safe_exception_handler(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled API error", exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "An internal error occurred. Please try again."})
