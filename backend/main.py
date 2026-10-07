"""ScamSentry AI - FastAPI application.

Run from the repository root:
    uvicorn backend.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from dataclasses import asdict

from dotenv import load_dotenv

# Load .env before anything reads the environment. Real deployments inject
# variables directly; load_dotenv never overrides already-set variables.
load_dotenv()

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from backend.config import get_settings
from backend.schemas import HealthResponse, PredictRequest, PredictResponse
from backend.services import prediction_service
from backend.services.model_service import ModelService
from backend.services.threat_intel.openphish_cache import openphish_cache

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
settings = get_settings()


def _env_flag(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Load the model once at startup and share it across requests.
    service = ModelService(settings.model_path)
    service.load()
    app.state.model_service = service

    log = logging.getLogger("scamsentry")
    log.info("URLhaus: %s", "CONFIGURED" if os.environ.get("URLHAUS_AUTH_KEY") else "NOT CONFIGURED")
    log.info("Google Safe Browsing: %s", "CONFIGURED" if os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") else "NOT CONFIGURED")

    # OpenPhish feed: fetched in the background so startup never blocks on the network.
    # Tests set OPENPHISH_BACKGROUND_REFRESH=false to avoid live network calls.
    if _env_flag("OPENPHISH_BACKGROUND_REFRESH", True):
        openphish_cache.start()
    else:
        log.info("OpenPhish background refresh: DISABLED")

    try:
        yield
    finally:
        # Cancel and await the refresh loop so no task is left pending at shutdown.
        await openphish_cache.shutdown()


app = FastAPI(
    title=settings.app_name,
    version=settings.api_version,
    description=(
        "AI-powered message threat analysis. Combines a TF-IDF + Logistic Regression "
        "spam classifier with a transparent rule-based scam-risk engine."
    ),
    lifespan=lifespan,
)

from backend.routers import config

cors_origins = os.environ.get("CORS_PRODUCTION_ORIGINS")
origins = []
regex_origin = None

if cors_origins:
    for o in cors_origins.split(","):
        o = o.strip()
        if not o:
            continue
        if "*" in o and o != "*":
            # Very basic regex conversion for things like chrome-extension://*
            # For production, tighter regex is better.
            import re
            regex_origin = o.replace("*", ".*")
        else:
            origins.append(o)
else:
    origins = ["*"] # Development default

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_origin_regex=regex_origin,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "*"],
)

app.include_router(config.router, prefix="/config")

from backend.middleware.rate_limiter import SimpleRateLimitMiddleware

app.add_middleware(SimpleRateLimitMiddleware, window_seconds=60)

from fastapi.exceptions import RequestValidationError
from starlette.responses import JSONResponse

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content={"error": {"code": "VALIDATION_ERROR", "message": "Invalid request payload.", "details": exc.errors()}}
    )

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logging.getLogger("scamsentry").error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"error": {"code": "INTERNAL_SERVER_ERROR", "message": "An unexpected error occurred."}}
    )

def _model(request: Request) -> ModelService:
    return request.app.state.model_service


@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse(url="/docs")


@app.get("/health", response_model=HealthResponse, tags=["system"])
def health(request: Request) -> HealthResponse:
    """Liveness probe. Reports whether the application is alive."""
    service = _model(request)
    return HealthResponse(
        status="ok" if service.is_loaded else "degraded",
        model_loaded=service.is_loaded,
        model_version=service.version,
        api_version=settings.api_version,
    )

@app.get("/ready", tags=["system"])
def ready(request: Request):
    """Readiness probe. Answers whether all subsystems are ready."""
    service = _model(request)
    op_health = openphish_cache.get_health()
    return {
        "status": "ready" if service.is_loaded else "starting",
        "ml": "ready" if service.is_loaded else "starting",
        "openphish": "ready" if op_health.get("cache_loaded") else "stale",
        "providers": {
            "urlhaus": "ready" if os.environ.get("URLHAUS_AUTH_KEY") else "not_configured",
            "google_safe_browsing": "ready" if os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY") else "not_configured",
            "virustotal": "ready" if os.environ.get("VIRUSTOTAL_ENABLED") == "true" and os.environ.get("VIRUSTOTAL_API_KEY") else "not_configured"
        }
    }


@app.post("/predict", response_model=PredictResponse, tags=["analysis"])
async def predict(payload: PredictRequest, request: Request) -> PredictResponse:
    """Classify a message as SAFE, SPAM or SCAM and explain why."""
    service = _model(request)
    if not service.is_loaded:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Model is not loaded. Train it with `python -m ml.train` and restart the API.",
        )
    try:
        result = await prediction_service.predict(payload.text, service)
    except Exception as exc:  # noqa: BLE001 - never leak a stack trace to clients
        logging.getLogger(__name__).exception("Prediction failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Prediction failed due to an internal error.",
        ) from exc

    data = asdict(result)
    return PredictResponse(**data, model_version=service.version or "unknown")

from backend.schemas.prediction import ScanUrlRequest, PageScanRequest, PageScanResponse
from backend.services.page_risk_engine import page_risk_engine
import uuid

import time

SCAN_RESULTS = {}
MAX_SCAN_RESULTS = 1000

# simple cleanup function
def cleanup_old_scans():
    now = time.time()
    expired = [k for k, v in SCAN_RESULTS.items() if now - v.get("_timestamp", now) > 3600]
    for k in expired:
        del SCAN_RESULTS[k]
        
    # Cap maximum entries
    if len(SCAN_RESULTS) > MAX_SCAN_RESULTS:
        # Sort by timestamp and remove oldest
        sorted_keys = sorted(SCAN_RESULTS.keys(), key=lambda k: SCAN_RESULTS[k].get("_timestamp", 0))
        for k in sorted_keys[:len(SCAN_RESULTS) - MAX_SCAN_RESULTS]:
            del SCAN_RESULTS[k]

@app.post("/scan-page", response_model=PageScanResponse, tags=["analysis"])
async def api_scan_page(payload: PageScanRequest) -> PageScanResponse:
    if len(payload.links) > 50:
        raise HTTPException(status_code=400, detail="Too many links. Maximum 50 allowed.")
    
    cleanup_old_scans()
    result = await page_risk_engine.analyze_page(payload.page_url, payload.links)
    scan_id = str(uuid.uuid4())
    result["scan_id"] = scan_id
    result["_timestamp"] = time.time()
    SCAN_RESULTS[scan_id] = result
    return PageScanResponse(**result)

@app.get("/scan-result/{scan_id}", response_model=PageScanResponse, tags=["analysis"])
async def api_get_scan_result(scan_id: str) -> PageScanResponse:
    cleanup_old_scans()
    if scan_id not in SCAN_RESULTS:
        raise HTTPException(status_code=404, detail="Scan result not found or expired")
    return PageScanResponse(**SCAN_RESULTS[scan_id])

@app.post("/scan-url", response_model=PredictResponse, tags=["analysis"])
async def scan_url(payload: ScanUrlRequest) -> PredictResponse:
    """Scan a single URL using structural analysis and threat intelligence."""
    try:
        result = await prediction_service.scan_url(payload.url)
    except Exception as exc:
        logging.getLogger(__name__).exception("URL scan failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="URL scan failed due to an internal error.",
        ) from exc

    data = asdict(result)
    return PredictResponse(**data, model_version="N/A")
