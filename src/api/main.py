from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Query, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional
from datetime import datetime, timedelta

from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert, ThreatIntelligence, Report
from pydantic import BaseModel
from src.models.schemas import AlertUpdateSchema, DashboardSummarySchema, ApiResponse
from src.services.log_ingestion import AnalysisPipeline
from src.services.report_generator import ReportGenerator
from src.services.redis_consumer import RedisConsumer
from src.services.scheduler import TaskScheduler
from threading import Thread
import logging

# V1 API Router, Health endpoints, and Admin API
from src.api.v1_router import router as v1_router
from src.api.health import router as health_router
from src.api.admin_router import router as admin_router, verify_admin_key

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app):
    """FastAPI lifespan handler — runs on startup and shutdown."""
    import os, sys
    # --- Startup ---
    # Safety: if DATABASE_URL points to an in-memory database (e.g. leaked
    # from test fixtures), clear it so the YAML config's file-based path is used.
    # Skip this guard when running under pytest — tests intentionally use :memory:.
    _in_test = 'pytest' in sys.modules
    if not _in_test:
        db_url_env = os.environ.get('DATABASE_URL', '')
        if ':memory:' in db_url_env:
            del os.environ['DATABASE_URL']
        
        # Re-initialize if the engine was already created with a :memory: URL
        if db_manager.engine is not None and ':memory:' in str(db_manager.engine.url):
            db_manager.engine.dispose()
            db_manager.engine = None
            db_manager.Session = None
    
    if db_manager.engine is None:
        db_manager.initialize()
    
    yield
    # --- Shutdown ---

app = FastAPI(
    title="Intelligence Analyzer API", 
    version="1.0.0",
    description="SIEM Intelligence Engine API - V1",
    docs_url=None,  # Disable built-in docs
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# Mount local Swagger UI static files
import os as os_module
swagger_static_path = os_module.path.join(os_module.path.dirname(os_module.path.dirname(os_module.path.dirname(__file__))), "static", "swagger-ui")
if os_module.path.exists(swagger_static_path):
    app.mount("/static/swagger-ui", StaticFiles(directory=swagger_static_path), name="swagger-ui")

# Mount full static folder for API tester and other assets
static_path = os_module.path.join(os_module.path.dirname(os_module.path.dirname(os_module.path.dirname(__file__))), "static")
if os_module.path.exists(static_path):
    app.mount("/static", StaticFiles(directory=static_path, html=True), name="static")

# Custom Swagger UI endpoint using local assets
@app.get("/docs", include_in_schema=False)
async def custom_swagger_ui_html():
    return HTMLResponse("""
<!DOCTYPE html>
<html>
<head>
    <link type="text/css" rel="stylesheet" href="/static/swagger-ui/swagger-ui.css">
    <title>Intelligence Analyzer API - Swagger UI</title>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="/static/swagger-ui/swagger-ui-bundle.js"></script>
    <script>
    const ui = SwaggerUIBundle({
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        layout: 'BaseLayout',
        deepLinking: true,
        showExtensions: true,
        showCommonExtensions: true,
        presets: [
            SwaggerUIBundle.presets.apis,
            SwaggerUIBundle.SwaggerUIStandalonePreset
        ]
    })
    </script>
</body>
</html>
    """)

# Global Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Global Exception: {str(exc)}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "status": "error",
            "message": "An unexpected internal server error occurred.",
            "detail": str(exc) if app.debug else "Internal Server Error"
        }
    )

# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    
    # Skip strict CSP for Swagger UI paths
    if request.url.path in ["/docs", "/redoc", "/openapi.json"]:
        return response
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    # Allow CDN resources for Swagger UI
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https://cdn.jsdelivr.net; "
        "font-src 'self' https://cdn.jsdelivr.net;"
    )
    return response


# Enable CORS for frontend development
# Strict CORS for Production
import os
origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# Serve static files from the dashboard directory
dashboard_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "dashboard")
if os.path.exists(dashboard_path):
    app.mount("/dashboard", StaticFiles(directory=dashboard_path, html=True), name="dashboard")

# Register V1 API Router, Health endpoints, and Admin API
app.include_router(v1_router)
app.include_router(health_router)
app.include_router(admin_router)

import logging
logger = logging.getLogger(__name__)

# Dependency to get DB session
def get_db():
    db = db_manager.get_session()
    try:
        yield db
    finally:
        db.close()

# Startup logic is handled by the lifespan context manager above.
# Authentication removed — managed by Repo 1 (Afric Analyzer).

class ReportRequest(BaseModel):
    tenant_id: str = "default"
    report_type: str = "custom"
    days_back: Optional[int] = 1
    start_date: Optional[str] = None
    end_date: Optional[str] = None


# Note: Legacy top-level routes for stats, alerts, logs, and reports have been removed. 
# These are now handled exclusively by the v1_router under the /api/v1 prefix.

@app.patch("/alerts/{alert_id}")
def update_alert_status(alert_id: int, update_data: AlertUpdateSchema, db: Session = Depends(get_db)):
    """Update alert status (e.g., mark as acknowledged or resolved)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = update_data.status
    if update_data.analyst_comment:
        # Assuming we might want to store comments in the description or a new field
        # For now, let's just append it to the description if it fits the schema
        alert.description = f"{alert.description} | Analyst: {update_data.analyst_comment}"
        
    db.commit()
    return {"status": "success", "alert_id": alert_id, "new_status": alert.status}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
