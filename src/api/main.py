from contextlib import asynccontextmanager
from fastapi import FastAPI, Depends, Query, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session
from sqlalchemy import func, desc
from typing import List, Optional
from datetime import datetime, timedelta

from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert, ThreatIntelligence, Report, Tenant, User
from src.utils.auth import get_password_hash, verify_password, create_access_token, decode_access_token

from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from src.models.schemas import AlertUpdateSchema, DashboardSummarySchema, ApiResponse
from src.services.log_ingestion import AnalysisPipeline

# V1 API Router and Health endpoints
from src.api.v1_router import router as v1_router
from src.api.health import router as health_router

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, HTMLResponse

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login", auto_error=False)

limiter = Limiter(key_func=get_remote_address)

@asynccontextmanager
async def lifespan(app):
    """FastAPI lifespan handler — runs on startup and shutdown."""
    # --- Startup ---
    if db_manager.engine is None:
        db_manager.initialize()
    # Create default superadmin if not exists
    with db_manager.session_scope() as session:
        admin = session.query(User).filter(User.role == 'superadmin').first()
        if not admin:
            from src.utils.auth import get_password_hash
            default_admin = User(
                username="admin",
                password_hash=get_password_hash("admin123"),
                role="superadmin",
                tenant_id="system"
            )
            session.add(default_admin)
            session.commit()
            print("Default superadmin created: admin / admin123")
    yield
    # --- Shutdown (cleanup if needed) ---

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

# Register V1 API Router and Health endpoints
app.include_router(v1_router)
app.include_router(health_router)

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

async def get_current_user(token: str = Depends(oauth2_scheme), token_query: Optional[str] = Query(None, alias="token"), db: Session = Depends(get_db)):
    if not token and token_query:
        token = token_query
    
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    username: str = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

def superadmin_only(user: User = Depends(get_current_user)):
    if user.role != 'superadmin':
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return user

class LoginRequest(BaseModel):
    username: str
    password: str

@app.post("/auth/login")
@limiter.limit("5/minute")
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    print(f"Login attempt for user: {form_data.username}")
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user:
        print(f"User {form_data.username} not found in DB")
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    if not verify_password(form_data.password, user.password_hash):
        print(f"Password verification failed for user: {form_data.username}")
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    
    print(f"Login successful for user: {form_data.username}")
    access_token = create_access_token(data={"sub": user.username, "role": user.role, "tenant_id": user.tenant_id})
    return {
        "status": "success",
        "data": {
            "access_token": access_token, 
            "token_type": "bearer", 
            "role": user.role, 
            "tenant_id": user.tenant_id
        }
    }

# Admin Endpoints
@app.post("/admin/tenants")
def create_tenant(name: str, tenant_id: str, db: Session = Depends(get_db), admin: User = Depends(superadmin_only)):
    existing = db.query(Tenant).filter(Tenant.tenant_id == tenant_id).first()
    if existing:
        raise HTTPException(status_code=400, detail="Tenant ID already exists")
    
    new_tenant = Tenant(tenant_id=tenant_id, name=name)
    db.add(new_tenant)
    db.commit()
    return {"status": "success", "tenant_id": tenant_id}

@app.post("/admin/users")
def create_business_user(username: str, password: str, tenant_id: str, db: Session = Depends(get_db), admin: User = Depends(superadmin_only)):
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    
    new_user = User(
        username=username,
        password_hash=get_password_hash(password),
        role="business",
        tenant_id=tenant_id
    )
    db.add(new_user)
    db.commit()
    return {"status": "success", "username": username}

@app.get("/health")
def health_check():
    return {"status": "success", "data": {"status": "healthy", "timestamp": datetime.utcnow()}}

@app.get("/tenants")
def get_tenants(db: Session = Depends(get_db)):
    """Get list of all active tenants."""
    tenants = db.query(Tenant).filter(Tenant.is_active == True).all()
    # If no tenants exist, return a default one
    if not tenants:
        return [{"tenant_id": "default", "name": "Default Tenant"}]
    return tenants

@app.get("/stats")
def get_stats(tenant_id: str = "default", db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Get high-level statistics."""
    # Enforce tenant isolation
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
    
    query_logs = db.query(NormalizedLog).filter(NormalizedLog.tenant_id == tenant_id)
    query_alerts = db.query(Alert).filter(Alert.tenant_id == tenant_id)
    
    total_logs = query_logs.count()
    total_alerts = query_alerts.count()
    
    # Active threats (global or tenant-specific depending on how you store them)
    # For now, let's assume threat intel is global but we match it against tenant logs
    active_threats = db.query(ThreatIntelligence).filter(ThreatIntelligence.is_active == True).count()
    
    # Severity breakdown for tenant
    severity_counts = db.query(Alert.severity, func.count(Alert.id))\
        .filter(Alert.tenant_id == tenant_id)\
        .group_by(Alert.severity).all()
    severity_map = {s: c for s, c in severity_counts}
    
    return {
        "status": "success",
        "data": {
            "tenant_id": tenant_id,
            "total_logs": total_logs,
            "total_alerts": total_alerts,
            "active_threats": active_threats,
            "severity_breakdown": severity_map
        }
    }

@app.get("/alerts")
@limiter.limit("20/minute")
def get_alerts(
    request: Request,
    tenant_id: str = "default",
    limit: int = 50, 
    severity: Optional[str] = None, 
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Get recent alerts."""
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
        
    query = db.query(Alert).filter(Alert.tenant_id == tenant_id)
    if severity:
        query = query.filter(Alert.severity == severity)
    
    alerts = query.order_by(desc(Alert.created_at)).limit(limit).all()
    # Convert models to dict for standardization if needed or just return list
    return {"status": "success", "data": alerts}

@app.get("/logs")
@limiter.limit("50/minute")
def get_logs(
    request: Request,
    tenant_id: str = "default",
    limit: int = 50, 
    vendor: Optional[str] = None,
    device: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user)
):
    """Get recent logs with enhanced filtering and search."""
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
        
    query = db.query(NormalizedLog).filter(NormalizedLog.tenant_id == tenant_id)
    if vendor:
        query = query.filter(NormalizedLog.vendor == vendor)
    if device:
        query = query.filter(NormalizedLog.device_hostname == device)
    if severity:
        query = query.filter(NormalizedLog.severity == severity)
    if search:
        query = query.filter(NormalizedLog.message.ilike(f"%{search}%"))
    
    logs = query.order_by(desc(NormalizedLog.timestamp)).limit(limit).all()
    return {"status": "success", "data": logs}

@app.get("/reports")
@limiter.limit("5/minute")
def list_reports(
    request: Request,
    tenant_id: str = "default", 
    report_type: Optional[str] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    db: Session = Depends(get_db), 
    user: User = Depends(get_current_user)
):
    """List generated reports for a tenant with filtering."""
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
    
    query = db.query(Report).filter(Report.tenant_id == tenant_id)
    if report_type:
        query = query.filter(Report.report_type == report_type)
    if start_date:
        query = query.filter(Report.created_at >= datetime.fromisoformat(start_date))
    if end_date:
        query = query.filter(Report.created_at <= datetime.fromisoformat(end_date))
        
    reports = query.order_by(desc(Report.created_at)).all()
    return reports

@app.get("/reports/{report_id}/download")
def download_report(
    report_id: int, 
    token: Optional[str] = Query(None),
    db: Session = Depends(get_db), 
    user: Optional[User] = Depends(get_current_user)
):
    """Download a specific report file. Supports token via query param for browser downloads."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if user.role != 'superadmin' and report.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file missing on server")
        
    from fastapi.responses import FileResponse
    return FileResponse(report.file_path, filename=os.path.basename(report.file_path))

@app.get("/analytics/business-insights")
def get_business_insights(tenant_id: str = "default", db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Analyze logs based on business context (hours/days)."""
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
        
    # Get last 7 days of logs for more stable insights
    since = datetime.utcnow() - timedelta(days=7)
    logs = db.query(NormalizedLog).filter(
        NormalizedLog.tenant_id == tenant_id,
        NormalizedLog.timestamp >= since
    ).all()
    
    insights = {
        "business_hours": 0,
        "after_hours": 0,
        "weekdays": 0,
        "weekends": 0,
        "by_vendor": {},
        "top_business_sources": []
    }
    
    vendor_counts = {}
    
    for log in logs:
        ts = log.timestamp
        # Business hours: 8 AM - 6 PM (adjust based on user's sample which has received_at around 09:58)
        if 8 <= ts.hour < 18:
            insights["business_hours"] += 1
        else:
            insights["after_hours"] += 1
            
        # Weekdays: 0=Monday, 6=Sunday in Python weekday()? 
        # Actually weekday() 0 is Monday, 5-6 are Saturday/Sunday
        if ts.weekday() < 5:
            insights["weekdays"] += 1
        else:
            insights["weekends"] += 1
            
        v = log.vendor or "unknown"
        vendor_counts[v] = vendor_counts.get(v, 0) + 1
        
    insights["by_vendor"] = vendor_counts
    return {"status": "success", "data": insights}

@app.get("/trends")
def get_trends(tenant_id: str = "default", db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Get data for activity charts."""
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
        
    now = datetime.utcnow()
    last_24h = now - timedelta(hours=24)
    
    if db_manager.engine.name == 'sqlite':
        log_hour = func.strftime('%Y-%m-%d %H:00:00', NormalizedLog.timestamp)
        alert_hour = func.strftime('%Y-%m-%d %H:00:00', Alert.created_at)
    else:
        log_hour = func.date_trunc('hour', NormalizedLog.timestamp)
        alert_hour = func.date_trunc('hour', Alert.created_at)
        
    log_trends = db.query(
        log_hour.label('hour'),
        func.count(NormalizedLog.id).label('count')
    ).filter(NormalizedLog.tenant_id == tenant_id, NormalizedLog.timestamp >= last_24h)\
     .group_by('hour').order_by('hour').all()
    
    alert_trends = db.query(
        alert_hour.label('hour'),
        func.count(Alert.id).label('count')
    ).filter(Alert.tenant_id == tenant_id, Alert.created_at >= last_24h)\
     .group_by('hour').order_by('hour').all()
    
    return {
        "status": "success",
        "data": {
            "tenant_id": tenant_id,
            "logs": [{"hour": t.hour, "count": t.count} for t in log_trends],
            "alerts": [{"hour": t.hour, "count": t.count} for t in alert_trends]
        }
    }

@app.get("/analytics/top-ips")
def get_top_ips(tenant_id: str = "default", limit: int = 10, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Get top source and destination IPs."""
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
        
    top_sources = db.query(NormalizedLog.source_ip, func.count(NormalizedLog.id).label('count'))\
        .filter(NormalizedLog.tenant_id == tenant_id)\
        .group_by(NormalizedLog.source_ip).order_by(desc('count')).limit(limit).all()
        
    top_destinations = db.query(NormalizedLog.destination_ip, func.count(NormalizedLog.id).label('count'))\
        .filter(NormalizedLog.tenant_id == tenant_id)\
        .group_by(NormalizedLog.destination_ip).order_by(desc('count')).limit(limit).all()
        
    return {
        "status": "success",
        "data": {
            "sources": [{"ip": t.source_ip, "count": t.count} for t in top_sources],
            "destinations": [{"ip": t.destination_ip, "count": t.count} for t in top_destinations]
        }
    }

@app.get("/analytics/protocols")
def get_protocol_breakdown(tenant_id: str = "default", db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Get protocol distribution."""
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
        
    protocols = db.query(NormalizedLog.protocol, func.count(NormalizedLog.id).label('count'))\
        .filter(NormalizedLog.tenant_id == tenant_id)\
        .group_by(NormalizedLog.protocol).all()
    return {"status": "success", "data": [{"protocol": p.protocol or "Unknown", "count": p.count} for p in protocols]}



@app.get("/config")
def get_siem_config(user: User = Depends(superadmin_only)):
    """Get current SIEM configuration (Superadmin only)."""
    from src.core.config import config as siem_config
    return {
        "brute_force_threshold": siem_config.brute_force_threshold,
        "port_scan_threshold": siem_config.port_scan_threshold,
        "log_level": siem_config.log_level,
        "multi_tenant_enabled": siem_config.multi_tenant_enabled
    }

@app.post("/config")
def update_siem_config(new_config: dict, user: User = Depends(superadmin_only)):
    """Update SIEM configuration and persist to yaml."""
    from src.core.config import config as siem_config
    try:
        if "brute_force_threshold" in new_config:
            siem_config.set("detection.brute_force.threshold", int(new_config["brute_force_threshold"]))
        if "port_scan_threshold" in new_config:
            siem_config.set("detection.port_scan.threshold", int(new_config["port_scan_threshold"]))
        if "log_level" in new_config:
            siem_config.set("logging.level", new_config["log_level"])
        
        return {"status": "success", "message": "Configuration updated and persisted"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update config: {str(e)}")

@app.get("/api/dashboard-summary")
@limiter.limit("10/minute")
def get_dashboard_summary(request: Request, tenant_id: str = "default", db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """
    Get a comprehensive summary for the dashboard in a single request.
    This reduces the number of initial API calls needed by the React frontend.
    """
    if user.role != 'superadmin':
        tenant_id = user.tenant_id
        
    # Reuse existing logic to compile data
    stats = get_stats(tenant_id, db, user)
    trends = get_trends(tenant_id, db, user)
    top_ips = get_top_ips(tenant_id, 10, db, user)
    protocols = get_protocol_breakdown(tenant_id, db, user)
    recent_alerts = get_alerts(request, tenant_id, 5, None, db, user)
    business_insights = get_business_insights(tenant_id, db, user)
    
    # Intelligence Exposure - Enriched metadata
    # Top 5 threats by score
    top_threats = db.query(NormalizedLog).filter(NormalizedLog.tenant_id == tenant_id)\
        .order_by(desc(func.json_extract(NormalizedLog.business_context, '$.threat_score')))\
        .limit(5).all()
        
    # Geo distribution summary
    geo_counts = db.query(
        func.json_extract(NormalizedLog.business_context, '$.geoip.country').label('country'),
        func.count(NormalizedLog.id).label('count')
    ).filter(NormalizedLog.tenant_id == tenant_id)\
     .group_by('country').order_by(desc('count')).all()

    # Helper to convert SA models to dict and remove state
    def to_dict(obj):
        d = dict(obj.__dict__)
        d.pop('_sa_instance_state', None)
        return d
    
    return {
        "status": "success",
        "data": {
            "tenant_id": tenant_id,
            "stats": stats["data"],
            "trends": trends["data"],
            "top_ips": top_ips["data"],
            "protocols": protocols["data"],
            "recent_alerts": [to_dict(alert) for alert in recent_alerts["data"]],
            "business_insights": business_insights["data"],
            "intelligence": {
                "top_threats": [to_dict(log) for log in top_threats],
                "geo_distribution": [{"country": g.country or "Unknown", "count": g.count} for g in geo_counts]
            }
        }
    }

@app.patch("/alerts/{alert_id}")
def update_alert_status(alert_id: int, update_data: AlertUpdateSchema, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    """Update alert status (e.g., mark as acknowledged or resolved)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
        
    if user.role != 'superadmin' and alert.tenant_id != user.tenant_id:
        raise HTTPException(status_code=403, detail="Not authorized to update this alert")
        
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
