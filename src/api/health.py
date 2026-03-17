"""Health and metrics endpoints for monitoring."""

import time
from datetime import datetime

import redis
from fastapi import APIRouter
from sqlalchemy import text

from src.core.config import config
from src.core.database import db_manager

from typing import Any, Dict, List, Set
router = APIRouter(tags=["Health & Metrics"])

# Metrics storage (in-memory for simplicity)
_metrics = {"logs_processed": 0, "alerts_created": 0, "api_requests": 0, "errors": 0, "start_time": time.time()}


def increment_metric(name: str, value: int = 1):
    """Increment a metric counter."""
    if name in _metrics:
        _metrics[name] += value


@router.get("/health")
def health_check():
    """
    Basic health check endpoint.

    Returns:
        Health status with component checks.
    """
    health: Dict[str, Any] = {"status": "healthy", "timestamp": datetime.utcnow().isoformat(), "version": "1.0.0", "components": {}}

    # Check database
    try:
        with db_manager.session_scope() as session:
            session.execute(text("SELECT 1"))
        health["components"]["database"] = {"status": "healthy"}
    except Exception as e:
        health["status"] = "degraded"
        health["components"]["database"] = {"status": "unhealthy", "error": str(e)}

    # Check Redis
    try:
        redis_client = redis.from_url(config.redis_url, socket_connect_timeout=2)
        redis_client.ping()
        health["components"]["redis"] = {"status": "healthy"}
    except Exception as e:
        health["status"] = "degraded"
        health["components"]["redis"] = {"status": "unhealthy", "error": str(e)}

    # Check Log Consumer Heartbeat
    try:
        redis_client = redis.from_url(config.redis_url, socket_connect_timeout=2)
        heartbeat = redis_client.get("health:consumer:heartbeat")
        if heartbeat:
            last_heartbeat = float(heartbeat)
            if time.time() - last_heartbeat < 60:  # Within 60s is healthy
                health["components"]["consumer"] = {"status": "healthy", "last_heartbeat": last_heartbeat}
            else:
                health["status"] = "degraded"
                health["components"]["consumer"] = {"status": "stale", "last_heartbeat": last_heartbeat}
        else:
            health["status"] = "degraded"
            health["components"]["consumer"] = {"status": "down", "error": "No heartbeat found"}
    except Exception as e:
        health["status"] = "degraded"
        health["components"]["consumer"] = {"status": "unhealthy", "error": str(e)}

    # Check Identity Provider (Repo 1)
    try:
        import httpx

        repo1_url = (config.repo1_base_url or "http://host.docker.internal:8080").rstrip("/")
        with httpx.Client(timeout=2.0) as client:
            resp = client.get(f"{repo1_url}/health")
            if resp.status_code == 200:
                health["components"]["identity"] = {"status": "healthy"}
            else:
                health["status"] = "degraded"
                health["components"]["identity"] = {"status": "unhealthy", "status_code": resp.status_code}
    except Exception as e:
        health["status"] = "degraded"
        health["components"]["identity"] = {"status": "unhealthy", "error": str(e)}

    return health


@router.get("/health/live")
def liveness_check():
    """
    Kubernetes liveness probe.

    Returns 200 if the application is running.
    """
    return {"status": "alive"}


@router.get("/health/ready")
def readiness_check():
    """
    Kubernetes readiness probe.

    Returns 200 if the application is ready to serve traffic.
    """
    # Check if database is accessible
    try:
        with db_manager.session_scope() as session:
            session.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception:
        return {"status": "not_ready"}, 503


@router.get("/metrics")
def get_metrics():
    """
    Get application metrics in Prometheus format.
    """
    uptime = time.time() - _metrics["start_time"]

    # Prometheus text format
    lines = [
        "# HELP siem_logs_processed_total Total number of logs processed",
        "# TYPE siem_logs_processed_total counter",
        f"siem_logs_processed_total {_metrics['logs_processed']}",
        "",
        "# HELP siem_alerts_created_total Total number of alerts created",
        "# TYPE siem_alerts_created_total counter",
        f"siem_alerts_created_total {_metrics['alerts_created']}",
        "",
        "# HELP siem_api_requests_total Total number of API requests",
        "# TYPE siem_api_requests_total counter",
        f"siem_api_requests_total {_metrics['api_requests']}",
        "",
        "# HELP siem_errors_total Total number of errors",
        "# TYPE siem_errors_total counter",
        f"siem_errors_total {_metrics['errors']}",
        "",
        "# HELP siem_uptime_seconds Application uptime in seconds",
        "# TYPE siem_uptime_seconds gauge",
        f"siem_uptime_seconds {uptime:.2f}",
    ]

    # Get database stats
    try:
        with db_manager.session_scope() as session:
            log_count = session.execute(text("SELECT COUNT(*) FROM logs")).scalar()
            alert_count = session.execute(text("SELECT COUNT(*) FROM alerts")).scalar()

            lines.extend(
                [
                    "",
                    "# HELP siem_database_logs_total Total logs in database",
                    "# TYPE siem_database_logs_total gauge",
                    f"siem_database_logs_total {log_count}",
                    "",
                    "# HELP siem_database_alerts_total Total alerts in database",
                    "# TYPE siem_database_alerts_total gauge",
                    f"siem_database_alerts_total {alert_count}",
                ]
            )
    except Exception:
        pass

    # Get Redis queue size

    try:
        redis_client = redis.from_url(config.redis_url, socket_connect_timeout=2)
        queue_size = 0
        for key in redis_client.scan_iter(match="logs:*:ingest", count=100):
            queue_size += redis_client.llen(key)
        for key in redis_client.scan_iter(match="logs:*:clean", count=100):
            queue_size += redis_client.llen(key)
        for key in redis_client.scan_iter(match="logs:*:dead", count=100):
            queue_size += redis_client.llen(key)

        lines.extend(
            [
                "",
                "# HELP siem_redis_queue_size Current size of log queue",
                "# TYPE siem_redis_queue_size gauge",
                f"siem_redis_queue_size {queue_size}",
            ]
        )

    except Exception:
        pass

    from fastapi.responses import PlainTextResponse

    return PlainTextResponse(content="\n".join(lines), media_type="text/plain")


@router.get("/metrics/json")
def get_metrics_json():
    """
    Get application metrics in JSON format.
    """
    uptime = time.time() - _metrics["start_time"]

    result: Dict[str, Any] = {
        "logs_processed": _metrics["logs_processed"],
        "alerts_created": _metrics["alerts_created"],
        "api_requests": _metrics["api_requests"],
        "errors": _metrics["errors"],
        "uptime_seconds": round(uptime, 2),
    }

    # Get database stats
    try:
        with db_manager.session_scope() as session:
            result["database"] = {
                "logs": session.execute(text("SELECT COUNT(*) FROM logs")).scalar(),
                "alerts": session.execute(text("SELECT COUNT(*) FROM alerts")).scalar(),
            }
    except Exception as e:
        result["database"] = {"error": str(e)}

    # Get Redis queue size
    try:
        redis_client = redis.from_url(config.redis_url, socket_connect_timeout=2)
        queue_size = 0
        for key in redis_client.scan_iter(match="logs:*:ingest", count=100):
            queue_size += redis_client.llen(key)
        for key in redis_client.scan_iter(match="logs:*:clean", count=100):
            queue_size += redis_client.llen(key)
        for key in redis_client.scan_iter(match="logs:*:dead", count=100):
            queue_size += redis_client.llen(key)
        result["redis"] = {"queue_size": queue_size}
    except Exception as e:
        result["redis"] = {"error": str(e)}

    return result
