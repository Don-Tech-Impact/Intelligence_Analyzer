"""Tests for Reporting and AI Assistant endpoints."""

import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta
import os

from src.api.main import app
from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert, Report

# Disable rate limiting for tests
app.state.limiter.enabled = False

client = TestClient(app)
ADMIN_API_KEY = "changeme-admin-key"

@pytest.fixture(scope="module")
def setup_db():
    """Initialize database for tests."""
    db_manager.initialize()
    yield
    # Cleanup after tests
    if db_manager.engine:
        db_manager.engine.dispose()

@pytest.fixture(scope="module")
def sample_data(setup_db):
    """Create sample data for report testing."""
    with db_manager.session_scope() as session:
        # Create some logs
        for i in range(20):
            log = NormalizedLog(
                tenant_id="default",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                source_ip=f"192.168.1.{i+1}",
                destination_ip="10.0.0.1",
                message=f"Attack simulation {i}",
                severity=["low", "medium", "high", "critical"][i % 4],
                vendor="Firewall-X",
                log_type="security"
            )
            session.add(log)
            
        # Create some alerts
        for i in range(10):
            alert = Alert(
                tenant_id="default",
                alert_type="brute_force",
                severity=["high", "critical", "medium"][i % 3],
                source_ip="192.168.1.100",
                description=f"Persistent brute force {i}",
                status="open"
            )
            session.add(alert)
        session.commit()
    return True

class TestReportingAI:
    """Test the newly implemented reporting and AI related endpoints."""

    def test_generate_report_custom_dates(self, sample_data):
        """Test report generation with explicit start and end dates."""
        payload = {
            "tenant_id": "default",
            "report_type": "custom",
            "start_date": (datetime.utcnow() - timedelta(days=5)).isoformat(),
            "end_date": datetime.utcnow().isoformat()
        }
        headers = {"X-Admin-Key": ADMIN_API_KEY}
        response = client.post("/reports/generate", json=payload, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "report_id" in data
        """Test the manual report generation endpoint."""
        payload = {
            "tenant_id": "default",
            "report_type": "daily",
            "days_back": 1
        }
        headers = {"X-Admin-Key": ADMIN_API_KEY}
        response = client.post("/reports/generate", json=payload, headers=headers)
        
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "report_id" in data
        return data["report_id"]

    def test_list_reports(self, sample_data):
        """Test listing reports."""
        headers = {"X-Admin-Key": ADMIN_API_KEY}
        response = client.get("/reports?tenant_id=default", headers=headers)
        
        assert response.status_code == 200
        reports = response.json()
        assert isinstance(reports, list)
        assert len(reports) >= 0

    def test_get_report_content(self, sample_data):
        """Test fetching report HTML content."""
        # First generate a report
        headers = {"X-Admin-Key": ADMIN_API_KEY}
        gen_res = client.post("/reports/generate", json={"tenant_id": "default"}, headers=headers)
        report_id = gen_res.json()["report_id"]
        
        response = client.get(f"/reports/{report_id}/content", headers=headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "html" in data["data"]
        assert "Security Intelligence Executive Summary" in data["data"]["html"]
        assert "Risk Distribution" in data["data"]["html"]

    def test_report_download(self, sample_data):
        """Test the report download endpoint."""
        headers = {"X-Admin-Key": ADMIN_API_KEY}
        gen_res = client.post("/reports/generate", json={"tenant_id": "default"}, headers=headers)
        report_id = gen_res.json()["report_id"]
        
        response = client.get(f"/reports/{report_id}/download", headers=headers)
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/html; charset=utf-8"

    def test_unauthorized_access(self):
        """Test that endpoints are protected."""
        # Missing Header (FastAPI returns 422 because it's required)
        response = client.post("/reports/generate", json={})
        assert response.status_code == 422
        
        # Incorrect Header (System returns 403)
        response = client.get("/reports/1/content", headers={"X-Admin-Key": "wrong-key"})
        assert response.status_code == 403
