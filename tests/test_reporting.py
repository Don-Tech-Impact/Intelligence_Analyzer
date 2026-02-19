import pytest
from datetime import datetime, timedelta
from src.services.report_generator import ReportGenerator
from src.core.database import db_manager
from src.models.database import NormalizedLog, Alert, Base
import os

@pytest.fixture(scope="module", autouse=True)
def setup_db():
    # Use in-memory database for tests
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    db_manager.initialize()
    Base.metadata.drop_all(db_manager.engine)
    Base.metadata.create_all(db_manager.engine)
    
    # Add some dummy data
    with db_manager.session_scope() as session:
        # Logs
        for i in range(5):
            log = NormalizedLog(
                tenant_id="report_tenant",
                timestamp=datetime.utcnow() - timedelta(hours=i),
                source_ip=f"192.168.1.{10+i}",
                log_type="firewall",
                severity="low"
            )
            session.add(log)
        
        # Alerts
        alert = Alert(
            tenant_id="report_tenant",
            alert_type="Brute Force",
            severity="high",
            source_ip="1.2.3.4",
            description="Test Alert"
        )
        session.add(alert)
        session.commit()
    
    yield
    
    # Cleanup
    db_manager.close()
    if db_manager.engine:
        db_manager.engine.dispose()

def test_generate_daily_report():
    generator = ReportGenerator(output_dir="test_reports")
    # Yesterday's report
    yesterday = datetime.utcnow() - timedelta(days=1)
    
    # Add a log for yesterday
    with db_manager.session_scope() as session:
        log = NormalizedLog(
            tenant_id="report_tenant",
            timestamp=yesterday,
            source_ip="1.1.1.1",
            log_type="firewall",
            severity="info"
        )
        session.add(log)
    
    report = generator.generate_daily_report(date=yesterday.date(), tenant_id="report_tenant")
    
    assert report is not None
    assert report.total_logs >= 1
    assert os.path.exists(report.file_path)
    
    # Cleanup generated files
    if os.path.exists(report.file_path):
        os.remove(report.file_path)
        # Also remove the CSV
        csv_path = report.file_path.replace(".html", ".csv")
        if os.path.exists(csv_path):
            os.remove(csv_path)

def test_collect_report_data():
    generator = ReportGenerator()
    start = datetime.utcnow() - timedelta(days=1)
    end = datetime.utcnow()
    
    data = generator._collect_report_data(start, end, "report_tenant")
    
    assert "total_logs" in data
    assert "total_alerts" in data
    assert "alerts_by_severity" in data
    assert data["total_alerts"] >= 1
