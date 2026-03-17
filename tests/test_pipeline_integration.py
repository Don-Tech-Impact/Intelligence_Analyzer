import pytest
import os
from datetime import datetime
from unittest.mock import MagicMock, patch

from src.models.database import Base, NormalizedLog, Alert
from src.core.database import db_manager
from src.services.redis_consumer import RedisConsumer
from src.analyzers.base import analyzer_manager

# --- Mocks ---
class MockRedis:
    def __init__(self):
        self.data = {}
        
    def incr(self, key):
        self.data[key] = self.data.get(key, 0) + 1
        return self.data[key]
        
    def expire(self, key, seconds):
        return True
        
    def ttl(self, key):
        return 60

@pytest.fixture(scope="module", autouse=True)
def test_db():
    """Setup in-memory SQLite for processing tests."""
    os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
    db_manager.initialize()
    Base.metadata.create_all(db_manager.engine)
    yield
    db_manager.close()

class TestPipelineIntegration:
    """End-to-end integration tests for the ingestion pipeline."""

    @patch('src.services.redis_consumer.RedisConsumer._auto_register_device')
    def test_full_ingest_to_alert_flow(self, mock_register):
        """Test a log entry going through normalization, enrichment, and analysis."""
        
        # 1. Setup Consumer with Mock Redis
        mock_redis = MockRedis()
        consumer = RedisConsumer()
        consumer.redis = mock_redis
        
        # 2. Prepare a "Malicious" Log (V1 format)
        bad_log = {
            "schema_version": "v1",
            "tenant_id": "nairobi_university",
            "raw_log": "Mar 17 00:00:00 win_defender: Threat Name: Cobalt Strike Beacon detected",
            "level": "critical",
            "metadata": {
                "device_type": "windows_endpoint",
                "source_ip": "1.2.3.4"
            }
        }
        
        # 3. Process the log
        consumer._handle_ingest_log(bad_log, tenant_id="nairobi_university")
        
        # 4. Trigger Batch Flush & Analysis
        batch = consumer.batch_ingest
        consumer._run_analysis_on_batch(batch)
        consumer._flush_batches()
        
        # 5. Verify Database State
        with db_manager.session_scope() as session:
            # Check NormalizedLog was stored
            log = session.query(NormalizedLog).filter(NormalizedLog.source_ip == "1.2.3.4").first()
            assert log is not None
            assert log.severity == "critical" 
            assert log.business_context['alert_triggered'] is True
            assert 'payload_attack' in log.business_context['triggered_alerts']
            
            # Check Alert was created
            alert = session.query(Alert).filter(Alert.source_ip == "1.2.3.4").first()
            assert alert is not None
            assert alert.alert_type == "payload_attack"
            assert "MALWARE" in alert.description.upper()

    @patch('src.services.redis_consumer.RedisConsumer._auto_register_device')
    def test_brute_force_accumulation(self, mock_register):
        """Test that multiple logs from same IP trigger a stateful alert."""
        
        mock_redis = MockRedis()
        consumer = RedisConsumer()
        consumer.redis = mock_redis
        
        # Reset analyzers to ensure fresh state
        from src.analyzers.base import analyzer_manager
        for a in analyzer_manager.analyzers:
            if hasattr(a, 'redis_client'):
                a.redis_client = mock_redis
        
        # Clear database for this specific test
        with db_manager.session_scope() as session:
            session.query(Alert).delete()
            session.query(NormalizedLog).delete()
            session.commit()
            
        # Send 10 failed auth logs (Threshold is 5)
        # It should trigger once and then be suppressed by deduplication (5 min window)
        for i in range(10):
            auth_log = {
                "schema_version": "v1",
                "tenant_id": "test_tenant",
                "raw_log": f"Mar 17 00:00:00 sshd[123]: Failed password for root from 1.1.1.1",
                "metadata": {"device_type": "linux_server"}
            }
            consumer._handle_ingest_log(auth_log, tenant_id="test_tenant")
            consumer._run_analysis_on_batch(consumer.batch_ingest)
            consumer._flush_batches()
            consumer.batch_ingest = []
            
        # Verify logs and alert
        with db_manager.session_scope() as session:
            logs = session.query(NormalizedLog).filter(NormalizedLog.source_ip == "1.1.1.1").all()
            assert len(logs) == 10
            
            alerts = session.query(Alert).filter(Alert.source_ip == "1.1.1.1").all()
            # Deduplication should keep it to 1 alert
            assert len(alerts) == 1
            assert alerts[0].alert_type == "brute_force"
