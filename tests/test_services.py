import pytest
from unittest.mock import MagicMock, patch
from src.services.log_ingestion import AnalysisPipeline
from src.models.schemas import NormalizedLogSchema
from src.core.database import db_manager
from src.services.redis_consumer import RedisConsumer

from src.models.database import NormalizedLog

@pytest.fixture(scope="module", autouse=True)
def init_db():
    db_manager.initialize()
    yield
    db_manager.close()

class TestServices:

    @patch('src.services.log_ingestion.LogAdapter.normalize')
    @patch('src.services.log_ingestion.AnalysisPipeline._store_log')
    @patch('src.services.log_ingestion.EnrichmentService.enrich')
    @patch('src.services.log_ingestion.analyzer_manager.analyze_log')
    def test_log_analysis_pipeline(self, mock_analyze, mock_enrich, mock_store, mock_normalize):
        service = AnalysisPipeline()
        
        # Mock the normalization result
        mock_schema = MagicMock(spec=NormalizedLogSchema)
        mock_normalize.return_value = mock_schema
        
        # USE A REAL LOG ENTRY to avoid SQLAlchemy mock errors
        log_entry = NormalizedLog(
            tenant_id="test",
            source_ip="1.2.3.4",
            message="test message",
            raw_data={"test": "data"}
        )
        mock_store.return_value = log_entry
        
        # Mock analyzer result
        mock_analyze.return_value = []
        
        result = service.process_log({"raw": "data"})
        
        assert result is True
        mock_normalize.assert_called_once()
        mock_store.assert_called_once()
        mock_enrich.assert_called_once_with(log_entry)
        mock_analyze.assert_called_once_with(log_entry)

    @patch('src.services.redis_consumer.redis.from_url')
    def test_redis_consumer_connection(self, mock_from_url):
        consumer = RedisConsumer()
        mock_client = MagicMock()
        mock_from_url.return_value = mock_client
        
        consumer.connect()
        
        assert consumer.redis_client is not None
        mock_client.ping.assert_called_once()
