
import pytest
from unittest.mock import MagicMock, patch
from src.services.redis_consumer import RedisConsumer
from src.core.config import config

class TestRedisIntegration:
    
    @patch('redis.from_url')
    def test_connect_with_redis_url(self, mock_from_url):
        """Test that connect uses redis.from_url with the config property."""
        # Setup
        consumer = RedisConsumer()
        # Mock the config property if needed or rely on the fact that we patched from_url
        
        # Act
        consumer.connect()
        
        # Assert
        mock_from_url.assert_called_once()
        # Check that it called with the default URL (either env or localhost fallback)
        assert mock_from_url.call_args[0][0].startswith("redis")
        
    @patch('redis.from_url')
    def test_cloud_redis_params(self, mock_from_url):
        """Test that we pass the correct params for robust cloud connections."""
        consumer = RedisConsumer()
        consumer.connect()
        
        kwargs = mock_from_url.call_args[1]
        assert kwargs['socket_keepalive'] is True
        assert kwargs['decode_responses'] is True


from unittest.mock import MagicMock, patch
from src.services.redis_consumer import RedisConsumer

class TestTenantQueueDiscovery:
    """Test dynamic tenant queue discovery."""

    def test_discover_finds_tenants(self):
        """scan_iter returns tenant queues → tenants are tracked."""
        consumer = RedisConsumer.__new__(RedisConsumer)
        consumer.redis_client = MagicMock()
        consumer.known_tenants = set()
        consumer.discovered_queues = []
        consumer.metrics = {"tenants_discovered": 0}

        consumer.redis_client.scan_iter.side_effect = [
            iter(["logs:EBK:ingest", "logs:ACME:ingest"]),  # ingest scan
            iter(["logs:EBK:dead"]),                         # dead scan
            iter([]),                                        # clean scan
        ]

        consumer._discover_tenant_queues()

        assert consumer.known_tenants == {"EBK", "ACME"}
        assert "logs:EBK:ingest" in consumer.discovered_queues
        assert "logs:ACME:ingest" in consumer.discovered_queues
        assert "logs:EBK:dead" in consumer.discovered_queues

    def test_get_queue_type(self):
        assert RedisConsumer._get_queue_type("logs:EBK:ingest") == "ingest"
        assert RedisConsumer._get_queue_type("logs:EBK:dead") == "dead"
        assert RedisConsumer._get_queue_type("logs:EBK:clean") == "clean"
        assert RedisConsumer._get_queue_type("bad_format") == "unknown"

    def test_get_queue_tenant(self):
        assert RedisConsumer._get_queue_tenant("logs:EBK:ingest") == "EBK"
        assert RedisConsumer._get_queue_tenant("logs:ACME:dead") == "ACME"


class TestMessageRouting:
    """Test process_message routes by queue suffix."""

    def setup_method(self):
        self.consumer = RedisConsumer.__new__(RedisConsumer)
        self.consumer.batch_dead = []
        self.consumer.batch_ingest = []
        self.consumer.batch_clean = []
        self.consumer.log_adapter = MagicMock()
        self.consumer.log_adapter.normalize.return_value = MagicMock(
            tenant_id="EBK", timestamp=None, source_ip="10.0.0.1",
            destination_ip=None, source_port=None, destination_port=None,
            protocol=None, action=None, log_type="raw_ingest",
            vendor="cisco", device_hostname=None, severity="info",
            message="test", raw_data={}, business_context={}
        )

    def test_ingest_queue_routes_to_handler(self):
        msg = '{"schema_version":"v1","tenant_id":"EBK","raw_log":"test","metadata":{}}'
        result = self.consumer.process_message("logs:EBK:ingest", msg)
        assert result is True
        assert len(self.consumer.batch_ingest) == 1

    def test_dead_queue_routes_to_handler(self):
        msg = '{"tenant_id":"EBK","error_type":"parse_error","error_message":"bad"}'
        result = self.consumer.process_message("logs:EBK:dead", msg)
        assert result is True
        assert len(self.consumer.batch_dead) == 1

    def test_clean_queue_routes_to_handler(self):
        msg = '{"schema_version":"v2.0","tenant_id":"EBK","source":{"ip":"1.2.3.4"}}'
        result = self.consumer.process_message("logs:EBK:clean", msg)
        assert result is True
        assert len(self.consumer.batch_clean) == 1
