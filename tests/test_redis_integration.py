
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
