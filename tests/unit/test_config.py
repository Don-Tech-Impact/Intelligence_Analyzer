# tests/unit/test_config.py
import pytest
from src.core.config import Settings


def test_settings_loads():
    """Settings object should instantiate without error."""
    settings = Settings()
    assert settings is not None


def test_settings_has_required_fields():
    settings = Settings()
    assert hasattr(settings, 'DATABASE_URL') or hasattr(settings, 'REDIS_URL')
