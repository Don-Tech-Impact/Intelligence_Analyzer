import pytest
from datetime import datetime
from src.services.log_adapter import LogAdapter
from src.models.schemas import NormalizedLogSchema

def test_pfsense_normalization():
    raw_log = {
        "metadata": {
            "tenant_id": "pfsense_tenant",
            "vendor": "pfSense"
        },
        "event": {
            "timestamp": "2024-01-24T12:00:00Z",
            "action": "block",
            "severity": "high"
        },
        "source": {
            "ip": "192.168.1.100",
            "port": 45678
        },
        "destination": {
            "ip": "8.8.8.8",
            "port": 53
        },
        "network": {
            "protocol": "UDP"
        },
        "device": {
            "hostname": "pfsense-01"
        }
    }
    
    normalized = LogAdapter.normalize(raw_log)
    
    assert normalized.tenant_id == "pfsense_tenant"
    assert normalized.vendor == "pfSense"
    assert normalized.source_ip == "192.168.1.100"
    assert normalized.destination_ip == "8.8.8.8"
    assert normalized.source_port == 45678
    assert normalized.protocol == "UDP"
    assert normalized.action == "block"
    assert normalized.severity == "high"
    assert normalized.device_hostname == "pfsense-01"

def test_generic_standard_normalization():
    raw_log = {
        "tenant_id": "tenant123",
        "timestamp": "2024-01-24T12:05:00Z",
        "message": "Failed login attempt for user admin",
        "source_ip": "10.0.0.5",
        "action": "login_failed",
        "log_type": "auth"
    }
    
    normalized = LogAdapter.normalize(raw_log)
    
    assert normalized.tenant_id == "tenant123"
    assert normalized.source_ip == "10.0.0.5"
    assert normalized.action == "login_failed"
    assert normalized.log_type == "auth"
    assert normalized.message == "Failed login attempt for user admin"

def test_validation_failure_fallback():
    # Pass missing required fields (if any, but pydantic defaults many)
    # The LogAdapter now catches errors and returns a fallback schema
    normalized = LogAdapter.normalize({"metadata": "invalid"})
    
    assert "Validation error" in normalized.message
