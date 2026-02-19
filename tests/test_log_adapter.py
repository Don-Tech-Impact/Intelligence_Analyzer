"""
Unit Tests for LogAdapter (v2.0 Schema Support)

Tests the schema adaptation layer that converts Repo1 v2.0 logs
to our internal NormalizedLogSchema format.
"""

import pytest
from datetime import datetime
from src.services.log_adapter import LogAdapter
from src.models.schemas import NormalizedLogSchema


class TestLogAdapterV2Schema:
    """Tests for v2.0 schema handling."""
    
    def test_v2_schema_detected_by_version(self):
        """Test that schema_version: v2.x triggers v2 handling."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "test-tenant",
            "vendor": "fortinet",
            "event": {"action": "allow", "category": "network", "timestamp": "2026-02-08T10:00:00Z"},
            "source": {"ip": "10.0.0.1", "port": 12345},
            "destination": {"ip": "8.8.8.8", "port": 443},
            "network": {"protocol": "tcp"},
            "raw": {"message": "test log message"}
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.source_ip == "10.0.0.1"
        assert result.destination_ip == "8.8.8.8"
        assert result.source_port == 12345
        assert result.destination_port == 443
        assert result.protocol == "tcp"
        assert result.action == "allow"
        assert result.log_type == "network"
        assert result.message == "test log message"
    
    def test_v2_nested_extraction(self):
        """Test all nested field paths are correctly extracted."""
        log = {
            "schema_version": "v2.0",
            "log_id": "abc-123",
            "tenant_id": "central-uni",
            "vendor": "paloalto",
            
            "device": {
                "hostname": "PA-500",
                "vendor": "paloalto",
                "model": "PA-500",
                "role": "firewall"
            },
            
            "event": {
                "timestamp": "2026-02-08T14:30:00Z",
                "category": "authentication",
                "action": "deny",
                "outcome": "failure",
                "severity": "high"
            },
            
            "source": {
                "ip": "192.168.1.100",
                "port": 54321,
                "mac": "00:11:22:33:44:55",
                "user": "admin"
            },
            
            "destination": {
                "ip": "10.0.0.1",
                "port": 22,
                "service": "ssh"
            },
            
            "network": {
                "protocol": "tcp",
                "bytes": 1500,
                "direction": "inbound"
            },
            
            "business_context": {
                "is_business_hour": True,
                "day_of_week": "Monday"
            },
            
            "raw": {
                "message": "SSH login failed for user admin"
            }
        }
        
        result = LogAdapter.normalize(log)
        
        # Identity
        assert result.tenant_id == "central-uni"
        assert result.vendor == "paloalto"
        assert result.device_hostname == "PA-500"
        
        # Source
        assert result.source_ip == "192.168.1.100"
        assert result.source_port == 54321
        
        # Destination
        assert result.destination_ip == "10.0.0.1"
        assert result.destination_port == 22
        
        # Network  
        assert result.protocol == "tcp"
        
        # Event
        assert result.action == "deny"
        assert result.log_type == "authentication"
        assert result.severity == "high"
        
        # Content
        assert result.message == "SSH login failed for user admin"
        
        # Business context
        assert result.business_context == {"is_business_hour": True, "day_of_week": "Monday"}
    
    def test_v2_missing_optional_fields(self):
        """Test that missing optional fields default correctly."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "minimal-tenant",
            "event": {"timestamp": "2026-02-08T12:00:00Z"},
            "source": {"ip": "1.2.3.4"}
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "minimal-tenant"
        assert result.source_ip == "1.2.3.4"
        assert result.destination_ip is None
        assert result.destination_port is None
        assert result.protocol is None
        assert result.action is None
        assert result.severity == "low"  # Default
        assert result.log_type == "generic"  # Default
    
    def test_v2_timestamp_parsing(self):
        """Test ISO8601 timestamp parsing."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "test",
            "event": {"timestamp": "2026-02-08T14:30:05Z"},
            "source": {"ip": "10.0.0.1"}
        }
        
        result = LogAdapter.normalize(log)
        
        assert isinstance(result.timestamp, datetime)
        assert result.timestamp.year == 2026
        assert result.timestamp.month == 2
        assert result.timestamp.day == 8
        assert result.timestamp.hour == 14
        assert result.timestamp.minute == 30
        assert result.timestamp.second == 5


class TestLogAdapterLegacyFormats:
    """Tests for backward compatibility with legacy formats."""
    
    def test_normalized_wrapper_format(self):
        """Test legacy 'normalized' wrapper is handled."""
        log = {
            "normalized": {
                "tenant_id": "legacy-tenant",
                "source_ip": "10.0.0.1",
                "destination_ip": "10.0.0.2",
                "action": "allow"
            }
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "legacy-tenant"
        assert result.source_ip == "10.0.0.1"
        assert result.destination_ip == "10.0.0.2"
        assert result.action == "allow"
    
    def test_parsed_metadata_wrapper(self):
        """Test legacy 'parsed/metadata' wrapper is handled."""
        log = {
            "parsed": {
                "src_ip": "192.168.1.1",
                "dst_ip": "8.8.8.8",
                "src_port": 12345,
                "dst_port": 53,
                "proto": "udp"
            },
            "metadata": {
                "tenant_id": "parsed-tenant",
                "severity": "medium"
            },
            "timestamp": "2026-02-08T10:00:00Z"
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "parsed-tenant"
        assert result.source_ip == "192.168.1.1"
        assert result.destination_ip == "8.8.8.8"
        assert result.source_port == 12345
        assert result.destination_port == 53
        assert result.protocol == "udp"
        assert result.severity == "medium"
    
    def test_flat_format(self):
        """Test flat format without any wrapper."""
        log = {
            "tenant_id": "flat-tenant",
            "source_ip": "10.10.10.10",
            "destination_ip": "20.20.20.20",
            "action": "drop",
            "protocol": "icmp"
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "flat-tenant"
        assert result.source_ip == "10.10.10.10"
        assert result.destination_ip == "20.20.20.20"
        assert result.action == "drop"
        assert result.protocol == "icmp"
    
    def test_nested_sif_without_version(self):
        """Test nested format detected by structure, not version."""
        log = {
            # No schema_version, but has nested structure
            "tenant_id": "sif-tenant",
            "source": {"ip": "1.1.1.1"},
            "destination": {"ip": "2.2.2.2"},
            "event": {"action": "allow", "category": "network"}
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.source_ip == "1.1.1.1"
        assert result.destination_ip == "2.2.2.2"
        assert result.action == "allow"
        assert result.log_type == "network"


class TestLogAdapterEdgeCases:
    """Tests for edge cases and error handling."""
    
    def test_empty_log(self):
        """Test handling of empty log dict."""
        result = LogAdapter.normalize({})
        
        assert result.tenant_id == "default"
        assert result.source_ip is None
        assert result.log_type == "generic"
    
    def test_malformed_timestamp(self):
        """Test handling of invalid timestamp."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "test",
            "event": {"timestamp": "not-a-valid-timestamp"},
            "source": {"ip": "10.0.0.1"}
        }
        
        result = LogAdapter.normalize(log)
        
        # Should fall back to current time
        assert isinstance(result.timestamp, datetime)
        assert result.source_ip == "10.0.0.1"  # Other fields still work
    
    def test_tenant_id_strip_brackets(self):
        """Test that tenant_id is stripped of brackets."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "[test-tenant]",
            "source": {"ip": "10.0.0.1"}
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "test-tenant"  # Brackets removed
    
    def test_port_as_string(self):
        """Test that string ports are converted to int."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "test",
            "source": {"ip": "10.0.0.1", "port": "12345"},
            "destination": {"ip": "10.0.0.2", "port": "443"}
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.source_port == 12345
        assert result.destination_port == 443
    
    def test_invalid_port(self):
        """Test that invalid port values become None."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "test",
            "source": {"ip": "10.0.0.1", "port": "not-a-number"}
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.source_port is None  # Invalid port becomes None
    
    def test_raw_data_preserved(self):
        """Test that original log is preserved in raw_data."""
        original_log = {
            "schema_version": "v2.0",
            "log_id": "unique-id-123",
            "tenant_id": "test",
            "vendor": "custom",
            "custom_field": "should be preserved",
            "source": {"ip": "10.0.0.1"}
        }
        
        result = LogAdapter.normalize(original_log)
        
        assert result.raw_data == original_log
        assert result.raw_data.get("custom_field") == "should be preserved"


class TestLogAdapterBruteForceCompatibility:
    """Tests ensuring BruteForceAnalyzer gets required fields."""
    
    def test_auth_failure_log_has_required_fields(self):
        """Test that auth failure logs have all fields BruteForceAnalyzer needs."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "security-tenant",
            "vendor": "fortinet",
            "event": {
                "timestamp": "2026-02-08T14:30:00Z",
                "category": "authentication",
                "action": "deny",
                "outcome": "failure",
                "severity": "high"
            },
            "source": {
                "ip": "203.0.113.50",
                "port": 52341,
                "user": "admin"
            },
            "destination": {
                "ip": "192.168.1.10",
                "port": 22
            },
            "raw": {
                "message": "Failed password for admin from 203.0.113.50"
            }
        }
        
        result = LogAdapter.normalize(log)
        
        # Required for BruteForceAnalyzer
        assert result.source_ip is not None
        assert result.tenant_id is not None
        
        # Required for auth failure detection
        assert result.log_type == "authentication"
        assert result.action == "deny"
        
        # Required for alert context
        assert result.destination_ip is not None
        assert result.destination_port == 22


class TestLogAdapterPortScanCompatibility:
    """Tests ensuring PortScanAnalyzer gets required fields."""
    
    def test_network_log_has_required_fields(self):
        """Test that network logs have all fields PortScanAnalyzer needs."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "network-tenant",
            "vendor": "cisco",
            "event": {
                "timestamp": "2026-02-08T14:30:00Z",
                "category": "network",
                "action": "drop"
            },
            "source": {
                "ip": "10.10.10.100",
                "port": 44444
            },
            "destination": {
                "ip": "192.168.1.50",
                "port": 22  # Each scan hits different port
            },
            "network": {
                "protocol": "tcp"
            }
        }
        
        result = LogAdapter.normalize(log)
        
        # Required for PortScanAnalyzer
        assert result.source_ip is not None
        assert result.destination_ip is not None
        assert result.destination_port is not None


class TestLogAdapterBeaconingCompatibility:
    """Tests ensuring BeaconingAnalyzer gets required fields."""
    
    def test_outbound_log_has_required_fields(self):
        """Test that outbound logs have all fields BeaconingAnalyzer needs."""
        log = {
            "schema_version": "v2.0",
            "tenant_id": "beacon-tenant",
            "vendor": "paloalto",
            "event": {
                "timestamp": "2026-02-08T14:30:00Z",
                "category": "network",
                "action": "allow"
            },
            "source": {
                "ip": "192.168.1.200"
            },
            "destination": {
                "ip": "45.33.32.156",
                "port": 443
            },
            "network": {
                "protocol": "tcp",
                "direction": "outbound"
            }
        }
        
        result = LogAdapter.normalize(log)
        
        # Required for BeaconingAnalyzer
        assert result.source_ip is not None
        assert result.destination_ip is not None
        assert result.timestamp is not None


class TestLogAdapterRealRepo1Format:
    """Tests for ACTUAL Repo1 production log format (from Redis)."""
    
    def test_real_fortinet_log_from_repo1(self):
        """Test parsing actual Fortinet log from Repo1's FortinetAdapter."""
        log = {
            "schema_version": "v2.0",
            "log_id": "11621449-d5c9-4e72-b5bb-0a55245b9d98",
            "tenant_id": "default",
            "vendor": "fortinet",
            "metadata": {
                "raw_log": 'date=2024-10-24 time=08:15:23 devname="FG100E" logid="0000000013" type="traffic" subtype="allowed" srcip=192.168.1.100 srcport=44321 dstip=8.8.8.8 dstport=443 proto=6 action="allow"',
                "received_at": None,
                "processed_at": "2026-02-08T23:13:37.897796+00:00",
                "parsed_at": "2026-02-08T23:13:37.897796+00:00",
                "vendor": "fortinet",
                "log_type": "traffic",
                "parser": "FortinetAdapter",
                "confidence": 0.95,
                "queue_destination": "clean"
            },
            "event": {
                "timestamp": "2024-10-24T08:15:23+00:00",
                "action": "allowed",
                "outcome": "allowed",
                "category": "network",
                "type": "connection_attempt",
                "severity": "low"
            },
            "source": {
                "ip": "192.168.1.100",
                "port": 44321,
                "hostname": None,
                "mac": None
            },
            "destination": {
                "ip": "8.8.8.8",
                "port": 443,
                "hostname": None,
                "service": "https"
            },
            "network": {
                "protocol": "tcp",
                "direction": "outbound"
            },
            "device": {
                "hostname": "FG100E",
                "vendor": "fortinet",
                "type": "firewall"
            },
            "hmac_signature": "1bcbc1eb5bdca745241f51aa677832047e555915d6e69fd860ec1d29f5b11283",
            "hmac_algorithm": "HMAC-SHA256",
            "source_info": {
                "authenticated": True,
                "source_ip": "127.0.0.1",
                "api_key": "xg5AabiMBoc15GRmaeOrRA"
            }
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "default"
        assert result.source_ip == "192.168.1.100"
        assert result.destination_ip == "8.8.8.8"
        assert result.source_port == 44321
        assert result.destination_port == 443
        assert result.protocol == "tcp"
        assert result.action == "allowed"
        assert result.log_type == "network"
        assert result.vendor == "fortinet"
        assert result.device_hostname == "FG100E"
        # Message should come from metadata.raw_log
        assert "devname" in result.message
        assert "srcip=192.168.1.100" in result.message
    
    def test_real_ubiquiti_log_from_repo1(self):
        """Test parsing actual Ubiquiti EdgeRouter log from Repo1."""
        log = {
            "schema_version": "v2.0",
            "log_id": "28770058-0f21-4e14-92e2-497aa3180db7",
            "tenant_id": "default",
            "vendor": "ubiquiti",
            "metadata": {
                "raw_log": "Feb 8 17:00:01 EdgeRouter-X kernel: [WAN_LOCAL-default-D]IN=eth0 OUT= MAC=00:11:22:33:44:55 SRC=203.0.113.50 DST=192.168.1.1 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=12345 PROTO=TCP SPT=52341 DPT=22",
                "vendor": "ubiquiti_edge",
                "log_type": "firewall",
                "parser": "EdgeRouterFirewallLog",
                "confidence": 1.0,
                "queue_destination": "clean"
            },
            "event": {
                "timestamp": "2026-02-08T17:00:01+00:00Z",
                "action": "block",
                "outcome": "denied",
                "category": "network",
                "severity": "medium"
            },
            "source": {
                "ip": "203.0.113.50",
                "port": 52341
            },
            "destination": {
                "ip": "192.168.1.1",
                "port": 22,
                "service": "ssh"
            },
            "network": {
                "protocol": "tcp",
                "direction": "inbound"
            },
            "device": {
                "hostname": "EdgeRouter-X",
                "vendor": "ubiquiti_edge"
            },
            "threat_intel": {
                "indicators": ["remote_access_attempt"],
                "risk_score": 7
            }
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "default"
        assert result.source_ip == "203.0.113.50"
        assert result.destination_ip == "192.168.1.1"
        assert result.destination_port == 22
        assert result.action == "block"
        assert result.log_type == "network"
        assert result.severity == "medium"
        # Message should come from metadata.raw_log
        assert "EdgeRouter-X" in result.message
        assert "SRC=203.0.113.50" in result.message
    
    def test_real_pfsense_log_from_repo1(self):
        """Test parsing actual pfSense log from Repo1."""
        log = {
            "schema_version": "v2.0",
            "log_id": "4c0366a9-533a-44a9-a80a-dc28c0f75dd3",
            "tenant_id": "default",
            "vendor": "pfsense",
            "metadata": {
                "raw_log": "<134>Aug 23 14:32:00 pfSense filterlog: 1,16777216,,1000000103,em0,match,pass,in,4,0x0,,64,0,0,0,6,tcp,60,192.168.1.100,192.168.1.1,44321,80,0,S,12345,,mss",
                "parser": "PfSenseAdapter",
                "confidence": 0.94,
                "queue_destination": "clean"
            },
            "event": {
                "timestamp": "1900-08-23T14:32:00",
                "action": "allowed",
                "category": "network",
                "severity": "low"
            },
            "source": {
                "ip": "192.168.1.100",
                "port": 44321
            },
            "destination": {
                "ip": "192.168.1.1",
                "port": 80,
                "service": "http"
            },
            "network": {
                "protocol": "tcp",
                "direction": "inbound",
                "interface": "em0"
            },
            "device": {
                "hostname": "pfSense",
                "vendor": "pfsense",
                "type": "firewall"
            }
        }
        
        result = LogAdapter.normalize(log)
        
        assert result.tenant_id == "default"
        assert result.source_ip == "192.168.1.100"
        assert result.destination_ip == "192.168.1.1"
        assert result.action == "allowed"
        # Message from metadata.raw_log
        assert "pfSense filterlog" in result.message


# Run with: pytest tests/test_log_adapter.py -v
