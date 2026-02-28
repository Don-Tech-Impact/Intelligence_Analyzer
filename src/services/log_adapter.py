"""
This adapter handles multiple log formats from Repo1:

 1. Repo1 V1 Schema (raw ingest):
    - Raw syslog in: log["raw_log"]
    - Metadata:      log["metadata"]["device_type"], log["metadata"]["source_ip"]

 2. v2.0 Schema (Current Production):
    - Fields nested under: source, destination, event, network, device
    - Example: log["source"]["ip"], log["event"]["action"]

 3. Legacy 'normalized' Wrapper:
    - Fields inside: log["normalized"]["source_ip"]

 4. Legacy 'parsed/metadata' Wrapper:
    - Fields inside: log["parsed"]["src_ip"], log["metadata"]["tenant_id"]

 5. Flat Format:
    - Direct fields: log["source_ip"], log["action"]
=============================================================================
"""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from src.models.schemas import NormalizedLogSchema

logger = logging.getLogger(__name__)


class LogAdapter:
    """
    Adapts raw log data from Repo1 to NormalizedLogSchema.
    
    Supports Repo1 V1 (raw), v2.0 (structured), and legacy formats.
    """

    @staticmethod
    def normalize(raw_log: Dict[str, Any], tenant_id_fallback: Optional[str] = None) -> NormalizedLogSchema:
        """
        Convert any supported log format to NormalizedLogSchema.
        
        Detection Order:
        1. Check for V1 schema (has 'schema_version' starting with 'v1')
        2. Check for v2.0 schema (has 'schema_version' starting with 'v2.')
        3. Check for 'normalized' wrapper (legacy clean_log format)
        4. Check for 'parsed' wrapper (legacy ingest_log format)
        5. Assume flat or nested SIF format
        
        Args:
            raw_log: Raw log dictionary from Redis queue
            tenant_id_fallback: Optional tenant_id to use if not found in raw_log
            
        Returns:
            NormalizedLogSchema instance with flattened fields
        """
        try:
            # Inject fallback if needed BEFORE normalization
            if tenant_id_fallback and not raw_log.get('tenant_id'):
                raw_log['tenant_id'] = tenant_id_fallback

            schema_version = raw_log.get('schema_version', '')
            
            # =================================================================
            # CASE 1: Repo1 V1 Schema (raw ingest — has raw_log string)
            # =================================================================
            if schema_version.startswith('v1'):
                return LogAdapter._normalize_v1(raw_log)
            
            # =================================================================
            # CASE 2: Repo1 v2.0 Schema (parsed and structured)
            # =================================================================
            if schema_version.startswith('v2.'):
                return LogAdapter._normalize_v2(raw_log)
            
            # =================================================================
            # CASE 3: Legacy 'normalized' Wrapper
            # =================================================================
            if 'normalized' in raw_log and isinstance(raw_log.get('normalized'), dict):
                inner = raw_log['normalized']
                if inner.get('schema_version', '').startswith('v2.'):
                    return LogAdapter._normalize_v2(inner)
                return LogAdapter._normalize_flat(inner, raw_log)
            
            # =================================================================
            # CASE 4: Legacy 'parsed/metadata' Wrapper
            # =================================================================
            if 'parsed' in raw_log and isinstance(raw_log.get('parsed'), dict):
                return LogAdapter._normalize_parsed_wrapper(raw_log)
            
            # =================================================================
            # CASE 5: Nested SIF or Flat Format (detect by structure)
            # =================================================================
            if any(key in raw_log for key in ['source', 'destination', 'event']):
                return LogAdapter._normalize_v2(raw_log)
            
            # Assume flat format
            return LogAdapter._normalize_flat(raw_log, raw_log)

        except Exception as e:
            logger.error(f"Log normalization failed: {e}", exc_info=True)
            return LogAdapter._create_error_log(raw_log, str(e))

    # =========================================================================
    # V1 SCHEMA (Repo1 raw ingest)
    # =========================================================================

    @staticmethod
    def _normalize_v1(log: Dict[str, Any]) -> NormalizedLogSchema:
        """
        Normalize Repo1 V1 schema (raw ingest).
        
        V1 Structure (from logs:{TENANT}:ingest):
        {
            "schema_version": "v1",
            "log_id": "uuid",
            "tenant_id": "EBK",
            "api_key_id": "...",
            "raw_log": "%ASA-6-302013: Built outbound TCP connection...",
            "timestamp": "2026-02-19T20:22:27.068798",
            "level": "info",
            "metadata": {
                "tenant_id": "EBK",
                "device_type": "cisco_asa",
                "source_ip": "192.168.1.100",
                "environment": "production",
                "tags": []
            }
        }
        """
        metadata = log.get('metadata', {})
        
        # Map device_type to vendor name
        device_type = metadata.get('device_type', 'unknown')
        vendor = LogAdapter._map_device_type_to_vendor(device_type)
        
        return NormalizedLogSchema(
            tenant_id=str(log.get('tenant_id', 'default')).strip('[]'),
            company_id=log.get('tenant_id'),
            device_id=metadata.get('device_id') or f"{vendor}_{device_type}",
            timestamp=LogAdapter._parse_timestamp(log.get('timestamp')),
            source_ip=metadata.get('source_ip'),
            destination_ip=None,
            source_port=None,
            destination_port=None,
            protocol=None,
            action=None,
            log_type='raw_ingest',
            vendor=vendor,
            device_hostname=None,
            severity=log.get('level', 'info'),
            message=log.get('raw_log', ''),
            raw_data=log,
            business_context={}
        )

    @staticmethod
    def _map_device_type_to_vendor(device_type: str) -> str:
        """Map Repo1 device_type to vendor name."""
        mapping = {
            'cisco_asa': 'cisco',
            'cisco_ios': 'cisco',
            'pfsense': 'pfsense',
            'ubiquiti': 'ubiquiti',
            'ubiquiti_edge': 'ubiquiti',
            'fortinet': 'fortinet',
            'fortigate': 'fortinet',
            'generic_syslog': 'generic',
        }
        return mapping.get(device_type, device_type or 'unknown')

    # =========================================================================
    # V2 SCHEMA (Repo1 parsed/structured)
    # =========================================================================

    @staticmethod
    def _normalize_v2(log: Dict[str, Any]) -> NormalizedLogSchema:
        """
        Normalize Repo1 v2.0 schema to flat format.
        
        v2.0 Structure:
        {
            "schema_version": "v2.0",
            "log_id": "uuid",
            "tenant_id": "central-uni",
            "vendor": "fortinet",
            "device": {"hostname": "FW-01", "vendor": "fortinet", "role": "firewall"},
            "metadata": {"confidence": 0.95, "parsed_at": "...", "queue_destination": "clean"},
            "event": {"timestamp": "...", "category": "network", "action": "allow", "severity": "low"},
            "source": {"ip": "192.168.1.100", "port": 44321, "user": "john"},
            "destination": {"ip": "8.8.8.8", "port": 443, "service": "https"},
            "network": {"protocol": "tcp", "bytes": 1024, "direction": "outbound"},
            "threat_intel": {"is_threat": false, "threat_score": 0},
            "business_context": {"is_business_hour": true, "day_of_week": "Thursday"},
            "raw": {"message": "[original log line]"}
        }
        """
        event = log.get('event', {})
        source = log.get('source', {})
        destination = log.get('destination', {})
        network = log.get('network', {})
        device = log.get('device', {})
        metadata = log.get('metadata', {})
        threat_intel = log.get('threat_intel', {})
        business_context = log.get('business_context', {})
        raw = log.get('raw', {})
        
        timestamp = LogAdapter._parse_timestamp(
            event.get('timestamp') or metadata.get('parsed_at') or log.get('timestamp')
        )
        
        return NormalizedLogSchema(
            tenant_id=str(log.get('tenant_id', 'default')).strip('[]'),
            company_id=log.get('tenant_id'),
            device_id=f"{device.get('vendor', 'unknown')}_{device.get('hostname', 'unknown')}",
            timestamp=timestamp,
            source_ip=source.get('ip'),
            source_port=LogAdapter._safe_int(source.get('port')),
            destination_ip=destination.get('ip'),
            destination_port=LogAdapter._safe_int(destination.get('port')),
            protocol=network.get('protocol'),
            action=event.get('action') or event.get('outcome'),
            log_type=event.get('category', 'generic'),
            severity=event.get('severity', 'low'),
            vendor=log.get('vendor') or device.get('vendor', 'unknown'),
            device_hostname=device.get('hostname'),
            message=raw.get('message') or metadata.get('raw_log', ''),
            raw_data=log,
            business_context=business_context
        )

    # =========================================================================
    # LEGACY FORMATS
    # =========================================================================

    @staticmethod
    def _normalize_parsed_wrapper(log: Dict[str, Any]) -> NormalizedLogSchema:
        """Normalize legacy parsed/metadata wrapper format."""
        parsed = log.get('parsed', {})
        metadata = log.get('metadata', {})
        
        return NormalizedLogSchema(
            tenant_id=str(metadata.get('tenant_id', 'default')).strip('[]'),
            company_id=metadata.get('tenant_id') or metadata.get('company_id'),
            device_id=metadata.get('device_id') or parsed.get('device_id'),
            timestamp=LogAdapter._parse_timestamp(log.get('timestamp')),
            source_ip=parsed.get('src_ip') or parsed.get('source_ip'),
            destination_ip=parsed.get('dst_ip') or parsed.get('dest_ip') or parsed.get('destination_ip'),
            source_port=LogAdapter._safe_int(parsed.get('src_port') or parsed.get('source_port')),
            destination_port=LogAdapter._safe_int(parsed.get('dst_port') or parsed.get('dest_port') or parsed.get('destination_port')),
            protocol=parsed.get('proto') or parsed.get('protocol'),
            action=parsed.get('action') or parsed.get('status'),
            log_type=log.get('type', 'ingest_log'),
            vendor=log.get('source', 'unknown'),
            device_hostname=parsed.get('hostname') or parsed.get('device'),
            severity=metadata.get('severity', 'low'),
            message=parsed.get('message') or log.get('raw_log', ''),
            raw_data=log,
            business_context=metadata.get('business_context', {})
        )

    @staticmethod
    def _normalize_flat(data: Dict[str, Any], original: Dict[str, Any]) -> NormalizedLogSchema:
        """Normalize flat format where fields are at root level."""
        return NormalizedLogSchema(
            tenant_id=str(data.get('tenant_id', 'default')).strip('[]'),
            company_id=data.get('tenant_id') or data.get('company_id'),
            device_id=data.get('device_id'),
            timestamp=LogAdapter._parse_timestamp(data.get('timestamp')),
            source_ip=data.get('source_ip'),
            destination_ip=data.get('destination_ip'),
            source_port=LogAdapter._safe_int(data.get('source_port')),
            destination_port=LogAdapter._safe_int(data.get('destination_port')),
            protocol=data.get('protocol'),
            action=data.get('action'),
            log_type=data.get('log_type', 'generic'),
            vendor=data.get('vendor', 'unknown'),
            device_hostname=data.get('device_hostname'),
            severity=data.get('severity', 'low'),
            message=data.get('message', ''),
            raw_data=original,
            business_context=data.get('business_context', {})
        )

    @staticmethod
    def _create_error_log(raw_log: Any, error: str) -> NormalizedLogSchema:
        """Create a log entry for failed normalization."""
        tenant_id = 'default'
        if isinstance(raw_log, dict):
            tenant_id = raw_log.get('tenant_id') or \
                       raw_log.get('metadata', {}).get('tenant_id', 'default')
        
        return NormalizedLogSchema(
            tenant_id=str(tenant_id).strip('[]'),
            message=f"Normalization error: {error}",
            raw_data=raw_log if isinstance(raw_log, dict) else {'raw': str(raw_log)},
            severity='low',
            log_type='error'
        )

    # =========================================================================
    # UTILITIES
    # =========================================================================

    @staticmethod
    def _parse_timestamp(ts: Any) -> datetime:
        """Parse timestamp from various formats."""
        if ts is None:
            return datetime.utcnow()
        
        if isinstance(ts, datetime):
            return ts
        
        if isinstance(ts, (int, float)):
            try:
                return datetime.fromtimestamp(ts)
            except:
                return datetime.utcnow()
        
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace('Z', '+00:00'))
            except ValueError:
                try:
                    for fmt in ['%Y-%m-%dT%H:%M:%S', '%Y-%m-%d %H:%M:%S']:
                        try:
                            return datetime.strptime(ts, fmt)
                        except:
                            continue
                except:
                    pass
        
        return datetime.utcnow()

    @staticmethod
    def _safe_int(value: Any) -> Optional[int]:
        """Safely convert value to int or return None."""
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None