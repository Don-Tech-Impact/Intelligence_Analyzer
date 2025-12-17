"""Log adapter service for normalization."""

import logging
from typing import Dict, Any, Optional
from datetime import datetime
from src.models.schemas import NormalizedLogSchema

logger = logging.getLogger(__name__)

class LogAdapter:
    """Adapts raw log data to NormalizedLogSchema."""

    @staticmethod
    def normalize(raw_log: Dict[str, Any]) -> NormalizedLogSchema:
        """
        Normalize a raw log dictionary into a NormalizedLogSchema.

        Args:
            raw_log: Dictionary containing raw log data.

        Returns:
            NormalizedLogSchema instance.
        """
        # Create a copy to avoid modifying the original
        data = raw_log.copy()

        # Extract known fields.
        # If fields are missing in the top level but present in 'raw_data' key (nested), extract them?
        # The current requirement implies the input might be flat or nested.
        # However, the Redis consumer usually receives a flat JSON.
        # We will assume the input dictionary matches the keys expected by NormalizedLogSchema
        # or we map them if they have different names.

        # Mapping strategy:
        # 1. Direct mapping for matching keys
        # 2. 'raw_data' will contain the full original log

        try:
            # Pydantic will handle type validation and defaults
            normalized = NormalizedLogSchema(
                tenant_id=data.get('tenant_id', 'default'),
                timestamp=data.get('timestamp', datetime.utcnow()),
                source_ip=data.get('source_ip'),
                destination_ip=data.get('destination_ip'),
                source_port=data.get('source_port'),
                destination_port=data.get('destination_port'),
                protocol=data.get('protocol'),
                action=data.get('action'),
                log_type=data.get('log_type', 'generic'),
                message=data.get('message'),
                raw_data=data # Store original data
            )
            return normalized
        except Exception as e:
            logger.error(f"Error normalizing log: {e}")
            # Return a basic valid schema on error to prevent data loss,
            # with the error in message or raw_data?
            # For now, let's re-raise or return a safe default.
            # Returning a safe default with raw_data preserved.
            return NormalizedLogSchema(
                raw_data=data,
                message=f"Normalization failed: {str(e)}"
            )
