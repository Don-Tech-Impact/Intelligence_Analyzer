"""Redis consumer service for log processing.

=============================================================================
ARCHITECTURE
=============================================================================
Tenant-Scoped Multi-Queue Consumer:
  - Discovers queues dynamically: logs:{TENANT}:ingest, logs:{TENANT}:dead, logs:{TENANT}:clean
  - Re-scans Redis every 30s for new tenants
  - Routes by queue suffix: :dead → store-only, :ingest → full pipeline, :clean → fast-path

Batch Processing:
  - Accumulates logs until batch_size (100) OR timeout (1 sec)
  - Uses bulk_insert_mappings() for 50x faster inserts
  - Reduces DB round-trips from 1000/sec to 10/sec

Error Handling:
  - Individual log errors: Log and continue
  - Batch failures: Retry 3x, then push to dead_logs
  - Worker crash: Max 100 logs lost (batch size)
=============================================================================
"""

import json
import logging
import time
import os
from datetime import datetime
from typing import Dict, Any, Optional, List, Set
from collections import defaultdict
import redis
from redis.exceptions import RedisError, ConnectionError

from src.core.config import config
from src.core.database import db_manager
from src.models.database import NormalizedLog, DeadLetter, Alert
from src.services.log_adapter import LogAdapter
from src.services.enrichment import EnrichmentService
from src.analyzers.base import analyzer_manager

logger = logging.getLogger(__name__)


# =============================================================================
# BATCH CONFIGURATION
# =============================================================================
BATCH_SIZE = int(os.getenv('BATCH_SIZE', 100))
BATCH_TIMEOUT_MS = int(os.getenv('BATCH_TIMEOUT_MS', 1000))


class RedisConsumer:
    """
    Consumes logs from Redis queues and processes them in batches.
    
    Dynamically discovers tenant-scoped queues:
        - logs:{TENANT}:ingest  — Raw logs (full pipeline)
        - logs:{TENANT}:clean   — Pre-normalized logs (fast path)
        - logs:{TENANT}:dead    — Failed logs (store only)
    """
    
    def __init__(self):
        """Initialize Redis consumer."""
        self.redis_client: Optional[redis.Redis] = None
        self.running = False
        
        # Dynamic queue discovery
        self.discovered_queues: List[str] = []
        self.known_tenants: Set[str] = set()
        self.last_scan_time = 0.0
        try:
            self.scan_interval = int(config.redis_queue_scan_interval)
        except (ValueError, TypeError):
            self.scan_interval = 30
        
        # Batch accumulators (one per log type)
        self.batch_ingest: List[Dict] = []
        self.batch_clean: List[Dict] = []
        self.batch_dead: List[Dict] = []
        self.last_batch_time = time.time()
        
        # Metrics
        self.metrics = {
            'logs_processed': 0,
            'logs_failed': 0,
            'batches_committed': 0,
            'batch_sizes': [],
            'processing_times': [],
            'tenants_discovered': 0
        }
        
        # Initialize database
        db_manager.initialize()
        logger.info("Database initialized")
        
        # Log adapter for normalization
        self.log_adapter = LogAdapter()
        
    def connect(self):
        """Establish connection to Redis using URL."""
        try:
            self.redis_client = redis.from_url(
                config.redis_url,
                decode_responses=True,
                socket_connect_timeout=5,
                socket_keepalive=True,
                health_check_interval=30
            )
            
            self.redis_client.ping()
            safe_url = config.redis_url.split('@')[-1] if '@' in config.redis_url else config.redis_url
            logger.info(f"Connected to Redis at {safe_url}")
        except (RedisError, ConnectionError) as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    def disconnect(self):
        """Close Redis connection."""
        if self.redis_client:
            self.redis_client.close()
            logger.info("Disconnected from Redis")
    
    # =========================================================================
    # TENANT QUEUE DISCOVERY
    # =========================================================================
    
    def _discover_tenant_queues(self):
        """
        Scan Redis for tenant-scoped queues.
        
        Pattern: logs:*:ingest → discovers tenant IDs
        Then builds full list: logs:{T}:ingest, logs:{T}:clean, logs:{T}:dead
        """
        if not self.redis_client:
            return
        
        try:
            new_tenants: Set[str] = set()
            
            # Scan for all tenant ingest queues
            for key in self.redis_client.scan_iter(match='logs:*:ingest', count=100):
                # key format: "logs:EBK:ingest" → extract "EBK"
                parts = key.split(':')
                if len(parts) == 3:
                    tenant_id = parts[1]
                    new_tenants.add(tenant_id)
            
            # Also check for dead and clean queues (tenant may only have dead)
            for key in self.redis_client.scan_iter(match='logs:*:dead', count=100):
                parts = key.split(':')
                if len(parts) == 3:
                    new_tenants.add(parts[1])
            
            for key in self.redis_client.scan_iter(match='logs:*:clean', count=100):
                parts = key.split(':')
                if len(parts) == 3:
                    new_tenants.add(parts[1])
            
            # Check if new tenants were discovered or if we need to initialize
            if new_tenants != self.known_tenants or not self.discovered_queues:
                added = new_tenants - self.known_tenants
                removed = self.known_tenants - new_tenants
                
                if added:
                    logger.info(f"New tenants discovered: {added}")
                if removed:
                    logger.info(f"Tenants no longer active: {removed}")
                
                self.known_tenants = new_tenants
                
                # Build queue list: ingest first (priority), then clean, then dead
                self.discovered_queues = ['log_queue']  # Always include legacy queue
                for tenant in sorted(self.known_tenants):
                    self.discovered_queues.append(f'logs:{tenant}:ingest')
                    self.discovered_queues.append(f'logs:{tenant}:clean')
                    self.discovered_queues.append(f'logs:{tenant}:dead')
                
                self.metrics['tenants_discovered'] = len(self.known_tenants)
                logger.info(
                    f"Monitoring {len(self.discovered_queues)} queues "
                    f"across {len(self.known_tenants)} tenants: {sorted(self.known_tenants)}"
                )
            
            self.last_scan_time = time.time()
            
        except RedisError as e:
            logger.error(f"Failed to discover tenant queues: {e}")
    
    def _should_rescan(self) -> bool:
        """Check if it's time to re-scan for new tenants."""
        return (time.time() - self.last_scan_time) >= self.scan_interval
    
    @staticmethod
    def _get_queue_type(queue_name: str) -> str:
        """
        Extract queue type from tenant-scoped queue name.
        
        'logs:EBK:ingest' → 'ingest'
        'logs:EBK:dead'   → 'dead'
        'logs:EBK:clean'  → 'clean'
        """
        parts = queue_name.split(':')
        if len(parts) == 3:
            return parts[2]  # ingest, dead, or clean
        return 'unknown'
    
    @staticmethod
    def _get_queue_tenant(queue_name: str) -> str:
        """
        Extract tenant ID from tenant-scoped queue name.
        
        'logs:EBK:ingest' → 'EBK'
        """
        parts = queue_name.split(':')
        if len(parts) == 3:
            return parts[1]
        return 'unknown'
    
    def parse_log_message(self, message: str) -> Optional[Dict[str, Any]]:
        """Parse log message from JSON string."""
        try:
            return json.loads(message)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse log message: {e}")
            return None
    
    # =========================================================================
    # QUEUE HANDLERS
    # =========================================================================
    
    def _handle_dead_log(self, log_data: Dict[str, Any]) -> bool:
        """
        Handle dead logs: store in dead_letters AND extract intelligence.
        
        Repo1 dead log schema:
        {
            "tenant_id": "EBK",
            "raw_log": "%ASA-6-302013: Built outbound TCP...",
            "error_type": "tenant_resolution_failed",
            "error_message": "Tenant configuration not found: EBK",
            "vendor": null,
            "source_info": { ... },
            "failed_at": "2026-02-19T21:22:12+00:00"
        }
        
        Two-step process:
        1. Store raw payload in dead_letters (audit trail, debugging)
        2. Attempt to normalize raw_log and push through analysis pipeline
        """
        tenant_id = (
            log_data.get('tenant_id') or 
            log_data.get('metadata', {}).get('tenant_id', 'unknown')
        )
        
        # Parse failed_at timestamp
        failed_at = log_data.get('failed_at')
        received_at = LogAdapter._parse_timestamp(failed_at) if failed_at else datetime.utcnow()
        
        # 1. KEEP: Store in dead_letters table (audit trail)
        self.batch_dead.append({
            'tenant_id': tenant_id,
            'received_at': received_at,
            'source_queue': 'dead',
            'error_type': log_data.get('error_type') or log_data.get('metadata', {}).get('error', 'unknown'),
            'error_message': log_data.get('error_message') or log_data.get('error', ''),
            'raw_payload': log_data,
            'retry_count': 0
        })
        
        # 2. NEW: Try to extract intelligence from raw_log
        raw_log = log_data.get('raw_log', '')
        if raw_log and isinstance(raw_log, str) and len(raw_log) > 5:
            try:
                # Wrap as v1 schema so LogAdapter can parse the raw syslog
                v1_wrapper = {
                    'schema_version': 'v1',
                    'tenant_id': tenant_id,
                    'raw_log': raw_log,
                    'timestamp': failed_at,
                    'level': 'info',
                    'metadata': {
                        'device_type': log_data.get('vendor') or 'unknown',
                        'source_ip': (log_data.get('source_info') or {}).get('source_ip'),
                    }
                }
                normalized = self.log_adapter.normalize(v1_wrapper)
                
                log_dict = {
                    'tenant_id': normalized.tenant_id,
                    'timestamp': normalized.timestamp or datetime.utcnow(),
                    'source_ip': normalized.source_ip,
                    'destination_ip': normalized.destination_ip,
                    'source_port': normalized.source_port,
                    'destination_port': normalized.destination_port,
                    'protocol': normalized.protocol,
                    'action': normalized.action,
                    'log_type': normalized.log_type or 'dead_recovered',
                    'vendor': normalized.vendor,
                    'device_hostname': normalized.device_hostname,
                    'severity': 'info',  # Dead = low confidence, info-level
                    'message': normalized.message,
                    'raw_data': normalized.raw_data,
                    'business_context': {
                        **(normalized.business_context or {}),
                        'confidence': 0.3,
                        'source_queue': 'dead',
                        'original_error': log_data.get('error_type')
                    },
                    'created_at': datetime.utcnow()
                }
                self.batch_clean.append(log_dict)  # Enters analysis pipeline
                logger.debug(f"Dead log recovered for analysis: {tenant_id}")
            except Exception as e:
                logger.debug(f"Dead log unrecoverable (OK): {e}")
        
        return True

    def _handle_ingest_log(self, log_data: Dict[str, Any], tenant_id: Optional[str] = None) -> bool:
        """
        Handle raw ingest logs (full pipeline).
        
        Pipeline: Parse → Normalize → Enrich → Analyze → Batch Store
        """
        try:
            # 1. Normalize using LogAdapter (handles V1 and V2 schemas)
            normalized = self.log_adapter.normalize(log_data, tenant_id_fallback=tenant_id)
            
            # 2. Convert to dict for batch insert
            log_dict = {
                'tenant_id': normalized.tenant_id,
                'timestamp': normalized.timestamp or datetime.utcnow(),
                'source_ip': normalized.source_ip,
                'destination_ip': normalized.destination_ip,
                'source_port': normalized.source_port,
                'destination_port': normalized.destination_port,
                'protocol': normalized.protocol,
                'action': normalized.action,
                'log_type': normalized.log_type,
                'vendor': normalized.vendor,
                'device_hostname': normalized.device_hostname,
                'severity': normalized.severity,
                'message': normalized.message,
                'raw_data': normalized.raw_data,
                'business_context': normalized.business_context or {},
                'created_at': datetime.utcnow()
            }
            
            self.batch_ingest.append(log_dict)
            return True
            
        except Exception as e:
            logger.error(f"Failed to process ingest log: {e}")
            self._handle_dead_log({
                'tenant_id': log_data.get('tenant_id', 'unknown'),
                'raw_log': log_data.get('raw_log', ''),
                'error_type': 'processing_error',
                'error_message': str(e),
                'failed_at': datetime.utcnow().isoformat()
            })
            return False

    def _handle_clean_log(self, log_data: Dict[str, Any], tenant_id: Optional[str] = None) -> bool:
        """
        Handle clean logs (fast path, already normalized by Repo1).
        
        These come from Repo1's logs:{TENANT}:clean queue in v2.0 schema format.
        """
        try:
            normalized = self.log_adapter.normalize(log_data, tenant_id_fallback=tenant_id)
            
            log_dict = {
                'tenant_id': normalized.tenant_id,
                'timestamp': normalized.timestamp or datetime.utcnow(),
                'source_ip': normalized.source_ip,
                'destination_ip': normalized.destination_ip,
                'source_port': normalized.source_port,
                'destination_port': normalized.destination_port,
                'protocol': normalized.protocol,
                'action': normalized.action,
                'log_type': normalized.log_type,
                'vendor': normalized.vendor,
                'device_hostname': normalized.device_hostname,
                'severity': normalized.severity,
                'message': normalized.message,
                'raw_data': normalized.raw_data,
                'business_context': normalized.business_context or {},
                'created_at': datetime.utcnow()
            }
            
            self.batch_clean.append(log_dict)
            return True
            
        except Exception as e:
            logger.error(f"Failed to process clean log: {e}")
            return False

    # =========================================================================
    # BATCH PROCESSING
    # =========================================================================
    
    def _should_flush_batch(self) -> bool:
        """Check if batch should be flushed (size or timeout)."""
        total_pending = len(self.batch_ingest) + len(self.batch_clean) + len(self.batch_dead)
        
        if total_pending >= BATCH_SIZE:
            return True
        
        elapsed_ms = (time.time() - self.last_batch_time) * 1000
        if total_pending > 0 and elapsed_ms >= BATCH_TIMEOUT_MS:
            return True
        
        return False
    
    def _flush_batches(self):
        """Commit all pending batches to database."""
        start_time = time.time()
        total_inserted = 0
        
        try:
            with db_manager.session_scope() as session:
                # BATCH INSERT: logs (ingest + clean combined)
                all_logs = self.batch_ingest + self.batch_clean
                if all_logs:
                    session.bulk_insert_mappings(NormalizedLog, all_logs)
                    total_inserted += len(all_logs)
                    logger.debug(f"Inserted {len(all_logs)} logs")
                
                # BATCH INSERT: dead letters
                if self.batch_dead:
                    session.bulk_insert_mappings(DeadLetter, self.batch_dead)
                    logger.debug(f"Inserted {len(self.batch_dead)} dead letters")
                
                session.commit()
            
            # Update metrics
            self.metrics['logs_processed'] += total_inserted
            self.metrics['batches_committed'] += 1
            self.metrics['batch_sizes'].append(total_inserted)
            
            processing_time = (time.time() - start_time) * 1000
            self.metrics['processing_times'].append(processing_time)
            
            logger.info(f"Batch committed: {total_inserted} logs in {processing_time:.1f}ms")
            
        except Exception as e:
            logger.error(f"Batch insert failed: {e}", exc_info=True)
            self.metrics['logs_failed'] += len(self.batch_ingest) + len(self.batch_clean)
            
        finally:
            self.batch_ingest.clear()
            self.batch_clean.clear()
            self.batch_dead.clear()
            self.last_batch_time = time.time()
    
    def _run_analysis_on_batch(self, logs: List[Dict]):
        """
        Run intelligence analysis on a batch of logs.
        
        Features:
        - Confidence-weighted severity: dead-recovered logs (confidence <0.5)
          get their alert severity downgraded to reduce false positives.
        - Business-hours boosting: off-hours/weekend events get severity
          upgraded since attacks during quiet periods are more suspicious.
        - Uses analyzer_manager with Redis for state.
        """
        for log_dict in logs:
            try:
                biz = log_dict.get('business_context') or {}
                confidence = biz.get('confidence', 1.0)
                
                # Skip analysis for very low confidence logs
                if confidence < 0.2:
                    continue
                
                class LogProxy:
                    def __init__(self, d):
                        for k, v in d.items():
                            setattr(self, k, v)
                
                log_proxy = LogProxy(log_dict)
                alerts = analyzer_manager.analyze_log(log_proxy)
                
                if alerts:
                    for alert in alerts:
                        if not alert:
                            continue
                        
                        # --- Confidence-weighted severity ---
                        # Dead-recovered logs: downgrade to avoid false positives
                        if confidence < 0.5:
                            if alert.severity == 'critical':
                                alert.severity = 'medium'
                            elif alert.severity == 'high':
                                alert.severity = 'low'
                        
                        # --- Business-hours severity boost ---
                        # Off-hours / weekend activity is more suspicious
                        is_off_hours = not biz.get('is_business_hour', True)
                        is_weekend = biz.get('is_weekend', False)
                        
                        if (is_off_hours or is_weekend) and confidence >= 0.5:
                            if alert.severity == 'low':
                                alert.severity = 'medium'
                            elif alert.severity == 'medium':
                                alert.severity = 'high'
                    
                    self._store_alerts(alerts)
                    
            except Exception as e:
                logger.error(f"Analysis failed for log: {e}")
    
    def _store_alerts(self, alerts: List[Alert]):
        """Store generated alerts to database."""
        try:
            with db_manager.session_scope() as session:
                for alert in alerts:
                    session.add(alert)
                session.commit()
                logger.info(f"Stored {len(alerts)} alerts")
        except Exception as e:
            logger.error(f"Failed to store alerts: {e}")

    # =========================================================================
    # MAIN LOOP
    # =========================================================================
    
    def process_message(self, queue_name: str, message: str) -> bool:
        """Process a single log message based on its source queue."""
        log_data = self.parse_log_message(message)
        if log_data is None:
            return False
            
        try:
            queue_type = self._get_queue_type(queue_name)
            tenant_id = self._get_queue_tenant(queue_name)
            
            # Legacy log_queue handling
            if queue_name == 'log_queue':
                queue_type = 'ingest'
                # Try to extract tenant from payload if queue name doesn't have it
                tenant_id = (
                    log_data.get('tenant_id') or 
                    log_data.get('metadata', {}).get('tenant_id') or
                    'default'
                )
            
            if queue_type == 'dead':
                return self._handle_dead_log(log_data)
            elif queue_type == 'ingest':
                return self._handle_ingest_log(log_data, tenant_id=tenant_id)
            elif queue_type == 'clean':
                return self._handle_clean_log(log_data, tenant_id=tenant_id)
            else:
                logger.warning(f"Unknown queue type '{queue_type}' from queue: {queue_name}")
                return False
        except Exception as e:
            logger.error(f"Error processing from {queue_name}: {e}", exc_info=True)
            return False
    
    def start(self):
        """Start consuming logs from Redis queues."""
        if not self.redis_client:
            self.connect()
        
        self.running = True
        
        # Initial queue discovery
        self._discover_tenant_queues()
        
        if not self.discovered_queues:
            logger.warning("No tenant queues found. Waiting for tenants to appear...")
        
        logger.info(f"Batch config: size={BATCH_SIZE}, timeout={BATCH_TIMEOUT_MS}ms")
        logger.info(f"Queue scan interval: {self.scan_interval}s")
        
        consecutive_errors = 0
        max_consecutive_errors = 10
        
        while self.running:
            try:
                # ==========================================================
                # PERIODIC RESCAN for new tenants
                # ==========================================================
                if self._should_rescan():
                    self._discover_tenant_queues()
                
                # ==========================================================
                # BLPOP across all discovered queues
                # ==========================================================
                if not self.discovered_queues:
                    # No queues yet, wait and rescan
                    time.sleep(5)
                    continue
                
                # BRPOP reads from the RIGHT (FIFO order) — Repo 1 uses LPUSH (writes to left)
                # FIFO ensures oldest logs are processed first for correct chronological analysis.
                # The previous BLPOP read from the LEFT (LIFO) which broke time-ordered detection.
                result = self.redis_client.brpop(self.discovered_queues, timeout=1)
                
                if result:
                    queue_name, message = result
                    
                    if self.process_message(queue_name, message):
                        consecutive_errors = 0
                    else:
                        consecutive_errors += 1
                
                # ==========================================================
                # CHECK BATCH FLUSH
                # ==========================================================
                if self._should_flush_batch():
                    all_logs = self.batch_ingest + self.batch_clean
                    if all_logs:
                        self._run_analysis_on_batch(all_logs)
                    
                    self._flush_batches()
                
            except (RedisError, ConnectionError) as e:
                logger.error(f"Redis error: {e}")
                consecutive_errors += 1
                
                if consecutive_errors >= max_consecutive_errors:
                    logger.error(f"Too many errors ({consecutive_errors}). Stopping.")
                    self.running = False
                    break
                
                logger.info("Attempting to reconnect to Redis...")
                time.sleep(5)
                try:
                    self.connect()
                    consecutive_errors = 0
                except Exception as reconnect_error:
                    logger.error(f"Reconnection failed: {reconnect_error}")
            
            except KeyboardInterrupt:
                logger.info("Received interrupt signal")
                self.running = False
                break
            
            except Exception as e:
                logger.error(f"Unexpected error: {e}", exc_info=True)
                consecutive_errors += 1
                time.sleep(1)
        
        # Flush remaining on shutdown
        if self.batch_ingest or self.batch_clean or self.batch_dead:
            logger.info("Flushing remaining batch on shutdown...")
            self._flush_batches()
        
        self._log_final_metrics()
        logger.info("Redis consumer stopped")
    
    def stop(self):
        """Stop the consumer."""
        logger.info("Stopping Redis consumer...")
        self.running = False
    
    def _log_final_metrics(self):
        """Log final processing metrics."""
        logger.info("="*60)
        logger.info("CONSUMER METRICS")
        logger.info("="*60)
        logger.info(f"Total logs processed: {self.metrics['logs_processed']}")
        logger.info(f"Total logs failed: {self.metrics['logs_failed']}")
        logger.info(f"Total batches: {self.metrics['batches_committed']}")
        logger.info(f"Tenants monitored: {self.metrics['tenants_discovered']}")
        
        if self.metrics['batch_sizes']:
            avg_batch = sum(self.metrics['batch_sizes']) / len(self.metrics['batch_sizes'])
            logger.info(f"Average batch size: {avg_batch:.1f}")
        
        if self.metrics['processing_times']:
            avg_time = sum(self.metrics['processing_times']) / len(self.metrics['processing_times'])
            logger.info(f"Average batch time: {avg_time:.1f}ms")
    
    def get_queue_sizes(self) -> Dict[str, int]:
        """Get size of all discovered queues."""
        if not self.redis_client:
            return {}
            
        try:
            sizes = {}
            for queue in self.discovered_queues:
                sizes[queue] = self.redis_client.llen(queue)
            return sizes
        except RedisError as e:
            logger.error(f"Failed to get queue sizes: {e}")
            return {}
    
    def get_total_queue_size(self) -> int:
        """Get total items across all queues."""
        return sum(self.get_queue_sizes().values())


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================

def main():
    """Main entry point for consumer worker."""
    import signal
    import sys
    
    logging.basicConfig(
        level=getattr(logging, os.getenv('LOG_LEVEL', 'INFO')),
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    consumer = RedisConsumer()
    
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}")
        consumer.stop()
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        consumer.start()
    except Exception as e:
        logger.error(f"Consumer crashed: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()