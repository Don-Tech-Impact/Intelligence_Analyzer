"""
Redis Queue Adapter — BRPOP Fix + Corrected Consumer Pattern
=============================================================

PROBLEM:
  src/services/redis_consumer.py uses `redis_client.blpop(...)` which reads
  from the LEFT of the list (LIFO order).

  Repo 1 uses `LPUSH` to write logs (pushes to the LEFT).
  FIFO order (oldest log first) requires reading from the RIGHT → `BRPOP`.

  Using BLPOP gives LIFO: newest log is processed first, which breaks
  chronological analysis for brute-force detection, beaconing, and timelines.

FIX:
  Change the single `blpop` call in RedisConsumer.start() to `brpop`.

PATCH (one line change in src/services/redis_consumer.py):
  Find:    result = self.redis_client.blpop(self.discovered_queues, timeout=1)
  Replace: result = self.redis_client.brpop(self.discovered_queues, timeout=1)

This file also provides a standalone corrected consumer for reference and
integration testing without importing the full app stack.
"""

import json
import logging
import os
import time
from typing import Callable, Dict, List, Optional, Set

import redis
from redis.exceptions import ConnectionError, RedisError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Queue naming helpers (mirrors redis_consumer.py)
# ---------------------------------------------------------------------------

def build_ingest_queue(tenant_id: str) -> str:
    """Return the raw ingest queue name for a tenant."""
    return f"logs:{tenant_id}:ingest"


def build_clean_queue(tenant_id: str) -> str:
    """Return the clean (parsed) queue name for a tenant. Repo 2 reads this."""
    return f"logs:{tenant_id}:clean"


def build_dead_queue(tenant_id: str) -> str:
    """Return the dead-letter queue name for a tenant."""
    return f"logs:{tenant_id}:dead"


def get_tenant_from_queue(queue_name: str) -> str:
    """Extract tenant_id from a queue name. 'logs:acme_corp:clean' → 'acme_corp'."""
    parts = queue_name.split(":")
    return parts[1] if len(parts) == 3 else "unknown"


def get_type_from_queue(queue_name: str) -> str:
    """Extract queue type from a queue name. 'logs:acme_corp:clean' → 'clean'."""
    parts = queue_name.split(":")
    return parts[2] if len(parts) == 3 else "unknown"


def discover_tenant_queues(r: redis.Redis) -> List[str]:
    """
    Scan Redis for all tenant queues matching the Repo 1 contract pattern.

    Returns a list of queue names ordered: ingest first, clean second, dead last.
    This ordering means BRPOP prefers ingest over clean over dead when all
    have messages — ensuring raw logs are processed before pre-parsed ones.
    """
    tenants: Set[str] = set()
    for pattern in ("logs:*:ingest", "logs:*:clean", "logs:*:dead"):
        for key in r.scan_iter(match=pattern, count=100):
            parts = key.split(":")
            if len(parts) == 3:
                tenants.add(parts[1])

    queues: List[str] = []
    for tenant in sorted(tenants):
        queues.append(build_ingest_queue(tenant))
        queues.append(build_clean_queue(tenant))
        queues.append(build_dead_queue(tenant))

    return queues


# ---------------------------------------------------------------------------
# Corrected BRPOP consumer (standalone reference implementation)
# ---------------------------------------------------------------------------

class BrpopConsumer:
    """
    Corrected Redis consumer using BRPOP (FIFO) instead of BLPOP (LIFO).

    This is a standalone reference implementation. To fix the production
    consumer, apply the one-line patch described at the top of this file.

    Usage:
        consumer = BrpopConsumer(redis_url="redis://localhost:6379/0")
        consumer.run(handler=my_log_handler)
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        scan_interval: int = 30,
        brpop_timeout: int = 1,
    ):
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self.scan_interval = scan_interval
        self.brpop_timeout = brpop_timeout
        self.running = False
        self._r: Optional[redis.Redis] = None
        self._queues: List[str] = []
        self._last_scan = 0.0

    def connect(self) -> None:
        """Connect to Redis."""
        self._r = redis.from_url(
            self.redis_url,
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            health_check_interval=30,
        )
        self._r.ping()
        logger.info(f"BrpopConsumer connected to Redis")

    def _maybe_rescan(self) -> None:
        if time.time() - self._last_scan >= self.scan_interval:
            self._queues = discover_tenant_queues(self._r)
            self._last_scan = time.time()
            if self._queues:
                logger.info(f"Monitoring queues: {self._queues}")

    def run(self, handler: Callable[[str, str, dict], None]) -> None:
        """
        Start consuming. Calls handler(queue_name, tenant_id, log_dict) for
        each message.

        handler signature:
            queue_name: str  — e.g. "logs:acme_corp:clean"
            tenant_id:  str  — e.g. "acme_corp"
            log_dict:   dict — parsed JSON payload
        """
        if not self._r:
            self.connect()

        self.running = True
        logger.info("BrpopConsumer started (FIFO order via BRPOP)")

        while self.running:
            try:
                self._maybe_rescan()

                if not self._queues:
                    time.sleep(5)
                    continue

                # KEY FIX: brpop reads from the RIGHT (FIFO) not left (LIFO)
                result = self._r.brpop(self._queues, timeout=self.brpop_timeout)

                if result is None:
                    continue  # timeout, loop again

                queue_name, raw_message = result
                tenant_id = get_tenant_from_queue(queue_name)

                try:
                    log_dict = json.loads(raw_message)
                except json.JSONDecodeError as exc:
                    logger.error(f"Bad JSON in {queue_name}: {exc}")
                    continue

                try:
                    handler(queue_name, tenant_id, log_dict)
                except Exception as exc:
                    logger.error(f"Handler error for {queue_name}: {exc}", exc_info=True)

            except (RedisError, ConnectionError) as exc:
                logger.error(f"Redis error: {exc} — retrying in 5s")
                time.sleep(5)
                try:
                    self.connect()
                except Exception:
                    pass

            except KeyboardInterrupt:
                self.running = False

        logger.info("BrpopConsumer stopped")

    def stop(self) -> None:
        self.running = False


# ---------------------------------------------------------------------------
# Queue depth monitoring helper
# ---------------------------------------------------------------------------

def get_queue_depths(r: redis.Redis, tenant_ids: List[str]) -> Dict[str, int]:
    """
    Return current depth of all queues for the given tenants.

    Example:
        depths = get_queue_depths(r, ["acme_corp", "central_uni"])
        # {"logs:acme_corp:clean": 42, "logs:acme_corp:dead": 0, ...}
    """
    depths: Dict[str, int] = {}
    for tenant_id in tenant_ids:
        for queue in (
            build_ingest_queue(tenant_id),
            build_clean_queue(tenant_id),
            build_dead_queue(tenant_id),
        ):
            try:
                depths[queue] = r.llen(queue)
            except RedisError:
                depths[queue] = -1
    return depths


def alert_on_dead_letter_threshold(
    r: redis.Redis,
    tenant_ids: List[str],
    threshold: int = 100,
) -> List[str]:
    """
    Return list of tenants whose dead-letter queue exceeds `threshold`.

    Use this in a monitoring loop or cron job to detect parsing failures.
    Threshold is read from DEAD_LETTER_ALERT_THRESHOLD env var if not passed.
    """
    threshold = int(os.getenv("DEAD_LETTER_ALERT_THRESHOLD", threshold))
    alerts: List[str] = []
    for tenant_id in tenant_ids:
        dead_queue = build_dead_queue(tenant_id)
        try:
            depth = r.llen(dead_queue)
            if depth >= threshold:
                logger.warning(
                    f"Dead-letter threshold exceeded for tenant '{tenant_id}': "
                    f"{depth} >= {threshold}"
                )
                alerts.append(tenant_id)
        except RedisError:
            pass
    return alerts


# ---------------------------------------------------------------------------
# Patch instructions
# ---------------------------------------------------------------------------

PATCH = """
=============================================================================
PATCH: src/services/redis_consumer.py — BLPOP → BRPOP (LIFO → FIFO)
=============================================================================

In the RedisConsumer.start() method, find the BLPOP call and replace:

    BEFORE (LIFO — wrong):
        result = self.redis_client.blpop(self.discovered_queues, timeout=1)

    AFTER (FIFO — correct per Repo 1 contract):
        result = self.redis_client.brpop(self.discovered_queues, timeout=1)

Why it matters:
  - Repo 1 uses LPUSH (writes to LEFT of list)
  - BRPOP reads from RIGHT → oldest log first (FIFO) ✅
  - BLPOP reads from LEFT → newest log first (LIFO) ✗

  FIFO is required for correct chronological analysis (brute force, beaconing,
  timeline reconstruction). LIFO may cause the analyzer to miss multi-step
  attack sequences because it sees the attack result before the probes.
=============================================================================
"""

if __name__ == "__main__":
    print(PATCH)
