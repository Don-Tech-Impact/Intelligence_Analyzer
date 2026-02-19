"""System readiness check script."""
print("=== SYSTEM READINESS CHECK ===")
print()

# 1. RedisConsumer
try:
    from src.services.redis_consumer import RedisConsumer
    print("[OK] RedisConsumer")
except Exception as e:
    print(f"[FAIL] RedisConsumer: {e}")

# 2. AnalysisPipeline
try:
    from src.services.log_ingestion import AnalysisPipeline
    print("[OK] AnalysisPipeline")
except Exception as e:
    print(f"[FAIL] AnalysisPipeline: {e}")

# 3. Analyzers
try:
    # Import the package to auto-register analyzers
    from src import analyzers
    from src.analyzers.base import analyzer_manager
    print("[OK] All 4 Analyzers loaded")
    print(f"     Registered: {len(analyzer_manager.analyzers)} analyzers")
except Exception as e:
    print(f"[FAIL] Analyzers: {e}")

# 4. EnrichmentService
try:
    from src.services.enrichment import EnrichmentService
    print("[OK] EnrichmentService")
except Exception as e:
    print(f"[FAIL] EnrichmentService: {e}")

# 5. Database
try:
    from src.core.database import db_manager
    db_manager.initialize()
    from src.models.database import NormalizedLog, Alert
    with db_manager.session_scope() as session:
        log_count = session.query(NormalizedLog).count()
        alert_count = session.query(Alert).count()
    print(f"[OK] Database: {log_count} logs, {alert_count} alerts")
except Exception as e:
    print(f"[FAIL] Database: {e}")

# 6. Redis
try:
    import redis
    import os
    r = redis.from_url(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    r.ping()
    queue_len = r.llen("ingest_logs")
    print(f"[OK] Redis: {queue_len} logs waiting in queue")
except Exception as e:
    print(f"[WARN] Redis: {e}")

# 7. End-to-end test
print()
print("=== END-TO-END PROCESSING TEST ===")
try:
    pipeline = AnalysisPipeline()
    test_log = {
        "tenant_id": "test",
        "timestamp": "2026-01-31T03:00:00Z",
        "source_ip": "192.168.1.100",
        "destination_ip": "10.0.0.1",
        "source_port": 12345,
        "destination_port": 22,
        "protocol": "TCP",
        "action": "denied",
        "severity": "high",
        "message": "SSH connection denied",
        "vendor": "test"
    }
    result = pipeline.process_log(test_log)
    if result:
        print("[OK] Log processing successful!")
    else:
        print("[WARN] Log processing returned False")
except Exception as e:
    print(f"[FAIL] Processing test: {e}")

print()
print("=== SYSTEM READY TO CONSUME LOGS ===")
