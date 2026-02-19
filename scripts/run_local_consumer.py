
import os
import sys
import logging

# Set project root
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Configure environment variables for local Redis & Postgres
os.environ['DATABASE_URL'] = "postgresql://siem_user:siem_secure_password_2026@localhost:5432/siem_db"
# Point to local Redis instance (Memurai/Repo1 Redis)
os.environ['REDIS_URL'] = "redis://localhost:6379/0"

# Map queues to existing Repo1 keys (tenant: default)
os.environ['REDIS_INGEST_QUEUE'] = "logs:default:ingest"    # Raw logs needing parsing
os.environ['REDIS_CLEAN_QUEUE'] = "logs:default:clean"      # Normalized logs from Repo1
os.environ['REDIS_DEAD_QUEUE'] = "logs:default:dead"        # Dead/failed logs

# App configuration
os.environ['LOG_LEVEL'] = "INFO"

if __name__ == "__main__":
    print(f"Starting Local Consumer...")
    print(f"Connecting to Redis: {os.environ['REDIS_URL']}")
    print(f"Connecting to DB: {os.environ['DATABASE_URL']}")
    print(f"Queues: ingest={os.environ['REDIS_INGEST_QUEUE']}, clean={os.environ['REDIS_CLEAN_QUEUE']}")
    
    # Import main consumer entry point
    from src.services.redis_consumer import main
    main()
