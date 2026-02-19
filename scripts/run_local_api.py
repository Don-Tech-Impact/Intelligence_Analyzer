
import os
import sys
import uvicorn

# Set project root
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Configure environment variables for local Redis & Postgres
os.environ['DATABASE_URL'] = "postgresql://siem_user:siem_secure_password_2026@localhost:5432/siem_db"
os.environ['REDIS_URL'] = "redis://localhost:6379/0"

os.environ['REDIS_INGEST_QUEUE'] = "ingest_logs"
os.environ['REDIS_CLEAN_QUEUE'] = "logs:central-uni:clean"
os.environ['REDIS_DEAD_QUEUE'] = "logs:central-uni:dead"

if __name__ == "__main__":
    print(f"Starting Local API on port 8000...")
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=True)
