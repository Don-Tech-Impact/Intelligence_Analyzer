
import os
import sys
import uvicorn

# Set project root
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

# Configure environment variables for SQLite
# We use the existing siem_analyzer.db
database_path = os.path.join(project_root, 'siem_analyzer.db')
os.environ['DATABASE_URL'] = f"sqlite:///{database_path}"
os.environ['REDIS_URL'] = "redis://localhost:6379/1" # Use different DB for safety

if __name__ == "__main__":
    print(f"Starting Local API with SQLite at {database_path}...")
    uvicorn.run("src.api.main:app", host="0.0.0.0", port=8000, reload=False)
