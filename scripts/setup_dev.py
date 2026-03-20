import os
from sqlalchemy import create_engine, text, inspect
from src.core.config import config

def fix_schema():
    db_url = config.database_url
    print(f"Connecting to database: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    
    try:
        engine = create_engine(db_url)
        # Verify connection
        with engine.connect() as conn:
            pass
    except Exception as e:
        if "localhost" in db_url or "127.0.0.1" in db_url:
            print(f"Connection to 5432 failed, trying dev port 5433...")
            db_url = db_url.replace(":5432", ":5433")
            engine = create_engine(db_url)
        else:
            raise e

    inspector = inspect(engine)
    with engine.connect() as conn:
        print("Auditing 'tenants' table...")
        # Get existing columns
        columns = [c['name'] for c in inspector.get_columns('tenants')]
        
        # Add 'description' if missing
        if 'description' not in columns:
            print("  -> Adding missing column: 'description'")
            conn.execute(text("ALTER TABLE tenants ADD COLUMN description TEXT;"))
        
        # Add 'updated_at' if missing
        if 'updated_at' not in columns:
            print("  -> Adding missing column: 'updated_at'")
            # SQLite vs Postgres syntax handled automatically by using a simple column definition
            conn.execute(text("ALTER TABLE tenants ADD COLUMN updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP;"))
            
        conn.commit()
        print("[PASS] Schema is now aligned with the application.")

def provision_tenants(engine):
    """Ensure required tenants for development exist in the database."""
    required_tenants = [
        ("nairobi_university", "Nairobi University", "Primary Higher Education Tenant"),
        ("default", "Default Tenant", "Fallback for system logs")
    ]
    
    with engine.connect() as conn:
        print("Provisioning required tenants...")
        for tid, name, desc in required_tenants:
            # Check if exists
            exists = conn.execute(
                text("SELECT 1 FROM tenants WHERE tenant_id = :tid"), 
                {"tid": tid}
            ).fetchone()
            
            if not exists:
                print(f"  [+] Provisioning tenant: {tid}")
                conn.execute(
                    text("INSERT INTO tenants (tenant_id, name, description, is_active) VALUES (:tid, :name, :desc, true)"),
                    {"tid": tid, "name": name, "desc": desc}
                )
            else:
                print(f"  [PASS] Tenant '{tid}' already exists.")
        
        conn.commit()
    print("[SUCCESS] Tenant provisioning complete.")

if __name__ == "__main__":
    # Get engine with port fallback
    db_url = config.database_url
    try:
        engine = create_engine(db_url)
        with engine.connect() as conn:
            pass
    except Exception:
        if "5432" in db_url:
            db_url = db_url.replace(":5432", ":5433")
            engine = create_engine(db_url)
    
    fix_schema()
    provision_tenants(engine)
