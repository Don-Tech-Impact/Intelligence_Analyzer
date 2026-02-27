
import sqlite3
import os

db_path = 'siem_analyzer.db'
if os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Map all 'default' and 'EBK' to 'my_company' to ensure visibility for the logged in user
    cursor.execute("UPDATE logs SET tenant_id = 'my_company' WHERE tenant_id IN ('default', 'EBK')")
    logs_count = cursor.rowcount
    
    cursor.execute("UPDATE alerts SET tenant_id = 'my_company' WHERE tenant_id IN ('default', 'EBK')")
    alerts_count = cursor.rowcount
    
    conn.commit()
    conn.close()
    print(f"Successfully updated {logs_count} logs and {alerts_count} alerts to 'my_company' tenant.")
else:
    print("Database not found.")
