
import requests
try:
    url = "http://localhost:8000/api/v1/assets/managed?tenant_id=my_company"
    r = requests.post(url, json={"name": "test", "ip_address": "1.2.3.4"})
    print(f"Status: {r.status_code}")
    print(f"Body: {r.text}")
except Exception as e:
    print(f"Error: {e}")
