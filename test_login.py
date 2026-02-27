import httpx
import os
from dotenv import load_dotenv

# Load from Repo 2's .env
load_dotenv(".env")

repo1_base = os.getenv("REPO1_BASE_URL", "http://host.docker.internal:8080")
url = f"{repo1_base}/admin/login"

print(f"Testing Repo 1 Login: {url}")

payload = {
    "email": "admin@africanalyzer.com",
    "password": "password"
}

try:
    with httpx.Client(timeout=10.0) as client:
        response = client.post(url, json=payload)
        print(f"Status: {response.status_code}")
        try:
            data = response.json()
            print(f"JSON Body: {data}")
            print(f"Keys: {list(data.keys())}")
            print(f"Has 'access_token': {'access_token' in data}")
        except:
            print(f"Text Body: {response.text}")
except Exception as e:
    print(f"Error: {e}")
