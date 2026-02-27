import httpx
import os
from dotenv import load_dotenv

# Load from Repo 2's .env
load_dotenv(".env")

# This time we test Repo 2's Proxy on port 8000
proxy_url = "http://localhost:8000/api/admin/proxy/login"

print(f"Testing Repo 2 Proxy Login: {proxy_url}")

payload = {
    "email": "admin@africanalyzer.com",
    "password": "password"
}

try:
    with httpx.Client(timeout=10.0) as client:
        response = client.post(proxy_url, json=payload)
        print(f"Proxy Status: {response.status_code}")
        try:
            data = response.json()
            print(f"JSON Body: {data}")
            print(f"Has 'access_token': {'access_token' in data}")
        except:
            print(f"Text Body: {response.text}")
except Exception as e:
    print(f"Error: {e}")
