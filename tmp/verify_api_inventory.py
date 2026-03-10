import asyncio
import httpx
import json

async def verify_aggregator():
    API_BASE = "http://localhost:8000/api/admin"
    HEADERS = {"X-Admin-Key": "changeme-admin-key"} # Update if necessary
    
    print("--- Verifying Global API Key Aggregation ---")
    async with httpx.AsyncClient(timeout=15.0) as client:
        try:
            # 1. Test Global Keys
            resp = await client.get(f"{API_BASE}/api-keys", headers=HEADERS)
            print(f"Status: {resp.status_code}")
            if resp.status_code == 200:
                data = resp.json()
                print(f"Total keys found: {data.get('total')}")
                keys = data.get('keys', [])
                if keys:
                    print(f"Sample Key: {json.dumps(keys[0], indent=2)}")
                else:
                    print("No keys returned (Expected if none exist, but check logs if surprising)")
            else:
                print(f"Error: {resp.text}")
                
            # 2. Test Tenant Specific
            tenants_resp = await client.get(f"{API_BASE}/tenants", headers=HEADERS)
            if tenants_resp.status_code == 200:
                tenants = tenants_resp.json().get('tenants', [])
                if tenants:
                    tid = tenants[0]['tenant_id']
                    print(f"\n--- Testing Tenant {tid} ---")
                    t_resp = await client.get(f"{API_BASE}/tenants/{tid}/api-keys", headers=HEADERS)
                    print(f"Status: {t_resp.status_code}")
                    print(f"Body snippet: {t_resp.text[:200]}...")
            
        except Exception as e:
            print(f"Failed to connect: {e}")

if __name__ == "__main__":
    asyncio.run(verify_aggregator())
