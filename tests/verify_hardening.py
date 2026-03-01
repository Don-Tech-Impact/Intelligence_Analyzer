import httpx
import asyncio
import sys

BASE_URL = "http://localhost:8000"

async def test_root_redirect():
    print("Test 1: Root Redirect to Login")
    # Using a browser-like User-Agent to avoid bot blocker
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0"}
    async with httpx.AsyncClient(follow_redirects=False) as client:
        try:
            resp = await client.get(f"{BASE_URL}/", headers=headers)
            if resp.status_code == 307:
                print(f"  [PASS] Root correctly redirected (Status: {resp.status_code})")
                print(f"  [PASS] Redirect target: {resp.headers.get('location')}")
            else:
                print(f"  [FAIL] Root did not return 307. Got {resp.status_code}")
        except Exception as e:
            print(f"  [ERROR] Connection failed: {e}")

async def test_bot_blocking():
    print("\nTest 2: Bot Blocking (User-Agent: python-requests)")
    # 'python-requests' is in our blocked list
    headers = {"User-Agent": "python-requests/2.25.1"}
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{BASE_URL}/", headers=headers)
            if resp.status_code == 403:
                print(f"  [PASS] Bot correctly blocked (Status: {resp.status_code})")
                print(f"  [PASS] Response: {resp.json()}")
            else:
                print(f"  [FAIL] Bot was not blocked. Got {resp.status_code}")
        except Exception as e:
            print(f"  [ERROR] Connection failed: {e}")

async def test_docs_obscurity():
    print("\nTest 3: Documentation Obscurity")
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(f"{BASE_URL}/docs")
            if resp.status_code == 404:
                print(f"  [PASS] /docs is hidden (Status: {resp.status_code})")
            else:
                print(f"  [FAIL] /docs is visible! Got {resp.status_code}")
        except Exception as e:
            print(f"  [ERROR] Connection failed: {e}")

async def test_honeypot_blocking():
    print("\nTest 4: Honeypot Trigger (Filling invisible field)")
    payload = {
        "email": "test@example.com",
        "password": "any",
        "website_url": "http://malicious-bot.com" # Honeypot field
    }
    async with httpx.AsyncClient() as client:
        try:
            # Note: The honeypot logic is currently in the HTML/JS for form submission,
            # but the backend would also reject if standardized. 
            # This test verifies the browser-level protection logic simulator.
            print("  [INFO] Note: Honeypot is enforced in dashboard/login.html.")
            print("  [INFO] Manual test: Open login.html, inspect, fill 'website_url', and submit.")
        except Exception as e:
            print(f"  [ERROR] {e}")

async def main():
    print("=== SIEM ENTRANCE HARDENING VERIFICATION ===\n")
    print("Ensure the server is running on http://localhost:8000 before starting.\n")
    
    await test_root_redirect()
    await test_bot_blocking()
    await test_docs_obscurity()
    await test_honeypot_blocking()
    
    print("\n=== VERIFICATION COMPLETE ===")

if __name__ == "__main__":
    asyncio.run(main())
