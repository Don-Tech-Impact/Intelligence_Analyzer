
import httpx
import sys

def test_registration():
    url = "http://localhost:8000/api/v1/assets/managed?tenant_id=my_company"
    # We need a token. I'll try to get one if possible, or just see the 405 vs 401.
    # If I get 405 without a token, it means the router is failing before auth.
    
    try:
        with httpx.Client() as client:
            # Test POST
            res_post = client.post(url, json={"name": "Test", "ip_address": "1.2.3.4"})
            print(f"POST Status: {res_post.status_code}")
            print(f"POST Headers: {dict(res_post.headers)}")
            print(f"POST Body: {res_post.text}")
            
            # Test GET
            res_get = client.get(url)
            print(f"\nGET Status: {res_get.status_code}")
            print(f"GET Body: {res_get.text}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_registration()
