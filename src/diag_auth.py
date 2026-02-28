
import os
import sys
from jose import jwt, JWTError
import redis
import json

# Add current dir to path
sys.path.append(os.getcwd())

from src.core.config import config

def test_config():
    print("--- Configuration ---")
    print(f"SECRET_KEY: {config.secret_key[:10]}...")
    print(f"REDIS_URL: {config.redis_url}")
    print(f"ADMIN_KEY: {config.admin_api_key[:10]}...")

def test_redis():
    print("\n--- Redis Connection ---")
    try:
        r = redis.from_url(config.redis_url, decode_responses=True)
        r.ping()
        print("✅ Redis: Connected successfully")
        
        # Check for key keys
        secret = r.get("admin:jwt_secret")
        print(f"✅ Redis: Found 'admin:jwt_secret' = {secret == config.secret_key}")
        
    except Exception as e:
        print(f"❌ Redis: Connection failed: {e}")

def test_token(token):
    print("\n--- Token Verification ---")
    try:
        # Silently decode first
        header = jwt.get_unverified_header(token)
        print(f"Header: {header}")
        unverified_payload = jwt.get_unverified_claims(token)
        print(f"Unverified Payload: {unverified_payload}")
        
        # Verify
        payload = jwt.decode(
            token, 
            config.secret_key, 
            algorithms=["HS256"],
            options={"verify_aud": False}
        )
        print("✅ Token: Verified successfully")
        print(f"Verified Payload: {payload}")
        
        # Check admin perms
        role = str(payload.get("role", "")).lower()
        is_admin = payload.get("is_admin", False)
        print(f"Role: {role}, IsAdmin: {is_admin}")
        
    except jwt.ExpiredSignatureError:
        print("❌ Token: Expired")
    except JWTError as e:
        print(f"❌ Token: Verification failed: {e}")
    except Exception as e:
        print(f"❌ Token: Error: {e}")

if __name__ == "__main__":
    test_config()
    test_redis()
    if len(sys.argv) > 1:
        test_token(sys.argv[1])
    else:
        print("\n(Tip: Pass a JWT as an argument to verify it)")
