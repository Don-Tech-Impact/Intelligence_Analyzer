
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from jose import jwt
import time

def generate_superadmin_token():
    secret_key = "Fv2pkCopnlN9WkwjSjHWowOxjJfXSwdeOyDh_NLVaMNMcmL4uJTwPSwyz3XmMJZi"
    payload = {
        "sub": "test-superadmin",
        "role": "superadmin",
        "username": "superadmin",
        "is_admin": True,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time())
    }
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    print(token)

if __name__ == "__main__":
    generate_superadmin_token()
