import os
from src.core.config import config
from src.api.auth import get_public_key

print("--- Auth Diagnostics ---")
print(f"Loaded SECRET_KEY (first 5 chars): {config.secret_key[:5]}...")
print(f"SECRET_KEY Length: {len(config.secret_key)}")
print(f"JWT Public Key configured: {get_public_key() is not None}")
print(f"Allowed Origins: {config.allowed_origins}")

# Test hypothetical decoding if we had a token
# from jose import jwt
# try:
#     # jwt.decode(token, config.secret_key, algorithms=["HS256"])
#     pass
# except Exception as e:
#     print(f"Hypothetical decode error: {e}")
