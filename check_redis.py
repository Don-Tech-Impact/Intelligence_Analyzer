import redis
from src.core.config import config
print("Connecting to Redis at:", config.redis_url)
try:
    r = redis.from_url(config.redis_url, decode_responses=True)
    secret = r.get("admin:jwt_secret")
    print(f"Secret from Redis: '{secret}'")
except Exception as e:
    print("Redis error:", e)
