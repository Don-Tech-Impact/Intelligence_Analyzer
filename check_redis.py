import redis
from src.core.config import config
# print("Connecting to Redis at:", config.redis_url)
# try:
#     r = redis.from_url(config.redis_url, decode_responses=True)
#     secret = r.get("admin:jwt_secret")
#     print(f"Secret from Redis: '{secret}'")
# except Exception as e:
#     print("Redis error:", e)


def __get_Admin() -> str:
    return config.admin_api_key

def _get_repo1_base() -> str:
    return config.repo1_base_url

if __name__ == "__main__":
    print(_get_repo1_base())    


