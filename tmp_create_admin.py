import redis
from src.api.admin.auth import admin_auth_service
import os

# Use the Redis URL from Repo 1 config or environment
# In Repo 1, it's often 'redis://afric-analyzer-redis-local:6379/0'
redis_url = os.environ.get('REDIS_URL', 'redis://afric-analyzer-redis-local:6379/0')

r = redis.from_url(redis_url)
admin_auth_service.init(r)

try:
    result = admin_auth_service.create_admin('admin@example.com', 'SecurePass123!', 'admin')
    print(f"Successfully created admin: {result}")
except Exception as e:
    print(f"Admin creation failed or already exists: {e}")
