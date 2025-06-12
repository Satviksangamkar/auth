import redis
from .config import settings

# Build a connection pool with decode_responses so you get str, not bytes
_pool = redis.ConnectionPool(
    host=settings.REDIS_HOST,
    port=settings.REDIS_PORT,
    username=settings.REDIS_USERNAME or None,
    password=settings.REDIS_PASSWORD or None,
    decode_responses=True
)

# Use the pool for all Redis commands
r = redis.Redis(connection_pool=_pool)
