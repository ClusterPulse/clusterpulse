"""Redis connection management."""

from functools import lru_cache

import redis

from clusterpulse.config.settings import settings
from clusterpulse.core.logging import get_logger

logger = get_logger(__name__)


@lru_cache(maxsize=1)
def get_redis_pool() -> redis.ConnectionPool:
    """Get or create Redis connection pool."""
    return redis.ConnectionPool(
        host=settings.redis_host,
        port=settings.redis_port,
        password=settings.redis_password,
        db=settings.redis_db,
        decode_responses=True,
        max_connections=50,
    )


@lru_cache(maxsize=1)
def get_redis_client() -> redis.Redis:
    """Get Redis client with shared connection pool."""
    client = redis.Redis(connection_pool=get_redis_pool())

    # Test connection on first creation
    try:
        client.ping()
        logger.info("Redis connection established")
    except redis.RedisError as e:
        logger.error(f"Redis connection failed: {e}")
        raise

    return client


def close_redis_connection():
    """Close Redis connection pool."""
    try:
        pool = get_redis_pool()
        pool.disconnect()
        # Clear the cache so next call creates new pool
        get_redis_pool.cache_clear()
        get_redis_client.cache_clear()
        logger.info("Redis connection pool closed")
    except Exception as e:
        logger.error(f"Error closing Redis pool: {e}")
