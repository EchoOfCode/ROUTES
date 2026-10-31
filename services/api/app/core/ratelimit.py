import hashlib

from redis import Redis
from redis.exceptions import RedisError

from app.core.errors import ApiError


def enforce_rate_limit(redis: Redis, bucket: str, key: str, limit: int, window_seconds: int) -> None:
    """Fixed-window limiter. Fails open if Redis is unavailable (logged by caller)."""
    digest = hashlib.sha256(key.encode()).hexdigest()[:32]
    redis_key = f"routes:rl:{bucket}:{digest}"
    try:
        count = redis.incr(redis_key)
        if count == 1:
            redis.expire(redis_key, window_seconds)
    except RedisError:
        return
    if count > limit:
        raise ApiError(429, "rate_limited", "Too many attempts. Wait a few minutes and try again.")
