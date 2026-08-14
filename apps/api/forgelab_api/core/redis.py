"""Redis connection used for the worker queue and the run-event stream."""

from redis.asyncio import ConnectionPool, Redis

from forgelab_api.core.config import get_settings

_settings = get_settings()

pool = ConnectionPool.from_url(_settings.redis_url, decode_responses=True)


def get_redis() -> Redis:
    """Return a Redis client bound to the shared connection pool."""
    return Redis(connection_pool=pool)


def run_event_stream(run_id: str) -> str:
    """Stream key for a single agent run's events."""
    return f"forgelab:run:{run_id}:events"


def challenge_event_stream(challenge_id: str) -> str:
    """Stream key the dashboard subscribes to for all lanes of a challenge."""
    return f"forgelab:challenge:{challenge_id}:events"
