"""Infrastructure settings.

This module holds environment/deployment configuration only. Domain guardrails
(agent count, run bounds, roles, supported languages) belong in the domain
constants module owned by WO-001 — do not add them here.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_prefix="FORGELAB_", extra="ignore"
    )

    environment: str = "local"
    debug: bool = False

    # Postgres — authoritative store for challenges, runs, events, evaluations.
    database_url: str = "postgresql+asyncpg://forgelab:forgelab@localhost:5432/forgelab"
    db_pool_size: int = 10
    db_max_overflow: int = 5

    # Redis — worker queue plus Redis Streams event bus backing SSE replay.
    redis_url: str = "redis://localhost:6379/0"
    event_stream_maxlen: int = 10_000

    # Daytona sandbox provider.
    daytona_api_key: str | None = None
    daytona_api_url: str | None = None
    daytona_target: str = "us"

    # LLM providers — one per agent lane.
    openai_api_key: str | None = None
    anthropic_api_key: str | None = None
    qwen_api_key: str | None = None

    # GitHub App used for repository access and PR creation.
    github_app_id: str | None = None
    github_private_key: str | None = None
    github_webhook_secret: str | None = None

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:3000"])


@lru_cache
def get_settings() -> Settings:
    return Settings()
