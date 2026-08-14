"""Infrastructure settings.

This module holds environment/deployment configuration only. Domain guardrails
(agent count, run bounds, roles, supported languages) belong in the domain
constants module owned by WO-001 — do not add them here.
"""

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

#: Placeholder signing key so local development and tests need no setup. It is
#: a known constant and therefore worthless as a secret — `signing_secret_problems`
#: refuses it in production.
DEV_JWT_SECRET = "dev-only-insecure-signing-key-do-not-use-in-production"


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

    # Session authentication.
    jwt_secret: str = DEV_JWT_SECRET
    jwt_algorithm: str = "HS256"
    refresh_cookie_name: str = "forgelab_refresh"
    #: Scoped to the auth routes so the refresh credential is not attached to
    #: every request that touches the API.
    refresh_cookie_path: str = "/auth"
    refresh_cookie_samesite: str = "lax"
    #: None means "decide from the environment"; set explicitly to override.
    refresh_cookie_secure: bool | None = None

    #: Issues a session for a known user without verifying any secret. A demo
    #: affordance until real authentication exists — never enable in production.
    allow_bootstrap_login: bool = True

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}

    @property
    def cookie_secure(self) -> bool:
        """Secure cookies everywhere except plain-HTTP local development."""
        if self.refresh_cookie_secure is not None:
            return self.refresh_cookie_secure
        return self.environment.lower() not in {"local", "test"}

    @property
    def bootstrap_login_enabled(self) -> bool:
        """Bootstrap login is refused in production regardless of the flag."""
        return self.allow_bootstrap_login and not self.is_production

    def signing_secret_problems(self) -> list[str]:
        """Configuration faults that must not reach production.

        Reported rather than raised so a deployment check can surface all of
        them at once instead of failing on the first.
        """
        problems: list[str] = []
        if self.is_production:
            if self.jwt_secret == DEV_JWT_SECRET:
                problems.append("FORGELAB_JWT_SECRET is still the development default")
            if len(self.jwt_secret) < 32:
                problems.append("FORGELAB_JWT_SECRET is shorter than 32 characters")
            if self.allow_bootstrap_login:
                problems.append("FORGELAB_ALLOW_BOOTSTRAP_LOGIN must be false in production")
        return problems


@lru_cache
def get_settings() -> Settings:
    return Settings()
