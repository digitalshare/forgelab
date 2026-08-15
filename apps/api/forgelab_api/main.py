"""FastAPI application factory."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from forgelab_api import __version__
from forgelab_api.api.router import api_router
from forgelab_api.core.config import get_settings
from forgelab_api.core.redis import pool
from forgelab_api.core.request_context import RequestContextMiddleware
from forgelab_api.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    await engine.dispose()
    await pool.aclose()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="ForgeLab API",
        version=__version__,
        description="Runs three AI agents against one challenge in isolated Daytona sandboxes.",
        lifespan=lifespan,
    )

    # Outermost: every later layer, including audit writes, sees the identifier.
    app.add_middleware(RequestContextMiddleware)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router)
    return app


app = create_app()
