.PHONY: help up down api worker web test lint migrate

help:
	@grep -E '^[a-z-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-10s\033[0m %s\n", $$1, $$2}'

up:  ## Start Postgres and Redis
	docker compose up -d

down:  ## Stop infrastructure
	docker compose down

api:  ## Run the FastAPI app with reload
	cd apps/api && uv run uvicorn forgelab_api.main:app --reload --port 8000

worker:  ## Run the arq worker
	cd apps/api && uv run arq forgelab_api.worker.WorkerSettings

web:  ## Run the Next.js dashboard
	cd apps/web && npm run dev

test:  ## Run the backend test suite
	cd apps/api && uv run pytest -q

lint:  ## Lint and type-check the backend
	cd apps/api && uv run ruff check . && uv run mypy forgelab_api

migrate:  ## Apply database migrations
	cd apps/api && uv run alembic upgrade head
