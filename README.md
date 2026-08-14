# ForgeLab

Give three AI agents the same GitHub issue. Each gets an isolated Daytona
sandbox. They independently fix the code. ForgeLab runs the tests, evaluates the
patches, ranks the agents, and generates the winning pull request.

Tracked in Forge as `REF-088`.

## Layout

```
apps/
  api/                     FastAPI modular monolith
    forgelab_api/
      core/                settings, Redis, cross-cutting infrastructure
      db/                  engine, sessions, shared model conventions
      api/routes/          HTTP surface
      domains/             one package per domain service
      worker.py            arq worker entrypoint
    alembic/               migrations
    tests/
  web/                     Next.js dashboard (App Router, Tailwind)
challenges/
  checkout-api/            demo fixture — 3 seeded bugs, 3/6 tests failing
```

The backend is a modular monolith. Each domain owns its tables, commands,
events, and policy checks; domains communicate through explicit domain events
rather than reaching into each other's internals.

## Stack

| Layer | Choice |
|---|---|
| Frontend | Next.js (App Router), React 19, Tailwind 4, SSE for live updates |
| Backend | FastAPI, Python 3.12, SQLAlchemy 2 (async), Alembic |
| Worker | arq |
| Data | PostgreSQL 16, Redis 7 Streams |
| Sandboxes | Daytona |
| Providers | OpenAI, Anthropic, Qwen |

## Getting started

```bash
cp .env.example .env                    # fill in provider and Daytona keys
make up                                 # Postgres + Redis (needs Docker running)
cd apps/api && uv venv --python 3.12 && uv pip install -e ".[dev]"
cd ../web && npm install

make api      # http://localhost:8000  (docs at /docs)
make web      # http://localhost:3000
make worker   # arq worker
make test     # backend suite
make lint     # ruff + mypy
```

`/healthz` is a dependency-free liveness probe. `/readyz` reports Postgres and
Redis separately and always answers, even when both are down.

## Security boundary

Agent-generated code executes only inside Daytona sandboxes, never on the
backend. Production secrets, provider keys, database passwords, and long-lived
GitHub tokens must never enter a sandbox — agents receive short-lived scoped
credentials from the broker instead.
