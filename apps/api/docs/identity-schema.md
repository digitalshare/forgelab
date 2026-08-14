# Identity schema

Delivered by WO-002. Eight tables covering tenancy, users, projects, membership,
repository links, refresh sessions, audit, and policy decisions.

## Relationships

```
tenants
  ├── users                     (tenant_id)
  ├── projects                  (tenant_id)
  │     ├── project_memberships (project_id, user_id)
  │     └── repository_connections (project_id)
  ├── refresh_sessions          (tenant_id, user_id)
  ├── audit_events              (tenant_id, actor_user_id?, project_id?)
  └── policy_decisions          (tenant_id, actor_user_id?, project_id?)
```

Every foreign key to `tenants` is `ON DELETE CASCADE`, so removing a tenant
removes its data rather than stranding orphans. `actor_user_id` is
`ON DELETE SET NULL` — deleting a user must not erase the audit trail of what
they did.

## Isolation model

Isolation is **logical**, not enforced by the database. There is no row-level
security policy; correctness depends on every read filtering `tenant_id`.

That filtering lives in `forgelab_api.domains.identity.repository`. Its
functions take `tenant_id` as a required keyword argument so it cannot be
omitted by accident. **Query the models directly and the guarantee is gone** —
go through the repository layer.

`test_identity_persistence.py` asserts this against a two-tenant fixture: for
each helper, tenant A's query must withhold rows that genuinely exist under
tenant B. A single-tenant fixture would pass even with the filter deleted.

## Decisions worth knowing

**No ORM relationships.** Under async SQLAlchemy, touching a lazy-loaded
relationship raises `MissingGreenlet` far from the cause. Joins are explicit in
the repository layer instead.

**Enums are CHECK-constrained strings**, not native PostgreSQL enum types.
`native_enum=False` alone produces a bare `VARCHAR` that accepts anything —
`create_constraint=True` is what emits the CHECK. Adding a value to a native
enum needs `ALTER TYPE`; editing a CHECK is an ordinary migration.

**Active membership uniqueness is a partial index**
(`WHERE status = 'active'`). Revoked rows are retained for audit, so a plain
unique constraint on `(project_id, user_id)` would permanently block re-granting
access after a revocation.

**Refresh sessions store only `token_hash`.** A database disclosure yields no
usable credential. Expiry and revocation are filtered in SQL by
`get_active_refresh_session`, so a caller cannot honour a dead session by
forgetting to check the columns.

**Audit and policy rows are append-only** — no `updated_at`. Policy decisions
are kept separate from audit events because a decision carries a verdict and a
reason, and denials are the interesting rows; mixing them into the audit stream
would bury them.

## Known gaps

- `challenge_id` and `run_id` on `audit_events` and `policy_decisions` are plain
  UUID columns with **no foreign keys** — the `challenges` and `agent_runs`
  tables arrive with WO-007 and WO-012. Add the constraints then.
- No row-level security. If a future service reaches the database without going
  through the repository layer, consider RLS as defence in depth.
- Retention is unbounded. The architecture estimates ~1.5 GB of event metadata
  over a 30-day beta; audit growth needs a policy before that matters.

## Running the database tests

```bash
docker compose up -d                 # from the repo root
cd apps/api && uv run pytest -q
```

Integration tests create `forgelab_test`, apply **migrations** (not
`create_all`, so a broken migration fails the build), and roll back after each
test. If Postgres is unreachable they **skip** rather than fail — a skip means
unverified, not passed. Point them elsewhere with `FORGELAB_TEST_DATABASE_URL`.
