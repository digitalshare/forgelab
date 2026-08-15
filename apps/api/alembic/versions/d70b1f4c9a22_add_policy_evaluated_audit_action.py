"""Add policy.evaluated to the audit_action check constraint

Hand-written for the same reason as a1c4e77b21d5 and c93f2a5e08b7: Alembic does
not detect drift in non-native enum CHECK constraints, so a new AuditAction
member is invisible to autogenerate and fails at first insert instead.

Revision ID: d70b1f4c9a22
Revises: c93f2a5e08b7
"""

import sqlalchemy as sa
from alembic import op

revision = "d70b1f4c9a22"
down_revision = "c93f2a5e08b7"
branch_labels = None
depends_on = None

TABLE_NAME = "audit_events"
CONSTRAINT_NAME = "audit_action"

PREVIOUS_ACTIONS = (
    "repository.connected",
    "challenge.launched",
    "agent.rerun_requested",
    "result.reviewed",
    "result.approved",
    "pull_request.created",
    "sandbox.created",
    "sandbox.destroyed",
    "credential.issued",
    "credential.revoked",
    "run.limit_reached",
    "session.issued",
    "session.refreshed",
    "session.revoked",
    "session.replay_detected",
    "session.denied",
)

NEW_ACTIONS = ("policy.evaluated",)


def _in_clause(values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"action IN ({rendered})"


def upgrade() -> None:
    op.drop_constraint(CONSTRAINT_NAME, TABLE_NAME, type_="check")
    op.create_check_constraint(
        CONSTRAINT_NAME, TABLE_NAME, sa.text(_in_clause(PREVIOUS_ACTIONS + NEW_ACTIONS))
    )


def downgrade() -> None:
    # Policy rows would violate the narrower constraint. Deleting audit records
    # is lossy; that is the cost of moving backwards past this migration.
    op.execute(sa.text(f"DELETE FROM {TABLE_NAME} WHERE {_in_clause(NEW_ACTIONS)}"))  # noqa: S608
    op.drop_constraint(CONSTRAINT_NAME, TABLE_NAME, type_="check")
    op.create_check_constraint(
        CONSTRAINT_NAME, TABLE_NAME, sa.text(_in_clause(PREVIOUS_ACTIONS))
    )
