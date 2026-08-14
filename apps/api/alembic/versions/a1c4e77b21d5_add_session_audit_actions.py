"""Add session lifecycle values to the audit_action check constraint

Adding a member to a Python StrEnum does not change the database. The
`audit_action` CHECK constraint still listed only the original eleven values,
so writing `session.issued` failed at insert time. Alembic's autogenerate does
not detect changes to non-native enum CHECK constraints, so this migration is
written by hand — any future AuditAction addition needs the same treatment.

Revision ID: a1c4e77b21d5
Revises: 9466ae0563e3
"""

import sqlalchemy as sa
from alembic import op

revision = "a1c4e77b21d5"
down_revision = "9466ae0563e3"
branch_labels = None
depends_on = None

CONSTRAINT_NAME = "audit_action"
TABLE_NAME = "audit_events"

PREVIOUS_VALUES = (
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
)

SESSION_VALUES = (
    "session.issued",
    "session.refreshed",
    "session.revoked",
    "session.replay_detected",
)


def _condition(values: tuple[str, ...]) -> str:
    rendered = ", ".join(f"'{value}'" for value in values)
    return f"action IN ({rendered})"


def upgrade() -> None:
    op.drop_constraint(CONSTRAINT_NAME, TABLE_NAME, type_="check")
    op.create_check_constraint(
        CONSTRAINT_NAME,
        TABLE_NAME,
        sa.text(_condition(PREVIOUS_VALUES + SESSION_VALUES)),
    )


def downgrade() -> None:
    # Session rows would violate the narrower constraint, so remove them first.
    # They are audit records; deleting them is lossy, which is the honest cost
    # of moving backwards past this migration.
    op.execute(
        sa.text(
            f"DELETE FROM {TABLE_NAME} WHERE {_condition(SESSION_VALUES)}"  # noqa: S608
        )
    )
    op.drop_constraint(CONSTRAINT_NAME, TABLE_NAME, type_="check")
    op.create_check_constraint(
        CONSTRAINT_NAME,
        TABLE_NAME,
        sa.text(_condition(PREVIOUS_VALUES)),
    )
