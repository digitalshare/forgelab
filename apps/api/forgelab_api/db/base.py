"""Declarative base and shared column conventions.

Every tenant-scoped table carries `tenant_id`; most user-facing resources also
carry `project_id`. Domain models import these mixins so that isolation columns
and their indexes stay consistent across the schema.
"""

import uuid
from datetime import datetime
from enum import StrEnum

from sqlalchemy import DateTime, ForeignKey, func
from sqlalchemy import Enum as SAEnum
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def enum_column(enum_cls: type[StrEnum], name: str) -> SAEnum:
    """Store a StrEnum as its value in a length-bounded, CHECK-constrained column.

    `create_constraint=True` is required — SQLAlchemy defaults it to False,
    which would leave a bare VARCHAR accepting any string. The Python enum only
    guards writes going through the ORM; the CHECK also covers raw SQL, data
    loads, and any future service that bypasses these models.

    Adding a member to an existing enum needs a hand-written migration: Alembic
    does not detect drift in non-native enum constraints. See migration
    a1c4e77b21d5 for a worked example.
    """
    return SAEnum(
        enum_cls,
        name=name,
        native_enum=False,
        create_constraint=True,
        length=64,
        values_callable=lambda members: [member.value for member in members],
    )


class Base(DeclarativeBase):
    """Base class for all ForgeLab ORM models."""


class UUIDPrimaryKeyMixin:
    id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False, index=True
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class TenantScopedMixin:
    """Applied to every tenant-owned table for multi-tenant isolation."""

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        PGUUID(as_uuid=True), ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
