"""Scope device identity per user

Revision ID: c4c36e750e4b
Revises: 0001_v1_baseline
Create Date: 2026-09-05 21:54:18.390782

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = "c4c36e750e4b"
down_revision: Union[str, Sequence[str], None] = "0001_v1_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def devices_table(device_id_unique: bool) -> sa.Table:
    metadata = sa.MetaData()
    table = sa.Table(
        "devices",
        metadata,
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("device_id", sa.String(), nullable=False),
        sa.Column("device_name", sa.String(), nullable=True),
        sa.Column("os", sa.String(), nullable=True),
        sa.Column("user_id", sa.String(), sa.ForeignKey("users.user_id"), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=True),
        sa.Column("push_subscription", sa.String(), nullable=True),
        sa.Column("push_subscription_updated_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "user_id", "device_id", name="uq_device_user_id_device_id"
        ) if not device_id_unique else sa.UniqueConstraint("device_id"),
    )
    sa.Index("ix_devices_id", table.c.id)
    sa.Index("ix_devices_device_id", table.c.device_id, unique=device_id_unique)
    sa.Index("ix_devices_user_id", table.c.user_id)
    sa.Index("ix_devices_last_seen", table.c.last_seen)
    return table


def upgrade() -> None:
    with op.batch_alter_table(
        "devices", recreate="always", copy_from=devices_table(device_id_unique=False)
    ):
        pass


def downgrade() -> None:
    with op.batch_alter_table(
        "devices", recreate="always", copy_from=devices_table(device_id_unique=True)
    ):
        pass
