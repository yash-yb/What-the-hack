"""Widen byte and packet counters to BIGINT.

A 60-second window on a busy link, or a single large flow, can exceed the 2.1 GB limit
of a 32-bit INTEGER. The master plan specified BIGINT for these columns.

Revision ID: 20260902_0005
Revises: 20260902_0004
Create Date: 2026-09-02
"""

import sqlalchemy as sa
from alembic import op

revision = "20260902_0005"
down_revision = "20260902_0004"
branch_labels = None
depends_on = None

COLUMNS = (
    ("raw_flows", "byte_count", None),
    ("traffic_windows", "packet_count", "0"),
    ("traffic_windows", "byte_count", "0"),
)


def upgrade() -> None:
    for table, column, default in COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.Integer(),
            type_=sa.BigInteger(),
            existing_nullable=False,
            existing_server_default=default,
        )


def downgrade() -> None:
    for table, column, default in COLUMNS:
        op.alter_column(
            table,
            column,
            existing_type=sa.BigInteger(),
            type_=sa.Integer(),
            existing_nullable=False,
            existing_server_default=default,
        )
