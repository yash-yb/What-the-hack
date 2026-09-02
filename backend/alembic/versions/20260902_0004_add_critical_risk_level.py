"""Add the critical risk level (feature schema contract v1).

Revision ID: 20260902_0004
Revises: 20260831_0003
Create Date: 2026-09-02
"""

import sqlalchemy as sa
from alembic import op

revision = "20260902_0004"
down_revision = "20260831_0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # risk_level is a non-native enum stored as VARCHAR sized to the longest value.
    op.alter_column(
        "predictions",
        "risk_level",
        existing_type=sa.String(length=6),
        type_=sa.String(length=8),
        existing_nullable=False,
    )


def downgrade() -> None:
    op.execute("UPDATE predictions SET risk_level = 'high' WHERE risk_level = 'critical'")
    op.alter_column(
        "predictions",
        "risk_level",
        existing_type=sa.String(length=8),
        type_=sa.String(length=6),
        existing_nullable=False,
    )
