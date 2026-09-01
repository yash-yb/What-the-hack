"""Prevent duplicate traffic windows on repeat builds.

Revision ID: 20260831_0003
Revises: 20260830_0002
Create Date: 2026-08-31
"""

from alembic import op

revision = "20260831_0003"
down_revision = "20260830_0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        "uq_traffic_windows_source_scope_range",
        "traffic_windows",
        ["traffic_source_id", "scope_type", "scope_key", "window_start", "window_end"],
    )


def downgrade() -> None:
    op.drop_constraint("uq_traffic_windows_source_scope_range", "traffic_windows", type_="unique")
