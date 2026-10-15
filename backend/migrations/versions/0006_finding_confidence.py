"""finding confidence

Revision ID: 0006
Revises: 0005
Create Date: 2026-10-12
"""
import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vulnerability_findings",
                  sa.Column("confidence", sa.String(length=8), nullable=False, server_default="high"))


def downgrade() -> None:
    op.drop_column("vulnerability_findings", "confidence")
