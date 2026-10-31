"""finding_end_line

Revision ID: 0003
Revises: 0002
Create Date: 2026-10-31 21:30:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('security_findings', sa.Column('end_line', sa.Integer(), nullable=True))


def downgrade() -> None:
    op.drop_column('security_findings', 'end_line')
