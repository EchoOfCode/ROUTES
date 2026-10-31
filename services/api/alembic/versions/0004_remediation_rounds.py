"""remediation_rounds

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-01 10:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('remediations', sa.Column('finding_status', sa.String(length=32), nullable=False,
                                             server_default='open'))
    op.alter_column('remediations', 'finding_status', server_default=None)
    op.add_column('remediation_iterations', sa.Column('round_no', sa.Integer(), nullable=True))
    op.add_column('remediation_iterations', sa.Column('batch_id', sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column('remediation_iterations', 'batch_id')
    op.drop_column('remediation_iterations', 'round_no')
    op.drop_column('remediations', 'finding_status')
