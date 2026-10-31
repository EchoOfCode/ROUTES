"""remediation_cancel_and_candidate

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-01 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('remediations', sa.Column('cancel_requested', sa.Boolean(), nullable=False,
                                             server_default=sa.false()))
    op.alter_column('remediations', 'cancel_requested', server_default=None)
    op.add_column('remediation_iterations', sa.Column('candidate_code', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('remediation_iterations', 'candidate_code')
    op.drop_column('remediations', 'cancel_requested')
