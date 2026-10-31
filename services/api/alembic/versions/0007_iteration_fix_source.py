"""iteration_fix_source

Records where a round's candidate fix came from: the deterministic
known-bad -> known-good table (worker.fix_table) or LLM B. Additive only.

Revision ID: 0007
Revises: 0006
Create Date: 2026-11-01 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('remediation_iterations', sa.Column('fix_source', sa.String(length=64), nullable=True))
    op.add_column('remediation_iterations', sa.Column('fix_note', sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column('remediation_iterations', 'fix_note')
    op.drop_column('remediation_iterations', 'fix_source')
