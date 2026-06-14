"""Add framework column to assessments for multi-framework support.

Revision ID: 017
Revises: 016
"""

from alembic import op
import sqlalchemy as sa

revision = '017'
down_revision = '016'


def upgrade():
    op.add_column(
        'assessments',
        sa.Column('framework', sa.String(32), nullable=False, server_default='nis2'),
    )
    op.execute("UPDATE assessments SET framework = 'nis2'")


def downgrade():
    op.drop_column('assessments', 'framework')
