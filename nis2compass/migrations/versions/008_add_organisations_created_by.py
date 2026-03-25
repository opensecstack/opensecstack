"""Add created_by column to organisations table for ownership tracking

Revision ID: 008
Revises: 007
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa

revision = '008'
down_revision = '007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'organisations',
        sa.Column('created_by', sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('organisations', 'created_by')
