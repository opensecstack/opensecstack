"""Add expires_at to api_keys table

Revision ID: 010
Revises: 009
Create Date: 2026-03-26
"""
from alembic import op
import sqlalchemy as sa

revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'api_keys',
        sa.Column('expires_at', sa.TIMESTAMP(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('api_keys', 'expires_at')
