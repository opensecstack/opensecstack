"""Add role column to api_keys

Revision ID: 019
Revises: 018
Create Date: 2026-05-24

The ApiKey model (app/models.py) declares a `role` column, but no migration
ever added it, leaving the model and schema out of sync — listing API keys
failed with "column api_keys.role does not exist". This backfills the column
to match the model: VARCHAR(20) NOT NULL DEFAULT 'assessor'
(roles: admin | assessor | auditor | viewer).
"""
from alembic import op
import sqlalchemy as sa

revision = '019'
down_revision = '018'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'api_keys',
        sa.Column('role', sa.String(20), nullable=False, server_default='assessor'),
    )


def downgrade() -> None:
    op.drop_column('api_keys', 'role')
