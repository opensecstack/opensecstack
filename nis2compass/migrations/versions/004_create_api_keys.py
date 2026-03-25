"""Create api_keys table

Revision ID: 004
Revises: 003
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '004'
down_revision = '003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'api_keys',
        sa.Column('id',           postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('key_hash',     sa.String(64),  nullable=False, unique=True),  # SHA-256 hex of plaintext key
        sa.Column('label',        sa.String(100), nullable=True),
        sa.Column('scope',        sa.String(20),  nullable=False, server_default='read_write'),
        sa.Column('is_active',    sa.Boolean,     nullable=False, server_default=sa.text('true')),
        sa.Column('created_by',   sa.String(255), nullable=True),
        sa.Column('created_at',   sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('last_used_at', sa.TIMESTAMP(timezone=True), nullable=True),
        sa.CheckConstraint("scope IN ('read', 'read_write')", name='ck_api_keys_scope'),
    )
    op.create_index('idx_api_keys_key_hash',  'api_keys', ['key_hash'])
    op.create_index('idx_api_keys_is_active', 'api_keys', ['is_active'])


def downgrade() -> None:
    op.drop_table('api_keys')
