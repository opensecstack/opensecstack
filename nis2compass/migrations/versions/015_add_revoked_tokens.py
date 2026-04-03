"""Add revoked_tokens table for JWT revocation fallback when Redis is unavailable.

Revision ID: 015
Revises: 014
"""

from alembic import op
import sqlalchemy as sa

revision = '015'
down_revision = '014'


def upgrade():
    op.create_table(
        'revoked_tokens',
        sa.Column('jti', sa.String(36), primary_key=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index('ix_revoked_tokens_expires_at', 'revoked_tokens', ['expires_at'])


def downgrade():
    op.drop_index('ix_revoked_tokens_expires_at', table_name='revoked_tokens')
    op.drop_table('revoked_tokens')
