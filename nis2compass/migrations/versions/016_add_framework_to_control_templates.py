"""Add framework column to control_templates for multi-framework support.

Revision ID: 016
Revises: 015
"""

from alembic import op
import sqlalchemy as sa

revision = '016'
down_revision = '015'


def upgrade():
    op.add_column(
        'control_templates',
        sa.Column('framework', sa.String(32), nullable=False, server_default='nis2'),
    )
    op.create_index('ix_control_templates_framework', 'control_templates', ['framework'])
    op.execute("UPDATE control_templates SET framework = 'nis2'")


def downgrade():
    op.drop_index('ix_control_templates_framework', table_name='control_templates')
    op.drop_column('control_templates', 'framework')
