"""Create control_templates table

Revision ID: 005
Revises: 004
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa

revision = '005'
down_revision = '004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        'control_templates',
        sa.Column('id',            sa.Integer,     primary_key=True, autoincrement=True),
        sa.Column('measure_ref',   sa.CHAR(1),     nullable=False, unique=True),
        sa.Column('article_ref',   sa.String(20),  nullable=False),
        sa.Column('title',         sa.String(255), nullable=False),
        sa.Column('description',   sa.Text,        nullable=False),
        sa.Column('nist_category', sa.String(20),  nullable=False),
        sa.Column('guidance',      sa.Text,        nullable=True),
    )
    op.create_index('idx_control_templates_measure_ref', 'control_templates', ['measure_ref'])


def downgrade() -> None:
    op.drop_table('control_templates')
