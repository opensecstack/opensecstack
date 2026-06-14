"""Add remediation workflow fields to controls table

Revision ID: 006
Revises: 005
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa

revision = '006'
down_revision = '005'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column('controls', sa.Column('remediation_owner',  sa.String(255), nullable=True))
    op.add_column('controls', sa.Column('remediation_status', sa.String(20),  nullable=True, server_default='not_started'))
    op.add_column('controls', sa.Column('external_ticket_url', sa.Text,       nullable=True))
    op.add_column('controls', sa.Column('remediation_notes',  sa.Text,        nullable=True))

    op.create_check_constraint(
        'ck_controls_external_ticket_url',
        'controls',
        "external_ticket_url IS NULL OR external_ticket_url LIKE 'http%'",
    )
    op.create_check_constraint(
        'ck_controls_remediation_status',
        'controls',
        "remediation_status IN ('not_started', 'in_progress', 'blocked', 'completed')",
    )


def downgrade() -> None:
    op.drop_constraint('ck_controls_external_ticket_url', 'controls', type_='check')
    op.drop_constraint('ck_controls_remediation_status',  'controls', type_='check')
    op.drop_column('controls', 'remediation_notes')
    op.drop_column('controls', 'external_ticket_url')
    op.drop_column('controls', 'remediation_status')
    op.drop_column('controls', 'remediation_owner')
