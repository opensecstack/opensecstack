"""Add compliance_snapshots table for compliance score history.

Revision ID: 014
Revises: 013
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

revision = '014'
down_revision = '013'


def upgrade():
    op.create_table(
        'compliance_snapshots',
        sa.Column('id', UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('assessment_id', UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('score', sa.Float, nullable=True),
        sa.Column('total_controls', sa.Integer, nullable=False),
        sa.Column('compliant_controls', sa.Integer, nullable=False),
        sa.Column('partially_compliant_controls', sa.Integer, nullable=False),
        sa.Column('non_compliant_controls', sa.Integer, nullable=False),
        sa.Column('snapshot_at', sa.DateTime, nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('ix_compliance_snapshots_assessment_id', 'compliance_snapshots', ['assessment_id'])


def downgrade():
    op.drop_index('ix_compliance_snapshots_assessment_id', table_name='compliance_snapshots')
    op.drop_table('compliance_snapshots')
