"""Add compliance features: scoring, approval, locking, proof signatures, gap analysis.

Revision ID: 013
Revises: 012
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = '013'
down_revision = '012'


def upgrade():
    # ── Assessment: approval workflow + locking + scoring ──────────────
    op.add_column('assessments', sa.Column('compliance_score', sa.Numeric(5, 2), nullable=True))
    op.add_column('assessments', sa.Column('approval_state', sa.String(20), nullable=True, server_default='none'))
    op.add_column('assessments', sa.Column('approved_by', sa.String(255), nullable=True))
    op.add_column('assessments', sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('assessments', sa.Column('approval_notes', sa.Text, nullable=True))
    op.add_column('assessments', sa.Column('locked', sa.Boolean, nullable=False, server_default='false'))
    op.add_column('assessments', sa.Column('locked_by', sa.String(255), nullable=True))
    op.add_column('assessments', sa.Column('locked_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('assessments', sa.Column('lock_reason', sa.String(500), nullable=True))
    op.add_column('assessments', sa.Column('gap_report', JSONB, nullable=True))
    op.add_column('assessments', sa.Column('gap_generated_at', sa.DateTime(timezone=True), nullable=True))

    # ── Artifact: digital proof signatures ────────────────────────────
    op.add_column('artifacts', sa.Column('signature', sa.String(128), nullable=True))
    op.add_column('artifacts', sa.Column('signed_by', sa.String(255), nullable=True))
    op.add_column('artifacts', sa.Column('signed_at', sa.DateTime(timezone=True), nullable=True))


def downgrade():
    op.drop_column('artifacts', 'signed_at')
    op.drop_column('artifacts', 'signed_by')
    op.drop_column('artifacts', 'signature')

    op.drop_column('assessments', 'gap_generated_at')
    op.drop_column('assessments', 'gap_report')
    op.drop_column('assessments', 'lock_reason')
    op.drop_column('assessments', 'locked_at')
    op.drop_column('assessments', 'locked_by')
    op.drop_column('assessments', 'locked')
    op.drop_column('assessments', 'approval_notes')
    op.drop_column('assessments', 'approved_at')
    op.drop_column('assessments', 'approved_by')
    op.drop_column('assessments', 'approval_state')
    op.drop_column('assessments', 'compliance_score')
