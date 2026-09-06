"""Add CITADEL compliance evidence tracking columns to assessments

Revision ID: 021
Revises: 020
Create Date: 2026-09-05

Adds citadel_evidence_id and citadel_evidence_submitted_at to assessments,
matching the Assessment model (app/models.py) columns added alongside the
new NIS2 Compass -> CITADEL Compliance Evidence push pipeline
(app/citadel_client.py's submit_compliance_evidence, wired into
app/api/assessments.py's generate_report). Both columns are nullable:
submission is best-effort (see submit_compliance_evidence's docstring), so
an assessment may legitimately have no evidence reference yet.
"""
from alembic import op
import sqlalchemy as sa

revision = '021'
down_revision = '020'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'assessments',
        sa.Column('citadel_evidence_id', sa.String(64), nullable=True),
    )
    op.add_column(
        'assessments',
        sa.Column('citadel_evidence_submitted_at', sa.DateTime(timezone=True), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('assessments', 'citadel_evidence_submitted_at')
    op.drop_column('assessments', 'citadel_evidence_id')
