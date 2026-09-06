"""Add CITADEL compliance evidence tracking columns to assessments

Revision ID: 022
Revises: 021
Create Date: 2026-09-05

Adds citadel_evidence_id and citadel_evidence_submitted_at to assessments,
matching the Assessment model (app/models.py) columns added alongside the
new NIS2 Compass -> CITADEL Compliance Evidence push pipeline
(app/citadel_client.py's submit_compliance_evidence, wired into
app/api/assessments.py's generate_report). Both columns are nullable:
submission is best-effort (see submit_compliance_evidence's docstring), so
an assessment may legitimately have no evidence reference yet.

Renumbered from its original 021 to 022 (and down_revision retargeted from
020 to 021) when merging with the concurrently-developed Article 23
incident-timer migration, which also claimed 021 off the same 020 parent —
see docs/v1.0.0-readiness-roadmap.md Phase 5 for both.
"""
from alembic import op
import sqlalchemy as sa

revision = '022'
down_revision = '021'
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
