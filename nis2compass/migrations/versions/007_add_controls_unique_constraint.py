"""Add UNIQUE(assessment_id, measure_ref) constraint to controls table

Revision ID: 007
Revises: 006
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa

revision = '007'
down_revision = '006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_unique_constraint(
        'uq_controls_assessment_measure',
        'controls',
        ['assessment_id', 'measure_ref'],
    )


def downgrade() -> None:
    op.drop_constraint('uq_controls_assessment_measure', 'controls', type_='unique')
