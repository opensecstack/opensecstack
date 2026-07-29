"""Add created_by column to assessments

Revision ID: 020
Revises: 019
Create Date: 2026-07-26

The Assessment model (app/models.py) declares a `created_by` column
(String(255), nullable) and app/api/assessments.py sets it on every create
(`created_by=g.actor`), but no migration ever added it to the `assessments`
table — the same class of model/migration drift fixed for api_keys.role in
019. This broke every assessment creation with
"column assessments.created_by does not exist". Backfills the column to
match the model.
"""
from alembic import op
import sqlalchemy as sa

revision = '020'
down_revision = '019'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        'assessments',
        sa.Column('created_by', sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_column('assessments', 'created_by')
