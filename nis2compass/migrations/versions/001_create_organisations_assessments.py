"""Create organisations and assessments tables

Revision ID: 001
Revises:
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Extensions
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ENUM types
    op.execute("CREATE TYPE org_size AS ENUM ('micro', 'small', 'medium', 'large')")
    op.execute("CREATE TYPE entity_type AS ENUM ('essential', 'important')")
    op.execute("CREATE TYPE assessment_status AS ENUM ('draft', 'in_progress', 'under_review', 'completed', 'archived')")

    # organisations
    op.create_table(
        'organisations',
        sa.Column('id',                  postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('name',                sa.String(255), nullable=False),
        sa.Column('industry',            sa.String(100), nullable=False),
        sa.Column('country',             sa.CHAR(2),     nullable=False),
        sa.Column('size',                postgresql.ENUM('micro', 'small', 'medium', 'large', name='org_size', create_type=False), nullable=False, server_default='medium'),
        sa.Column('entity_type',         postgresql.ENUM('essential', 'important', name='entity_type', create_type=False), nullable=False, server_default='important'),
        sa.Column('registration_number', sa.String(100), nullable=True),
        sa.Column('contact_email',       sa.String(255), nullable=True),
        sa.Column('created_at',          sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at',          sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_organisations_country',  'organisations', ['country'])
    op.create_index('idx_organisations_industry', 'organisations', ['industry'])

    # assessments
    op.create_table(
        'assessments',
        sa.Column('id',                postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id',            postgresql.UUID(as_uuid=True), sa.ForeignKey('organisations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title',             sa.String(255), nullable=False),
        sa.Column('status',            postgresql.ENUM('draft', 'in_progress', 'under_review', 'completed', 'archived', name='assessment_status', create_type=False), nullable=False, server_default='draft'),
        sa.Column('framework_version', sa.String(20),  nullable=False, server_default='NIS2-2022/0383'),
        sa.Column('scope',             sa.Text,        nullable=True),
        sa.Column('assessor',          sa.String(255), nullable=True),
        sa.Column('due_date',          sa.Date,        nullable=True),
        sa.Column('completed_at',      sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('created_at',        sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at',        sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_assessments_org_id', 'assessments', ['org_id'])
    op.create_index('idx_assessments_status', 'assessments', ['status'])

    # updated_at trigger function
    op.execute("""
        CREATE OR REPLACE FUNCTION set_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = NOW();
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql
    """)
    op.execute("CREATE TRIGGER trg_organisations_updated_at BEFORE UPDATE ON organisations FOR EACH ROW EXECUTE FUNCTION set_updated_at()")
    op.execute("CREATE TRIGGER trg_assessments_updated_at   BEFORE UPDATE ON assessments   FOR EACH ROW EXECUTE FUNCTION set_updated_at()")


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_assessments_updated_at   ON assessments")
    op.execute("DROP TRIGGER IF EXISTS trg_organisations_updated_at ON organisations")
    op.execute("DROP FUNCTION IF EXISTS set_updated_at()")
    op.drop_table('assessments')
    op.drop_table('organisations')
    op.execute("DROP TYPE IF EXISTS assessment_status")
    op.execute("DROP TYPE IF EXISTS entity_type")
    op.execute("DROP TYPE IF EXISTS org_size")
