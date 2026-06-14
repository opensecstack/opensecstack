"""Create controls and artifacts tables

Revision ID: 002
Revises: 001
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '002'
down_revision = '001'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE TYPE control_status AS ENUM ('not_assessed', 'compliant', 'partially_compliant', 'non_compliant', 'not_applicable')")
    op.execute("CREATE TYPE artifact_type  AS ENUM ('policy', 'procedure', 'evidence', 'report', 'screenshot', 'log', 'certificate', 'contract')")
    op.execute("CREATE TYPE nist_category  AS ENUM ('identify', 'protect', 'detect', 'respond', 'recover')")

    # controls
    op.create_table(
        'controls',
        sa.Column('id',               postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('assessment_id',    postgresql.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('article_ref',      sa.String(20),  nullable=False),
        sa.Column('measure_ref',      sa.CHAR(1),     nullable=False),
        sa.Column('nist_category',    postgresql.ENUM('identify', 'protect', 'detect', 'respond', 'recover', name='nist_category', create_type=False), nullable=False),
        sa.Column('title',            sa.String(255), nullable=False),
        sa.Column('description',      sa.Text,        nullable=True),
        sa.Column('status',           postgresql.ENUM('not_assessed', 'compliant', 'partially_compliant', 'non_compliant', 'not_applicable', name='control_status', create_type=False), nullable=False, server_default='not_assessed'),
        sa.Column('evidence',         postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('gap_description',  sa.Text,        nullable=True),
        sa.Column('remediation_plan', sa.Text,        nullable=True),
        sa.Column('remediation_due',  sa.Date,        nullable=True),
        sa.Column('risk_score',       sa.Numeric(3,1), nullable=True),
        sa.Column('notes',            sa.Text,        nullable=True),
        sa.Column('assessed_by',      sa.String(255), nullable=True),
        sa.Column('assessed_at',      sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('created_at',       sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at',       sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.CheckConstraint("measure_ref IN ('a','b','c','d','e','f','g','h','i','j')", name='ck_controls_measure_ref'),
        sa.CheckConstraint("risk_score >= 0.0 AND risk_score <= 10.0", name='ck_controls_risk_score'),
    )
    op.create_index('idx_controls_assessment_id', 'controls', ['assessment_id'])
    op.create_index('idx_controls_status',        'controls', ['status'])
    op.create_index('idx_controls_measure_ref',   'controls', ['measure_ref'])
    op.create_index('idx_controls_nist_category', 'controls', ['nist_category'])
    op.execute("CREATE TRIGGER trg_controls_updated_at BEFORE UPDATE ON controls FOR EACH ROW EXECUTE FUNCTION set_updated_at()")

    # artifacts
    op.create_table(
        'artifacts',
        sa.Column('id',            postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('assessment_id', postgresql.UUID(as_uuid=True), sa.ForeignKey('assessments.id', ondelete='CASCADE'), nullable=False),
        sa.Column('control_id',    postgresql.UUID(as_uuid=True), sa.ForeignKey('controls.id',    ondelete='SET NULL'), nullable=True),
        sa.Column('type',          postgresql.ENUM('policy', 'procedure', 'evidence', 'report', 'screenshot', 'log', 'certificate', 'contract', name='artifact_type', create_type=False), nullable=False),
        sa.Column('filename',      sa.String(255),  nullable=False),
        sa.Column('file_path',     sa.String(1024), nullable=False),
        sa.Column('hash',          sa.CHAR(64),     nullable=False),
        sa.Column('size_bytes',    sa.BigInteger,   nullable=True),
        sa.Column('mime_type',     sa.String(100),  nullable=True),
        sa.Column('description',   sa.Text,         nullable=True),
        sa.Column('created_by',    sa.String(255),  nullable=False),
        sa.Column('created_at',    sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_artifacts_assessment_id', 'artifacts', ['assessment_id'])
    op.create_index('idx_artifacts_control_id',    'artifacts', ['control_id'])
    op.create_index('idx_artifacts_hash',          'artifacts', ['hash'])


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_controls_updated_at ON controls")
    op.drop_table('artifacts')
    op.drop_table('controls')
    op.execute("DROP TYPE IF EXISTS nist_category")
    op.execute("DROP TYPE IF EXISTS artifact_type")
    op.execute("DROP TYPE IF EXISTS control_status")
