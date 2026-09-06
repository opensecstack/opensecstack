"""Add incidents and incident_reports tables (NIS2 Article 23 timer subsystem)

Revision ID: 021
Revises: 020
Create Date: 2026-09-05

Introduces the data model backing EU NIS2 Directive Article 23 incident
reporting: `incidents` (one row per tracked security incident, keyed to
an organisation) and `incident_reports` (one row per Article 23 reporting
obligation — early_warning / notification / final_report — per incident,
recording whether/when it was submitted). Deadlines are deliberately NOT
stored as columns; they are computed from `incidents.detected_at` (and
`resolved_at`) at read time — see app/incident_timers.py and the model
docstrings in app/models.py for the full rationale.
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '021'
down_revision = '020'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE TYPE incident_severity AS ENUM ('low', 'medium', 'high', 'critical')")
    op.execute("CREATE TYPE incident_status AS ENUM ('active', 'contained', 'resolved')")
    op.execute("CREATE TYPE incident_report_type AS ENUM ('early_warning', 'notification', 'final_report')")

    op.create_table(
        'incidents',
        sa.Column('id',            postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('org_id',        postgresql.UUID(as_uuid=True), sa.ForeignKey('organisations.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title',         sa.String(255), nullable=False),
        sa.Column('description',  sa.Text,        nullable=True),
        sa.Column('detected_at',   sa.TIMESTAMP(timezone=True), nullable=False),
        sa.Column('severity',      postgresql.ENUM('low', 'medium', 'high', 'critical', name='incident_severity', create_type=False), nullable=False, server_default='medium'),
        sa.Column('status',        postgresql.ENUM('active', 'contained', 'resolved', name='incident_status', create_type=False), nullable=False, server_default='active'),
        sa.Column('resolved_at',   sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('significant',   sa.Boolean, nullable=False, server_default=sa.text('false')),
        sa.Column('created_by',    sa.String(255), nullable=True),
        sa.Column('created_at',    sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.Column('updated_at',    sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_incidents_org_id', 'incidents', ['org_id'])
    op.create_index('idx_incidents_status', 'incidents', ['status'])
    op.create_index('idx_incidents_significant', 'incidents', ['significant'])
    op.execute("CREATE TRIGGER trg_incidents_updated_at BEFORE UPDATE ON incidents FOR EACH ROW EXECUTE FUNCTION set_updated_at()")

    op.create_table(
        'incident_reports',
        sa.Column('id',            postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('incident_id',   postgresql.UUID(as_uuid=True), sa.ForeignKey('incidents.id', ondelete='CASCADE'), nullable=False),
        sa.Column('report_type',   postgresql.ENUM('early_warning', 'notification', 'final_report', name='incident_report_type', create_type=False), nullable=False),
        sa.Column('submitted_at',  sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column('submitted_by',  sa.String(255), nullable=True),
        sa.Column('content',       sa.Text, nullable=True),
        sa.Column('created_at',    sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
        sa.UniqueConstraint('incident_id', 'report_type', name='uq_incident_reports_incident_report_type'),
    )
    op.create_index('idx_incident_reports_incident_id', 'incident_reports', ['incident_id'])
    op.create_index('idx_incident_reports_report_type', 'incident_reports', ['report_type'])


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_incidents_updated_at ON incidents")
    op.drop_table('incident_reports')
    op.drop_table('incidents')
    op.execute("DROP TYPE IF EXISTS incident_report_type")
    op.execute("DROP TYPE IF EXISTS incident_status")
    op.execute("DROP TYPE IF EXISTS incident_severity")
