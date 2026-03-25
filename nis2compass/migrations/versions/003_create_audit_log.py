"""Create audit_log table with CITADEL WORM immutability

Revision ID: 003
Revises: 002
Create Date: 2026-03-25
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = '003'
down_revision = '002'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("CREATE TYPE audit_risk_class AS ENUM ('INFO', 'WARNING', 'CRITICAL')")

    op.create_table(
        'audit_log',
        sa.Column('id',                 postgresql.UUID(as_uuid=True), primary_key=True, server_default=sa.text('gen_random_uuid()')),
        sa.Column('action',             sa.String(100), nullable=False),
        sa.Column('actor',              sa.String(255), nullable=False),
        sa.Column('resource_type',      sa.String(100), nullable=False),
        sa.Column('resource_id',        postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('risk_class',         sa.Enum('INFO', 'WARNING', 'CRITICAL', name='audit_risk_class'), nullable=False, server_default='INFO'),
        sa.Column('metadata',           postgresql.JSONB, nullable=False, server_default='{}'),
        sa.Column('object_fingerprint', sa.CHAR(64),     nullable=True),
        sa.Column('prev_hash',          sa.CHAR(64),     nullable=True),
        sa.Column('chain_hash',         sa.CHAR(64),     nullable=False),
        sa.Column('timestamp',          sa.TIMESTAMP(timezone=True), nullable=False, server_default=sa.text('NOW()')),
    )
    op.create_index('idx_audit_log_actor',       'audit_log', ['actor'])
    op.create_index('idx_audit_log_action',      'audit_log', ['action'])
    op.create_index('idx_audit_log_resource_id', 'audit_log', ['resource_id'])
    op.create_index('idx_audit_log_timestamp',   'audit_log', ['timestamp'], postgresql_ops={'timestamp': 'DESC'})

    # CITADEL WORM immutability: block UPDATE and DELETE
    op.execute("""
        CREATE OR REPLACE FUNCTION audit_log_immutable()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit_log is immutable: % operations are not permitted', TG_OP;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql
    """)
    op.execute("""
        CREATE TRIGGER enforce_audit_log_immutability
            BEFORE UPDATE OR DELETE ON audit_log
            FOR EACH ROW
            EXECUTE FUNCTION audit_log_immutable()
    """)


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS enforce_audit_log_immutability ON audit_log")
    op.execute("DROP FUNCTION IF EXISTS audit_log_immutable()")
    op.drop_table('audit_log')
    op.execute("DROP TYPE IF EXISTS audit_risk_class")
