"""Add seq BIGSERIAL column to audit_log for deterministic chain ordering

Revision ID: 012
Revises: 011
Create Date: 2026-03-26
"""
from alembic import op
import sqlalchemy as sa

revision = '012'
down_revision = '011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Add a BIGSERIAL column as a monotonically increasing sequence number.
    # BIGSERIAL is syntactic sugar for BIGINT + a sequence with server_default;
    # we spell it out explicitly so Alembic can manage it cleanly.
    op.execute("CREATE SEQUENCE IF NOT EXISTS audit_log_seq_seq")
    op.add_column(
        'audit_log',
        sa.Column(
            'seq',
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("nextval('audit_log_seq_seq')"),
        ),
    )
    op.execute("ALTER SEQUENCE audit_log_seq_seq OWNED BY audit_log.seq")
    op.create_index('idx_audit_log_seq', 'audit_log', ['seq'])


def downgrade() -> None:
    op.drop_index('idx_audit_log_seq', table_name='audit_log')
    op.drop_column('audit_log', 'seq')
    # The sequence is dropped automatically because it is OWNED BY the column,
    # but we drop it explicitly in case the ownership link was not set.
    op.execute("DROP SEQUENCE IF EXISTS audit_log_seq_seq")
