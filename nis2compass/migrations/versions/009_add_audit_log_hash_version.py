"""Add hash_version column to audit_log to support chain-hash formula versioning

Revision ID: 009
Revises: 008
Create Date: 2026-03-26

Background
----------
The NIS2 chain-hash formula was updated to use '||' as a field delimiter
between the seven input fields (id, action, actor, resource_type, resource_id,
prev_hash, timestamp).  Rows written before that change used bare concatenation
with no delimiter (hash_version=1).  Rows written after this migration are
stamped hash_version=2 by the application.

Verification must therefore select the formula that matches each row's own
hash_version value rather than applying a single formula to the whole chain.

Migration strategy
------------------
* DEFAULT 1 is used so that every existing row is automatically marked as
  legacy (bare-concatenation) without touching the immutable chain_hash values.
  The WORM trigger forbids UPDATE/DELETE, so we cannot re-hash old rows, nor
  would it be correct to do so.
* New rows written by the application always carry hash_version=2 (set
  explicitly in audit.write_audit()).
"""
from alembic import op
import sqlalchemy as sa


revision = '009'
down_revision = '008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # DEFAULT 1: all pre-existing rows receive version 1 (legacy bare-concat formula).
    # New rows will be inserted with hash_version=2 explicitly set by the application.
    op.add_column(
        'audit_log',
        sa.Column('hash_version', sa.SmallInteger, nullable=False, server_default='1'),
    )


def downgrade() -> None:
    op.drop_column('audit_log', 'hash_version')
