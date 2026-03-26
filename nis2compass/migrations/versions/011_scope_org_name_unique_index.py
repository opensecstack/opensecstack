"""Scope organisations name unique index to (name, created_by)

Revision ID: 011
Revises: 010
Create Date: 2026-03-26

Previously the unique index on organisations.name was global, which meant two
different actors could not create organisations with the same name even though
they belong to completely separate tenants.  Scoping the index to
(name, created_by) enforces uniqueness per actor while allowing different
actors to reuse the same organisation name.
"""
from alembic import op

revision = '011'
down_revision = '010'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_index('idx_organisations_name', table_name='organisations')
    op.create_index(
        'idx_organisations_name',
        'organisations',
        ['name', 'created_by'],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index('idx_organisations_name', table_name='organisations')
    op.create_index(
        'idx_organisations_name',
        'organisations',
        ['name'],
        unique=True,
    )
