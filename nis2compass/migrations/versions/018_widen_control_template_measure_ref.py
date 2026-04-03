"""Widen control_templates.measure_ref from CHAR(1) to VARCHAR(20) and change
the unique constraint from (measure_ref) to (measure_ref, framework) so that
SOC 2 and ISO 27001 references (e.g. CC1.1, A.5.1) can coexist alongside the
single-character NIS2 measure refs.

Revision ID: 018
Revises: 017
"""

from alembic import op
import sqlalchemy as sa

revision = '018'
down_revision = '017'


def upgrade():
    # Drop old single-column unique constraint and index
    op.drop_index('idx_control_templates_measure_ref', table_name='control_templates')
    op.drop_constraint('control_templates_measure_ref_key', 'control_templates', type_='unique')

    # Widen the column
    op.alter_column(
        'control_templates',
        'measure_ref',
        existing_type=sa.CHAR(1),
        type_=sa.String(20),
        nullable=False,
    )

    # Add composite unique constraint and index
    op.create_unique_constraint(
        'uq_control_templates_measure_ref_framework',
        'control_templates',
        ['measure_ref', 'framework'],
    )
    op.create_index(
        'idx_control_templates_measure_ref',
        'control_templates',
        ['measure_ref'],
    )


def downgrade():
    op.drop_index('idx_control_templates_measure_ref', table_name='control_templates')
    op.drop_constraint(
        'uq_control_templates_measure_ref_framework',
        'control_templates',
        type_='unique',
    )

    op.alter_column(
        'control_templates',
        'measure_ref',
        existing_type=sa.String(20),
        type_=sa.CHAR(1),
        nullable=False,
    )

    op.create_unique_constraint(
        'control_templates_measure_ref_key',
        'control_templates',
        ['measure_ref'],
    )
    op.create_index(
        'idx_control_templates_measure_ref',
        'control_templates',
        ['measure_ref'],
    )
