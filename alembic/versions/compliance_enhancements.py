"""compliance_enhancements

Revision ID: compliance_enhancements
Revises: bfc43d354022
Create Date: 2025-01-17 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'compliance_enhancements'
down_revision = 'bfc43d354022'
branch_labels = None
depends_on = None


def upgrade():
    # Add updated_at column to compliance_reports if it doesn't exist
    try:
        op.add_column('compliance_reports', sa.Column('updated_at', sa.DateTime(), nullable=True))
    except Exception:
        # Column might already exist
        pass
    
    # Add index on framework and status for better query performance
    try:
        op.create_index('ix_compliance_reports_framework_status', 'compliance_reports', ['framework', 'status'])
    except Exception:
        # Index might already exist
        pass
    
    # Add index on created_at for time-based queries
    try:
        op.create_index('ix_compliance_reports_created_at', 'compliance_reports', ['created_at'])
    except Exception:
        # Index might already exist
        pass


def downgrade():
    # Remove indexes
    try:
        op.drop_index('ix_compliance_reports_created_at', table_name='compliance_reports')
    except Exception:
        pass
    
    try:
        op.drop_index('ix_compliance_reports_framework_status', table_name='compliance_reports')
    except Exception:
        pass
    
    # Remove updated_at column
    try:
        op.drop_column('compliance_reports', 'updated_at')
    except Exception:
        pass