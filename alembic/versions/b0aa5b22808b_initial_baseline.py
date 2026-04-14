"""Initial baseline
Revision ID: b0aa5b22808b
Revises: 
Create Date: 2026-04-12 22:52:55.457810
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'b0aa5b22808b'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # Check for existing tables to allow safe execution on pre-existing databases
    conn = op.get_bind()
    inspector = sa.inspect(conn)
    existing_tables = inspector.get_table_names()

    if 'alerts' not in existing_tables:
        op.create_table('alerts',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=64), nullable=False),
    sa.Column('company_id', sa.String(length=100), nullable=True),
    sa.Column('device_id', sa.String(length=100), nullable=True),
    sa.Column('alert_type', sa.String(length=64), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('source_ip', sa.String(length=45), nullable=True),
    sa.Column('destination_ip', sa.String(length=45), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('details', sa.JSON(), nullable=True),
    sa.Column('status', sa.String(length=32), nullable=True),
    sa.Column('notified', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('resolved_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
        op.create_index('idx_alerts_source_ip', 'alerts', ['source_ip', 'created_at'], unique=False)
        op.create_index('idx_alerts_tenant_severity', 'alerts', ['tenant_id', 'severity', 'created_at'], unique=False)
        op.create_index('idx_alerts_tenant_status', 'alerts', ['tenant_id', 'status', 'created_at'], unique=False)
        op.create_index(op.f('ix_alerts_alert_type'), 'alerts', ['alert_type'], unique=False)
        op.create_index(op.f('ix_alerts_company_id'), 'alerts', ['company_id'], unique=False)
        op.create_index(op.f('ix_alerts_created_at'), 'alerts', ['created_at'], unique=False)
        op.create_index(op.f('ix_alerts_device_id'), 'alerts', ['device_id'], unique=False)
        op.create_index(op.f('ix_alerts_severity'), 'alerts', ['severity'], unique=False)
        op.create_index(op.f('ix_alerts_source_ip'), 'alerts', ['source_ip'], unique=False)
        op.create_index(op.f('ix_alerts_status'), 'alerts', ['status'], unique=False)
        op.create_index(op.f('ix_alerts_tenant_id'), 'alerts', ['tenant_id'], unique=False)

    if 'dead_letters' not in existing_tables:
        op.create_table('dead_letters',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=64), nullable=True),
    sa.Column('received_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('source_queue', sa.String(length=64), nullable=True),
    sa.Column('error_type', sa.String(length=64), nullable=True),
    sa.Column('error_message', sa.Text(), nullable=True),
    sa.Column('raw_payload', sa.JSON(), nullable=False),
    sa.Column('retry_count', sa.Integer(), nullable=True),
    sa.Column('last_retry_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
        op.create_index('idx_dead_letters_error_type', 'dead_letters', ['error_type', 'received_at'], unique=False)
        op.create_index('idx_dead_letters_tenant_received', 'dead_letters', ['tenant_id', 'received_at'], unique=False)
        op.create_index(op.f('ix_dead_letters_received_at'), 'dead_letters', ['received_at'], unique=False)
        op.create_index(op.f('ix_dead_letters_tenant_id'), 'dead_letters', ['tenant_id'], unique=False)
    if 'logs' not in existing_tables:
        op.create_table('logs',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=True),
    sa.Column('tenant_id', sa.String(length=64), nullable=False),
    sa.Column('company_id', sa.String(length=100), nullable=True),
    sa.Column('device_id', sa.String(length=100), nullable=True),
    sa.Column('source_ip', sa.String(length=45), nullable=True),
    sa.Column('destination_ip', sa.String(length=45), nullable=True),
    sa.Column('source_port', sa.Integer(), nullable=True),
    sa.Column('destination_port', sa.Integer(), nullable=True),
    sa.Column('protocol', sa.String(length=16), nullable=True),
    sa.Column('action', sa.String(length=32), nullable=True),
    sa.Column('log_type', sa.String(length=64), nullable=True),
    sa.Column('vendor', sa.String(length=64), nullable=True),
    sa.Column('device_hostname', sa.String(length=128), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('message', sa.Text(), nullable=True),
    sa.Column('raw_data', sa.JSON(), nullable=True),
    sa.Column('business_context', sa.JSON(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
        op.create_index('idx_logs_dest_ip_timestamp', 'logs', ['destination_ip', 'timestamp'], unique=False)
        op.create_index('idx_logs_source_ip_timestamp', 'logs', ['source_ip', 'timestamp'], unique=False)
        op.create_index('idx_logs_tenant_severity', 'logs', ['tenant_id', 'severity', 'timestamp'], unique=False)
        op.create_index('idx_logs_tenant_timestamp', 'logs', ['tenant_id', 'timestamp'], unique=False)
        op.create_index('idx_logs_type_tenant', 'logs', ['log_type', 'tenant_id'], unique=False)
        op.create_index(op.f('ix_logs_company_id'), 'logs', ['company_id'], unique=False)
        op.create_index(op.f('ix_logs_destination_ip'), 'logs', ['destination_ip'], unique=False)
        op.create_index(op.f('ix_logs_device_hostname'), 'logs', ['device_hostname'], unique=False)
        op.create_index(op.f('ix_logs_device_id'), 'logs', ['device_id'], unique=False)
        op.create_index(op.f('ix_logs_log_type'), 'logs', ['log_type'], unique=False)
        op.create_index(op.f('ix_logs_severity'), 'logs', ['severity'], unique=False)
        op.create_index(op.f('ix_logs_source_ip'), 'logs', ['source_ip'], unique=False)
        op.create_index(op.f('ix_logs_tenant_id'), 'logs', ['tenant_id'], unique=False)
        op.create_index(op.f('ix_logs_timestamp'), 'logs', ['timestamp'], unique=False)
        op.create_index(op.f('ix_logs_vendor'), 'logs', ['vendor'], unique=False)
    if 'managed_devices' not in existing_tables:
        op.create_table('managed_devices',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('ip_address', sa.String(length=45), nullable=False),
    sa.Column('device_id', sa.String(length=100), nullable=True),
    sa.Column('category', sa.String(length=32), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_log_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
        op.create_index('idx_managed_dev_tenant_id_corr', 'managed_devices', ['tenant_id', 'device_id'], unique=False)
        op.create_index('idx_managed_dev_tenant_ip', 'managed_devices', ['tenant_id', 'ip_address'], unique=False)
        op.create_index(op.f('ix_managed_devices_device_id'), 'managed_devices', ['device_id'], unique=False)
        op.create_index(op.f('ix_managed_devices_ip_address'), 'managed_devices', ['ip_address'], unique=False)
        op.create_index(op.f('ix_managed_devices_tenant_id'), 'managed_devices', ['tenant_id'], unique=False)
    if 'reports' not in existing_tables:
        op.create_table('reports',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=64), nullable=True),
    sa.Column('report_type', sa.String(length=32), nullable=False),
    sa.Column('start_date', sa.DateTime(timezone=True), nullable=False),
    sa.Column('end_date', sa.DateTime(timezone=True), nullable=False),
    sa.Column('total_logs', sa.Integer(), nullable=True),
    sa.Column('total_alerts', sa.Integer(), nullable=True),
    sa.Column('alerts_by_severity', sa.JSON(), nullable=True),
    sa.Column('top_source_ips', sa.JSON(), nullable=True),
    sa.Column('top_alert_types', sa.JSON(), nullable=True),
    sa.Column('file_path', sa.String(length=256), nullable=True),
    sa.Column('summary', sa.JSON(), nullable=True),
    sa.Column('format', sa.String(length=20), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
        op.create_index(op.f('ix_reports_created_at'), 'reports', ['created_at'], unique=False)
        op.create_index(op.f('ix_reports_tenant_id'), 'reports', ['tenant_id'], unique=False)
    if 'tenants' not in existing_tables:
        op.create_table('tenants',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=64), nullable=False),
    sa.Column('name', sa.String(length=128), nullable=False),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('settings', sa.JSON(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
        op.create_index(op.f('ix_tenants_is_active'), 'tenants', ['is_active'], unique=False)
        op.create_index(op.f('ix_tenants_tenant_id'), 'tenants', ['tenant_id'], unique=True)
    if 'threat_intelligence' not in existing_tables:
        op.create_table('threat_intelligence',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('indicator_type', sa.String(length=32), nullable=False),
    sa.Column('indicator_value', sa.String(length=256), nullable=False),
    sa.Column('threat_type', sa.String(length=64), nullable=True),
    sa.Column('confidence', sa.Float(), nullable=True),
    sa.Column('source', sa.String(length=128), nullable=True),
    sa.Column('description', sa.Text(), nullable=True),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
        op.create_index('idx_threat_intel_active', 'threat_intelligence', ['indicator_type', 'indicator_value', 'is_active'], unique=False)
        op.create_index(op.f('ix_threat_intelligence_indicator_type'), 'threat_intelligence', ['indicator_type'], unique=False)
        op.create_index(op.f('ix_threat_intelligence_indicator_value'), 'threat_intelligence', ['indicator_value'], unique=True)
        op.create_index(op.f('ix_threat_intelligence_is_active'), 'threat_intelligence', ['is_active'], unique=False)
    if 'users' not in existing_tables:
        op.create_table('users',
    sa.Column('id', sa.BigInteger().with_variant(sa.Integer(), 'sqlite'), autoincrement=True, nullable=False),
    sa.Column('tenant_id', sa.String(length=64), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=128), nullable=True),
    sa.Column('password_hash', sa.String(length=256), nullable=False),
    sa.Column('role', sa.String(length=32), nullable=True),
    sa.Column('is_superadmin', sa.Boolean(), nullable=True),
    sa.Column('functionalities', sa.JSON(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email')
    )
        op.create_index(op.f('ix_users_is_superadmin'), 'users', ['is_superadmin'], unique=False)
        op.create_index(op.f('ix_users_role'), 'users', ['role'], unique=False)
        op.create_index(op.f('ix_users_tenant_id'), 'users', ['tenant_id'], unique=False)
        op.create_index(op.f('ix_users_username'), 'users', ['username'], unique=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_users_username'), table_name='users')
    op.drop_index(op.f('ix_users_tenant_id'), table_name='users')
    op.drop_index(op.f('ix_users_role'), table_name='users')
    op.drop_index(op.f('ix_users_is_superadmin'), table_name='users')
    op.drop_table('users')
    op.drop_index(op.f('ix_threat_intelligence_is_active'), table_name='threat_intelligence')
    op.drop_index(op.f('ix_threat_intelligence_indicator_value'), table_name='threat_intelligence')
    op.drop_index(op.f('ix_threat_intelligence_indicator_type'), table_name='threat_intelligence')
    op.drop_index('idx_threat_intel_active', table_name='threat_intelligence')
    op.drop_table('threat_intelligence')
    op.drop_index(op.f('ix_tenants_tenant_id'), table_name='tenants')
    op.drop_index(op.f('ix_tenants_is_active'), table_name='tenants')
    op.drop_table('tenants')
    op.drop_index(op.f('ix_reports_tenant_id'), table_name='reports')
    op.drop_index(op.f('ix_reports_created_at'), table_name='reports')
    op.drop_table('reports')
    op.drop_index(op.f('ix_managed_devices_tenant_id'), table_name='managed_devices')
    op.drop_index(op.f('ix_managed_devices_ip_address'), table_name='managed_devices')
    op.drop_index(op.f('ix_managed_devices_device_id'), table_name='managed_devices')
    op.drop_index('idx_managed_dev_tenant_ip', table_name='managed_devices')
    op.drop_index('idx_managed_dev_tenant_id_corr', table_name='managed_devices')
    op.drop_table('managed_devices')
    op.drop_index(op.f('ix_logs_vendor'), table_name='logs')
    op.drop_index(op.f('ix_logs_timestamp'), table_name='logs')
    op.drop_index(op.f('ix_logs_tenant_id'), table_name='logs')
    op.drop_index(op.f('ix_logs_source_ip'), table_name='logs')
    op.drop_index(op.f('ix_logs_severity'), table_name='logs')
    op.drop_index(op.f('ix_logs_log_type'), table_name='logs')
    op.drop_index(op.f('ix_logs_device_id'), table_name='logs')
    op.drop_index(op.f('ix_logs_device_hostname'), table_name='logs')
    op.drop_index(op.f('ix_logs_destination_ip'), table_name='logs')
    op.drop_index(op.f('ix_logs_company_id'), table_name='logs')
    op.drop_index('idx_logs_type_tenant', table_name='logs')
    op.drop_index('idx_logs_tenant_timestamp', table_name='logs')
    op.drop_index('idx_logs_tenant_severity', table_name='logs')
    op.drop_index('idx_logs_source_ip_timestamp', table_name='logs')
    op.drop_index('idx_logs_dest_ip_timestamp', table_name='logs')
    op.drop_table('logs')
    op.drop_index(op.f('ix_dead_letters_tenant_id'), table_name='dead_letters')
    op.drop_index(op.f('ix_dead_letters_received_at'), table_name='dead_letters')
    op.drop_index('idx_dead_letters_tenant_received', table_name='dead_letters')
    op.drop_index('idx_dead_letters_error_type', table_name='dead_letters')
    op.drop_table('dead_letters')
    op.drop_index(op.f('ix_alerts_tenant_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_status'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_source_ip'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_severity'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_device_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_created_at'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_company_id'), table_name='alerts')
    op.drop_index(op.f('ix_alerts_alert_type'), table_name='alerts')
    op.drop_index('idx_alerts_tenant_status', table_name='alerts')
    op.drop_index('idx_alerts_tenant_severity', table_name='alerts')
    op.drop_index('idx_alerts_source_ip', table_name='alerts')
    op.drop_table('alerts')
    # ### end Alembic commands ###
