-- NIS2 Compass — PostgreSQL init script
-- Creates the application user and grants privileges.
-- Run automatically by the postgres container on first start.

-- Create the application user (idempotent).
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'nis2compass') THEN
        CREATE ROLE nis2compass WITH LOGIN PASSWORD 'nis2compassdev';
    END IF;
END
$$;

-- Grant privileges on the database.
GRANT ALL PRIVILEGES ON DATABASE nis2compass TO nis2compass;
GRANT ALL ON SCHEMA public TO nis2compass;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO nis2compass;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO nis2compass;
