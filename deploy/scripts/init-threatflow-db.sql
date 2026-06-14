-- Create ThreatFlow database and user if they don't exist.
-- Mounted as /docker-entrypoint-initdb.d/03-init-threatflow.sql

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'threatflow') THEN
    CREATE ROLE threatflow WITH LOGIN PASSWORD 'threatflow';
  END IF;
END
$$;

SELECT 'CREATE DATABASE threatflow OWNER threatflow'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'threatflow')\gexec

GRANT ALL PRIVILEGES ON DATABASE threatflow TO threatflow;
-- PostgreSQL 15+ no longer grants CREATE on schema public to non-owners.
\connect threatflow
GRANT ALL ON SCHEMA public TO threatflow;
ALTER SCHEMA public OWNER TO threatflow;
