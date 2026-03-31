-- Create ThreatFlow database and user if they don't exist.
-- Mounted as /docker-entrypoint-initdb.d/03-init-threatflow.sql

SELECT 'CREATE DATABASE threatflow'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'threatflow')\gexec

DO $$
BEGIN
  IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'threatflow') THEN
    CREATE ROLE threatflow WITH LOGIN PASSWORD 'threatflow';
  END IF;
END
$$;

GRANT ALL PRIVILEGES ON DATABASE threatflow TO threatflow;
