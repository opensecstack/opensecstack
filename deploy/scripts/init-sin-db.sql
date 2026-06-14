-- Create SIN (Community) database and user if they don't exist.
-- Mounted as /docker-entrypoint-initdb.d/04-init-sin.sql
-- NOTE: Change the password via ALTER ROLE in production after first run.

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sin') THEN
    CREATE ROLE sin WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE sin OWNER sin'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sin')\gexec
GRANT ALL PRIVILEGES ON DATABASE sin TO sin;
