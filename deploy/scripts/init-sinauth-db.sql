-- Create the sinauth identity-provider database and role.
-- Mounted at /docker-entrypoint-initdb.d/05-init-sinauth.sql
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sinauth') THEN
    CREATE ROLE sinauth WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE sinauth OWNER sinauth'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sinauth')\gexec
GRANT ALL PRIVILEGES ON DATABASE sinauth TO sinauth;
