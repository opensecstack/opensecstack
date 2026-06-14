DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'nis2compass') THEN
    CREATE ROLE nis2compass WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE nis2compass OWNER nis2compass'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'nis2compass')\gexec
GRANT ALL PRIVILEGES ON DATABASE nis2compass TO nis2compass;
