-- Dev-only: creates all platform databases and roles in one pass.
-- Mounted at /docker-entrypoint-initdb.d/10-init-dev-dbs.sql

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'citadel') THEN
    CREATE ROLE citadel WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE citadel OWNER citadel'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'citadel')\gexec
GRANT ALL PRIVILEGES ON DATABASE citadel TO citadel;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'irflow') THEN
    CREATE ROLE irflow WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE irflow OWNER irflow'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'irflow')\gexec
GRANT ALL PRIVILEGES ON DATABASE irflow TO irflow;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'opencsirt') THEN
    CREATE ROLE opencsirt WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE opencsirt OWNER opencsirt'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'opencsirt')\gexec
GRANT ALL PRIVILEGES ON DATABASE opencsirt TO opencsirt;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'vertguard') THEN
    CREATE ROLE vertguard WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE vertguard OWNER vertguard'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'vertguard')\gexec
GRANT ALL PRIVILEGES ON DATABASE vertguard TO vertguard;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'openscrub') THEN
    CREATE ROLE openscrub WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE openscrub OWNER openscrub'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'openscrub')\gexec
GRANT ALL PRIVILEGES ON DATABASE openscrub TO openscrub;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'cyberpath') THEN
    CREATE ROLE cyberpath WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE cyberpath OWNER cyberpath'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'cyberpath')\gexec
GRANT ALL PRIVILEGES ON DATABASE cyberpath TO cyberpath;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'securelab') THEN
    CREATE ROLE securelab WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE securelab OWNER securelab'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'securelab')\gexec
GRANT ALL PRIVILEGES ON DATABASE securelab TO securelab;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sin') THEN
    CREATE ROLE sin WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE sin OWNER sin'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sin')\gexec
GRANT ALL PRIVILEGES ON DATABASE sin TO sin;

DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'sinauth') THEN
    CREATE ROLE sinauth WITH LOGIN PASSWORD 'changeme';
  END IF;
END $$;
SELECT 'CREATE DATABASE sinauth OWNER sinauth'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sinauth')\gexec
GRANT ALL PRIVILEGES ON DATABASE sinauth TO sinauth;
