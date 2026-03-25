-- =============================================================================
-- APIGuard Development Database Reset
-- =============================================================================
-- Removes ALL data from every table while preserving the schema.
-- Tables are truncated in dependency order (children before parents)
-- so that foreign-key constraints are satisfied without needing CASCADE.
--
-- !! SAFETY WARNING !!
-- This script is intended for LOCAL DEVELOPMENT ONLY.
-- NEVER run this against a staging or production database.
-- It will destroy all data with no recovery path.
--
-- Usage:
--   psql $DATABASE_URL -f scripts/db_reset.sql
--
-- After reset, re-seed with:
--   psql $DATABASE_URL -f scripts/seed.sql
-- =============================================================================

BEGIN;

-- audit_log has CREATE RULE ... DO INSTEAD NOTHING guards that prevent
-- UPDATE and DELETE at the DML level, but TRUNCATE operates at the storage
-- level and bypasses those rules. In development this is the intended
-- behaviour — a superuser or the table owner can truncate freely.
-- In production, the audit log should be stored on write-once infrastructure
-- and this script must never be run there.

TRUNCATE TABLE audit_log     RESTART IDENTITY CASCADE;
TRUNCATE TABLE findings      RESTART IDENTITY CASCADE;
TRUNCATE TABLE scans         RESTART IDENTITY CASCADE;
TRUNCATE TABLE api_specs     RESTART IDENTITY CASCADE;
TRUNCATE TABLE api_inventory RESTART IDENTITY CASCADE;

COMMIT;
