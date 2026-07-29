DROP TABLE IF EXISTS scan_approvals;

-- PostgreSQL does not support removing a value from an enum type. The
-- 'pending_approval' value added by the up migration remains defined on
-- scan_status after rollback; this is harmless as long as no row uses it
-- (rolling back this migration implies the approval feature is disabled).
