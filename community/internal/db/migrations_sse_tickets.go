package db

const ddlSSETickets = `
CREATE TABLE IF NOT EXISTS sse_tickets (
    ticket     TEXT PRIMARY KEY,
    username   TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sse_tickets_expires_at ON sse_tickets(expires_at);`
