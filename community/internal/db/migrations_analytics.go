package db

const ddlAnalytics = `
CREATE TABLE IF NOT EXISTS post_views_daily (
    post_id UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    day     DATE NOT NULL,
    count   BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (post_id, day)
);
CREATE INDEX IF NOT EXISTS idx_pvd_post_day ON post_views_daily(post_id, day DESC);`
