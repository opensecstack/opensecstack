package db

var migrations = []string{
	ddlExtensions,
	ddlUsers,
	ddlPosts,
	ddlTags,
	ddlPostTags,
	ddlReactions,
	ddlReactionKindsUpdate,
	ddlComments,
	ddlSearch,
	ddlNotifications,
	ddlFollows,
	ddlTagFollows,
	ddlBookmarks,
	ddlViews,
	ddlEditedAt,
	ddlSensitive,
	ddlSeries,
	ddlUsersAuth,
	ddlOAuth,
	ddlGoogleOAuth,
	ddlSinauthOAuth,
	ddlTOTP,
	ddlBan,
	ddlEmailVerify,
	ddlPasswordReset,
	ddlSessions,
	ddlTOTPSetupSessions,
	ddlSSETickets,
	ddlInvites,
	ddlLock,
	ddlBroadcasts,
	ddlBlocks,
	ddlMutes,
	ddlProfileFields,
	ddlSchedule,
	ddlPin,
	ddlContextNotes,
	ddlDeletionRequests,
	ddlAuditLog,
	ddlArchive,
	ddlCanonicalUrl,
	ddlTagSuppressions,
	ddlReports,
	ddlModeratorNotes,
	ddlPostRevisions,
	ddlPostSubscriptions,
	ddlDeactivation,
	ddlNotificationPrefs,
	ddlEmailNotifPrefs,
	ddlNotificationPrefsCleanup,
	ddlTagAliases,
	ddlCommentReactions,
	ddlAPIKeys,
	ddlUserModNotes,
	ddlAnalytics,
	ddlReadingHistory,
	ddlPush,
	ddlTemplates,
	ddlWelcomeNotification,
	ddlSpaces,
	ddlSpaceMembers,
	ddlChannels,
	ddlSpaceInvites,
	ddlPostChannelRef,
	ddlDeletionApproval,
	ddlTOTPLastStep,
}

const ddlCanonicalUrl = `
ALTER TABLE posts ADD COLUMN IF NOT EXISTS canonical_url TEXT;`

const ddlExtensions = `
CREATE EXTENSION IF NOT EXISTS pgcrypto;`

const ddlUsers = `
CREATE TABLE IF NOT EXISTS users (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username      TEXT NOT NULL UNIQUE,
    display_name  TEXT NOT NULL DEFAULT '',
    bio           TEXT NOT NULL DEFAULT '',
    avatar_url    TEXT,
    platform_badge TEXT,
    role          TEXT NOT NULL DEFAULT 'author',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);`

const ddlPosts = `
CREATE TABLE IF NOT EXISTS posts (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    author_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title         TEXT NOT NULL,
    slug          TEXT NOT NULL UNIQUE,
    body          TEXT NOT NULL DEFAULT '',
    cover_image_url TEXT,
    state         TEXT NOT NULL DEFAULT 'draft' CHECK (state IN ('draft','published')),
    published_at  TIMESTAMPTZ,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    search_vector TSVECTOR GENERATED ALWAYS AS (
        to_tsvector('english', title || ' ' || body)
    ) STORED
);
CREATE INDEX IF NOT EXISTS posts_search ON posts USING GIN(search_vector);
CREATE INDEX IF NOT EXISTS posts_published ON posts(published_at DESC) WHERE state = 'published';`

const ddlTags = `
CREATE TABLE IF NOT EXISTS tags (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name        TEXT NOT NULL UNIQUE,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    color       TEXT NOT NULL DEFAULT '#6366f1',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);`

const ddlPostTags = `
CREATE TABLE IF NOT EXISTS post_tags (
    post_id UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    tag_id  UUID NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, tag_id)
);`

const ddlReactions = `
CREATE TABLE IF NOT EXISTS reactions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('heart','unicorn','fire')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (post_id, user_id, kind)
);`

const ddlComments = `
CREATE TABLE IF NOT EXISTS comments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    parent_id  UUID REFERENCES comments(id) ON DELETE CASCADE,
    author_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);`

const ddlSearch = `
CREATE INDEX IF NOT EXISTS tags_slug ON tags(slug);
CREATE INDEX IF NOT EXISTS users_username ON users(username);`

const ddlNotifications = `
CREATE TABLE IF NOT EXISTS notifications (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    actor_id    UUID REFERENCES users(id) ON DELETE SET NULL,
    type        TEXT NOT NULL CHECK (type IN ('comment_on_post','reaction_on_post','followed_by_user','mentioned_in_comment')),
    post_id     UUID REFERENCES posts(id) ON DELETE CASCADE,
    comment_id  UUID REFERENCES comments(id) ON DELETE CASCADE,
    read        BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id, read, created_at DESC);`

const ddlFollows = `
CREATE TABLE IF NOT EXISTS follows (
    follower_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    following_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (follower_id, following_id),
    CHECK (follower_id != following_id)
);
CREATE INDEX IF NOT EXISTS idx_follows_following_id ON follows(following_id);`

const ddlBookmarks = `
CREATE TABLE IF NOT EXISTS bookmarks (
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, post_id)
);
CREATE INDEX IF NOT EXISTS idx_bookmarks_user_id ON bookmarks(user_id, created_at DESC);`

const ddlViews = `
ALTER TABLE posts ADD COLUMN IF NOT EXISTS views BIGINT NOT NULL DEFAULT 0;`

const ddlSeries = `
CREATE TABLE IF NOT EXISTS series (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    author_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title       TEXT NOT NULL,
    slug        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS series_posts (
    series_id  UUID NOT NULL REFERENCES series(id) ON DELETE CASCADE,
    post_id    UUID NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    position   INT NOT NULL DEFAULT 0,
    PRIMARY KEY (series_id, post_id)
);
CREATE INDEX IF NOT EXISTS idx_series_author_id ON series(author_id);`
