// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2024 opensecstack contributors.

package db

func init() {
	migrations = append(migrations,
		`CREATE TABLE IF NOT EXISTS channel_messages (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id UUID NOT NULL REFERENCES channels(id) ON DELETE CASCADE,
    author_id  UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    content    TEXT NOT NULL CHECK (char_length(content) <= 4000),
    edited_at  TIMESTAMPTZ,
    parent_id  UUID REFERENCES channel_messages(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`,
		`CREATE INDEX IF NOT EXISTS idx_channel_messages_channel_id ON channel_messages(channel_id, created_at DESC)`,
		`CREATE TABLE IF NOT EXISTS channel_message_reactions (
    message_id UUID NOT NULL REFERENCES channel_messages(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    emoji      TEXT NOT NULL CHECK (char_length(emoji) <= 8),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (message_id, user_id, emoji)
)`,
		`CREATE TABLE IF NOT EXISTS channel_message_attachments (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID NOT NULL REFERENCES channel_messages(id) ON DELETE CASCADE,
    file_url   TEXT NOT NULL,
    file_name  TEXT NOT NULL,
    file_size  BIGINT NOT NULL DEFAULT 0,
    mime_type  TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
)`,
	)
}
