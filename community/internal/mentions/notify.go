package mentions

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// NotifyMentions looks up each username in the DB, skips the actor (actorID),
// skips non-existent users, and creates a notification of type
// "mentioned_in_comment" for each mentioned user. It returns without error if
// any individual lookup fails. postID and commentID may be empty strings to
// represent NULL.
func NotifyMentions(ctx context.Context, pool *pgxpool.Pool, actorID string, mentionedUsernames []string, postID string, commentID string) error {
	var postIDParam interface{}
	if postID != "" {
		postIDParam = postID
	}

	var commentIDParam interface{}
	if commentID != "" {
		commentIDParam = commentID
	}

	for _, username := range mentionedUsernames {
		var mentionedUserID string
		if err := pool.QueryRow(ctx,
			`SELECT id FROM users WHERE lower(username) = lower($1)`, username,
		).Scan(&mentionedUserID); err != nil {
			// User not found or DB error — skip silently.
			continue
		}

		// Do not notify the author about their own mention.
		if mentionedUserID == actorID {
			continue
		}

		pool.Exec(ctx, `
			INSERT INTO notifications (user_id, actor_id, type, post_id, comment_id)
			VALUES ($1, $2, 'mentioned_in_comment', $3, $4)
			ON CONFLICT DO NOTHING`,
			mentionedUserID, actorID, postIDParam, commentIDParam)
	}

	return nil
}
