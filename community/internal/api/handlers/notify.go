package handlers

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/push"
)

// createNotification inserts a notification from actorID to userID.
// Skips self-notifications (userID == actorID).
func createNotification(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, userID, actorID, notifType string, postID, commentID *string) {
	if userID == actorID {
		return
	}
	pool.Exec(ctx, `
		INSERT INTO notifications (user_id, actor_id, type, post_id, comment_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING`,
		userID, actorID, notifType, postID, commentID)

	notifySSE(pool, ctx, userID)

	go func() {
		pushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		push.SendToUser(pushCtx, pool, cfg, userID, notifPayload(notifType, postID))
	}()
}

// createSystemNotification inserts a self-triggered notification (e.g. password changed,
// space joined). Bypasses the self-notification guard since the actor is the user.
func createSystemNotification(ctx context.Context, pool *pgxpool.Pool, userID, notifType string, spaceID *string) {
	pool.Exec(ctx, `
		INSERT INTO notifications (user_id, actor_id, type, space_id)
		VALUES ($1, $1, $2, $3)
		ON CONFLICT DO NOTHING`,
		userID, notifType, spaceID)

	notifySSE(pool, ctx, userID)
}

// createSpaceNotification inserts a space-related notification from actorID to userID,
// storing the space_id for navigation in the frontend.
func createSpaceNotification(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, userID, actorID, notifType, spaceID string) {
	if userID == actorID {
		return
	}
	pool.Exec(ctx, `
		INSERT INTO notifications (user_id, actor_id, type, space_id)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT DO NOTHING`,
		userID, actorID, notifType, spaceID)

	notifySSE(pool, ctx, userID)

	go func() {
		pushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		push.SendToUser(pushCtx, pool, cfg, userID, notifPayload(notifType, nil))
	}()
}

// notifySSE wakes the user's active SSE stream via PostgreSQL LISTEN/NOTIFY.
func notifySSE(pool *pgxpool.Pool, ctx context.Context, userID string) {
	channel := "notif_" + strings.ReplaceAll(userID, "-", "")
	pool.Exec(ctx, "SELECT pg_notify($1, 'new')", channel)
}

// notifPayload builds the human-readable Web Push payload for a notification type.
func notifPayload(notifType string, postID *string) push.Notification {
	url := "/"
	if postID != nil && *postID != "" {
		url = "/posts/" + *postID
	}
	switch notifType {
	case "comment_on_post":
		return push.Notification{Title: "SIN", Body: "Someone commented on your post.", URL: url}
	case "reaction_on_post":
		return push.Notification{Title: "SIN", Body: "Someone reacted to your post.", URL: url}
	case "new_follower":
		return push.Notification{Title: "SIN", Body: "You have a new follower.", URL: "/"}
	case "mentioned_in_comment":
		return push.Notification{Title: "SIN", Body: "You were mentioned in a comment.", URL: url}
	case "welcome":
		return push.Notification{Title: "Welcome to SIN", Body: "Your account is ready. Start exploring!", URL: "/"}
	case "password_changed":
		return push.Notification{Title: "SIN Security", Body: "Your password was changed successfully.", URL: "/settings"}
	case "space_joined":
		return push.Notification{Title: "SIN", Body: "You joined a new space.", URL: "/spaces"}
	case "space_member_joined":
		return push.Notification{Title: "SIN", Body: "A new member joined your space.", URL: "/spaces"}
	case "space_invite":
		return push.Notification{Title: "SIN", Body: "You have been invited to a space.", URL: "/spaces"}
	default:
		return push.Notification{Title: "SIN", Body: "You have a new notification.", URL: "/"}
	}
}
