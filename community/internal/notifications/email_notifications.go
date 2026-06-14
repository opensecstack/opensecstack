package notifications

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/email"
)

// Mailer is a minimal interface for sending HTML emails. *email.Mailer satisfies it.
type Mailer interface {
	SendHTML(to, subject, body string) error
}

// SendFollowEmail sends a "X started following you" email to the followed user.
// It checks notification_preferences.email_follows before sending.
func SendFollowEmail(ctx context.Context, pool *pgxpool.Pool, mailer Mailer, cfg *config.Config, followerUsername, followedID string) error {
	// Check opt-in preference.
	var enabled bool
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(email_follows, true)
		 FROM notification_preferences
		 WHERE user_id = $1`, followedID,
	).Scan(&enabled)
	// If no row, the preference record may not exist yet — default to enabled.
	if err != nil {
		enabled = true
	}
	if !enabled {
		return nil
	}

	// Fetch recipient details.
	var toAddr, toName string
	if err := pool.QueryRow(ctx,
		`SELECT email, COALESCE(NULLIF(display_name,''), username) FROM users WHERE id = $1`, followedID,
	).Scan(&toAddr, &toName); err != nil || toAddr == "" {
		return nil
	}

	subject, body := email.RenderFollowEmail(followerUsername, toName, cfg.SiteURL)
	if err := mailer.SendHTML(toAddr, subject, body); err != nil {
		log.Printf("[notifications] SendFollowEmail to=%s: %v", toAddr, err)
		return err
	}
	return nil
}

// SendCommentEmail sends a "X commented on your post" email to the post author.
// It checks notification_preferences.email_comments before sending.
func SendCommentEmail(ctx context.Context, pool *pgxpool.Pool, mailer Mailer, cfg *config.Config, commenterUsername, postAuthorID, postSlug, postTitle, commentBody string) error {
	var enabled bool
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(email_comments, true)
		 FROM notification_preferences
		 WHERE user_id = $1`, postAuthorID,
	).Scan(&enabled)
	if err != nil {
		enabled = true
	}
	if !enabled {
		return nil
	}

	var toAddr, toName string
	if err := pool.QueryRow(ctx,
		`SELECT email, COALESCE(NULLIF(display_name,''), username) FROM users WHERE id = $1`, postAuthorID,
	).Scan(&toAddr, &toName); err != nil || toAddr == "" {
		return nil
	}

	subject, body := email.RenderCommentEmail(commenterUsername, postTitle, postSlug, commentBody, toName, cfg.SiteURL)
	if err := mailer.SendHTML(toAddr, subject, body); err != nil {
		log.Printf("[notifications] SendCommentEmail to=%s: %v", toAddr, err)
		return err
	}
	return nil
}

// SendReactionEmail sends a "X reacted to your post" email to the post author.
// It checks notification_preferences.email_reactions before sending.
// To avoid flooding, it skips sending if a reaction email for this post was
// already sent in the last 24 hours (tracked via a simple notifications table check).
func SendReactionEmail(ctx context.Context, pool *pgxpool.Pool, mailer Mailer, cfg *config.Config, reactorUsername, postAuthorID, postSlug, postTitle, reactionKind string) error {
	var enabled bool
	err := pool.QueryRow(ctx,
		`SELECT COALESCE(email_reactions, false)
		 FROM notification_preferences
		 WHERE user_id = $1`, postAuthorID,
	).Scan(&enabled)
	if err != nil {
		// Default for reactions is false — don't send unless explicitly opted in.
		return nil
	}
	if !enabled {
		return nil
	}

	// Rate-limit: skip if we already sent a reaction email for this post in the last 24 h.
	// We use the notifications table: look for a reaction_on_post notification for this user
	// that was created in the past 24 h.
	var recentCount int
	_ = pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM notifications
		 WHERE user_id = $1
		   AND type = 'reaction_on_post'
		   AND created_at > $2`,
		postAuthorID, time.Now().Add(-24*time.Hour),
	).Scan(&recentCount)
	if recentCount > 1 {
		// Already notified recently; suppress the email.
		return nil
	}

	var toAddr, toName string
	if err := pool.QueryRow(ctx,
		`SELECT email, COALESCE(NULLIF(display_name,''), username) FROM users WHERE id = $1`, postAuthorID,
	).Scan(&toAddr, &toName); err != nil || toAddr == "" {
		return nil
	}

	subject, body := email.RenderReactionEmail(reactorUsername, reactionKind, postTitle, postSlug, toName, cfg.SiteURL)
	if err := mailer.SendHTML(toAddr, subject, body); err != nil {
		log.Printf("[notifications] SendReactionEmail to=%s: %v", toAddr, err)
		return err
	}
	return nil
}

