package digest

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/email"
)

// Run fetches the top 5 posts from the past 7 days and sends the weekly digest
// email to all eligible users (email verified, digest opted in).
// It is safe to call from a cron job or an admin trigger endpoint.
func Run(ctx context.Context, pool *pgxpool.Pool, mailer *email.Mailer, cfg *config.Config) error {
	if !cfg.DigestEnabled {
		log.Println("[digest] digest is disabled via config, skipping")
		return nil
	}

	// --- 1. Fetch top 5 posts from the last 7 days ---
	postRows, err := pool.Query(ctx, `
SELECT
    p.title,
    p.slug,
    u.username  AS author_username,
    COUNT(DISTINCT rx.id)::int AS reaction_count,
    p.views::int               AS view_count,
    LEFT(p.body, 200)          AS excerpt
FROM posts p
JOIN users u ON u.id = p.author_id
LEFT JOIN reactions rx ON rx.post_id = p.id
WHERE p.state = 'published'
  AND p.published_at >= NOW() - INTERVAL '7 days'
GROUP BY p.id, p.title, p.slug, u.username, p.views, p.body
ORDER BY COUNT(DISTINCT rx.id) * 3 + p.views DESC
LIMIT 5`)
	if err != nil {
		return err
	}
	defer postRows.Close()

	var posts []email.DigestPost
	for postRows.Next() {
		var dp email.DigestPost
		if err := postRows.Scan(
			&dp.Title,
			&dp.Slug,
			&dp.AuthorUsername,
			&dp.ReactionCount,
			&dp.ViewCount,
			&dp.Excerpt,
		); err != nil {
			return err
		}
		posts = append(posts, dp)
	}
	if err := postRows.Err(); err != nil {
		return err
	}
	postRows.Close()

	// --- 2. Skip if nothing to send ---
	if len(posts) == 0 {
		log.Println("[digest] no published posts in the last 7 days, skipping digest")
		return nil
	}

	// --- 3. Fetch eligible users ---
	// Users must have a verified email and have digest_enabled = true in their
	// notification_preferences row. Users without a preferences row are excluded
	// (digest defaults to false).
	userRows, err := pool.Query(ctx, `
SELECT u.id, u.email, u.username
FROM users u
JOIN notification_preferences np ON np.user_id = u.id
WHERE u.email_verified = true
  AND np.digest_enabled = true
  AND u.email IS NOT NULL`)
	if err != nil {
		return err
	}
	defer userRows.Close()

	type recipient struct {
		id       string
		email    string
		username string
	}
	var recipients []recipient
	for userRows.Next() {
		var rec recipient
		if err := userRows.Scan(&rec.id, &rec.email, &rec.username); err != nil {
			log.Printf("[digest] scan user row: %v", err)
			continue
		}
		recipients = append(recipients, rec)
	}
	if err := userRows.Err(); err != nil {
		return err
	}
	userRows.Close()

	log.Printf("[digest] sending to %d recipients, %d top posts", len(recipients), len(posts))

	siteURL := cfg.SiteURL

	// --- 4. Send to each recipient with a small delay to respect rate limits ---
	for _, rec := range recipients {
		if err := mailer.SendWeeklyDigest(rec.email, rec.username, siteURL, posts); err != nil {
			log.Printf("[digest] send to %s (%s): %v", rec.username, rec.email, err)
			// Continue sending to other recipients even if one fails.
		} else {
			// Update last_digest_at so we can track delivery.
			_, updateErr := pool.Exec(ctx,
				`UPDATE users SET last_digest_at = NOW() WHERE id = $1`, rec.id)
			if updateErr != nil {
				log.Printf("[digest] update last_digest_at for %s: %v", rec.username, updateErr)
			}
		}
		// Brief pause between sends to avoid overwhelming the SMTP relay.
		time.Sleep(100 * time.Millisecond)
	}

	log.Println("[digest] done")
	return nil
}
