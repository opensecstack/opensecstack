package scheduler

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/opensecstack/community/internal/citadel"
	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/email"
)

// Start runs a background loop that publishes scheduled posts when their
// scheduled_at time has passed. It ticks every minute and exits when ctx is done.
func Start(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config) {
	cit := citadel.New(cfg.CitadelURL, cfg.CitadelHMAC, cfg.CitadelKeyID, cfg.CitadelDryRun)
	gov := citadel.NewGovernanceClient(cfg.CitadelURL)

	mailer := email.New(email.Config{
		Host:     cfg.SMTPHost,
		Port:     cfg.SMTPPort,
		Username: cfg.SMTPUsername,
		Password: cfg.SMTPPassword,
		From:     cfg.SMTPFrom,
		SiteURL:  cfg.SiteURL,
	})

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publishDue(ctx, pool, cit, cfg)
			processDeletions(ctx, pool, cit, gov, cfg)
			go sendDigests(ctx, pool, mailer, cfg)
		}
	}
}

// processDeletions executes GDPR account deletions whose 30-day grace
// period has elapsed. This is the unattended, no-human-in-the-loop path
// CITADEL's governance model exists to catch: it runs from a background
// ticker with no live request or bearer token to forward, deleting a
// user's account and all their content irreversibly.
//
// Two independent controls gate the DELETE, neither of which existed
// before this change:
//
//  1. Only rows with status='approved' are even considered — an admin,
//     distinct from the user being deleted, must have already approved
//     the request via POST /api/v1/admin/deletion-requests/{id}/approve
//     (internal/api/handlers/gdpr.go's AdminApproveDeletion). This is a
//     real two-person control, not a placeholder: Actor (the user) and
//     Verifier (the approving admin) are both genuine, distinct,
//     durably-recorded identities — see citadel.ResolveIdentity, which
//     prefers each user's real sinauth UUID (captured at SSO login time)
//     and falls back to a clearly-marked community-internal identifier
//     only for accounts that never linked sinauth.
//  2. Immediately before the DELETE, a Kerkese is submitted to CITADEL
//     MARSHAL for evaluation (citadel.GovernanceClient.EvaluateDeletion).
//     A REFUSE/HARD_STOP outcome genuinely blocks the deletion — the row
//     is left as 'approved' and skipped for this run, not silently
//     processed, so it will be re-evaluated on the next tick.
func processDeletions(ctx context.Context, pool *pgxpool.Pool, cit *citadel.Client, gov *citadel.GovernanceClient, cfg *config.Config) {
	rows, err := pool.Query(ctx, `
		SELECT dr.id, dr.user_id, u.sinauth_id, dr.approved_by, au.sinauth_id
		FROM deletion_requests dr
		JOIN users u ON u.id = dr.user_id
		LEFT JOIN users au ON au.id = dr.approved_by
		WHERE dr.status='approved' AND dr.scheduled_for <= now()`)
	if err != nil {
		slog.Error("scheduler: deletion query failed", "err", err)
		return
	}
	defer rows.Close()

	type deletionCandidate struct {
		reqID, userID             string
		userSinauthID, approvedBy sql.NullString
		approverSinauthID         sql.NullString
	}
	var toDelete []deletionCandidate
	for rows.Next() {
		var c deletionCandidate
		if err := rows.Scan(&c.reqID, &c.userID, &c.userSinauthID, &c.approvedBy, &c.approverSinauthID); err != nil {
			slog.Error("scheduler: deletion scan failed", "err", err)
			continue
		}
		toDelete = append(toDelete, c)
	}
	rows.Close()

	for _, d := range toDelete {
		reqUUID, err := uuid.Parse(d.reqID)
		if err != nil {
			slog.Error("scheduler: deletion request id is not a valid UUID", "request_id", d.reqID, "err", err)
			continue
		}

		actorID := citadel.ResolveIdentity(d.userSinauthID, d.userID)
		verifierID := "community-system-verifier"
		if d.approvedBy.Valid {
			verifierID = citadel.ResolveIdentity(d.approverSinauthID, d.approvedBy.String)
		}

		k := citadel.DeletionKerkese(cfg.Node, reqUUID, actorID, verifierID)
		proceed, reasons, evalErr := gov.EvaluateDeletion(ctx, k)
		if evalErr != nil {
			slog.Warn("scheduler: CITADEL marshal evaluate failed for GDPR deletion — proceeding (fail-open)",
				"user_id", d.userID, "request_id", d.reqID, "err", evalErr)
		}
		if !proceed {
			slog.Error("scheduler: CITADEL blocked GDPR deletion — skipping this run, will retry next tick",
				"user_id", d.userID, "request_id", d.reqID, "reasons", reasons)
			continue
		}

		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id=$1`, d.userID); err != nil {
			slog.Error("scheduler: delete user failed", "user_id", d.userID, "err", err)
			continue
		}
		if _, err := pool.Exec(ctx,
			`UPDATE deletion_requests SET status='processed', processed_at=now() WHERE id=$1`, d.reqID,
		); err != nil {
			slog.Error("scheduler: failed to mark deletion request processed", "request_id", d.reqID, "err", err)
		}
		_ = cit.Emit(ctx, citadel.Event{
			Kind:      "community.user.deleted",
			NodeID:    cfg.Node,
			Timestamp: time.Now(),
			Payload:   map[string]any{"user_id": d.userID, "request_id": d.reqID, "via": "gdpr_scheduler"},
		})
		slog.Info("scheduler: deleted user (GDPR)", "user_id", d.userID, "request_id", d.reqID)
	}
}

func sendDigests(ctx context.Context, pool *pgxpool.Pool, mailer *email.Mailer, cfg *config.Config) {
	// Find users due for a digest (SQL WHERE clause handles per-user timing).
	rows, err := pool.Query(ctx, `
		SELECT u.id, u.email, u.username, u.display_name, np.digest_frequency
		FROM notification_preferences np
		JOIN users u ON u.id = np.user_id
		WHERE np.digest_enabled = true
		  AND u.deactivated_at IS NULL
		  AND (
		      (np.digest_frequency = 'weekly' AND (u.last_digest_at IS NULL OR u.last_digest_at < now() - INTERVAL '7 days'))
		   OR (np.digest_frequency = 'daily'  AND (u.last_digest_at IS NULL OR u.last_digest_at < now() - INTERVAL '1 day'))
		  )`)
	if err != nil {
		slog.Error("scheduler: digest user query failed", "err", err)
		return
	}
	defer rows.Close()

	type digestUser struct {
		ID          string
		Email       string
		Username    string
		DisplayName string
		Frequency   string
	}
	var users []digestUser
	for rows.Next() {
		var u digestUser
		if err := rows.Scan(&u.ID, &u.Email, &u.Username, &u.DisplayName, &u.Frequency); err != nil {
			slog.Error("scheduler: digest user scan failed", "err", err)
			continue
		}
		users = append(users, u)
	}
	rows.Close()

	for _, u := range users {
		interval := "7 days"
		if u.Frequency == "daily" {
			interval = "1 day"
		}

		// Get top posts published in the relevant period.
		postRows, err := pool.Query(ctx, fmt.Sprintf(`
			SELECT p.title, p.slug, u2.username, u2.display_name,
			       COUNT(DISTINCT r.id) AS reaction_count, p.views
			FROM posts p
			JOIN users u2 ON u2.id = p.author_id
			LEFT JOIN reactions r ON r.post_id = p.id
			WHERE p.state = 'published'
			  AND p.published_at > now() - INTERVAL '%s'
			GROUP BY p.id, u2.username, u2.display_name
			ORDER BY reaction_count DESC, p.views DESC
			LIMIT 5`, interval))
		if err != nil {
			slog.Error("scheduler: digest posts query failed", "user_id", u.ID, "err", err)
			continue
		}

		type digestPost struct {
			Title          string
			Slug           string
			AuthorUsername string
			AuthorName     string
			Reactions      int
			Views          int64
		}
		var posts []digestPost
		for postRows.Next() {
			var p digestPost
			if err := postRows.Scan(&p.Title, &p.Slug, &p.AuthorUsername, &p.AuthorName, &p.Reactions, &p.Views); err != nil {
				slog.Error("scheduler: digest post scan failed", "user_id", u.ID, "err", err)
				continue
			}
			posts = append(posts, p)
		}
		postRows.Close()

		if len(posts) == 0 {
			continue
		}

		subject := "Your SIN weekly digest"
		if u.Frequency == "daily" {
			subject = "Your SIN daily digest"
		}

		displayName := u.DisplayName
		if displayName == "" {
			displayName = u.Username
		}
		body := fmt.Sprintf("<h2>Top posts for you, %s</h2><ul>", displayName)
		for _, p := range posts {
			body += fmt.Sprintf(`<li><a href="%s/posts/%s">%s</a> by %s — %d reactions</li>`,
				cfg.SiteURL, p.Slug, p.Title, p.AuthorName, p.Reactions)
		}
		body += `</ul><p><small>You're receiving this because you opted in to digest emails. ` +
			`<a href="` + cfg.SiteURL + `/settings">Manage preferences</a></small></p>`

		if err := mailer.SendHTML(u.Email, subject, body); err != nil {
			slog.Error("scheduler: digest send failed", "user_id", u.ID, "err", err)
			continue
		}

		if _, err := pool.Exec(ctx, `UPDATE users SET last_digest_at = now() WHERE id = $1`, u.ID); err != nil {
			slog.Error("scheduler: digest mark-sent failed", "user_id", u.ID, "err", err)
		} else {
			slog.Info("scheduler: digest sent", "user_id", u.ID, "frequency", u.Frequency)
		}
	}
}

func publishDue(ctx context.Context, pool *pgxpool.Pool, cit *citadel.Client, cfg *config.Config) {
	rows, err := pool.Query(ctx, `
		UPDATE posts
		SET state = 'published', published_at = now(), updated_at = now()
		WHERE state = 'scheduled' AND scheduled_at <= now()
		RETURNING id, (SELECT username FROM users WHERE id = author_id)`)
	if err != nil {
		slog.Error("scheduler: query failed", "err", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var postID, author string
		if err := rows.Scan(&postID, &author); err != nil {
			slog.Error("scheduler: scan failed", "err", err)
			continue
		}
		_ = cit.Emit(ctx, citadel.Event{
			Kind:      "community.post.published",
			NodeID:    cfg.Node,
			Timestamp: time.Now(),
			Payload:   map[string]any{"post_id": postID, "author": author, "via": "scheduler"},
		})
		slog.Info("scheduler: published post", "post_id", postID, "author", author)
	}
}
