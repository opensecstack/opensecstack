package push

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
)

// Notification is the payload sent to the browser via Web Push.
type Notification struct {
	Title string `json:"title"`
	Body  string `json:"body"`
	URL   string `json:"url"`
}

// SendToUser sends a push notification to all active subscriptions for userID.
// It is a no-op when VAPID keys are not configured.
//
// Each send runs in its own goroutine with a 10 s timeout (independent of the
// caller's request context, which may be cancelled before the send completes).
// Subscriptions that return 410 Gone or 404 are automatically removed from the DB.
func SendToUser(ctx context.Context, pool *pgxpool.Pool, cfg *config.Config, userID string, n Notification) {
	if cfg.VAPIDPublicKey == "" || cfg.VAPIDPrivateKey == "" {
		return
	}

	rows, err := pool.Query(ctx,
		`SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE user_id=$1`, userID)
	if err != nil {
		return
	}

	type sub struct{ endpoint, p256dh, auth string }
	var subs []sub
	for rows.Next() {
		var s sub
		if err := rows.Scan(&s.endpoint, &s.p256dh, &s.auth); err != nil {
			continue
		}
		subs = append(subs, s)
	}
	rows.Close()

	if len(subs) == 0 {
		return
	}

	payload, _ := json.Marshal(n)

	for _, s := range subs {
		s := s
		go func() {
			sendCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			resp, err := webpush.SendNotification(payload, &webpush.Subscription{
				Endpoint: s.endpoint,
				Keys:     webpush.Keys{P256dh: s.p256dh, Auth: s.auth},
			}, &webpush.Options{
				VAPIDPublicKey:  cfg.VAPIDPublicKey,
				VAPIDPrivateKey: cfg.VAPIDPrivateKey,
				Subscriber:      cfg.VAPIDEmail,
				TTL:             30,
			})
			if err != nil {
				log.Printf("push send error endpoint=%s: %v", s.endpoint, err)
				return
			}
			defer resp.Body.Close()

			// 410 Gone or 404 Not Found → subscription is expired/invalid; remove it.
			if resp.StatusCode == http.StatusGone || resp.StatusCode == http.StatusNotFound {
				if _, err := pool.Exec(sendCtx, `DELETE FROM push_subscriptions WHERE endpoint=$1`, s.endpoint); err != nil {
					log.Printf("push: failed to remove expired subscription endpoint=%s: %v", s.endpoint, err)
				}
			}
		}()
	}
}
