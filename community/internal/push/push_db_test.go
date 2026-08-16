package push_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
	"github.com/opensecstack/community/internal/db"
	"github.com/opensecstack/community/internal/push"
)

const defaultTestDBURL = "postgres://apiguard@localhost:5434/community_test?sslmode=disable"

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	url := os.Getenv("COMMUNITY_TEST_DB_URL")
	if url == "" {
		url = defaultTestDBURL
	}
	pool, err := db.Connect(url, 5)
	if err != nil {
		t.Skipf("real test DB unavailable, skipping DB-backed test: %v", err)
	}
	t.Cleanup(pool.Close)
	if err := db.Migrate(pool); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return pool
}

func randomSuffix() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// validSubscriptionKeys generates a real P-256 EC public key (p256dh) and a
// 16-byte auth secret, both base64url encoded exactly the way a browser's
// PushSubscription.getKey() would produce them. webpush-go performs real
// RFC 8291 encryption against these before it ever touches the network, so
// a fake/short string would fail inside SendNotification before our
// httptest.Server ever saw a request.
func validSubscriptionKeys(t *testing.T) (p256dh, auth string) {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate subscriber EC key: %v", err)
	}
	p256dh = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())

	authSecret := make([]byte, 16)
	if _, err := rand.Read(authSecret); err != nil {
		t.Fatalf("generate auth secret: %v", err)
	}
	auth = base64.RawURLEncoding.EncodeToString(authSecret)
	return
}

func createPushUser(t *testing.T, pool *pgxpool.Pool, username string) string {
	t.Helper()
	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (username) VALUES ($1) RETURNING id`, username,
	).Scan(&id)
	if err != nil {
		t.Fatalf("create test user: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, id)
	})
	return id
}

func insertSubscription(t *testing.T, pool *pgxpool.Pool, userID, endpoint, p256dh, auth string) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO push_subscriptions (user_id, endpoint, p256dh, auth) VALUES ($1, $2, $3, $4)`,
		userID, endpoint, p256dh, auth,
	); err != nil {
		t.Fatalf("insert push_subscriptions: %v", err)
	}
}

func subscriptionExists(t *testing.T, pool *pgxpool.Pool, endpoint string) bool {
	t.Helper()
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM push_subscriptions WHERE endpoint = $1`, endpoint,
	).Scan(&count); err != nil {
		t.Fatalf("count push_subscriptions: %v", err)
	}
	return count > 0
}

// TestSendToUser_SuccessfulDelivery_KeepsSubscription verifies the full
// happy path end-to-end: SendToUser must build a valid RFC 8291-encrypted
// request and POST it to the subscription's endpoint. A 201 Created
// response is not 410/404, so the subscription row must survive.
func TestSendToUser_SuccessfulDelivery_KeepsSubscription(t *testing.T) {
	pool := testPool(t)
	suffix := randomSuffix()
	userID := createPushUser(t, pool, "push-user-"+suffix)

	received := make(chan *http.Request, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	p256dh, auth := validSubscriptionKeys(t)
	endpoint := server.URL + "/push/" + suffix
	insertSubscription(t, pool, userID, endpoint, p256dh, auth)

	vapidPriv, vapidPub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("GenerateVAPIDKeys: %v", err)
	}
	cfg := &config.Config{VAPIDPublicKey: vapidPub, VAPIDPrivateKey: vapidPriv, VAPIDEmail: "mailto:ops@sin.to"}

	push.SendToUser(context.Background(), pool, cfg, userID, push.Notification{
		Title: "Hi", Body: "there", URL: "https://sin.to",
	})

	select {
	case r := <-received:
		if r.Method != http.MethodPost {
			t.Errorf("expected POST to the push endpoint, got %s", r.Method)
		}
		if r.Header.Get("Authorization") == "" {
			t.Error("expected a VAPID Authorization header on the push request")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("push endpoint never received a request within 5s")
	}

	// Give the DELETE-on-Gone branch (which we don't expect to fire here) a
	// moment in case it fires erroneously, then confirm the row is intact.
	time.Sleep(200 * time.Millisecond)
	if !subscriptionExists(t, pool, endpoint) {
		t.Error("expected the subscription to remain after a successful (201) push")
	}
}

// TestSendToUser_GoneResponse_RemovesExpiredSubscription verifies that a
// 410 Gone response causes SendToUser to delete the now-invalid
// subscription row, so future sends don't keep hitting a dead endpoint.
func TestSendToUser_GoneResponse_RemovesExpiredSubscription(t *testing.T) {
	pool := testPool(t)
	suffix := randomSuffix()
	userID := createPushUser(t, pool, "push-gone-user-"+suffix)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer server.Close()

	p256dh, auth := validSubscriptionKeys(t)
	endpoint := server.URL + "/push/" + suffix
	insertSubscription(t, pool, userID, endpoint, p256dh, auth)

	vapidPriv, vapidPub, err := webpush.GenerateVAPIDKeys()
	if err != nil {
		t.Fatalf("GenerateVAPIDKeys: %v", err)
	}
	cfg := &config.Config{VAPIDPublicKey: vapidPub, VAPIDPrivateKey: vapidPriv, VAPIDEmail: "mailto:ops@sin.to"}

	push.SendToUser(context.Background(), pool, cfg, userID, push.Notification{
		Title: "Hi", Body: "there", URL: "https://sin.to",
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !subscriptionExists(t, pool, endpoint) {
			return // deleted, as expected
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("expected the subscription to be deleted after a 410 Gone response, but it still exists after 5s")
}

// TestSendToUser_NoSubscriptions_NoRequestsSent verifies that a user with
// zero push_subscriptions rows results in no outbound requests at all
// (rather than e.g. panicking on an empty slice).
func TestSendToUser_NoSubscriptions_NoRequestsSent(t *testing.T) {
	pool := testPool(t)
	suffix := randomSuffix()
	userID := createPushUser(t, pool, "push-nosub-user-"+suffix)

	requestSeen := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestSeen <- struct{}{}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	cfg := &config.Config{VAPIDPublicKey: "pub", VAPIDPrivateKey: "priv"}

	push.SendToUser(context.Background(), pool, cfg, userID, push.Notification{
		Title: "Hi", Body: "there", URL: "https://sin.to",
	})

	select {
	case <-requestSeen:
		t.Fatal("expected no requests to be sent for a user with no push subscriptions")
	case <-time.After(300 * time.Millisecond):
		// no request arrived, as expected
	}
}
