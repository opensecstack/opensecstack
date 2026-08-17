package handlers_test

// Tests for push.go — SubscribePush and UnsubscribePush had zero coverage
// prior to this file. They cover: the auth guard, request validation, the
// "user not found" branch, and the real DB upsert / delete behavior.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

func TestSubscribePush_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/push-subscription", nil)
	w := httptest.NewRecorder()

	handlers.SubscribePush(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestSubscribePush_InvalidBody_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/push-subscription", bytes.NewReader([]byte("not json")))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SubscribePush(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed body, got %d", w.Code)
	}
}

func TestSubscribePush_MissingFields_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	body, _ := json.Marshal(map[string]string{"endpoint": "https://push.example.com/x"})
	// p256dh and auth are missing.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/push-subscription", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SubscribePush(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for missing fields, got %d", w.Code)
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "endpoint, p256dh and auth are required" {
		t.Errorf("unexpected error message: %q", resp["error"])
	}
}

func TestSubscribePush_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	body, _ := json.Marshal(map[string]string{
		"endpoint": "https://push.example.com/x",
		"p256dh":   "p256dh-key",
		"auth":     "auth-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/push-subscription", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "ghost-user", Role: "author"})
	w := httptest.NewRecorder()

	handlers.SubscribePush(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when the claimed user has no DB row, got %d", w.Code)
	}
}

// TestSubscribePush_HappyPath_UpsertsSubscriptionRow proves SubscribePush
// actually writes a row into push_subscriptions for the authenticated user,
// against a real DB.
func TestSubscribePush_HappyPath_UpsertsSubscriptionRow(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")
	endpoint := "https://push.example.com/" + handlers.RandomSuffix()

	body, _ := json.Marshal(map[string]string{
		"endpoint": endpoint,
		"p256dh":   "p256dh-key",
		"auth":     "auth-secret",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/push-subscription", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.SubscribePush(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var p256dh, authSecret string
	err := d.Pool.QueryRow(context.Background(),
		`SELECT p256dh, auth FROM push_subscriptions WHERE endpoint = $1`, endpoint,
	).Scan(&p256dh, &authSecret)
	if err != nil {
		t.Fatalf("expected a push_subscriptions row for endpoint %q: %v", endpoint, err)
	}
	if p256dh != "p256dh-key" || authSecret != "auth-secret" {
		t.Errorf("unexpected stored values: p256dh=%q auth=%q", p256dh, authSecret)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM push_subscriptions WHERE endpoint = $1`, endpoint)
	})
}

// TestSubscribePush_ConflictingEndpoint_UpdatesExistingRow proves the
// ON CONFLICT(endpoint) DO UPDATE branch actually re-keys an existing
// subscription's keys rather than erroring or leaving stale data.
func TestSubscribePush_ConflictingEndpoint_UpdatesExistingRow(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")
	endpoint := "https://push.example.com/" + handlers.RandomSuffix()
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM push_subscriptions WHERE endpoint = $1`, endpoint)
	})

	firstBody, _ := json.Marshal(map[string]string{
		"endpoint": endpoint, "p256dh": "old-key", "auth": "old-secret",
	})
	req1 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/me/push-subscription", bytes.NewReader(firstBody)), &auth.Claims{Sub: username, Role: "author"})
	handlers.SubscribePush(d)(httptest.NewRecorder(), req1)

	secondBody, _ := json.Marshal(map[string]string{
		"endpoint": endpoint, "p256dh": "new-key", "auth": "new-secret",
	})
	req2 := withClaims(httptest.NewRequest(http.MethodPost, "/api/v1/me/push-subscription", bytes.NewReader(secondBody)), &auth.Claims{Sub: username, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.SubscribePush(d)(w2, req2)

	if w2.Code != http.StatusNoContent {
		t.Fatalf("expected 204 on re-subscribe, got %d", w2.Code)
	}

	var p256dh string
	var count int
	err := d.Pool.QueryRow(context.Background(),
		`SELECT p256dh FROM push_subscriptions WHERE endpoint = $1`, endpoint,
	).Scan(&p256dh)
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if p256dh != "new-key" {
		t.Errorf("expected upsert to overwrite p256dh with %q, got %q", "new-key", p256dh)
	}
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM push_subscriptions WHERE endpoint = $1`, endpoint,
	).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 1 {
		t.Errorf("expected exactly one row for the endpoint after upsert, got %d", count)
	}
}

func TestUnsubscribePush_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/push-subscription", nil)
	w := httptest.NewRecorder()

	handlers.UnsubscribePush(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without claims, got %d", w.Code)
	}
}

func TestUnsubscribePush_InvalidBody_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/push-subscription", bytes.NewReader([]byte("not json")))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnsubscribePush(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for malformed body, got %d", w.Code)
	}
}

func TestUnsubscribePush_MissingEndpoint_Returns400(t *testing.T) {
	d := newDepsWithBadDB(t)
	body, _ := json.Marshal(map[string]string{})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/push-subscription", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "alice", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnsubscribePush(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing endpoint, got %d", w.Code)
	}
}

func TestUnsubscribePush_UserNotFound_Returns404(t *testing.T) {
	d := newDepsWithBadDB(t)
	body, _ := json.Marshal(map[string]string{"endpoint": "https://push.example.com/x"})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/push-subscription", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: "ghost-user", Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnsubscribePush(d)(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("expected 404 when the claimed user has no DB row, got %d", w.Code)
	}
}

// TestUnsubscribePush_HappyPath_DeletesSubscriptionRow proves UnsubscribePush
// actually removes the row for the authenticated user + endpoint pair, and
// leaves other users' subscriptions on the same endpoint alone would not
// apply here (endpoint is globally unique), so we instead prove it only
// deletes the matching row and not unrelated subscriptions for the same
// user.
func TestUnsubscribePush_HappyPath_DeletesSubscriptionRow(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")
	targetEndpoint := "https://push.example.com/target-" + handlers.RandomSuffix()
	otherEndpoint := "https://push.example.com/other-" + handlers.RandomSuffix()

	var userID string
	if err := d.Pool.QueryRow(context.Background(), `SELECT id FROM users WHERE username=$1`, username).Scan(&userID); err != nil {
		t.Fatalf("lookup user id: %v", err)
	}
	for _, ep := range []string{targetEndpoint, otherEndpoint} {
		if _, err := d.Pool.Exec(context.Background(),
			`INSERT INTO push_subscriptions(user_id, endpoint, p256dh, auth) VALUES ($1,$2,'k','s')`,
			userID, ep,
		); err != nil {
			t.Fatalf("seed subscription %q: %v", ep, err)
		}
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM push_subscriptions WHERE endpoint IN ($1,$2)`, targetEndpoint, otherEndpoint)
	})

	body, _ := json.Marshal(map[string]string{"endpoint": targetEndpoint})
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/me/push-subscription", bytes.NewReader(body))
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.UnsubscribePush(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}

	var count int
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM push_subscriptions WHERE endpoint = $1`, targetEndpoint,
	).Scan(&count); err != nil {
		t.Fatalf("count target: %v", err)
	}
	if count != 0 {
		t.Errorf("expected target endpoint subscription to be deleted, still found %d row(s)", count)
	}
	if err := d.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM push_subscriptions WHERE endpoint = $1`, otherEndpoint,
	).Scan(&count); err != nil {
		t.Fatalf("count other: %v", err)
	}
	if count != 1 {
		t.Errorf("expected unrelated subscription to survive, found %d row(s)", count)
	}
}
