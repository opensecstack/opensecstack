package handlers

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/opensecstack/community/internal/config"
)

func newBadPoolForNotifyTests(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), "postgres://invalid:invalid@127.0.0.1:1/nodb?connect_timeout=1")
	if err != nil {
		t.Skip("cannot create pool stub:", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestCreateNotification_SelfNotification_SkipsInsert verifies the guard:
// when userID == actorID, createNotification must return without issuing
// any DB call. We can't directly observe "no call happened", but we CAN
// prove it doesn't panic/hang against a nil pool, which it would if it
// tried to call pool.Exec on a nil *pgxpool.Pool.
func TestCreateNotification_SelfNotification_SkipsInsert(t *testing.T) {
	cfg := &config.Config{}
	createNotification(context.Background(), nil, cfg, "user-1", "user-1", "comment_on_post", nil, nil)
}

// TestCreateSpaceNotification_SelfNotification_SkipsInsert mirrors the
// above guard on createSpaceNotification.
func TestCreateSpaceNotification_SelfNotification_SkipsInsert(t *testing.T) {
	cfg := &config.Config{}
	createSpaceNotification(context.Background(), nil, cfg, "user-1", "user-1", "space_joined", "space-1")
}

// TestCreateNotification_DifferentActor_DoesNotPanicOnDBError verifies the
// non-self-notification path handles a failing pool.Exec gracefully.
func TestCreateNotification_DifferentActor_DoesNotPanicOnDBError(t *testing.T) {
	pool := newBadPoolForNotifyTests(t)
	cfg := &config.Config{}
	postID := "post-1"
	createNotification(context.Background(), pool, cfg, "user-1", "user-2", "comment_on_post", &postID, nil)
}

// TestCreateSystemNotification_DoesNotPanicOnDBError verifies
// createSystemNotification (which bypasses the self-notify guard by design)
// handles a failing pool.Exec gracefully.
func TestCreateSystemNotification_DoesNotPanicOnDBError(t *testing.T) {
	pool := newBadPoolForNotifyTests(t)
	createSystemNotification(context.Background(), pool, "user-1", "welcome", nil)
}

// TestNotifPayload_KnownTypes verifies each notification type maps to its
// documented title/body/URL. This is an internal (package handlers) test
// because notifPayload is unexported.
func TestNotifPayload_KnownTypes(t *testing.T) {
	postID := "post-123"
	tests := []struct {
		notifType string
		postID    *string
		wantTitle string
		wantURL   string
	}{
		{"comment_on_post", &postID, "SIN", "/posts/post-123"},
		{"reaction_on_post", &postID, "SIN", "/posts/post-123"},
		{"new_follower", &postID, "SIN", "/"},
		{"mentioned_in_comment", &postID, "SIN", "/posts/post-123"},
		{"welcome", nil, "Welcome to SIN", "/"},
		{"password_changed", nil, "SIN Security", "/settings"},
		{"space_joined", nil, "SIN", "/spaces"},
		{"space_member_joined", nil, "SIN", "/spaces"},
		{"space_invite", nil, "SIN", "/spaces"},
		{"totally_unknown_type", nil, "SIN", "/"},
	}
	for _, tt := range tests {
		got := notifPayload(tt.notifType, tt.postID)
		if got.Title != tt.wantTitle {
			t.Errorf("%s: expected title %q, got %q", tt.notifType, tt.wantTitle, got.Title)
		}
		if got.URL != tt.wantURL {
			t.Errorf("%s: expected URL %q, got %q", tt.notifType, tt.wantURL, got.URL)
		}
		if got.Body == "" {
			t.Errorf("%s: expected non-empty body", tt.notifType)
		}
	}
}

func TestNotifPayload_NilPostID_UsesRootURL(t *testing.T) {
	got := notifPayload("comment_on_post", nil)
	if got.URL != "/" {
		t.Errorf("expected root URL when postID is nil, got %q", got.URL)
	}
}

func TestNotifPayload_EmptyPostID_UsesRootURL(t *testing.T) {
	empty := ""
	got := notifPayload("comment_on_post", &empty)
	if got.URL != "/" {
		t.Errorf("expected root URL when postID is empty string, got %q", got.URL)
	}
}
