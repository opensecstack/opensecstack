package handlers_test

// Live-DB tests for the notifications HTTP handlers (notifications.go):
// ListNotifications, MarkNotificationRead, MarkAllNotificationsRead. This is
// distinct from internal/notifications (the email/digest package), which is
// out of scope here. Pure helpers (encodeCursor/decodeCursor) are already
// covered by notifications_cursor_internal_test.go.
//
// Authz is the important thing to prove: every query here is scoped by the
// resolved user_id, so one user must never be able to read or mark another
// user's notifications as read via a guessed/enumerated notification ID.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/opensecstack/community/internal/api/handlers"
	"github.com/opensecstack/community/internal/auth"
)

// seedNotification inserts a notification row for userID and returns its id.
func seedNotification(t *testing.T, d handlers.Deps, userID, notifType string) string {
	t.Helper()
	var id string
	err := d.Pool.QueryRow(context.Background(),
		`INSERT INTO notifications (user_id, type, read) VALUES ($1,$2,false) RETURNING id`,
		userID, notifType,
	).Scan(&id)
	if err != nil {
		t.Fatalf("seedNotification: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Pool.Exec(context.Background(), `DELETE FROM notifications WHERE id=$1`, id)
	})
	return id
}

func TestListNotifications_Success_ReturnsOwnNotificationsAndUnreadCount(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")
	otherID, _ := createTestUser(t, d.Pool, "author")

	ownID := seedNotification(t, d, userID, "welcome")
	seedNotification(t, d, otherID, "welcome") // must not appear

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListNotifications(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var resp struct {
		Notifications []map[string]any `json:"notifications"`
		Count         int              `json:"count"`
		UnreadCount   int              `json:"unread_count"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, n := range resp.Notifications {
		if n["id"] == ownID {
			found = true
		}
		if n["id"] == otherID {
			t.Errorf("IDOR: another user's notification %v must not appear in the list", n["id"])
		}
	}
	if !found {
		t.Errorf("expected own notification %q in list, got %+v", ownID, resp.Notifications)
	}
	if resp.UnreadCount < 1 {
		t.Errorf("expected unread_count >= 1, got %d", resp.UnreadCount)
	}
}

func TestListNotifications_NoClaims_Returns401(t *testing.T) {
	d := handlers.Deps{}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications", nil)
	w := httptest.NewRecorder()

	handlers.ListNotifications(d)(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestListNotifications_Pagination_CursorExcludesAlreadySeenRow(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")
	first := seedNotification(t, d, userID, "welcome")
	second := seedNotification(t, d, userID, "welcome")

	// Page 1: limit=1, expect the most recently created row and a next_cursor.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications?limit=1", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()
	handlers.ListNotifications(d)(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
	var page1 struct {
		Notifications []map[string]any `json:"notifications"`
		NextCursor    *string          `json:"next_cursor"`
	}
	_ = json.NewDecoder(w.Body).Decode(&page1)
	if len(page1.Notifications) != 1 {
		t.Fatalf("expected exactly 1 notification on page 1, got %d", len(page1.Notifications))
	}
	if page1.NextCursor == nil {
		t.Fatal("expected a next_cursor when the page is full")
	}
	firstPageID := page1.Notifications[0]["id"]
	if firstPageID != second {
		t.Errorf("expected most recent notification %q first, got %v", second, firstPageID)
	}

	// Page 2: use the cursor, expect the other notification and no overlap.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications?limit=1&cursor="+*page1.NextCursor, nil)
	req2 = withClaims(req2, &auth.Claims{Sub: username, Role: "author"})
	w2 := httptest.NewRecorder()
	handlers.ListNotifications(d)(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d — body: %s", w2.Code, w2.Body.String())
	}
	var page2 struct {
		Notifications []map[string]any `json:"notifications"`
	}
	_ = json.NewDecoder(w2.Body).Decode(&page2)
	if len(page2.Notifications) != 1 {
		t.Fatalf("expected exactly 1 notification on page 2, got %d", len(page2.Notifications))
	}
	if page2.Notifications[0]["id"] != first {
		t.Errorf("expected page 2 to contain the older notification %q, got %v", first, page2.Notifications[0]["id"])
	}
}

func TestListNotifications_InvalidCursor_Returns400(t *testing.T) {
	d := dbDeps(t)
	_, username := createTestUser(t, d.Pool, "author")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/notifications?cursor=not-valid-base64!!!", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.ListNotifications(d)(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for an invalid cursor, got %d", w.Code)
	}
}

func TestMarkNotificationRead_Success_MarksOwnNotification(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")
	notifID := seedNotification(t, d, userID, "welcome")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/notifications/"+notifID+"/read", nil)
	req.SetPathValue("id", notifID)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.MarkNotificationRead(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var read bool
	_ = d.Pool.QueryRow(context.Background(), `SELECT read FROM notifications WHERE id=$1`, notifID).Scan(&read)
	if !read {
		t.Error("expected notification to be marked read")
	}
}

// TestMarkNotificationRead_OtherUsersNotification_DoesNotMark_IDOR proves a
// user cannot mark another user's notification as read by guessing its ID —
// the UPDATE is scoped by `user_id = $2`, so it must affect zero rows and
// leave the victim's notification untouched.
func TestMarkNotificationRead_OtherUsersNotification_DoesNotMark_IDOR(t *testing.T) {
	d := dbDeps(t)
	victimID, _ := createTestUser(t, d.Pool, "author")
	_, attackerUsername := createTestUser(t, d.Pool, "author")
	notifID := seedNotification(t, d, victimID, "welcome")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/notifications/"+notifID+"/read", nil)
	req.SetPathValue("id", notifID)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.MarkNotificationRead(d)(w, req)

	// The handler always returns 204 regardless of whether a row matched
	// (result is discarded), so the only reliable signal is DB state.
	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204 (handler ignores exec result), got %d", w.Code)
	}
	var read bool
	_ = d.Pool.QueryRow(context.Background(), `SELECT read FROM notifications WHERE id=$1`, notifID).Scan(&read)
	if read {
		t.Error("IDOR: another user's notification must not be marked read by a non-owner request")
	}
}

func TestMarkAllNotificationsRead_Success_MarksAllOwnUnread(t *testing.T) {
	d := dbDeps(t)
	userID, username := createTestUser(t, d.Pool, "author")
	id1 := seedNotification(t, d, userID, "welcome")
	id2 := seedNotification(t, d, userID, "welcome")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/notifications/read-all", nil)
	req = withClaims(req, &auth.Claims{Sub: username, Role: "author"})
	w := httptest.NewRecorder()

	handlers.MarkAllNotificationsRead(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d — body: %s", w.Code, w.Body.String())
	}
	var unreadCount int
	_ = d.Pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM notifications WHERE id IN ($1,$2) AND read=false`, id1, id2,
	).Scan(&unreadCount)
	if unreadCount != 0 {
		t.Errorf("expected all own notifications to be marked read, %d still unread", unreadCount)
	}
}

// TestMarkAllNotificationsRead_DoesNotMarkOtherUsersNotifications_IDOR proves
// the bulk mark-all-read is scoped to the caller's own user_id.
func TestMarkAllNotificationsRead_DoesNotMarkOtherUsersNotifications_IDOR(t *testing.T) {
	d := dbDeps(t)
	victimID, _ := createTestUser(t, d.Pool, "author")
	_, attackerUsername := createTestUser(t, d.Pool, "author")
	victimNotifID := seedNotification(t, d, victimID, "welcome")

	req := httptest.NewRequest(http.MethodPost, "/api/v1/me/notifications/read-all", nil)
	req = withClaims(req, &auth.Claims{Sub: attackerUsername, Role: "author"})
	w := httptest.NewRecorder()

	handlers.MarkAllNotificationsRead(d)(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	var read bool
	_ = d.Pool.QueryRow(context.Background(), `SELECT read FROM notifications WHERE id=$1`, victimNotifID).Scan(&read)
	if read {
		t.Error("IDOR: another user's notification must not be marked read by MarkAllNotificationsRead")
	}
}
